use clap::{Parser, Subcommand};
use colored::Colorize;
use config::{Config, NetworkArgs, RelaySetting, Settings};
use iroh::{Endpoint, EndpointAddr, SecretKey};
use qs_core::{
    direct::Ticket,
    pairing::{
        code::{looks_like_code, Code},
        rendezvous::Client,
        Claim, Offer, PairingError, SlotHandle,
    },
    receive::{Receiver, ReceiverArgs},
    send::{SendError, Sender, SenderArgs},
    QS_PROTO_VERSION,
};
use std::{
    cell::RefCell,
    io::{self, IsTerminal, Write},
    path::PathBuf,
    process::ExitCode,
    rc::Rc,
    str::FromStr,
    sync::Mutex,
    time::Duration,
};
use tracing::Level;
use tracing_subscriber::{
    filter::{LevelFilter, Targets},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};
use ui::CliProgressBars;
use zeroize::Zeroizing;

mod config;
mod drop;
mod net;
mod password;
mod peers;
mod ui;

#[derive(Parser, Debug)]
#[clap(version = QS_PROTO_VERSION, author = env!("CARGO_PKG_AUTHORS"))]
struct Args {
    /// Log level
    #[clap(long, short, default_value = "error", global = true)]
    log_level: tracing::Level,

    /// Use this config file instead of the default one
    #[clap(long, value_name = "FILE", global = true)]
    config: Option<PathBuf>,

    #[clap(flatten)]
    network: NetworkArgs,

    /// Send or receive files
    #[clap(subcommand)]
    mode: Mode,
}

#[derive(Subcommand, Debug)]
enum Mode {
    #[clap(name = "send", about = "Send files", aliases = &["s"])]
    Send {
        /// Files/directories to send. Leave out to drag them into the terminal instead
        #[clap(name = "files or directories")]
        files: Vec<PathBuf>,

        /// Print a ticket with address and key instead of using the rendezvous server
        #[clap(long)]
        direct: bool,

        /// Protect the transfer with a password in addition to the code or ticket.
        /// You are asked for it, it is never given on the command line
        #[clap(long, short)]
        password: bool,

        /// Send to a saved peer, without code or ticket. It has to be waiting with
        /// `qs receive --from <you>`
        #[clap(long, value_name = "NAME", conflicts_with = "direct")]
        to: Option<String>,

        /// Save the receiver under this name for `--to`. Both sides have to ask for it
        #[clap(long, value_name = "NAME")]
        save_peer: Option<String>,
    },
    #[clap(name = "receive", about = "Receive files", aliases = &["r"])]
    Receive {
        /// Overwrite existing files and folders instead of resuming or renaming
        #[clap(long, short = 'f')]
        overwrite: bool,

        /// Output directory [default: from the config file, else your Downloads folder]
        #[clap(long, short)]
        output: Option<PathBuf>,

        /// Save into the directory you are in, same as `-o .`
        #[clap(long, conflicts_with = "output")]
        here: bool,

        /// The code or ticket of the sender
        code: Option<String>,

        /// Automatically accept the files
        #[clap(long, short = 'y')]
        auto_accept: bool,

        /// Ask for the password right away. Without this you are asked if the sender set one
        #[clap(long, short)]
        password: bool,

        /// Wait for a saved peer to send, without code or ticket
        #[clap(long, value_name = "NAME", conflicts_with = "code")]
        from: Option<String>,

        /// Save the sender under this name for `--from`. Both sides have to ask for it
        #[clap(long, value_name = "NAME")]
        save_peer: Option<String>,
    },
    #[clap(
        name = "config",
        about = "Show the config file and the settings in effect"
    )]
    Config,
    #[clap(name = "peers", about = "List the saved peers, or remove one")]
    Peers {
        #[clap(subcommand)]
        action: Option<PeersAction>,
    },
}

#[derive(Subcommand, Debug)]
enum PeersAction {
    #[clap(about = "Forget a saved peer")]
    Remove {
        /// The name the peer was saved under
        name: String,
    },
}

/// An error to show to the user as it is, without a backtrace
type Failure = Box<dyn std::error::Error>;

/// The slot to give up if the user presses Ctrl+C while a pairing is under way
static PENDING_SLOT: Mutex<Option<SlotHandle>> = Mutex::new(None);

fn set_pending_slot(slot: Option<SlotHandle>) {
    if let Ok(mut pending) = PENDING_SLOT.lock() {
        *pending = slot;
    }
}

/// Stop on Ctrl+C. A code that is still waiting is given up first, so the other side is
/// told at once instead of waiting for it to expire.
fn watch_ctrl_c() {
    tokio::spawn(async {
        if tokio::signal::ctrl_c().await.is_err() {
            return;
        }

        let slot = PENDING_SLOT.lock().ok().and_then(|mut slot| slot.take());
        if let Some(slot) = slot {
            let _ = tokio::time::timeout(Duration::from_secs(3), slot.cancel()).await;
        }

        // A prompt or progress bar may have hidden the cursor
        let _ = console::Term::stderr().show_cursor();
        eprintln!();
        std::process::exit(130);
    });
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Args = Args::parse();

    // Dependencies (mostly iroh) only log when debugging,
    // their errors on shutdown are noise for everyone else.
    let level = args.log_level;
    let dependencies = if level >= Level::DEBUG {
        LevelFilter::from_level(level)
    } else {
        LevelFilter::OFF
    };
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            Targets::new()
                .with_target("qs", level)
                .with_target("qs_core", level)
                .with_default(dependencies),
        )
        .init();

    // Make sure colors work correctly in cmd.exe.
    #[cfg(windows)]
    {
        let _ = colored::control::set_virtual_terminal(true);
    }

    tracing::debug!("qs {}", QS_PROTO_VERSION);
    watch_ctrl_c();

    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{} {e}", "error:".red().bold());
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<(), Failure> {
    let (config, config_path) = Config::load(args.config.as_deref())?;
    // Identity and saved peers live next to the config file
    let state_dir = || peers::state_dir(args.config.as_deref());

    match args.mode {
        Mode::Send {
            files,
            direct,
            password,
            to,
            save_peer,
        } => {
            let settings = Settings::resolve(&args.network, None, config);
            let peers = PeerOptions::new(to, save_peer, state_dir)?;
            send(settings, files, direct, password, peers).await
        }
        Mode::Receive {
            overwrite,
            output,
            here,
            code,
            auto_accept,
            password,
            from,
            save_peer,
        } => {
            // Paths may have been dragged into the terminal
            let output = if here {
                Some(PathBuf::from("."))
            } else {
                output.map(drop::normalize_path_arg)
            };
            let settings = Settings::resolve(&args.network, output, config);
            let peers = PeerOptions::new(from, save_peer, state_dir)?;
            receive(settings, code, overwrite, auto_accept, password, peers).await
        }
        Mode::Config => {
            let settings = Settings::resolve(&args.network, None, config);
            show_config(&settings, config_path.as_deref())
        }
        Mode::Peers { action } => {
            let settings = Settings::resolve(&args.network, None, config);
            match action {
                None => peers::list(&state_dir()?, &settings),
                Some(PeersAction::Remove { name }) => peers::remove(&state_dir()?, &name),
            }
        }
    }
}

/// What a transfer has to do with saved peers
struct PeerOptions {
    /// The saved peer to send to or receive from, instead of a code or ticket
    known: Option<String>,
    /// The name to save the other side under
    save_as: Option<String>,
    /// Where the identity and the saved peers are kept. Only looked up when needed.
    dir: Option<PathBuf>,
}

impl PeerOptions {
    fn new(
        known: Option<String>,
        save_as: Option<String>,
        state_dir: impl Fn() -> Result<PathBuf, Failure>,
    ) -> Result<Self, Failure> {
        let dir = (known.is_some() || save_as.is_some())
            .then(state_dir)
            .transpose()?;
        Ok(Self {
            known,
            save_as,
            dir,
        })
    }

    /// The key for this run: the identity that stays when peers are involved,
    /// otherwise a fresh one that nothing can be linked to
    fn secret_key(&self) -> Result<SecretKey, Failure> {
        match &self.dir {
            Some(dir) => peers::identity(dir),
            None => Ok(SecretKey::generate()),
        }
    }

    /// The own address to tell the other side, if this run uses the identity that stays
    fn announce(&self, addr: &EndpointAddr) -> Option<EndpointAddr> {
        self.dir.is_some().then(|| addr.clone())
    }

    /// Save the other side if that was asked for. `verified` says whether a code, a
    /// password or the key of a ticket vouches for it.
    fn remember(&self, peer: Option<&EndpointAddr>, verified: bool) -> Result<(), Failure> {
        match (&self.save_as, &self.dir) {
            (Some(alias), Some(dir)) => peers::remember(dir, alias, peer, verified),
            _ => Ok(()),
        }
    }

    /// How this device shows itself. When a peer is to be saved the fingerprint is
    /// longer, so the two sides can compare it.
    fn device(&self, id: &iroh::EndpointId) -> String {
        if self.save_as.is_some() {
            peers::fingerprint(id)
        } else {
            id.fmt_short().to_string()
        }
    }
}

/// The client for the rendezvous server in `settings`, if one is set
fn rendezvous(settings: &Settings, endpoint: &Endpoint) -> Result<Option<Client>, PairingError> {
    let client = settings
        .rendezvous_url
        .as_deref()
        .map(|url| Client::new(url, endpoint.tls_config().clone()))
        .transpose()?;

    if client.as_ref().is_some_and(Client::is_unprotected) {
        eprintln!(
            "{} the rendezvous server is reached without TLS. What is exchanged stays \
             sealed, but the pairing can be watched and disturbed on the way. Use https.",
            "note:".yellow().bold()
        );
    }

    Ok(client)
}

async fn send(
    settings: Settings,
    files: Vec<PathBuf>,
    direct: bool,
    password: bool,
    peers: PeerOptions,
) -> Result<(), Failure> {
    // Paths may have been dragged into the terminal
    let mut files: Vec<PathBuf> = files.into_iter().map(drop::normalize_path_arg).collect();

    // Without arguments, files are dragged into the terminal
    if files.is_empty() {
        if !io::stdin().is_terminal() {
            return Err("no files or directories to send given".into());
        }
        files = drop::select_files_interactively()?;
        if files.is_empty() {
            return Err("no files or directories selected".into());
        }
        println!();
    }

    // Check if the files even exist
    if let Some(missing) = files.iter().find(|file| !file.exists()) {
        return Err(SendError::FileDoesNotExists(missing.clone()).into());
    }

    let password = password.then(password::ask_new).transpose()?;

    let endpoint = net::bind(&settings, peers.secret_key()?).await?;
    let addr = net::own_addr(&endpoint, &settings.relay).await?;
    let announce = peers.announce(&addr);

    // A saved peer is dialed, it waits for this device and nobody else
    if let (Some(alias), Some(dir)) = (&peers.known, &peers.dir) {
        let peer = peers::address(dir, &settings, alias)?;
        println!("This device: {}", peers.device(&endpoint.id()));
        println!("Connecting to {} ({})...", alias, peer.id.fmt_short());

        let sender_args = SenderArgs {
            files,
            expected_peer: None,
            password,
            announce,
        };
        let sender = Sender::dial(endpoint, peer, sender_args)
            .await
            .map_err(|e| {
                format!(
                    "could not send to {alias}: {e}\n\
                     It has to be waiting with `qs receive --from <name of this device>`, \
                     and both sides have to have saved each other."
                )
            })?;
        // The receiver is the saved peer, the connection would not exist otherwise
        return send_to(sender, &peers, true).await;
    }

    // With a rendezvous server the receiver gets a short code, without one (or with
    // `--direct`) a ticket that carries the address and the key itself.
    let client = if direct {
        None
    } else {
        rendezvous(&settings, &endpoint)?
    };

    // On Linux the clipboard content is gone once this is dropped,
    // so it is kept alive until the transfer is over.
    let clipboard;

    let sender_args = match client {
        Some(client) => {
            let offer = Offer::create(&client, password.as_deref().map(String::as_str)).await?;
            set_pending_slot(Some(offer.handle()));

            let code = offer.code().to_string();
            clipboard = ui::copy_to_clipboard(&code);
            print_secret("Code", &code, clipboard.is_some());
            println!("on the other peer, run the following command:\n");
            println!("{}\n", format!("qs receive {code}").yellow());
            println!(
                "{}",
                format!(
                    "The other peer needs the same rendezvous server ({}).",
                    client.url()
                )
                .dimmed()
            );
            if password.is_some() {
                println!("{}", "It will be asked for the password.".dimmed());
            }
            println!("\nThis device: {}", peers.device(&endpoint.id()));

            // Only the receiver that knew the code is let in
            let peer = offer.wait_for_receiver(&addr).await?;
            set_pending_slot(None);

            SenderArgs {
                files,
                expected_peer: Some(peer),
                // The password already went into the pairing
                password: None,
                announce,
            }
        }
        None => {
            let ticket = Ticket::new(addr)?;
            let text = ticket.to_string();
            clipboard = ui::copy_to_clipboard(&text);
            print_secret("Ticket", &text, clipboard.is_some());

            // Without a relay the plain addresses are all there is, and short enough to type
            if settings.relay == RelaySetting::Disabled {
                println!("or, typed by hand, one of:\n");
                for line in ticket.typable() {
                    println!("{}", line.bright_white());
                }
                println!();
            }

            println!("on the other peer, run the following command:\n");
            println!("{}\n", "qs receive <ticket>".yellow());
            if password.is_some() {
                println!("{}", "It will be asked for the password.".dimmed());
            }
            println!("This device: {}", peers.device(&endpoint.id()));

            SenderArgs {
                files,
                expected_peer: None,
                password,
                announce,
            }
        }
    };

    // The receiver is vouched for if it knew the code or the password. With a plain
    // ticket it is whoever had the ticket first.
    let verified = sender_args.expected_peer.is_some() || sender_args.password.is_some();
    let sender = Sender::connect(endpoint, sender_args).await?;
    let result = send_to(sender, &peers, verified).await;

    std::mem::drop(clipboard);
    result
}

/// Send the files over a connection that is set up
async fn send_to(mut sender: Sender, peers: &PeerOptions, verified: bool) -> Result<(), Failure> {
    println!("Receiver:    {}", sender.remote_id().fmt_short());
    peers.remember(sender.peer_identity(), verified)?;

    // Give iroh some time to switch the connection to direct
    tokio::time::sleep(Duration::from_secs(4)).await;
    let conn_type = sender.connection_type();
    tracing::debug!("connected with type: {:?}", conn_type);
    println!(
        "Connection type: {}",
        ui::connection_type_info_msg(conn_type)
    );

    let progress_bars: Rc<RefCell<Option<CliProgressBars>>> = Rc::new(RefCell::new(None));
    let rc_clone = Rc::clone(&progress_bars);

    sender
        .send_files(
            || {
                print!("Waiting for the other peer to accept the files...");
                let _ = io::stdout().flush();
            },
            |_accepted| {},
            |initial_progress| {
                println!("\r{}", " ".repeat(49));
                *rc_clone.borrow_mut() = Some(CliProgressBars::new(initial_progress));
            },
            &mut |last_sent| {
                if let Some(pb) = &mut *progress_bars.borrow_mut() {
                    pb.update(last_sent);
                }
            },
            // In the CLI we don't handle the interruption as the user can just Ctrl+C
            &mut || true,
        )
        .await?;

    Ok(())
}

/// Show a code or ticket, and say whether it is on the clipboard
fn print_secret(name: &str, text: &str, copied: bool) {
    if copied {
        println!(
            "{name} (copied to your clipboard):\n\n{}\n",
            text.bright_white()
        );
    } else {
        println!("{name}:\n\n{}\n", text.bright_white());
    }
}

/// Find the sender's address with a short code. Asks for the password if the sender
/// set one and none was given yet.
async fn pair(
    settings: &Settings,
    endpoint: &Endpoint,
    input: &str,
    password: Option<Zeroizing<String>>,
) -> Result<EndpointAddr, Failure> {
    let code: Code = input.parse()?;

    let Some(client) = rendezvous(settings, endpoint)? else {
        return Err(
            "this looks like a short code, but no rendezvous server is set. \
             Use --rendezvous <url> or `rendezvous_url` in the config file"
                .into(),
        );
    };

    let claim = Claim::new(&client, code).await?;
    set_pending_slot(Some(claim.handle()));

    let password = match (claim.password_required(), password) {
        (true, None) => {
            println!("The sender protected this transfer with a password.");
            Some(password::ask()?)
        }
        (false, Some(_)) => {
            if !password::confirm_without()? {
                claim.handle().cancel().await;
                set_pending_slot(None);
                return Err(PairingError::UnexpectedPassword.into());
            }
            None
        }
        (_, password) => password,
    };

    let addr = claim
        .complete(password.as_deref().map(String::as_str), endpoint.id())
        .await?;
    set_pending_slot(None);

    Ok(addr)
}

async fn receive(
    settings: Settings,
    code: Option<String>,
    overwrite: bool,
    auto_accept: bool,
    password: bool,
    peers: PeerOptions,
) -> Result<(), Failure> {
    let output = resolve_output_dir(settings.output_dir.clone())?;
    println!(
        "Files will be saved to: {}\n",
        output.display().to_string().bright_white()
    );

    // A saved peer needs no code, everyone else is asked for one if none was given
    let input = match (&peers.known, code) {
        (Some(_), _) => None,
        (None, Some(code)) => Some(code),
        (None, None) => Some(
            dialoguer::Input::new()
                .with_prompt("Enter the code or ticket of the sender")
                .interact()?,
        ),
    };

    let mut password = password.then(password::ask).transpose()?;

    let endpoint = net::bind(&settings, peers.secret_key()?).await?;
    println!("This device: {}", peers.device(&endpoint.id()));

    // Telling the own address is only needed when the sender is to save this device
    let announce = match &peers.dir {
        Some(_) => peers.announce(&net::own_addr(&endpoint, &settings.relay).await?),
        None => None,
    };
    let receiver_args = || ReceiverArgs {
        resume: !overwrite,
        announce: announce.clone(),
    };

    let mut receiver = match (&peers.known, &peers.dir, input) {
        (Some(alias), Some(dir), _) => {
            let peer = peers::lookup(dir, &settings, alias)?;
            println!("Waiting for {} ({})...", alias, peer.id.fmt_short());
            let mut receiver = Receiver::accept(endpoint, peer.id, receiver_args()).await?;

            if receiver.password_required() && password.is_none() {
                return Err("the sender set a password. Start again with --password, \
                     the sender has to send again as well"
                    .into());
            }
            receiver
                .authenticate(password.as_deref().map(String::as_str))
                .await?;
            receiver
        }
        (_, _, Some(input)) if looks_like_code(&input) => {
            // The password goes into the pairing, the connection needs none after that
            let addr = pair(&settings, &endpoint, &input, password.take()).await?;
            Receiver::connect(endpoint, addr, receiver_args()).await?
        }
        (_, _, Some(input)) => {
            let addr = Ticket::from_str(&input)?.into_addr();
            let mut receiver = Receiver::connect(endpoint, addr.clone(), receiver_args()).await?;

            // The sender only waits a moment for the password. If it has to be asked for
            // first, hang up, ask, and come back with it.
            if receiver.password_required() && password.is_none() {
                let endpoint = receiver.disconnect().await;
                println!("The sender protected this transfer with a password.");
                password = Some(password::ask()?);
                receiver = Receiver::connect(endpoint, addr, receiver_args()).await?;
            }

            receiver
                .authenticate(password.as_deref().map(String::as_str))
                .await?;
            receiver
        }
        (_, _, None) => return Err("no code or ticket given".into()),
    };
    println!("Sender:      {}", receiver.remote_id().fmt_short());
    // The sender is always vouched for: by the code, by the key in the ticket, or by
    // being the saved peer this device waited for
    peers.remember(receiver.peer_identity(), true)?;

    // Give iroh some time to switch the connection to direct
    tokio::time::sleep(Duration::from_secs(4)).await;
    let conn_type = receiver.connection_type();
    tracing::debug!("connected with type: {:?}", conn_type);
    println!(
        "Connection type: {}",
        ui::connection_type_info_msg(conn_type)
    );

    let progress_bars: Rc<RefCell<Option<CliProgressBars>>> = Rc::new(RefCell::new(None));
    let rc_clone = Rc::clone(&progress_bars);

    receiver
        .receive_files(
            |initial_progress| {
                *rc_clone.borrow_mut() = Some(CliProgressBars::new(initial_progress));
            },
            |files_offered| {
                if auto_accept {
                    println!("auto accepting files");
                    tracing::debug!("auto accepting files");
                    Some(output.clone())
                } else if ui::accept_files(files_offered) {
                    Some(output.clone())
                } else {
                    None
                }
            },
            ui::print_destinations,
            &mut |last_received| {
                if let Some(pb) = &mut *progress_bars.borrow_mut() {
                    pb.update(last_received);
                }
            },
            // In the CLI we don't handle the interruption as the user can just Ctrl+C
            &mut || true,
        )
        .await?;

    Ok(())
}

/// Print where the config file is and which settings are in effect
fn show_config(settings: &Settings, path: Option<&std::path::Path>) -> Result<(), Failure> {
    match path {
        Some(path) if path.exists() => println!("Config file: {}", path.display()),
        Some(path) => println!("Config file: {} (not created yet)", path.display()),
        None => println!("Config file: no config directory on this system"),
    }

    println!("\nSettings in effect:");
    println!(
        "  rendezvous_url = {}",
        match &settings.rendezvous_url {
            Some(url) => url.clone(),
            None => "(none, tickets instead of short codes)".to_string(),
        }
    );
    println!("  relay          = {}", settings.relay);
    println!(
        "  output_dir     = {}",
        std::path::absolute(output_dir(settings.output_dir.clone()))?.display()
    );
    println!(
        "  port           = {}",
        match settings.port {
            Some(port) => port.to_string(),
            None => "(random)".to_string(),
        }
    );

    if !settings.known_peers.is_empty() {
        println!("\nKnown peers:");
        for (alias, id) in &settings.known_peers {
            println!("  {alias} = {id}");
        }
    }

    Ok(())
}

/// The output directory: the one given, or the Downloads folder
fn output_dir(output: Option<PathBuf>) -> PathBuf {
    output.unwrap_or_else(|| {
        dirs::download_dir()
            // Minimal setups often have no XDG user dirs configured
            .or_else(|| {
                dirs::home_dir()
                    .map(|home| home.join("Downloads"))
                    .filter(|d| d.is_dir())
            })
            .unwrap_or_else(|| PathBuf::from("."))
    })
}

/// The output directory, created if missing and as an absolute path.
/// A relative path, like `.`, is relative to the directory qs was started in.
fn resolve_output_dir(output: Option<PathBuf>) -> io::Result<PathBuf> {
    let output = output_dir(output);
    std::fs::create_dir_all(&output)?;
    std::path::absolute(output)
}
