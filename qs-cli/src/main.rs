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
    },
    #[clap(
        name = "config",
        about = "Show the config file and the settings in effect"
    )]
    Config,
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

    match args.mode {
        Mode::Send {
            files,
            direct,
            password,
        } => {
            let settings = Settings::resolve(&args.network, None, config);
            send(settings, files, direct, password).await
        }
        Mode::Receive {
            overwrite,
            output,
            here,
            code,
            auto_accept,
            password,
        } => {
            // Paths may have been dragged into the terminal
            let output = if here {
                Some(PathBuf::from("."))
            } else {
                output.map(drop::normalize_path_arg)
            };
            let settings = Settings::resolve(&args.network, output, config);
            receive(settings, code, overwrite, auto_accept, password).await
        }
        Mode::Config => {
            let settings = Settings::resolve(&args.network, None, config);
            show_config(&settings, config_path.as_deref())
        }
    }
}

/// The client for the rendezvous server in `settings`, if one is set
fn rendezvous(settings: &Settings, endpoint: &Endpoint) -> Result<Option<Client>, PairingError> {
    settings
        .rendezvous_url
        .as_deref()
        .map(|url| Client::new(url, endpoint.tls_config().clone()))
        .transpose()
}

async fn send(
    settings: Settings,
    files: Vec<PathBuf>,
    direct: bool,
    password: bool,
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

    let endpoint = net::bind(&settings, SecretKey::generate()).await?;
    let addr = net::own_addr(&endpoint, &settings.relay).await?;

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
            println!("\nThis device: {}", endpoint.id().fmt_short());

            // Only the receiver that knew the code is let in
            let peer = offer.wait_for_receiver(&addr).await?;
            set_pending_slot(None);

            SenderArgs {
                files,
                expected_peer: Some(peer),
                // The password already went into the pairing
                password: None,
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
            println!("This device: {}", endpoint.id().fmt_short());

            SenderArgs {
                files,
                expected_peer: None,
                password,
            }
        }
    };

    let mut sender = Sender::connect(endpoint, sender_args).await?;
    println!("Receiver:    {}", sender.remote_id().fmt_short());

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

    std::mem::drop(clipboard);
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
) -> Result<(), Failure> {
    let output = resolve_output_dir(settings.output_dir.clone())?;
    println!(
        "Files will be saved to: {}\n",
        output.display().to_string().bright_white()
    );

    let input = match code {
        Some(code) => code,
        None => dialoguer::Input::new()
            .with_prompt("Enter the code or ticket of the sender")
            .interact()?,
    };

    let mut password = password.then(password::ask).transpose()?;

    let endpoint = net::bind(&settings, SecretKey::generate()).await?;
    println!("This device: {}", endpoint.id().fmt_short());

    let receiver_args = || ReceiverArgs { resume: !overwrite };

    let mut receiver = if looks_like_code(&input) {
        // The password goes into the pairing, the connection needs none after that
        let addr = pair(&settings, &endpoint, &input, password.take()).await?;
        Receiver::connect(endpoint, addr, receiver_args()).await?
    } else {
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
    };
    println!("Sender:      {}", receiver.remote_id().fmt_short());

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
