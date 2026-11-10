use clap::{Parser, Subcommand};
use colored::Colorize;
use config::{Config, NetworkArgs, RelaySetting, Settings};
use iroh::SecretKey;
use qs_core::{
    direct::Ticket,
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
    time::Duration,
};
use tracing::Level;
use tracing_subscriber::{
    filter::{LevelFilter, Targets},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};
use ui::CliProgressBars;

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

        /// The ticket of the sender
        code: Option<String>,

        /// Automatically accept the files
        #[clap(long, short = 'y')]
        auto_accept: bool,
    },
    #[clap(
        name = "config",
        about = "Show the config file and the settings in effect"
    )]
    Config,
}

/// An error to show to the user as it is, without a backtrace
type Failure = Box<dyn std::error::Error>;

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
        Mode::Send { files, direct } => {
            let settings = Settings::resolve(&args.network, None, config);
            send(settings, files, direct).await
        }
        Mode::Receive {
            overwrite,
            output,
            here,
            code,
            auto_accept,
        } => {
            // Paths may have been dragged into the terminal
            let output = if here {
                Some(PathBuf::from("."))
            } else {
                output.map(drop::normalize_path_arg)
            };
            let settings = Settings::resolve(&args.network, output, config);
            receive(settings, code, overwrite, auto_accept).await
        }
        Mode::Config => {
            let settings = Settings::resolve(&args.network, None, config);
            show_config(&settings, config_path.as_deref())
        }
    }
}

async fn send(settings: Settings, files: Vec<PathBuf>, _direct: bool) -> Result<(), Failure> {
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

    let endpoint = net::bind(&settings, SecretKey::generate()).await?;
    let addr = net::own_addr(&endpoint, &settings.relay).await?;

    // TODO: with a rendezvous url configured and without `--direct`, do not print the
    // ticket. Create a slot, show the short code (`qs_core::pairing::code`), and finish the
    // pairing before connecting. Ask for the optional password through `password` first.
    let ticket = Ticket::new(addr)?;
    let text = ticket.to_string();

    // On Linux the clipboard content is gone once this is dropped,
    // so it is kept alive until the transfer is over.
    let clipboard = ui::copy_to_clipboard(&text);

    if clipboard.is_some() {
        println!(
            "Ticket (copied to your clipboard):\n\n{}\n",
            text.bright_white()
        );
    } else {
        println!("Ticket:\n\n{}\n", text.bright_white());
    }

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
    println!("This device: {}", endpoint.id().fmt_short());

    let sender_args = SenderArgs {
        files,
        expected_peer: None,
        password: None,
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

async fn receive(
    settings: Settings,
    code: Option<String>,
    overwrite: bool,
    auto_accept: bool,
) -> Result<(), Failure> {
    let output = resolve_output_dir(settings.output_dir.clone())?;
    println!(
        "Files will be saved to: {}\n",
        output.display().to_string().bright_white()
    );

    let input = match code {
        Some(code) => code,
        None => dialoguer::Input::new()
            .with_prompt("Enter the ticket to connect")
            .interact()?,
    };

    // TODO: accept a short code here as well as a ticket, tell them apart by length and
    // format. Errors must separate wrong code, slot expired, slot already used and server
    // unreachable.
    let ticket = Ticket::from_str(&input)?;

    let endpoint = net::bind(&settings, SecretKey::generate()).await?;
    println!("This device: {}", endpoint.id().fmt_short());

    let receiver_args = ReceiverArgs { resume: !overwrite };
    let mut receiver = Receiver::connect(endpoint, ticket.into_addr(), receiver_args).await?;
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
