use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use clap::{Parser, Subcommand};
use colored::Colorize;
use dialoguer::theme::ColorfulTheme;
use indicatif::{HumanBytes, MultiProgress, ProgressBar, ProgressStyle};
use iroh::{endpoint::presets, Endpoint, EndpointAddr, RelayMode, SecretKey};
use qs_core::{
    common::{ConnectionPath, FilesAvailable},
    destination::{Destination, Placement},
    receive::{ReceiveError, Receiver, ReceiverArgs},
    send::{SendError, Sender, SenderArgs},
    QuicSendError, QS_ALPN, QS_PROTO_VERSION,
};
use std::{
    cell::RefCell,
    io::{self, Write},
    path::PathBuf,
    rc::Rc,
    time::Duration,
};
use thiserror::Error;
use tracing::Level;
use tracing_subscriber::{
    filter::{LevelFilter, Targets},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};

mod drop;

#[derive(Parser, Debug)]
#[clap(version = QS_PROTO_VERSION, author = env!("CARGO_PKG_AUTHORS"))]
struct Args {
    /// Log level
    #[clap(long, short, default_value = "error")]
    log_level: tracing::Level,
    /// Send or receive files
    #[clap(subcommand)]
    mode: Mode,
}

#[derive(Subcommand, Debug)]
enum Mode {
    #[clap(name = "send", about = "Send files", aliases = &["s"])]
    Send {
        /// Files/directories to send
        #[clap(name = "files or directories", required = true)]
        files: Vec<PathBuf>,
    },
    #[clap(name = "receive", about = "Receive files", aliases = &["r"])]
    Receive {
        /// Overwrite existing files and folders instead of resuming or renaming
        #[clap(long, short = 'f')]
        overwrite: bool,

        /// Output directory [default: your Downloads folder]
        #[clap(long, short)]
        output: Option<PathBuf>,

        /// The code to connect to the sender
        code: Option<String>,

        /// Automatically accept the files
        #[clap(long, short = 'y')]
        auto_accept: bool,
    },
}

/// How long the sender waits for a relay before printing its ticket anyway
const ONLINE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the sender waits for any address after that
const ADDR_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Error, Debug)]
enum AppError {
    #[error("send error: {0}")]
    QuicSendCore(#[from] qs_core::QuicSendError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    let mut args: Args = Args::parse();

    color_eyre::install()?;
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
        colored::control::set_virtual_terminal(true).unwrap();
    }

    tracing::debug!("qs {}", QS_PROTO_VERSION);

    // Paths may have been dragged into the terminal
    match &mut args.mode {
        Mode::Send { files } => {
            *files = files.drain(..).map(drop::normalize_path_arg).collect();
        }
        Mode::Receive { output, .. } => {
            *output = output.take().map(drop::normalize_path_arg);
        }
    }

    // Check if the files even exist
    if let Mode::Send { files, .. } = &args.mode {
        for file in files {
            if !file.exists() {
                return Err(QuicSendError::Send(SendError::FileDoesNotExists(file.clone())).into());
            }
        }
    }

    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::generate())
        .alpns(vec![QS_ALPN.to_vec()])
        .relay_mode(RelayMode::Default)
        .bind()
        .await
        .map_err(|e| AppError::QuicSendCore(QuicSendError::Bind(e.to_string())))?;

    let progress_bars: Rc<RefCell<Option<CliProgressBars>>> = Rc::new(RefCell::new(None));
    let rc_clone = Rc::clone(&progress_bars);

    match args.mode {
        Mode::Send { files } => {
            // Wait until a relay is reachable, so the address is dialable from the internet.
            // Without a network this never happens, the local address is still printed then.
            if tokio::time::timeout(ONLINE_TIMEOUT, endpoint.online())
                .await
                .is_err()
            {
                tracing::warn!("no relay reachable, the ticket only has direct addresses");
            }

            // Local addresses can show up a moment after binding
            let mut addr = endpoint.addr();
            let deadline = tokio::time::Instant::now() + ADDR_TIMEOUT;
            while addr.is_empty() && tokio::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(100)).await;
                addr = endpoint.addr();
            }
            if addr.is_empty() {
                return Err(
                    AppError::QuicSendCore(QuicSendError::Send(SendError::EndpointAddr(
                        "neither a relay nor a local network address is available".to_string(),
                    )))
                    .into(),
                );
            }
            let serialized = postcard::to_stdvec(&addr).map_err(|e| {
                AppError::QuicSendCore(QuicSendError::Send(SendError::EndpointAddr(e.to_string())))
            })?;
            let ticket: String = BASE64_STANDARD_NO_PAD.encode(&serialized);

            // On Linux the clipboard content is gone once this is dropped,
            // so it is kept alive until the transfer is over.
            let clipboard = copy_to_clipboard(&ticket);

            if clipboard.is_some() {
                println!(
                    "Ticket (copied to your clipboard):\n\n{}\n",
                    ticket.bright_white()
                );
            } else {
                println!("Ticket:\n\n{}\n", ticket.bright_white());
            }
            println!("on the other peer, run the following command:\n");
            println!("{}", "qs receive <ticket>".yellow());

            let sender_args = SenderArgs { files };
            let mut sender = Sender::connect(endpoint, sender_args).await?;

            // Give iroh some time to switch the connection to direct
            tokio::time::sleep(Duration::from_secs(4)).await;
            let conn_type = sender.connection_type();
            tracing::debug!("connected with type: {:?}", conn_type);
            println!("Connection type: {}", connection_type_info_msg(conn_type));

            sender
                .send_files(
                    || {
                        print!("Waiting for the other peer to accept the files...");
                        io::stdout().flush().unwrap();
                    },
                    |_accepted| {},
                    |initial_progress| {
                        println!("\r{}", " ".repeat(49));
                        *rc_clone.borrow_mut() = Some(CliProgressBars::new(initial_progress));
                    },
                    &mut |last_sent| {
                        if let Some(pb) = &mut *rc_clone.borrow_mut() {
                            pb.update(last_sent);
                        }
                    },
                    // In the CLI we don't handle the interruption as the user can just Ctrl+C
                    &mut || true,
                )
                .await
                .map_err(QuicSendError::Send)?;

            drop(clipboard);
        }
        Mode::Receive {
            overwrite,
            output,
            code,
            auto_accept,
        } => {
            let output = resolve_output_dir(output)?;
            println!(
                "Files will be saved to: {}\n",
                output.display().to_string().bright_white()
            );

            let ticket = match code {
                Some(code) => code,
                None => dialoguer::Input::new()
                    .with_prompt("Enter the ticket to connect")
                    .interact()?,
            };

            let invalid =
                || AppError::QuicSendCore(QuicSendError::Receive(ReceiveError::InvalidCode));
            let ticket = BASE64_STANDARD_NO_PAD
                .decode(ticket.trim().as_bytes())
                .map_err(|_| invalid())?;
            let addr: EndpointAddr = postcard::from_bytes(&ticket).map_err(|_| invalid())?;

            let receiver_args = ReceiverArgs { resume: !overwrite };
            let mut receiver = Receiver::connect(endpoint, addr, receiver_args).await?;

            // Give iroh some time to switch the connection to direct
            tokio::time::sleep(Duration::from_secs(4)).await;
            let conn_type = receiver.connection_type();
            tracing::debug!("connected with type: {:?}", conn_type);
            println!("Connection type: {}", connection_type_info_msg(conn_type));

            receiver
                .receive_files(
                    |initial_progress| {
                        *progress_bars.borrow_mut() = Some(CliProgressBars::new(initial_progress));
                    },
                    |files_offered| {
                        if auto_accept {
                            println!("auto accepting files");
                            tracing::debug!("auto accepting files");
                            Some(output.clone())
                        } else if accept_files(files_offered) {
                            Some(output.clone())
                        } else {
                            None
                        }
                    },
                    print_destinations,
                    &mut |last_received| {
                        if let Some(pb) = &mut *progress_bars.borrow_mut() {
                            pb.update(last_received);
                        }
                    },
                    // In the CLI we don't handle the interruption as the user can just Ctrl+C
                    &mut || true,
                )
                .await
                .map_err(QuicSendError::Receive)?;
        }
    }

    Ok(())
}

/// Put `text` on the clipboard. Returns the clipboard handle on success.
fn copy_to_clipboard(text: &str) -> Option<arboard::Clipboard> {
    let mut clipboard = arboard::Clipboard::new().ok()?;
    clipboard.set_text(text).ok()?;
    Some(clipboard)
}

/// The output directory: the one given, or the Downloads folder.
/// Created if missing and returned as an absolute path.
fn resolve_output_dir(output: Option<PathBuf>) -> io::Result<PathBuf> {
    let output = output.unwrap_or_else(|| {
        dirs::download_dir()
            // Minimal setups often have no XDG user dirs configured
            .or_else(|| {
                dirs::home_dir()
                    .map(|home| home.join("Downloads"))
                    .filter(|d| d.is_dir())
            })
            .unwrap_or_else(|| PathBuf::from("."))
    });

    std::fs::create_dir_all(&output)?;
    std::path::absolute(output)
}

/// Show where each offered file/dir ends up, if that is not obvious
fn print_destinations(offered: &[FilesAvailable], destinations: &[Destination]) {
    for (offered, destination) in offered.iter().zip(destinations) {
        let name = destination
            .path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();

        let note = match destination.placement {
            Placement::New if name == offered.name() => continue,
            Placement::New => "name already taken, saving under a new name".yellow(),
            Placement::Resume => "resuming".green(),
            Placement::Overwrite => "overwriting".yellow(),
        };

        println!(" - {} ({})", name.blue(), note);
    }
}

/// Ask the receiver if they want to accept the files
fn accept_files(files_offered: &[FilesAvailable]) -> bool {
    println!("The following files will be received:\n");

    let longest_name = files_offered
        .iter()
        .map(|f| f.name().len())
        .max()
        .unwrap_or(0)
        + 1;

    let total_size = files_offered.iter().map(|f| f.size()).sum::<u64>();

    for file in files_offered {
        let size = file.size();
        let size_human_bytes = HumanBytes(size).to_string();
        let name = file.name();

        println!(
            " - {:<width$} {:>10}",
            if let FilesAvailable::Dir { .. } = file {
                format!("{}/", name).blue()
            } else {
                format!("{} ", name).blue()
            },
            size_human_bytes.red(),
            width = longest_name
        );
    }

    println!("\nTotal size: {}", HumanBytes(total_size).to_string().red());

    dialoguer::Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Do you want to receive these files?")
        .interact()
        .unwrap_or_default()
}

/// Send and receive progress bars
struct CliProgressBars {
    /// Per file/dir progress bars
    progerss_bars: Vec<ProgressBar>,
    /// Only used when multiple files are sent
    total_bar: Option<ProgressBar>,
}

impl CliProgressBars {
    /// Creates the progress bars using the callbacks in
    /// [qs_core::send::Sender::send_files] and [qs_core::receive::Receiver::receive_files]
    /// # Arguments
    /// * `callback_data` - The initial progress data for each file (name, current, total)
    fn new(callback_data: &[(String, u64, u64)]) -> Self {
        let total_name = "Total";

        let style = ProgressStyle::default_bar()
            .template(
                "{spinner:.green} {prefix} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
            )
            .unwrap()
            .progress_chars("#>-");

        let total_style = ProgressStyle::default_bar()
            .template(
                "{spinner:.green} {prefix} [{bar:40.yellow/yellow}] {bytes}/{total_bytes} ({eta})",
            )
            .unwrap()
            .progress_chars("#>-");

        let (mut longest_name, total_progress, total_size) = callback_data.iter().fold(
            (0, 0, 0),
            |(longest_name, total_progress, total_size), (name, progress, size)| {
                (
                    longest_name.max(name.len()),
                    total_progress + progress,
                    total_size + size,
                )
            },
        );

        longest_name = longest_name.max(total_name.len());

        let mp = MultiProgress::new();

        let mut bars = Vec::new();
        for (name, progress, size) in callback_data {
            let pb = mp.add(ProgressBar::new(*size));
            pb.set_prefix(format!("{:<width$}", name, width = longest_name));
            pb.set_style(style.clone());
            pb.set_position(*progress);
            pb.reset_eta();
            bars.push(pb);
        }

        let total_bar = if bars.len() > 1 {
            let pb = mp.add(ProgressBar::new(total_size));
            pb.set_prefix(format!("{:<width$}", total_name, width = longest_name));
            pb.set_style(total_style);
            pb.set_position(total_progress);
            pb.reset_eta();
            Some(pb)
        } else {
            None
        };

        Self {
            progerss_bars: bars,
            total_bar,
        }
    }

    /// Update the progress bars
    /// it is expected that the files will be downloaded in order
    pub fn update(&mut self, mut progress: u64) {
        if let Some(pb) = &self.total_bar {
            pb.inc(progress);
        }

        for pb in &self.progerss_bars {
            let remaining = pb
                .length()
                .unwrap_or_default()
                .saturating_sub(pb.position());

            if remaining == 0 {
                continue;
            }

            let this_bar_progress = progress.min(remaining);
            pb.inc(this_bar_progress);
            progress -= this_bar_progress;

            if progress == 0 {
                break;
            }
        }
    }
}

fn connection_type_info_msg(connection_type: ConnectionPath) -> String {
    match connection_type {
        ConnectionPath::Direct => "Direct".green().to_string(),
        ConnectionPath::Relay => "Relay".red().to_string(),
        ConnectionPath::Unknown => "???".red().to_string(),
    }
}
