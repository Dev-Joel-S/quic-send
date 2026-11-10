//! What the CLI shows: prompts, progress bars and messages.

use colored::Colorize;
use dialoguer::theme::ColorfulTheme;
use indicatif::{HumanBytes, MultiProgress, ProgressBar, ProgressStyle};
use qs_core::{
    common::{ConnectionPath, FilesAvailable},
    destination::{Destination, Placement},
};

/// Put `text` on the clipboard. Returns the clipboard handle on success.
///
/// Codes and tickets are secrets, and a clipboard history or a synced clipboard can show
/// them to others before they are used. `--no-clipboard` and `clipboard = false` in the
/// config file switch this off.
/// TODO (decision, audit finding N2): whether copying should be off unless asked for.
pub fn copy_to_clipboard(text: &str) -> Option<arboard::Clipboard> {
    let mut clipboard = arboard::Clipboard::new().ok()?;
    clipboard.set_text(text).ok()?;
    Some(clipboard)
}

/// Show where each offered file/dir ends up, if that is not obvious
pub fn print_destinations(offered: &[FilesAvailable], destinations: &[Destination]) {
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
pub fn accept_files(files_offered: &[FilesAvailable]) -> bool {
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
pub struct CliProgressBars {
    /// Per file/dir progress bars
    progress_bars: Vec<ProgressBar>,
    /// Only used when multiple files are sent
    total_bar: Option<ProgressBar>,
}

impl CliProgressBars {
    /// Creates the progress bars using the callbacks in
    /// [qs_core::send::Sender::send_files] and [qs_core::receive::Receiver::receive_files]
    /// # Arguments
    /// * `callback_data` - The initial progress data for each file (name, current, total)
    pub fn new(callback_data: &[(String, u64, u64)]) -> Self {
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
            progress_bars: bars,
            total_bar,
        }
    }

    /// Update the progress bars
    /// it is expected that the files will be downloaded in order
    pub fn update(&mut self, mut progress: u64) {
        if let Some(pb) = &self.total_bar {
            pb.inc(progress);
        }

        for pb in &self.progress_bars {
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

pub fn connection_type_info_msg(connection_type: ConnectionPath) -> String {
    match connection_type {
        ConnectionPath::Direct => "Direct".green().to_string(),
        ConnectionPath::Relay => "Relay".red().to_string(),
        ConnectionPath::Unknown => "???".red().to_string(),
    }
}
