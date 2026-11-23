//! Handling of paths that were dragged into a terminal.
//!
//! Terminals have no drop API, dropping a file pastes its path as text.
//! Depending on the terminal that text is quoted, backslash escaped or a
//! `file://` URI, so it has to be cleaned up before it can be used as a path.

use colored::Colorize;
use indicatif::HumanBytes;
use std::{
    io::{self, BufRead, Write},
    path::PathBuf,
};

/// Clean up a single path argument.
///
/// The shell already removed the quoting of arguments typed on the command line,
/// but some terminals paste `file://` URIs, and quotes survive if the path was
/// pasted inside quotes. A path that exists as given is never changed.
pub fn normalize_path_arg(path: PathBuf) -> PathBuf {
    if path.exists() {
        return path;
    }

    let Some(s) = path.to_str() else {
        // Not valid UTF-8, so it can't be quoted or a URI either.
        return path;
    };

    let s = s.trim();
    let s = strip_matching_quotes(s);

    match file_uri_to_path(s) {
        Some(p) => p,
        None => PathBuf::from(s),
    }
}

/// Remove one pair of matching surrounding quotes.
fn strip_matching_quotes(s: &str) -> &str {
    for q in ['\'', '"'] {
        if s.len() >= 2 && s.starts_with(q) && s.ends_with(q) {
            return &s[1..s.len() - 1];
        }
    }
    s
}

/// Convert a `file://` URI into a path.
///
/// Accepts `file:///abs/path`, `file://localhost/abs/path` and the Windows
/// form `file:///C:/dir/file`. Percent escapes are decoded.
/// Returns [None] if `s` is not a `file://` URI.
pub fn file_uri_to_path(s: &str) -> Option<PathBuf> {
    let rest = s
        .strip_prefix("file://")
        .or_else(|| s.strip_prefix("FILE://"))?;
    let rest = rest.strip_prefix("localhost").unwrap_or(rest);

    // A URI without an absolute path (e.g. `file://host/...`) is a remote file.
    if !rest.starts_with('/') {
        return None;
    }

    let decoded = percent_decode(rest)?;

    // `/C:/dir` -> `C:/dir`
    #[cfg(windows)]
    let decoded = {
        let b = &decoded;
        if b.len() >= 3 && b[0] == b'/' && b[1].is_ascii_alphabetic() && b[2] == b':' {
            b[1..].to_vec()
        } else {
            decoded
        }
    };

    Some(bytes_to_path(decoded))
}

/// Decode `%XX` escapes. Returns [None] on a malformed escape.
fn percent_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            let hex = std::str::from_utf8(hex).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }

    Some(out)
}

/// Parse one line of text pasted by dropping files into the terminal.
///
/// Terminals paste dropped paths differently:
/// - GNOME Terminal, Konsole: `'/path/with space'`, `'it'\''s'`
/// - Alacritty, foot: `/path/with\ space`
/// - some terminals: `file:///path/with%20space`
/// - Windows Terminal, conhost: `"C:\path\with space"`
/// - xterm and others: the bare path, spaces included
///
/// Several dropped files are separated by spaces.
/// `windows` selects Windows rules: backslashes are path separators and
/// only double quotes quote.
pub fn parse_drop_line(line: &str, windows: bool) -> Vec<PathBuf> {
    // Bracketed paste markers, in case the terminal sends them
    let line = line.replace("\x1b[200~", "").replace("\x1b[201~", "");
    let line = line.trim();

    if line.is_empty() {
        return Vec::new();
    }

    // A single bare path, which may contain unescaped spaces
    let whole = normalize_path_arg(PathBuf::from(line));
    if whole.exists() {
        return vec![whole];
    }

    split_words(line, windows)
        .into_iter()
        .map(|word| file_uri_to_path(&word).unwrap_or_else(|| PathBuf::from(word)))
        .collect()
}

/// Split a line into words the way a shell would, without any expansion.
fn split_words(line: &str, windows: bool) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            '"' => {
                in_word = true;
                while let Some(c) = chars.next() {
                    match c {
                        '"' => break,
                        '\\' if !windows
                            && matches!(chars.peek(), Some('"' | '\\' | '$' | '`')) =>
                        {
                            word.extend(chars.next());
                        }
                        c => word.push(c),
                    }
                }
            }
            '\'' if !windows => {
                in_word = true;
                for c in chars.by_ref() {
                    if c == '\'' {
                        break;
                    }
                    word.push(c);
                }
            }
            '\\' if !windows => {
                in_word = true;
                word.extend(chars.next());
            }
            c => {
                in_word = true;
                word.push(c);
            }
        }
    }

    if in_word {
        words.push(word);
    }

    words
}

/// Let the user drag files into the terminal, one or more per line.
/// An empty line finishes the selection.
pub fn select_files_interactively() -> io::Result<Vec<PathBuf>> {
    println!("Drag files or folders into this window, or type their paths.");
    println!("Press Enter on an empty line to send them, Ctrl+C to cancel.\n");

    let mut files: Vec<PathBuf> = Vec::new();
    let mut stdin = io::stdin().lock();

    loop {
        print!("{} ", ">".bold());
        io::stdout().flush()?;

        let mut line = String::new();
        if stdin.read_line(&mut line)? == 0 {
            // End of input
            println!();
            break;
        }

        let paths = parse_drop_line(&line, cfg!(windows));

        if paths.is_empty() {
            if files.is_empty() {
                println!("  {}", "nothing added yet".dimmed());
                continue;
            }
            break;
        }

        for path in paths {
            if files.contains(&path) {
                println!("  {} {}", "already added:".yellow(), path.display());
            } else if !path.exists() {
                println!("  {} {}", "not found:".red(), path.display());
            } else {
                println!("  {} {}", "+".green(), describe(&path));
                files.push(path);
            }
        }
    }

    Ok(files)
}

/// Name and size of a file or folder
fn describe(path: &std::path::Path) -> String {
    match qs_core::common::get_files_available(path) {
        Ok(available) => {
            let suffix = if path.is_dir() { "/" } else { "" };
            format!(
                "{}{} {}",
                available.name().blue(),
                suffix.blue(),
                HumanBytes(available.size()).to_string().red()
            )
        }
        Err(_) => path.display().to_string(),
    }
}

#[cfg(unix)]
fn bytes_to_path(bytes: Vec<u8>) -> PathBuf {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    PathBuf::from(OsString::from_vec(bytes))
}

#[cfg(not(unix))]
fn bytes_to_path(bytes: Vec<u8>) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn norm(s: &str) -> PathBuf {
        normalize_path_arg(PathBuf::from(s))
    }

    #[test]
    fn plain_path_unchanged() {
        assert_eq!(
            norm("/tmp/qs-does-not-exist"),
            PathBuf::from("/tmp/qs-does-not-exist")
        );
    }

    #[test]
    fn strips_quotes_and_whitespace() {
        assert_eq!(norm("  '/tmp/a b'  "), PathBuf::from("/tmp/a b"));
        assert_eq!(norm("\"/tmp/a b\"\n"), PathBuf::from("/tmp/a b"));
        // Mismatched quotes are left alone
        assert_eq!(norm("'/tmp/a b\""), PathBuf::from("'/tmp/a b\""));
    }

    #[test]
    fn file_uri() {
        assert_eq!(norm("file:///tmp/a%20b.txt"), PathBuf::from("/tmp/a b.txt"));
        assert_eq!(norm("file://localhost/tmp/x"), PathBuf::from("/tmp/x"));
        assert_eq!(
            norm("'file:///tmp/%C3%A4.txt'"),
            PathBuf::from("/tmp/ä.txt")
        );
    }

    #[test]
    fn remote_or_broken_uri_kept_as_is() {
        assert_eq!(
            norm("file://server/share"),
            PathBuf::from("file://server/share")
        );
        assert_eq!(norm("file:///tmp/%zz"), PathBuf::from("file:///tmp/%zz"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_drive_uri() {
        assert_eq!(
            norm("file:///C:/Users/x/a%20b.txt"),
            PathBuf::from("C:/Users/x/a b.txt")
        );
    }

    fn paths(v: &[&str]) -> Vec<PathBuf> {
        v.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn drop_gnome_terminal() {
        assert_eq!(
            parse_drop_line("'/home/j/My Files/a b.txt' '/home/j/x.txt' \n", false),
            paths(&["/home/j/My Files/a b.txt", "/home/j/x.txt"])
        );
        assert_eq!(
            parse_drop_line("'/home/j/Joel'\\''s file.txt' ", false),
            paths(&["/home/j/Joel's file.txt"])
        );
    }

    #[test]
    fn drop_backslash_escaped() {
        assert_eq!(
            parse_drop_line("/home/j/My\\ Files/a\\ b.txt /home/j/c\\'d", false),
            paths(&["/home/j/My Files/a b.txt", "/home/j/c'd"])
        );
    }

    #[test]
    fn drop_uris() {
        assert_eq!(
            parse_drop_line("file:///home/j/a%20b.txt file:///home/j/%C3%A4", false),
            paths(&["/home/j/a b.txt", "/home/j/ä"])
        );
    }

    #[test]
    fn drop_double_quotes_unix() {
        assert_eq!(
            parse_drop_line(r#""/home/j/a \"b\".txt" /home/j/c"#, false),
            paths(&["/home/j/a \"b\".txt", "/home/j/c"])
        );
    }

    #[test]
    fn drop_windows_terminal() {
        assert_eq!(
            parse_drop_line(
                r#""C:\Users\J\My Files\a b.txt" C:\Users\J\Joel's.txt"#,
                true
            ),
            paths(&[r"C:\Users\J\My Files\a b.txt", r"C:\Users\J\Joel's.txt"])
        );
        assert_eq!(parse_drop_line("\"D:\\x\"\r\n", true), paths(&[r"D:\x"]));
    }

    #[test]
    fn drop_bracketed_paste_and_blank() {
        assert_eq!(
            parse_drop_line("\x1b[200~'/tmp/a b'\x1b[201~", false),
            paths(&["/tmp/a b"])
        );
        assert!(parse_drop_line("  \r\n", false).is_empty());
        assert!(parse_drop_line("\x1b[200~\x1b[201~", false).is_empty());
    }

    #[test]
    fn drop_bare_path_with_spaces() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a file with spaces.txt");
        std::fs::write(&file, b"x").unwrap();

        let line = format!("{}\n", file.display());
        assert_eq!(parse_drop_line(&line, cfg!(windows)), vec![file]);
    }
}
