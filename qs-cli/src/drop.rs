//! Handling of paths that were dragged into a terminal.
//!
//! Terminals have no drop API, dropping a file pastes its path as text.
//! Depending on the terminal that text is quoted, backslash escaped or a
//! `file://` URI, so it has to be cleaned up before it can be used as a path.

use std::path::PathBuf;

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
}
