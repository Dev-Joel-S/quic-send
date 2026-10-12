//! Where received files end up on disk.
//!
//! File names are chosen by the sender, so they are untrusted. Every name is
//! checked before it is joined onto a local path.

use crate::common::FilesAvailable;
use std::collections::HashSet;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum NameError {
    #[error("the sender offered an unsafe file name: {0:?}")]
    Unsafe(String),
    #[error("the sender offered the file name {0:?} more than once in the same directory")]
    Duplicate(String),
}

/// Names Windows reserves for devices, also when followed by an extension.
const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// The local name for a name offered by the sender.
///
/// Names that could escape the destination directory are rejected. On Windows,
/// names that are valid on other platforms but not on Windows are rewritten.
pub fn local_name(name: &str) -> Result<String, NameError> {
    local_name_for(name, cfg!(windows))
}

fn local_name_for(name: &str, windows: bool) -> Result<String, NameError> {
    let is_unsafe =
        name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', '\0']);

    if is_unsafe {
        return Err(NameError::Unsafe(name.to_string()));
    }

    if !windows {
        return Ok(name.to_string());
    }

    let mut out: String = name
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '|' | '?' | '*' => '_',
            c if (c as u32) < 0x20 => '_',
            c => c,
        })
        .collect();

    // Windows silently drops trailing dots and spaces
    while out.ends_with(['.', ' ']) {
        out.pop();
    }
    if out.is_empty() {
        out.push('_');
    }

    let stem = out.split('.').next().unwrap_or_default().trim_end();
    if WINDOWS_RESERVED
        .iter()
        .any(|r| r.eq_ignore_ascii_case(stem))
    {
        out.insert(0, '_');
    }

    Ok(out)
}

/// Check every name in the offered trees.
///
/// Fails if a name is unsafe, or if two entries of the same directory would
/// end up at the same local path.
pub fn validate_offer(offered: &[FilesAvailable]) -> Result<(), NameError> {
    validate_names(offered, cfg!(windows))
}

fn validate_names(entries: &[FilesAvailable], windows: bool) -> Result<(), NameError> {
    let mut seen = HashSet::new();

    for entry in entries {
        let local = local_name_for(entry.name(), windows)?;
        // Windows file names are case insensitive
        let key = if windows { local.to_lowercase() } else { local };

        if !seen.insert(key) {
            return Err(NameError::Duplicate(entry.name().to_string()));
        }

        if let FilesAvailable::Dir { files, .. } = entry {
            validate_names(files, windows)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn file(name: &str) -> FilesAvailable {
        FilesAvailable::File {
            name: name.to_string(),
            size: 1,
        }
    }

    fn dir(name: &str, files: Vec<FilesAvailable>) -> FilesAvailable {
        FilesAvailable::Dir {
            name: name.to_string(),
            files,
        }
    }

    #[test]
    fn rejects_traversal() {
        for windows in [false, true] {
            for bad in ["", ".", "..", "../x", "a/b", "a\\b", "/etc", "x\0y"] {
                assert_eq!(
                    local_name_for(bad, windows),
                    Err(NameError::Unsafe(bad.to_string())),
                    "{bad:?} windows={windows}"
                );
            }
        }
        // Drive relative paths are defused by replacing the colon
        assert_eq!(local_name_for("C:x", true).unwrap(), "C_x");
    }

    #[test]
    fn unix_keeps_names() {
        for ok in ["a b", "a:b", "CON", "x.", "...", "ä?*"] {
            assert_eq!(local_name_for(ok, false).unwrap(), ok);
        }
    }

    #[test]
    fn windows_rewrites_names() {
        assert_eq!(local_name_for("a:b?.txt", true).unwrap(), "a_b_.txt");
        assert_eq!(local_name_for("x. .", true).unwrap(), "x");
        assert_eq!(local_name_for("...", true).unwrap(), "_");
        assert_eq!(local_name_for("con", true).unwrap(), "_con");
        assert_eq!(local_name_for("NUL.tar.gz", true).unwrap(), "_NUL.tar.gz");
        assert_eq!(local_name_for("console", true).unwrap(), "console");
        assert_eq!(local_name_for("a\tb", true).unwrap(), "a_b");
    }

    #[test]
    fn offer_validation() {
        let ok = vec![dir("d", vec![file("a"), file("A")]), file("d2")];
        assert_eq!(validate_names(&ok, false), Ok(()));
        // a and A collide on Windows
        assert_eq!(
            validate_names(&ok, true),
            Err(NameError::Duplicate("A".to_string()))
        );

        let dup = vec![file("x"), dir("x", vec![])];
        assert!(validate_names(&dup, false).is_err());

        let nested = vec![dir("d", vec![dir("e", vec![file("..")])])];
        assert_eq!(
            validate_names(&nested, false),
            Err(NameError::Unsafe("..".to_string()))
        );

        // `a?` and `a*` both become `a_` on Windows
        let sanitized = vec![file("a?"), file("a*")];
        assert!(validate_names(&sanitized, false).is_ok());
        assert!(validate_names(&sanitized, true).is_err());
    }
}
