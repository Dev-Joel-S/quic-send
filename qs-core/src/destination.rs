//! Where received files end up on disk.
//!
//! File names are chosen by the sender, so they are untrusted. Every name is
//! checked before it is joined onto a local path.
//!
//! Each offered top level entry gets its own destination in the output
//! directory. Files are written as `<name>.part` and renamed once complete.
//! Next to every destination a hidden resume state records what was offered,
//! so an interrupted transfer can be told apart from an unrelated file or
//! folder that happens to have the same name.

use crate::{
    common::{FilesAvailable, FilesToSkip},
    QS_PROTO_VERSION,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    io,
    path::{Path, PathBuf},
};
use thiserror::Error;

/// Suffix of files that are still being received
pub const PART_SUFFIX: &str = ".part";
/// Suffix of the resume state next to a destination
pub const STATE_SUFFIX: &str = ".qs-resume.json";
/// Bump when [ResumeState] changes incompatibly
const STATE_FORMAT: u32 = 1;

#[derive(Debug, Error, PartialEq)]
pub enum NameError {
    #[error("the sender offered an unsafe file name: {0:?}")]
    Unsafe(String),
    #[error("the sender offered the file name {0:?} more than once in the same directory")]
    Duplicate(String),
    #[error("the sender offered the file name {0:?}, which would clash with an incomplete file")]
    Reserved(String),
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
/// end up at the same local path, including the `.part` file of another entry.
pub fn validate_offer(offered: &[FilesAvailable]) -> Result<(), NameError> {
    validate_names(offered, cfg!(windows), true)
}

fn validate_names(
    entries: &[FilesAvailable],
    windows: bool,
    top_level: bool,
) -> Result<(), NameError> {
    // Windows file names are case insensitive
    let key = |name: &str| {
        if windows {
            name.to_lowercase()
        } else {
            name.to_string()
        }
    };

    let mut seen = HashSet::new();
    let mut part_files = Vec::new();

    for entry in entries {
        let local = local_name_for(entry.name(), windows)?;

        if top_level && local.ends_with(STATE_SUFFIX) {
            return Err(NameError::Reserved(entry.name().to_string()));
        }

        if !seen.insert(key(&local)) {
            return Err(NameError::Duplicate(entry.name().to_string()));
        }

        match entry {
            FilesAvailable::File { .. } => part_files.push(key(&(local + PART_SUFFIX))),
            FilesAvailable::Dir { files, .. } => validate_names(files, windows, false)?,
        }
    }

    if let Some(clash) = entries.iter().find(|e| {
        local_name_for(e.name(), windows).is_ok_and(|local| part_files.contains(&key(&local)))
    }) {
        return Err(NameError::Reserved(clash.name().to_string()));
    }

    Ok(())
}

/// The `n`th alternative name for a destination: `name (n)`.
/// Files keep their extension: `photo (1).jpg`.
pub fn numbered_name(name: &str, n: usize, is_file: bool) -> String {
    if n == 0 {
        return name.to_string();
    }

    match name.rfind('.') {
        // A leading dot is a hidden file, not an extension
        Some(dot) if is_file && dot > 0 => format!("{} ({n}){}", &name[..dot], &name[dot..]),
        _ => format!("{name} ({n})"),
    }
}

/// Path a file is written to while it is incomplete
pub fn part_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_owned();
    name.push(PART_SUFFIX);
    path.with_file_name(name)
}

/// Path of the resume state for a destination: `.<name>.qs-resume.json` next to it.
///
/// The state lives outside of a destination directory, so it can never clash
/// with a file inside the received folder.
pub fn state_path(destination: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from(".");
    name.push(destination.file_name().unwrap_or_default());
    name.push(STATE_SUFFIX);
    destination.with_file_name(name)
}

/// What is known about an interrupted transfer into a destination
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResumeState {
    /// Format of this file, see [STATE_FORMAT]
    pub format: u32,
    /// Protocol version of the transfer
    pub version: String,
    // TODO: once peers have a stable identity (`crate::peers`), compare the peer when
    // deciding whether to resume, as the spec asked. Until then it must stay informational.
    /// The sender, for information only. Endpoint ids are not stable across runs.
    pub peer: Option<String>,
    /// The entry that was offered, with sizes and modification times
    pub offer: FilesAvailable,
}

impl ResumeState {
    pub fn new(offer: &FilesAvailable, peer: Option<String>) -> Self {
        Self {
            format: STATE_FORMAT,
            version: QS_PROTO_VERSION.to_string(),
            peer,
            offer: offer.clone(),
        }
    }

    /// Whether this state belongs to a transfer of exactly `offer`
    pub fn matches(&self, offer: &FilesAvailable) -> bool {
        self.format == STATE_FORMAT && self.version == QS_PROTO_VERSION && &self.offer == offer
    }

    /// Read the state of a destination, [None] if there is none or it is unreadable
    pub fn read(destination: &Path) -> Option<Self> {
        let data = std::fs::read(state_path(destination)).ok()?;
        serde_json::from_slice(&data).ok()
    }

    /// Write the state of a destination
    pub fn write(&self, destination: &Path) -> io::Result<()> {
        let path = state_path(destination);
        let data = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;

        // A hidden file can only be replaced with matching attributes on Windows
        let _ = std::fs::remove_file(&path);

        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
            options.attributes(FILE_ATTRIBUTE_HIDDEN);
        }

        use std::io::Write;
        let mut file = options.open(path)?;
        file.write_all(&data)?;
        file.sync_all()
    }

    /// Remove the state of a destination once its transfer is complete
    pub fn remove(destination: &Path) -> io::Result<()> {
        match std::fs::remove_file(state_path(destination)) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            r => r,
        }
    }
}

/// How a destination is used
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// Nothing was there yet
    New,
    /// An interrupted transfer of the same offer is continued
    Resume,
    /// Whatever is there is overwritten
    Overwrite,
}

/// Where an offered top level entry is stored
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub path: PathBuf,
    pub placement: Placement,
}

/// Choose the destination for an offered top level entry inside `output`.
///
/// - destination free: use it
/// - destination exists and its resume state matches the offer: resume into it
/// - otherwise: try `name (1)`, `name (2)`, ...
/// - with `overwrite`, always use the plain name
///
/// `taken` holds destinations already chosen for this transfer.
pub fn resolve(
    output: &Path,
    offer: &FilesAvailable,
    overwrite: bool,
    taken: &[Destination],
) -> io::Result<Destination> {
    let local = local_name(offer.name()).map_err(io::Error::other)?;
    let is_file = matches!(offer, FilesAvailable::File { .. });

    if overwrite {
        return Ok(Destination {
            path: output.join(local),
            placement: Placement::Overwrite,
        });
    }

    for n in 0..10_000 {
        let path = output.join(numbered_name(&local, n, is_file));

        if taken.iter().any(|d| d.path == path) {
            continue;
        }

        let occupied = exists(&path) || (is_file && exists(&part_path(&path)));
        if !occupied {
            return Ok(Destination {
                path,
                placement: Placement::New,
            });
        }

        if ResumeState::read(&path).is_some_and(|state| state.matches(offer)) {
            return Ok(Destination {
                path,
                placement: Placement::Resume,
            });
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("no free name for {local} in {}", output.display()),
    ))
}

/// Exists, also as a dangling symlink
fn exists(path: &Path) -> bool {
    path.symlink_metadata().is_ok()
}

/// What of `offer` is already on disk at `destination`, as the files to skip.
///
/// A complete file has its final name and the offered size, a partial file
/// is a `.part` file no larger than the offered size.
pub fn local_progress(destination: &Path, offer: &FilesAvailable) -> Option<FilesToSkip> {
    match offer {
        FilesAvailable::File { name, size, .. } => {
            let len = |p: &Path| p.metadata().ok().filter(|m| m.is_file()).map(|m| m.len());

            let skip = match (len(destination), len(&part_path(destination))) {
                (Some(done), _) if done == *size => *size,
                (_, Some(partial)) if partial > 0 && partial <= *size => partial,
                _ => return None,
            };

            Some(FilesToSkip::File {
                name: name.clone(),
                skip,
            })
        }
        FilesAvailable::Dir { name, files } => {
            if !destination.is_dir() {
                return None;
            }

            let skippable: Vec<FilesToSkip> = files
                .iter()
                .filter_map(|f| {
                    let local = local_name(f.name()).ok()?;
                    local_progress(&destination.join(local), f)
                })
                .collect();

            if skippable.is_empty() {
                None
            } else {
                Some(FilesToSkip::Dir {
                    name: name.clone(),
                    files: skippable,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn file(name: &str) -> FilesAvailable {
        sized(name, 1)
    }

    fn sized(name: &str, size: u64) -> FilesAvailable {
        FilesAvailable::File {
            name: name.to_string(),
            size,
            mtime: Some(1_700_000_000),
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
        assert_eq!(validate_names(&ok, false, true), Ok(()));
        // a and A collide on Windows
        assert_eq!(
            validate_names(&ok, true, true),
            Err(NameError::Duplicate("A".to_string()))
        );

        let dup = vec![file("x"), dir("x", vec![])];
        assert!(validate_names(&dup, false, true).is_err());

        let nested = vec![dir("d", vec![dir("e", vec![file("..")])])];
        assert_eq!(
            validate_names(&nested, false, true),
            Err(NameError::Unsafe("..".to_string()))
        );

        // `a?` and `a*` both become `a_` on Windows
        let sanitized = vec![file("a?"), file("a*")];
        assert!(validate_names(&sanitized, false, true).is_ok());
        assert!(validate_names(&sanitized, true, true).is_err());
    }

    #[test]
    fn reserved_names() {
        let clash = vec![dir("d", vec![file("a.part"), file("a")])];
        assert_eq!(
            validate_names(&clash, false, true),
            Err(NameError::Reserved("a.part".to_string()))
        );
        // Only a file produces a .part file
        let fine = vec![dir("d", vec![file("a.part"), dir("a", vec![])])];
        assert!(validate_names(&fine, false, true).is_ok());

        let state = vec![file(".x.qs-resume.json")];
        assert!(validate_names(&state, false, true).is_err());
        let nested_state = vec![dir("d", vec![file(".x.qs-resume.json")])];
        assert!(validate_names(&nested_state, false, true).is_ok());
    }

    #[test]
    fn numbered_names() {
        assert_eq!(numbered_name("photo.jpg", 0, true), "photo.jpg");
        assert_eq!(numbered_name("photo.jpg", 1, true), "photo (1).jpg");
        assert_eq!(numbered_name("a.tar.gz", 2, true), "a.tar (2).gz");
        assert_eq!(numbered_name(".bashrc", 1, true), ".bashrc (1)");
        assert_eq!(numbered_name("README", 1, true), "README (1)");
        assert_eq!(numbered_name("my.folder", 3, false), "my.folder (3)");
    }

    #[test]
    fn side_paths() {
        let p = Path::new("/out/data.bin");
        assert_eq!(part_path(p), Path::new("/out/data.bin.part"));
        assert_eq!(state_path(p), Path::new("/out/.data.bin.qs-resume.json"));
        assert_eq!(
            state_path(Path::new("/out/dir")),
            Path::new("/out/.dir.qs-resume.json")
        );
    }

    fn resolve_in(out: &Path, offer: &FilesAvailable) -> Destination {
        resolve(out, offer, false, &[]).unwrap()
    }

    #[test]
    fn resolve_free_destination() {
        let out = tempfile::tempdir().unwrap();
        let offer = dir("d", vec![file("a")]);
        assert_eq!(
            resolve_in(out.path(), &offer),
            Destination {
                path: out.path().join("d"),
                placement: Placement::New
            }
        );
    }

    #[test]
    fn resolve_unrelated_folder_gets_a_number() {
        let out = tempfile::tempdir().unwrap();
        std::fs::create_dir(out.path().join("d")).unwrap();
        std::fs::create_dir(out.path().join("d (1)")).unwrap();

        let offer = dir("d", vec![file("a")]);
        assert_eq!(
            resolve_in(out.path(), &offer),
            Destination {
                path: out.path().join("d (2)"),
                placement: Placement::New
            }
        );
    }

    #[test]
    fn resolve_resumes_matching_state() {
        let out = tempfile::tempdir().unwrap();
        let offer = dir("d", vec![file("a")]);
        let dest = out.path().join("d");
        std::fs::create_dir(&dest).unwrap();
        ResumeState::new(&offer, None).write(&dest).unwrap();

        assert_eq!(
            resolve_in(out.path(), &offer),
            Destination {
                path: dest.clone(),
                placement: Placement::Resume
            }
        );

        // A different offer under the same name is unrelated
        let other = dir("d", vec![sized("a", 2)]);
        assert_eq!(
            resolve_in(out.path(), &other).path,
            out.path().join("d (1)")
        );

        // As is the same offer with a changed modification time
        let touched = dir(
            "d",
            vec![FilesAvailable::File {
                name: "a".to_string(),
                size: 1,
                mtime: Some(1_700_000_001),
            }],
        );
        assert_eq!(resolve_in(out.path(), &touched).placement, Placement::New);

        ResumeState::remove(&dest).unwrap();
        assert_eq!(
            resolve_in(out.path(), &offer).path,
            out.path().join("d (1)")
        );
    }

    #[test]
    fn resolve_resumes_numbered_copy() {
        let out = tempfile::tempdir().unwrap();
        let offer = sized("f.bin", 10);
        std::fs::write(out.path().join("f.bin"), b"unrelated").unwrap();
        let dest = out.path().join("f (1).bin");
        std::fs::write(part_path(&dest), b"12345").unwrap();
        ResumeState::new(&offer, None).write(&dest).unwrap();

        assert_eq!(
            resolve_in(out.path(), &offer),
            Destination {
                path: dest,
                placement: Placement::Resume
            }
        );
    }

    #[test]
    fn resolve_part_file_without_state_is_occupied() {
        let out = tempfile::tempdir().unwrap();
        std::fs::write(out.path().join("f.bin.part"), b"x").unwrap();
        assert_eq!(
            resolve_in(out.path(), &sized("f.bin", 10)).path,
            out.path().join("f (1).bin")
        );
    }

    #[test]
    fn resolve_stale_state_alone_does_not_occupy() {
        let out = tempfile::tempdir().unwrap();
        let dest = out.path().join("d");
        ResumeState::new(&file("other"), None).write(&dest).unwrap();
        assert_eq!(resolve_in(out.path(), &dir("d", vec![])).path, dest);
    }

    #[test]
    fn resolve_overwrite_and_taken() {
        let out = tempfile::tempdir().unwrap();
        std::fs::create_dir(out.path().join("d")).unwrap();
        let offer = dir("d", vec![]);

        let overwrite = resolve(out.path(), &offer, true, &[]).unwrap();
        assert_eq!(overwrite.path, out.path().join("d"));
        assert_eq!(overwrite.placement, Placement::Overwrite);

        let first = resolve_in(out.path(), &offer);
        let second = resolve(out.path(), &offer, false, std::slice::from_ref(&first)).unwrap();
        assert_eq!(first.path, out.path().join("d (1)"));
        assert_eq!(second.path, out.path().join("d (2)"));
    }

    #[test]
    fn progress_from_disk() {
        let out = tempfile::tempdir().unwrap();
        let dest = out.path().join("d");
        std::fs::create_dir_all(dest.join("sub")).unwrap();
        std::fs::write(dest.join("done"), b"1234").unwrap();
        std::fs::write(dest.join("half.part"), b"12").unwrap();
        std::fs::write(dest.join("sub/too-big.part"), b"123456").unwrap();
        std::fs::write(dest.join("wrong-size"), b"12").unwrap();

        let offer = dir(
            "d",
            vec![
                sized("done", 4),
                sized("half", 4),
                sized("missing", 4),
                sized("wrong-size", 4),
                dir("sub", vec![sized("too-big", 4)]),
            ],
        );

        assert_eq!(
            local_progress(&dest, &offer),
            Some(FilesToSkip::Dir {
                name: "d".to_string(),
                files: vec![
                    FilesToSkip::File {
                        name: "done".to_string(),
                        skip: 4
                    },
                    FilesToSkip::File {
                        name: "half".to_string(),
                        skip: 2
                    },
                ],
            })
        );

        assert_eq!(local_progress(&out.path().join("nope"), &offer), None);
    }
}
