//! Limits for everything the other peer sends.
//!
//! The other peer is authenticated, not trusted. Without limits a hostile peer can
//! make the receiver run out of memory or disk, or crash it.
//!
//! DONE: maximum size of a control packet, [MAX_PACKET_COMPRESSED]. Enforced in
//!       `common::receive_packet`, which no longer reads without a bound.
//! DONE: maximum size after decompressing a packet, [MAX_PACKET_SIZE], against gzip bombs.
//! DONE: maximum number of entries, depth and name length of an offered tree, checked by
//!       [check_offer] (called by the receiver before the offer is shown and by the sender
//!       before it offers). The depth is also enforced while decoding ([NestingGuard]),
//!       because a deeply nested tree would overflow the stack before any check could run.
//! DONE: free disk space is checked against what still has to be received before the files
//!       are accepted ([check_space], called in `receive::Receiver::receive_files`).
//!       What is already on disk when resuming is not counted again.
//! DONE: the data stream cannot deliver more than the offer promised. The receiver reads
//!       exactly the offered size of each file and never more, the decompressor works on a
//!       fixed buffer, so surplus bytes are simply never read.
//! DONE: the skip list the receiver sends back is validated by the sender
//!       (`FilesToSkip::applies_to`), it used to be able to make the sender panic.
//! TODO: a limit for how long the peer may stay silent in the middle of a transfer.

use crate::common::FilesAvailable;
use std::cell::Cell;
use thiserror::Error;

/// Largest control packet on the wire, compressed
pub const MAX_PACKET_COMPRESSED: usize = 16 * 1024 * 1024;
/// Largest control packet after decompression
pub const MAX_PACKET_SIZE: usize = 64 * 1024 * 1024;
/// Most files and directories in one offer
pub const MAX_ENTRIES: usize = 1_000_000;
/// Deepest nesting of directories in one offer
pub const MAX_DEPTH: usize = 128;
/// Longest name of a single file or directory, in bytes
pub const MAX_NAME_BYTES: usize = 1024;

#[derive(Debug, Error, PartialEq)]
pub enum LimitError {
    #[error("more than {MAX_ENTRIES} files and directories in one transfer")]
    TooManyEntries,
    #[error("directories nested deeper than {MAX_DEPTH} levels")]
    TooDeep,
    #[error("a file name is longer than {MAX_NAME_BYTES} bytes")]
    NameTooLong,
    #[error("the total size of the transfer is not a valid number")]
    SizeOverflow,
    #[error("a packet is larger than the limit of {0} bytes")]
    PacketTooLarge(usize),
    #[error("not enough free disk space: {needed} bytes needed, {available} bytes available")]
    NotEnoughSpace { needed: u64, available: u64 },
}

/// Check the shape of offered trees: number of entries, depth, name length, total size.
///
/// After this passed, walking the trees and summing up sizes is safe.
pub fn check_offer(offered: &[FilesAvailable]) -> Result<(), LimitError> {
    let mut entries = 0usize;
    let mut total = 0u64;

    fn walk(
        entry: &FilesAvailable,
        depth: usize,
        entries: &mut usize,
        total: &mut u64,
    ) -> Result<(), LimitError> {
        if depth > MAX_DEPTH {
            return Err(LimitError::TooDeep);
        }

        *entries += 1;
        if *entries > MAX_ENTRIES {
            return Err(LimitError::TooManyEntries);
        }

        if entry.name().len() > MAX_NAME_BYTES {
            return Err(LimitError::NameTooLong);
        }

        match entry {
            FilesAvailable::File { size, .. } => {
                *total = total.checked_add(*size).ok_or(LimitError::SizeOverflow)?;
            }
            FilesAvailable::Dir { files, .. } => {
                for file in files {
                    walk(file, depth + 1, entries, total)?;
                }
            }
        }

        Ok(())
    }

    for entry in offered {
        walk(entry, 1, &mut entries, &mut total)?;
    }

    Ok(())
}

/// Check that `needed` bytes fit into `available` bytes of free disk space
pub fn check_space(needed: u64, available: u64) -> Result<(), LimitError> {
    if needed > available {
        return Err(LimitError::NotEnoughSpace { needed, available });
    }
    Ok(())
}

thread_local! {
    /// How deep the tree currently being decoded on this thread is nested
    static NESTING: Cell<usize> = const { Cell::new(0) };
}

/// Counts the nesting of a tree while it is decoded.
///
/// Decoding a tree is recursive. Without a limit, a peer could send a tree nested deep
/// enough to overflow the stack. Every nested level holds a guard while it decodes.
pub(crate) struct NestingGuard(());

impl NestingGuard {
    pub(crate) fn enter() -> Result<Self, LimitError> {
        NESTING.with(|nesting| {
            if nesting.get() >= MAX_DEPTH {
                return Err(LimitError::TooDeep);
            }
            nesting.set(nesting.get() + 1);
            Ok(Self(()))
        })
    }
}

impl Drop for NestingGuard {
    fn drop(&mut self) {
        NESTING.with(|nesting| nesting.set(nesting.get() - 1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::FilesToSkip;
    use pretty_assertions::assert_eq;

    fn file(name: &str, size: u64) -> FilesAvailable {
        FilesAvailable::File {
            name: name.to_string(),
            size,
            mtime: None,
        }
    }

    fn dir(name: &str, files: Vec<FilesAvailable>) -> FilesAvailable {
        FilesAvailable::Dir {
            name: name.to_string(),
            files,
        }
    }

    /// `depth` directories inside each other
    fn nested(depth: usize) -> FilesAvailable {
        let mut tree = dir("d", vec![]);
        for _ in 1..depth {
            tree = dir("d", vec![tree]);
        }
        tree
    }

    #[test]
    fn offer_within_limits() {
        let offer = vec![dir("d", vec![file("a", 1), file("b", 2)]), file("c", 3)];
        assert_eq!(check_offer(&offer), Ok(()));
        assert_eq!(check_offer(&[nested(MAX_DEPTH)]), Ok(()));
    }

    #[test]
    fn offer_too_deep() {
        assert_eq!(
            check_offer(&[nested(MAX_DEPTH + 1)]),
            Err(LimitError::TooDeep)
        );
    }

    #[test]
    fn offer_too_many_entries() {
        let files = (0..MAX_ENTRIES).map(|_| file("f", 0)).collect();
        // The directory itself is one entry too many
        assert_eq!(
            check_offer(&[dir("d", files)]),
            Err(LimitError::TooManyEntries)
        );
    }

    #[test]
    fn offer_name_too_long() {
        let name = "x".repeat(MAX_NAME_BYTES + 1);
        assert_eq!(check_offer(&[file(&name, 0)]), Err(LimitError::NameTooLong));
        assert_eq!(check_offer(&[file(&name[1..], 0)]), Ok(()));
    }

    #[test]
    fn offer_size_overflow() {
        let offer = vec![file("a", u64::MAX), file("b", 1)];
        assert_eq!(check_offer(&offer), Err(LimitError::SizeOverflow));
    }

    #[test]
    fn space() {
        assert_eq!(check_space(10, 10), Ok(()));
        assert_eq!(
            check_space(11, 10),
            Err(LimitError::NotEnoughSpace {
                needed: 11,
                available: 10
            })
        );
    }

    #[test]
    fn decoding_stops_at_the_depth_limit() {
        let ok = postcard::to_stdvec(&nested(MAX_DEPTH)).unwrap();
        assert!(postcard::from_bytes::<FilesAvailable>(&ok).is_ok());

        let too_deep = postcard::to_stdvec(&nested(MAX_DEPTH + 1)).unwrap();
        assert!(postcard::from_bytes::<FilesAvailable>(&too_deep).is_err());

        // The counter is back at zero after a failure, decoding still works
        assert!(postcard::from_bytes::<FilesAvailable>(&ok).is_ok());
    }

    #[test]
    fn decoding_survives_hostile_nesting() {
        // A hand made tree nested a million levels deep, a few bytes per level.
        // Without the guard this overflows the stack.
        let mut bytes = Vec::new();
        for _ in 0..1_000_000 {
            // variant 1 (Dir), name "d", one child
            bytes.extend_from_slice(&[1, 1, b'd', 1]);
        }
        assert!(postcard::from_bytes::<FilesAvailable>(&bytes).is_err());
        assert!(postcard::from_bytes::<FilesToSkip>(&bytes).is_err());
    }
}
