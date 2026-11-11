use std::path::Path;

use crate::limits::{LimitError, NestingGuard, MAX_PACKET_COMPRESSED, MAX_PACKET_SIZE};
use async_compression::tokio::{bufread::GzipDecoder, write::GzipEncoder};
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Tree structure that represents the files that
/// are being sent/received
#[derive(Debug, PartialEq, Clone, Hash)]
pub enum FileSendRecvTree {
    File {
        name: String,
        skip: u64,
        size: u64,
    },
    Dir {
        name: String,
        files: Vec<FileSendRecvTree>,
    },
}

impl FileSendRecvTree {
    /// Name of the file or directory
    pub fn name(&self) -> &str {
        match self {
            FileSendRecvTree::File { name, .. } => name,
            FileSendRecvTree::Dir { name, .. } => name,
        }
    }

    /// Size of the tree in bytes
    pub fn size(&self) -> u64 {
        match self {
            FileSendRecvTree::File { size, .. } => *size,
            FileSendRecvTree::Dir { files, .. } => files.iter().map(|f| f.size()).sum(),
        }
    }

    /// Number of bytes being partially skipped
    /// [FileRecvSendTree] does not contain fully skipped files
    pub fn skip(&self) -> u64 {
        match self {
            FileSendRecvTree::File { skip, .. } => *skip,
            FileSendRecvTree::Dir { files, .. } => files.iter().map(|f| f.skip()).sum(),
        }
    }
}

/// Tree structure that represents the files that are available
#[derive(Debug, PartialEq, Clone, Hash, Serialize)]
pub enum FilesAvailable {
    File {
        name: String,
        size: u64,
        /// Modification time in seconds since the unix epoch, if known
        mtime: Option<u64>,
    },
    Dir {
        name: String,
        files: Vec<FilesAvailable>,
    },
}
/// What [FilesAvailable] looks like on the wire. Decoding goes through this type, so
/// every nested level passes the depth check in the [Deserialize] impl below.
#[derive(Deserialize)]
#[serde(rename = "FilesAvailable")]
enum FilesAvailableWire {
    File {
        name: String,
        size: u64,
        mtime: Option<u64>,
    },
    Dir {
        name: String,
        files: Vec<FilesAvailable>,
    },
}

impl<'de> Deserialize<'de> for FilesAvailable {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let _guard = NestingGuard::enter().map_err(serde::de::Error::custom)?;

        Ok(match FilesAvailableWire::deserialize(deserializer)? {
            FilesAvailableWire::File { name, size, mtime } => Self::File { name, size, mtime },
            FilesAvailableWire::Dir { name, files } => Self::Dir { name, files },
        })
    }
}

/// Get the available files
pub fn get_files_available(path: &Path) -> std::io::Result<FilesAvailable> {
    let name = entry_name(path)?;

    if path.is_file() {
        let metadata = path.metadata()?;
        let mtime = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs());

        Ok(FilesAvailable::File {
            name,
            size: metadata.len(),
            mtime,
        })
    } else {
        let mut entries = std::fs::read_dir(path)?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        // Same order on every run, so a resumed transfer offers the same tree
        entries.sort();

        let mut files = Vec::new();
        for entry in entries {
            files.push(get_files_available(&entry)?);
        }

        Ok(FilesAvailable::Dir { name, files })
    }
}

/// The name a path is offered under
///
/// Paths like `.` or `..` have no file name of their own, so they are resolved first.
fn entry_name(path: &Path) -> std::io::Result<String> {
    let name = match path.file_name() {
        Some(name) => name.to_owned(),
        None => path
            .canonicalize()?
            .file_name()
            .map(|n| n.to_owned())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("{} has no file name", path.display()),
                )
            })?,
    };

    name.into_string().map_err(|name| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("file name is not valid UTF-8: {}", name.to_string_lossy()),
        )
    })
}

impl FilesAvailable {
    /// Name of the file or directory
    pub fn name(&self) -> &str {
        match self {
            FilesAvailable::File { name, .. } => name,
            FilesAvailable::Dir { name, .. } => name,
        }
    }

    /// Size of the tree in bytes
    pub fn size(&self) -> u64 {
        match self {
            FilesAvailable::File { size, .. } => *size,
            FilesAvailable::Dir { files, .. } => files.iter().map(|f| f.size()).sum(),
        }
    }

    /// Convert the tree to a [FileSendRecvTree]
    pub fn to_send_recv_tree(&self) -> FileSendRecvTree {
        match self {
            FilesAvailable::File { name, size, .. } => FileSendRecvTree::File {
                name: name.to_string(),
                skip: 0,
                size: *size,
            },
            FilesAvailable::Dir { name, files } => FileSendRecvTree::Dir {
                name: name.to_string(),
                files: files.iter().map(|f| f.to_send_recv_tree()).collect(),
            },
        }
    }

    /// Fully/partially remove skipped files from the tree
    /// - Returns [std::option::Option::None] if the tree is fully skipped
    /// - panics if the tree roots do not match
    pub fn remove_skipped(&self, to_skip: &FilesToSkip) -> Option<FileSendRecvTree> {
        match (self, to_skip) {
            (
                FilesAvailable::File { name, size, .. },
                FilesToSkip::File {
                    name: skip_name,
                    skip,
                },
            ) => {
                if name == skip_name && size <= skip {
                    None
                } else {
                    Some(FileSendRecvTree::File {
                        name: name.clone(),
                        skip: *skip,
                        size: *size,
                    })
                }
            }
            (
                FilesAvailable::Dir { name, files },
                FilesToSkip::Dir {
                    name: skip_name,
                    files: skip_files,
                },
            ) => {
                if name != skip_name {
                    panic!("Tree roots do not match");
                }

                let mut remaining_files = Vec::new();
                for file in files {
                    if let Some(skip_file) = skip_files.iter().find(|sf| match (file, sf) {
                        (
                            FilesAvailable::File { name, .. },
                            FilesToSkip::File {
                                name: skip_name, ..
                            },
                        ) => name == skip_name,
                        (
                            FilesAvailable::Dir { name, .. },
                            FilesToSkip::Dir {
                                name: skip_name, ..
                            },
                        ) => name == skip_name,
                        _ => false,
                    }) {
                        if let Some(remaining) = file.remove_skipped(skip_file) {
                            remaining_files.push(remaining);
                        }
                    } else {
                        remaining_files.push(file.clone().to_send_recv_tree());
                    }
                }

                if remaining_files.is_empty() {
                    None
                } else {
                    Some(FileSendRecvTree::Dir {
                        name: name.clone(),
                        files: remaining_files,
                    })
                }
            }
            _ => panic!("Tree roots do not match"),
        }
    }

    /// Compare two trees and return the files that can be skipped.
    /// (e.g. compare local and remote files, returning those that can be skipped during transfer).
    /// it is expected that ``self`` is larger than ``local_files``
    /// # Returns
    /// - [std::option::Option::None] if no files can be skipped
    pub fn get_skippable(&self, local_files: &FilesAvailable) -> Option<FilesToSkip> {
        match (self, local_files) {
            (
                FilesAvailable::File { name, .. },
                FilesAvailable::File {
                    name: local_name,
                    size: local_size,
                    ..
                },
            ) => {
                if name == local_name {
                    Some(FilesToSkip::File {
                        name: name.clone(),
                        skip: *local_size,
                    })
                } else {
                    None
                }
            }
            (
                FilesAvailable::Dir { name, files },
                FilesAvailable::Dir {
                    name: local_name,
                    files: local_files,
                },
            ) => {
                if name != local_name {
                    return None;
                }

                let mut skippable_files = Vec::new();
                for file in files {
                    if let Some(remote_file) = local_files.iter().find(|rf| match (file, rf) {
                        (
                            FilesAvailable::File { name, .. },
                            FilesAvailable::File {
                                name: local_name, ..
                            },
                        ) => name == local_name,
                        (
                            FilesAvailable::Dir { name, .. },
                            FilesAvailable::Dir {
                                name: local_name, ..
                            },
                        ) => name == local_name,
                        _ => false,
                    }) {
                        if let Some(skippable) = file.get_skippable(remote_file) {
                            skippable_files.push(skippable);
                        }
                    }
                }

                if skippable_files.is_empty() {
                    None
                } else {
                    Some(FilesToSkip::Dir {
                        name: name.clone(),
                        files: skippable_files,
                    })
                }
            }
            _ => None,
        }
    }
}

/// Tree structure that represents files that have been requested for skipping
#[derive(Debug, PartialEq, Clone, Hash, Serialize)]
pub enum FilesToSkip {
    File {
        name: String,
        skip: u64,
    },
    Dir {
        name: String,
        files: Vec<FilesToSkip>,
    },
}

/// What [FilesToSkip] looks like on the wire, see [FilesAvailableWire]
#[derive(Deserialize)]
#[serde(rename = "FilesToSkip")]
enum FilesToSkipWire {
    File {
        name: String,
        skip: u64,
    },
    Dir {
        name: String,
        files: Vec<FilesToSkip>,
    },
}

impl<'de> Deserialize<'de> for FilesToSkip {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let _guard = NestingGuard::enter().map_err(serde::de::Error::custom)?;

        Ok(match FilesToSkipWire::deserialize(deserializer)? {
            FilesToSkipWire::File { name, skip } => Self::File { name, skip },
            FilesToSkipWire::Dir { name, files } => Self::Dir { name, files },
        })
    }
}

impl FilesToSkip {
    /// Whether this skip tree is a valid answer to `offered`.
    ///
    /// The receiver chooses it, so the sender must check it before using it: same root,
    /// every entry exists in the offer with the same kind, nothing is skipped past its size.
    pub fn applies_to(&self, offered: &FilesAvailable) -> bool {
        match (self, offered) {
            (
                FilesToSkip::File { name, skip },
                FilesAvailable::File {
                    name: offered_name,
                    size,
                    ..
                },
            ) => name == offered_name && skip <= size,
            (
                FilesToSkip::Dir { name, files },
                FilesAvailable::Dir {
                    name: offered_name,
                    files: offered_files,
                },
            ) => {
                // Every entry at most once, or the skipped bytes would add up to more
                // than the directory has
                let mut names = std::collections::HashSet::new();

                name == offered_name
                    && files.len() <= offered_files.len()
                    && files.iter().all(|skip| names.insert(skip.name()))
                    && files
                        .iter()
                        .all(|skip| offered_files.iter().any(|offered| skip.applies_to(offered)))
            }
            _ => false,
        }
    }

    /// Name of the file or directory
    pub fn name(&self) -> &str {
        match self {
            FilesToSkip::File { name, .. } => name,
            FilesToSkip::Dir { name, .. } => name,
        }
    }

    /// Number of bytes being skipped
    /// This will include fully skipped files
    pub fn skip(&self) -> u64 {
        match self {
            FilesToSkip::File { skip, .. } => *skip,
            FilesToSkip::Dir { files, .. } => files.iter().map(|f| f.skip()).sum(),
        }
    }
}

/// How the connection to the other peer is currently routed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionPath {
    /// Straight to the other peer
    Direct,
    /// Through a relay server
    Relay,
    /// No path selected yet
    Unknown,
}

/// The path currently used for data on `conn`
pub fn connection_path(conn: &iroh::endpoint::Connection) -> ConnectionPath {
    let paths = conn.paths();
    let selected = paths.iter().find(|p| p.is_selected());

    match selected {
        Some(p) if p.is_ip() => ConnectionPath::Direct,
        Some(p) if p.is_relay() => ConnectionPath::Relay,
        _ => ConnectionPath::Unknown,
    }
}

pub async fn send_packet<P: Serialize + std::fmt::Debug>(
    packet: P,
    conn: &iroh::endpoint::Connection,
) -> std::io::Result<()> {
    tracing::debug!("Sending packet: {:?}", packet);
    let mut send = conn.open_uni().await?;

    let data = postcard::to_stdvec(&packet).map_err(std::io::Error::other)?;
    let compressed = compress_gzip(&data).await?;
    send.write_all(&compressed).await?;

    send.flush().await?;
    send.finish()?;

    Ok(())
}

#[derive(Debug, Error)]
pub enum PacketRecvError {
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("decode error: {0}")]
    Decode(#[from] postcard::Error),
    #[error("connection error: {0}")]
    Connection(#[from] iroh::endpoint::ConnectionError),
    #[error("read error {0}")]
    Read(#[from] iroh::endpoint::ReadError),
    #[error("{0}")]
    Limit(#[from] LimitError),
}

/// Receive one packet.
///
/// Both the compressed packet and what it decompresses to are bounded, see [crate::limits].
pub async fn receive_packet<P: DeserializeOwned + std::fmt::Debug>(
    conn: &iroh::endpoint::Connection,
) -> Result<P, PacketRecvError> {
    let mut recv = conn.accept_uni().await?;

    let compressed = match recv.read_to_end(MAX_PACKET_COMPRESSED).await {
        Ok(data) => data,
        Err(iroh::endpoint::ReadToEndError::TooLong) => {
            return Err(LimitError::PacketTooLarge(MAX_PACKET_COMPRESSED).into());
        }
        Err(iroh::endpoint::ReadToEndError::Read(e)) => return Err(e.into()),
    };

    let decompressed = decompress_gzip(&compressed, MAX_PACKET_SIZE).await?;

    let packet = postcard::from_bytes(&decompressed)?;

    tracing::debug!("Received packet: {:?}", packet);

    Ok(packet)
}

async fn compress_gzip(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut encoder = GzipEncoder::new(&mut out);
    encoder.write_all(data).await?;
    encoder.shutdown().await?;

    Ok(out)
}

/// Decompress `data`, failing if the result is larger than `limit` bytes
async fn decompress_gzip(data: &[u8], limit: usize) -> Result<Vec<u8>, PacketRecvError> {
    let mut out = Vec::new();
    let decoder = GzipDecoder::new(data);
    // One byte more than allowed tells "exactly at the limit" and "too large" apart
    decoder.take(limit as u64 + 1).read_to_end(&mut out).await?;

    if out.len() > limit {
        return Err(LimitError::PacketTooLarge(limit).into());
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_compression() {
        let data = b"hellllllllllllllllllllllllo world";
        let compressed = compress_gzip(data).await.unwrap();
        let decompressed = decompress_gzip(&compressed, 1024).await.unwrap();

        assert!(compressed.len() < data.len());
        assert_eq!(data, &decompressed[..]);
    }

    #[tokio::test]
    async fn decompression_is_bounded() {
        // A megabyte of zeros compresses to about a kilobyte
        let bomb = compress_gzip(&vec![0u8; 1024 * 1024]).await.unwrap();
        assert!(bomb.len() < 4096);

        assert!(decompress_gzip(&bomb, 1024 * 1024).await.is_ok());
        assert!(matches!(
            decompress_gzip(&bomb, 1024 * 1024 - 1).await,
            Err(PacketRecvError::Limit(LimitError::PacketTooLarge(_)))
        ));
    }

    #[test]
    fn skip_tree_must_match_the_offer() {
        let file = |name: &str, size| FilesAvailable::File {
            name: name.to_string(),
            size,
            mtime: None,
        };
        let skip = |name: &str, skip| FilesToSkip::File {
            name: name.to_string(),
            skip,
        };
        let offered = FilesAvailable::Dir {
            name: "root".to_string(),
            files: vec![
                file("a", 10),
                FilesAvailable::Dir {
                    name: "sub".to_string(),
                    files: vec![file("b", 20)],
                },
            ],
        };
        let dir = |name: &str, files| FilesToSkip::Dir {
            name: name.to_string(),
            files,
        };

        assert!(dir("root", vec![skip("a", 10)]).applies_to(&offered));
        assert!(dir("root", vec![dir("sub", vec![skip("b", 5)])]).applies_to(&offered));
        assert!(dir("root", vec![]).applies_to(&offered));

        // Wrong root, unknown entry, wrong kind, skipping past the end
        assert!(!dir("other", vec![]).applies_to(&offered));
        assert!(!dir("root", vec![skip("zzz", 1)]).applies_to(&offered));
        assert!(!dir("root", vec![skip("sub", 1)]).applies_to(&offered));
        assert!(!dir("root", vec![skip("a", 11)]).applies_to(&offered));
        // The same entry twice
        assert!(!dir("root", vec![skip("a", 10), skip("a", 10)]).applies_to(&offered));
        assert!(!skip("root", 0).applies_to(&offered));
    }

    #[test]
    fn test_file_trees() {
        let files_offered = FilesAvailable::Dir {
            name: "root".to_string(),
            files: vec![
                FilesAvailable::File {
                    name: "file1".to_string(),
                    size: 10,
                    mtime: None,
                },
                FilesAvailable::Dir {
                    name: "dir1".to_string(),
                    files: vec![
                        FilesAvailable::File {
                            name: "file2".to_string(),
                            size: 20,
                            mtime: None,
                        },
                        FilesAvailable::File {
                            name: "file3".to_string(),
                            size: 30,
                            mtime: None,
                        },
                    ],
                },
            ],
        };

        let already_installed = FilesAvailable::Dir {
            name: "root".to_string(),
            files: vec![
                FilesAvailable::File {
                    name: "file1".to_string(),
                    size: 10,
                    mtime: None,
                },
                FilesAvailable::Dir {
                    name: "dir1".to_string(),
                    files: vec![FilesAvailable::File {
                        name: "file2".to_string(),
                        size: 15,
                        mtime: None,
                    }],
                },
            ],
        };

        let to_skip = files_offered.get_skippable(&already_installed).unwrap();
        assert_eq!(
            to_skip,
            FilesToSkip::Dir {
                name: "root".to_string(),
                files: vec![
                    FilesToSkip::File {
                        name: "file1".to_string(),
                        skip: 10
                    },
                    FilesToSkip::Dir {
                        name: "dir1".to_string(),
                        files: vec![FilesToSkip::File {
                            name: "file2".to_string(),
                            skip: 15
                        }],
                    },
                ],
            }
        );

        let new_tree_expected = FileSendRecvTree::Dir {
            name: "root".to_string(),
            files: vec![FileSendRecvTree::Dir {
                name: "dir1".to_string(),
                files: vec![
                    FileSendRecvTree::File {
                        name: "file2".to_string(),
                        skip: 15,
                        size: 20,
                    },
                    FileSendRecvTree::File {
                        name: "file3".to_string(),
                        skip: 0,
                        size: 30,
                    },
                ],
            }],
        };

        let new_tree = files_offered.remove_skipped(&to_skip).unwrap();
        assert_eq!(new_tree, new_tree_expected);
    }

    #[test]
    fn test_no_files_to_skip() {
        let offered = FilesAvailable::Dir {
            name: "root".to_string(),
            files: vec![
                FilesAvailable::File {
                    name: "file1".to_string(),
                    size: 10,
                    mtime: None,
                },
                FilesAvailable::Dir {
                    name: "dir1".to_string(),
                    files: vec![
                        FilesAvailable::File {
                            name: "file2".to_string(),
                            size: 20,
                            mtime: None,
                        },
                        FilesAvailable::File {
                            name: "file3".to_string(),
                            size: 30,
                            mtime: None,
                        },
                    ],
                },
            ],
        };

        let installed = FilesAvailable::Dir {
            name: "root".to_string(),
            files: vec![],
        };

        let to_skip = offered.get_skippable(&installed);
        assert_eq!(to_skip, None);
    }

    #[test]
    fn larger_directory() {
        let offered = FilesAvailable::Dir {
            name: "root".to_string(),
            files: vec![
                FilesAvailable::File {
                    name: "file1".to_string(),
                    size: 10,
                    mtime: None,
                },
                FilesAvailable::Dir {
                    name: "dir1".to_string(),
                    files: vec![
                        FilesAvailable::File {
                            name: "file2".to_string(),
                            size: 20,
                            mtime: None,
                        },
                        FilesAvailable::File {
                            name: "file3".to_string(),
                            size: 30,
                            mtime: None,
                        },
                        FilesAvailable::Dir {
                            name: "dir2".to_string(),
                            files: vec![FilesAvailable::File {
                                name: "file4".to_string(),
                                size: 40,
                                mtime: None,
                            }],
                        },
                    ],
                },
                FilesAvailable::Dir {
                    name: "dir3".to_string(),
                    files: vec![FilesAvailable::File {
                        name: "file5".to_string(),
                        size: 50,
                        mtime: None,
                    }],
                },
            ],
        };

        let installed = FilesAvailable::Dir {
            name: "root".to_string(),
            files: vec![
                FilesAvailable::File {
                    name: "file1".to_string(),
                    size: 10,
                    mtime: None,
                },
                FilesAvailable::Dir {
                    name: "dir1".to_string(),
                    files: vec![
                        FilesAvailable::File {
                            name: "file2".to_string(),
                            size: 5,
                            mtime: None,
                        },
                        FilesAvailable::Dir {
                            name: "dir2".to_string(),
                            files: vec![],
                        },
                    ],
                },
            ],
        };

        let to_skip = offered.get_skippable(&installed).unwrap();
        assert_eq!(
            to_skip,
            FilesToSkip::Dir {
                name: "root".to_string(),
                files: vec![
                    FilesToSkip::File {
                        name: "file1".to_string(),
                        skip: 10
                    },
                    FilesToSkip::Dir {
                        name: "dir1".to_string(),
                        files: vec![
                            FilesToSkip::File {
                                name: "file2".to_string(),
                                skip: 5
                            },
                            // FilesToSkip::Dir {
                            //     name: "dir2".to_string(),
                            //     files: vec![],
                            // },
                        ],
                    }
                ]
            }
        );

        let new_tree = offered.remove_skipped(&to_skip).unwrap();
        let new_tree_expected = FileSendRecvTree::Dir {
            name: "root".to_string(),
            files: vec![
                FileSendRecvTree::Dir {
                    name: "dir1".to_string(),
                    files: vec![
                        FileSendRecvTree::File {
                            name: "file2".to_string(),
                            skip: 5,
                            size: 20,
                        },
                        FileSendRecvTree::File {
                            name: "file3".to_string(),
                            skip: 0,
                            size: 30,
                        },
                        FileSendRecvTree::Dir {
                            name: "dir2".to_string(),
                            files: vec![FileSendRecvTree::File {
                                name: "file4".to_string(),
                                skip: 0,
                                size: 40,
                            }],
                        },
                    ],
                },
                FileSendRecvTree::Dir {
                    name: "dir3".to_string(),
                    files: vec![FileSendRecvTree::File {
                        name: "file5".to_string(),
                        skip: 0,
                        size: 50,
                    }],
                },
            ],
        };

        assert_eq!(new_tree, new_tree_expected);
    }
}
