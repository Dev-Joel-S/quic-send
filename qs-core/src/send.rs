#![allow(clippy::suspicious_open_options)]

use crate::{
    common::{
        connection_path, get_files_available, receive_packet, send_packet, ConnectionPath,
        FileSendRecvTree, FilesAvailable, PacketRecvError,
    },
    limits::{check_offer, LimitError},
    packets::{ReceiverToSender, SenderToReceiver},
    BUF_SIZE, QS_PROTO_VERSION,
};
use async_compression::tokio::write::GzipEncoder;
use std::path::PathBuf;
use thiserror::Error;
use tokio::io::AsyncWriteExt;

/// Generic send function
///
/// # Returns
/// * `Ok(true)` if the transfer should continue
/// * `Ok(false)` if the transfer should stop
pub async fn send_file<S, R>(
    send: &mut S,
    file: &mut R,
    skip: u64,
    size: u64,
    write_callback: &mut impl FnMut(u64),
    should_continue: &mut impl FnMut() -> bool,
) -> std::io::Result<bool>
where
    S: tokio::io::AsyncWriteExt + Unpin,
    R: tokio::io::AsyncReadExt + tokio::io::AsyncSeekExt + Unpin,
{
    file.seek(tokio::io::SeekFrom::Start(skip)).await?;

    let mut buf = vec![0; BUF_SIZE];
    let mut read = skip;

    while read < size {
        if !should_continue() {
            return Ok(false);
        }

        let to_read = std::cmp::min(BUF_SIZE as u64, size - read);
        let n = file.read_exact(&mut buf[..to_read as usize]).await?;

        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected eof",
            ));
        }

        send.write_all(&buf[..n]).await?;
        read += n as u64;

        write_callback(n as u64);
    }

    Ok(true)
}

/// # Returns
/// * `Ok(true)` if the transfer should continue
/// * `Ok(false)` if the transfer should stop
pub fn send_directory<S>(
    send: &mut S,
    root_path: &std::path::Path,
    files: &[FileSendRecvTree],
    write_callback: &mut impl FnMut(u64),
    should_continue: &mut impl FnMut() -> bool,
) -> std::io::Result<bool>
where
    S: tokio::io::AsyncWriteExt + Unpin + Send,
{
    for file in files {
        match file {
            FileSendRecvTree::File { name, skip, size } => {
                let path = root_path.join(name);

                let continues = tokio::task::block_in_place(|| {
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    rt.block_on(async {
                        let mut file = tokio::fs::OpenOptions::new().read(true).open(&path).await?;

                        if !send_file(
                            send,
                            &mut file,
                            *skip,
                            *size,
                            write_callback,
                            should_continue,
                        )
                        .await?
                        {
                            return Ok::<bool, std::io::Error>(false);
                        }

                        file.shutdown().await?;
                        Ok::<bool, std::io::Error>(true)
                    })
                })?;

                if !continues {
                    return Ok(false);
                }
            }
            FileSendRecvTree::Dir { name, files } => {
                let root_path = root_path.join(name);
                if !send_directory(send, &root_path, files, write_callback, should_continue)? {
                    return Ok(false);
                };
            }
        }
    }

    Ok(true)
}

#[derive(Debug, Error)]
pub enum SendError {
    #[error("files do not exist: {0}")]
    FileDoesNotExists(PathBuf),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("connect error: {0}")]
    Connect(String),
    #[error("connection error: {0}")]
    Connection(#[from] iroh::endpoint::ConnectionError),
    #[error("read error: {0}")]
    Read(#[from] iroh::endpoint::ReadError),
    #[error("wrong version, the receiver expected: {0}, but got: {1}")]
    WrongVersion(String, String),
    #[error("unexpected data packet: {0:?}")]
    UnexpectedDataPacket(ReceiverToSender),
    #[error("files rejected")]
    FilesRejected,
    #[error("receive packet error: {0}")]
    ReceivePacket(#[from] PacketRecvError),
    #[error("failed to fetch the endpoint address: {0}")]
    EndpointAddr(String),
    #[error("{0}")]
    Limit(#[from] LimitError),
    #[error("two of the files or directories to send are both named {0:?}")]
    DuplicateName(String),
    #[error("the receiver asked to skip files that were not offered")]
    InvalidSkip,
}

/// A name that more than one of the top level entries has
fn duplicate_name(files: &[FilesAvailable]) -> Option<String> {
    let mut seen = std::collections::HashSet::new();
    files
        .iter()
        .find(|file| !seen.insert(file.name()))
        .map(|file| file.name().to_string())
}

/// A client that can send files
pub struct Sender {
    /// Sender arguments
    args: SenderArgs,
    /// The connection to the receiver
    conn: iroh::endpoint::Connection,
    /// The local endpoint
    endpoint: iroh::Endpoint,
    /// Turns away everyone who connects after the receiver
    refuse_others: tokio::task::JoinHandle<()>,
}

impl Drop for Sender {
    fn drop(&mut self) {
        self.refuse_others.abort();
    }
}

/// Arguments for the sender
pub struct SenderArgs {
    /// Files/Directories to send
    pub files: Vec<PathBuf>,
    /// Only this peer may connect, everyone else is turned away.
    ///
    /// Known after a pairing or for a saved peer. With [None] the first peer that
    /// connects is taken, which is all a plain ticket can offer: whoever has the
    /// ticket may receive.
    pub expected_peer: Option<iroh::EndpointId>,
}

impl Sender {
    pub async fn connect(
        this_endpoint: iroh::Endpoint,
        args: SenderArgs,
    ) -> Result<Self, SendError> {
        let conn = loop {
            let Some(incoming) = this_endpoint.accept().await else {
                return Err(SendError::Connect("the endpoint was closed".to_string()));
            };

            // A broken or hostile connection attempt must not end the wait for the receiver
            let conn = match incoming.accept() {
                Ok(accepting) => match accepting.await {
                    Ok(conn) => conn,
                    Err(e) => {
                        tracing::debug!("incoming connection failed: {e}");
                        continue;
                    }
                },
                Err(e) => {
                    tracing::debug!("incoming connection failed: {e}");
                    continue;
                }
            };

            match args.expected_peer {
                Some(expected) if conn.remote_id() != expected => {
                    tracing::warn!(
                        "refused a connection from {}, expected {}",
                        conn.remote_id().fmt_short(),
                        expected.fmt_short()
                    );
                    conn.close(1u32.into(), b"unexpected peer");
                }
                _ => break conn,
            }
        };

        // One receiver per transfer: everybody else is refused from here on
        let refuse_others = tokio::spawn({
            let endpoint = this_endpoint.clone();
            async move {
                while let Some(incoming) = endpoint.accept().await {
                    tracing::debug!("refused a second connection");
                    incoming.refuse();
                }
            }
        });

        tracing::info!("receiver connected to sender");

        Ok(Self {
            args,
            conn,
            endpoint: this_endpoint,
            refuse_others,
        })
    }

    /// Close the connection
    pub async fn close(&mut self) {
        self.conn.close(0u32.into(), &[0]);
        self.endpoint.close().await;
    }

    /// Wait for the other peer to close the connection
    pub async fn wait_for_close(&mut self) {
        self.conn.closed().await;
    }

    /// How the connection is currently routed
    pub fn connection_type(&self) -> ConnectionPath {
        connection_path(&self.conn)
    }

    /// The id of the receiver that connected
    pub fn remote_id(&self) -> iroh::EndpointId {
        self.conn.remote_id()
    }

    /// Send files
    /// # Arguments
    /// * `wait_for_other_peer_to_accept_files_callback` - Callback to wait for the other peer to accept the files
    /// * `files_decision_callback` - Callback with the decision of the other peer to accept the files
    /// * `initial_progress_callback` - Callback with the initial progress of each file to send (name, current, total)
    /// * `write_callback` - Callback every time data is written to the connection
    /// * `should_continue` - Callback to check if the transfer should continue
    ///
    /// # Returns
    /// * `Ok(true)` if the transfer was finished successfully
    /// * `Ok(false)` if the transfer was stopped
    pub async fn send_files(
        &mut self,
        mut wait_for_other_peer_to_accept_files_callback: impl FnMut(),
        mut files_decision_callback: impl FnMut(bool),
        mut initial_progress_callback: impl FnMut(&[(String, u64, u64)]),
        write_callback: &mut impl FnMut(u64),
        should_continue: &mut impl FnMut() -> bool,
    ) -> Result<bool, SendError> {
        send_packet(
            SenderToReceiver::ConnRequest {
                version_num: QS_PROTO_VERSION.to_string(),
            },
            &self.conn,
        )
        .await?;

        match receive_packet::<ReceiverToSender>(&self.conn).await? {
            ReceiverToSender::Ok => (),
            ReceiverToSender::WrongVersion { expected } => {
                return Err(SendError::WrongVersion(
                    expected,
                    QS_PROTO_VERSION.to_string(),
                ));
            }
            p => return Err(SendError::UnexpectedDataPacket(p)),
        }

        let files_available = {
            let mut files = Vec::new();
            for file in &self.args.files {
                if !file.exists() {
                    return Err(SendError::FileDoesNotExists(file.clone()));
                }
                files.push(get_files_available(file)?);
            }
            files
        };

        // The receiver refuses an offer outside the limits, fail here with a clear reason
        check_offer(&files_available)?;
        if let Some(name) = duplicate_name(&files_available) {
            return Err(SendError::DuplicateName(name));
        }

        send_packet(
            SenderToReceiver::FileInfo {
                files: files_available.clone(),
            },
            &self.conn,
        )
        .await?;

        wait_for_other_peer_to_accept_files_callback();

        let to_skip = match receive_packet::<ReceiverToSender>(&self.conn).await? {
            ReceiverToSender::AcceptFilesSkip { files } => {
                files_decision_callback(true);
                files
            }
            ReceiverToSender::RejectFiles => {
                files_decision_callback(false);
                self.close().await;
                return Err(SendError::FilesRejected);
            }
            p => return Err(SendError::UnexpectedDataPacket(p)),
        };

        // The skip list comes from the receiver and is not trusted
        let valid = to_skip.len() == files_available.len()
            && to_skip
                .iter()
                .zip(&files_available)
                .all(|(skip, file)| skip.as_ref().is_none_or(|skip| skip.applies_to(file)));
        if !valid {
            self.close().await;
            return Err(SendError::InvalidSkip);
        }

        let to_send: Vec<Option<FileSendRecvTree>> = files_available
            .iter()
            .zip(&to_skip)
            .map(|(file, skip)| {
                if let Some(skip) = skip {
                    file.remove_skipped(skip)
                } else {
                    Some(file.to_send_recv_tree())
                }
            })
            .collect();

        let mut progress: Vec<(String, u64, u64)> = Vec::with_capacity(files_available.len());
        for (file, skip) in files_available.iter().zip(to_skip) {
            progress.push((
                file.name().to_string(),
                skip.as_ref().map(|s| s.skip()).unwrap_or(0),
                file.size(),
            ));
        }

        initial_progress_callback(&progress);

        let send = self.conn.open_uni().await?;
        let mut send = GzipEncoder::new(send);

        let mut interrupted = false;

        for (path, file) in self.args.files.iter().zip(to_send) {
            if let Some(file) = file {
                match file {
                    FileSendRecvTree::File { skip, size, .. } => {
                        let mut file = tokio::fs::File::open(&path).await?;
                        if !send_file(
                            &mut send,
                            &mut file,
                            skip,
                            size,
                            write_callback,
                            should_continue,
                        )
                        .await?
                        {
                            interrupted = true;
                            break;
                        }
                    }
                    FileSendRecvTree::Dir { files, .. } => {
                        if !send_directory(
                            &mut send,
                            path,
                            &files,
                            write_callback,
                            should_continue,
                        )? {
                            interrupted = true;
                            break;
                        }
                    }
                }
            }
        }

        send.shutdown().await?;

        if !interrupted {
            self.wait_for_close().await;
        } else {
            tracing::info!("the transfer was interrupted");
        }

        self.close().await;

        Ok(!interrupted)
    }
}
