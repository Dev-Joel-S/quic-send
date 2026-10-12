use crate::{
    common::{
        connection_path, receive_packet, send_packet, ConnectionPath, FileSendRecvTree,
        FilesAvailable, FilesToSkip, PacketRecvError,
    },
    destination::{
        local_name, local_progress, part_path, resolve, validate_offer, Destination, NameError,
        Placement, ResumeState,
    },
    packets::{ReceiverToSender, SenderToReceiver},
    BUF_SIZE, QS_ALPN, QS_PROTO_VERSION,
};
use async_compression::tokio::bufread::GzipDecoder;
use std::{
    io,
    path::{Path, PathBuf},
};
use thiserror::Error;
use tokio::io::AsyncWriteExt;

/// Generic receive function
///
/// # Returns
/// * `Ok(true)` if the transfer should continue
/// * `Ok(false)` if the transfer should stop
pub async fn receive_file<R, W>(
    recv: &mut R,
    file: &mut W,
    skip: u64,
    size: u64,
    read_callback: &mut impl FnMut(u64),
    should_continue: &mut impl FnMut() -> bool,
) -> std::io::Result<bool>
where
    R: tokio::io::AsyncReadExt + Unpin,
    W: tokio::io::AsyncWriteExt + tokio::io::AsyncSeekExt + Unpin,
{
    file.seek(tokio::io::SeekFrom::Start(skip)).await?;

    let mut buf = vec![0; BUF_SIZE];
    let mut written = skip;

    while written < size {
        if !should_continue() {
            return Ok(false);
        }

        let to_write = std::cmp::min(BUF_SIZE as u64, size - written);
        let n = recv.read_exact(&mut buf[..to_write as usize]).await?;

        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected eof",
            ));
        }

        file.write_all(&buf[..n]).await?;
        written += n as u64;

        read_callback(n as u64);
    }

    Ok(true)
}

/// Receive an entry of the transfer tree to `path`.
///
/// Files are written to `<path>.part` and renamed to `path` once complete,
/// so an interrupted transfer never leaves an incomplete file under its final name.
///
/// # Returns
/// * `Ok(true)` if the transfer should continue
/// * `Ok(false)` if the transfer should stop
pub async fn receive_entry<R>(
    recv: &mut R,
    path: &Path,
    entry: &FileSendRecvTree,
    read_callback: &mut impl FnMut(u64),
    should_continue: &mut impl FnMut() -> bool,
) -> std::io::Result<bool>
where
    R: tokio::io::AsyncReadExt + Unpin,
{
    match entry {
        FileSendRecvTree::File { skip, size, .. } => {
            let part = part_path(path);
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(&part)
                .await?;
            // Anything past the resume point is not trusted
            file.set_len(*skip).await?;

            let complete = receive_file(
                recv,
                &mut file,
                *skip,
                *size,
                read_callback,
                should_continue,
            )
            .await?;

            file.sync_all().await?;
            file.shutdown().await?;
            drop(file);

            if complete {
                rename_with_retry(&part, path).await?;
            }

            Ok(complete)
        }
        FileSendRecvTree::Dir { files, .. } => {
            tokio::fs::create_dir_all(path).await?;

            for file in files {
                let child = path.join(local_name(file.name()).map_err(io::Error::other)?);
                if !Box::pin(receive_entry(
                    recv,
                    &child,
                    file,
                    read_callback,
                    should_continue,
                ))
                .await?
                {
                    return Ok(false);
                }
            }

            Ok(true)
        }
    }
}

/// Rename, retrying for a moment on Windows,
/// where a virus scanner may still hold the freshly written file open.
async fn rename_with_retry(from: &Path, to: &Path) -> io::Result<()> {
    let mut attempt = 0;
    loop {
        match tokio::fs::rename(from, to).await {
            Err(e)
                if cfg!(windows) && e.kind() == io::ErrorKind::PermissionDenied && attempt < 5 =>
            {
                attempt += 1;
                tokio::time::sleep(std::time::Duration::from_millis(100 * attempt)).await;
            }
            r => return r,
        }
    }
}

#[derive(Debug, Error)]
pub enum ReceiveError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("connect error: {0}")]
    Connect(String),
    #[error("connection error: {0}")]
    Connection(#[from] iroh::endpoint::ConnectionError),
    #[error("write error: {0}")]
    Write(#[from] iroh::endpoint::WriteError),
    #[error("read error {0}")]
    Read(#[from] iroh::endpoint::ReadError),
    #[error("version mismatch, expected: {0}, got: {1}")]
    WrongVersion(String, String),
    #[error("unexpected data packet: {0:?}")]
    UnexpectedDataPacket(SenderToReceiver),
    #[error("files rejected")]
    FilesRejected,
    #[error("invalid code")]
    InvalidCode,
    #[error("receive packet error: {0}")]
    ReceivePacket(#[from] PacketRecvError),
    #[error("{0}")]
    FileName(#[from] NameError),
}

/// A receiver that can receive files
pub struct Receiver {
    /// Receiver arguments
    args: ReceiverArgs,
    /// The connection to the sender
    conn: iroh::endpoint::Connection,
    /// The local endpoint
    endpoint: iroh::Endpoint,
}

/// Arguments for the receiver
pub struct ReceiverArgs {
    /// Resume interrupted transfers.
    /// If false, existing destinations are overwritten instead.
    pub resume: bool,
}

impl Receiver {
    pub async fn connect(
        this_endpoint: iroh::Endpoint,
        addr: iroh::EndpointAddr,
        args: ReceiverArgs,
    ) -> Result<Self, ReceiveError> {
        let conn = this_endpoint
            .connect(addr, QS_ALPN)
            .await
            .map_err(|e| ReceiveError::Connect(e.to_string()))?;

        tracing::info!("receiver connected to sender");

        Ok(Self {
            args,
            conn,
            endpoint: this_endpoint,
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

    /// Receive files
    /// # Arguments
    /// * `initial_progress_callback` - Callback with the initial progress of each file to send (name, current, total)
    /// * `accept_files_callback` - Callback to accept or reject the files (Some(path) to accept, None to reject)
    /// * `destinations_callback` - Callback with the destination chosen for each offered file/dir
    /// * `read_callback` - Callback every time data is written to disk
    /// * `should_continue` - Callback to check if the transfer should continue
    ///
    /// # Returns
    /// * `Ok(true)` if the transfer was finished successfully
    /// * `Ok(false)` if the transfer was stopped
    pub async fn receive_files(
        &mut self,
        mut initial_progress_callback: impl FnMut(&[(String, u64, u64)]),
        mut accept_files_callback: impl FnMut(&[FilesAvailable]) -> Option<PathBuf>,
        mut destinations_callback: impl FnMut(&[FilesAvailable], &[Destination]),
        read_callback: &mut impl FnMut(u64),
        should_continue: &mut impl FnMut() -> bool,
    ) -> Result<bool, ReceiveError> {
        match receive_packet::<SenderToReceiver>(&self.conn).await? {
            SenderToReceiver::ConnRequest { version_num } => {
                if version_num != QS_PROTO_VERSION {
                    send_packet(
                        ReceiverToSender::WrongVersion {
                            expected: QS_PROTO_VERSION.to_string(),
                        },
                        &self.conn,
                    )
                    .await?;
                    return Err(ReceiveError::WrongVersion(
                        QS_PROTO_VERSION.to_string(),
                        version_num,
                    ));
                }
                send_packet(ReceiverToSender::Ok, &self.conn).await?;
            }
            p => return Err(ReceiveError::UnexpectedDataPacket(p)),
        }

        let files_offered = match receive_packet::<SenderToReceiver>(&self.conn).await? {
            SenderToReceiver::FileInfo { files } => files,
            p => return Err(ReceiveError::UnexpectedDataPacket(p)),
        };

        if let Err(e) = validate_offer(&files_offered) {
            send_packet(ReceiverToSender::RejectFiles, &self.conn).await?;
            self.wait_for_close().await;
            return Err(e.into());
        }

        let output_path = match accept_files_callback(&files_offered) {
            Some(path) => path,
            None => {
                send_packet(ReceiverToSender::RejectFiles, &self.conn).await?;
                // Wait for the sender to acknowledge the rejection
                self.wait_for_close().await;
                return Err(ReceiveError::FilesRejected);
            }
        };

        tokio::fs::create_dir_all(&output_path).await?;

        let mut destinations: Vec<Destination> = Vec::with_capacity(files_offered.len());
        for offered in &files_offered {
            let destination = resolve(&output_path, offered, !self.args.resume, &destinations)?;
            destinations.push(destination);
        }

        destinations_callback(&files_offered, &destinations);

        let files_to_skip: Vec<Option<FilesToSkip>> = destinations
            .iter()
            .zip(&files_offered)
            .map(|(destination, offered)| match destination.placement {
                Placement::Resume => local_progress(&destination.path, offered),
                Placement::New | Placement::Overwrite => None,
            })
            .collect();

        let to_receive: Vec<Option<FileSendRecvTree>> = files_offered
            .iter()
            .zip(&files_to_skip)
            .map(|(offered, skip)| {
                if let Some(skip) = skip {
                    offered.remove_skipped(skip)
                } else {
                    Some(offered.to_send_recv_tree())
                }
            })
            .collect();

        // progress callback
        let mut progress: Vec<(String, u64, u64)> = Vec::with_capacity(to_receive.len());
        for (offered, skip) in files_offered.iter().zip(&files_to_skip) {
            progress.push((
                offered.name().to_string(),
                skip.as_ref().map(|s| s.skip()).unwrap_or(0),
                offered.size(),
            ));
        }

        initial_progress_callback(&progress);

        // Record what is being received before the first byte is written
        let peer = Some(self.conn.remote_id().to_string());
        for (destination, offered) in destinations.iter().zip(&files_offered) {
            if destination.placement != Placement::Resume {
                ResumeState::new(offered, peer.clone()).write(&destination.path)?;
            }
        }

        send_packet(
            ReceiverToSender::AcceptFilesSkip {
                files: files_to_skip,
            },
            &self.conn,
        )
        .await?;

        let recv = self.conn.accept_uni().await?;
        let mut recv = GzipDecoder::new(tokio::io::BufReader::with_capacity(BUF_SIZE, recv));

        let mut interrupted = false;

        for (destination, entry) in destinations.iter().zip(to_receive) {
            // [None] means everything is already there
            if let Some(entry) = entry {
                if !receive_entry(
                    &mut recv,
                    &destination.path,
                    &entry,
                    read_callback,
                    should_continue,
                )
                .await?
                {
                    interrupted = true;
                    break;
                }
            }

            ResumeState::remove(&destination.path)?;
        }

        self.close().await;

        if interrupted {
            tracing::info!("transfer interrupted");
        }

        Ok(!interrupted)
    }
}
