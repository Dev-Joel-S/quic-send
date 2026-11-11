use crate::{
    common::{
        connection_path, receive_packet, send_packet, ConnectionPath, FileSendRecvTree,
        FilesAvailable, FilesToSkip, PacketRecvError,
    },
    crypto::{ensure_post_quantum, CryptoError},
    destination::{
        local_name, local_progress, part_path, refuse_symlink, resolve, validate_offer,
        Destination, NameError, Placement, ResumeState,
    },
    limits::{check_offer, check_space, LimitError},
    packets::{ReceiverToSender, SenderToReceiver},
    pairing::pake::Side,
    password::{self, PasswordError},
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
            // A link at this place would send the data somewhere else
            refuse_symlink(&part)?;
            let mut options = tokio::fs::OpenOptions::new();
            options.write(true).create(true).truncate(false);
            // Also refused by the system if a link appears between the check and here
            #[cfg(unix)]
            options.custom_flags(libc::O_NOFOLLOW);
            let mut file = options.open(&part).await?;
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
            // Only a real directory is entered. A link to a directory elsewhere, left in a
            // folder that is overwritten or resumed, would lead out of the destination.
            match tokio::fs::symlink_metadata(path).await {
                Ok(metadata) if metadata.is_dir() => {}
                Ok(_) => {
                    refuse_symlink(path)?;
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("{} exists and is not a directory", path.display()),
                    ));
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    tokio::fs::create_dir(path).await?;
                }
                Err(e) => return Err(e),
            }

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
    #[error("{0}")]
    Limit(#[from] LimitError),
    #[error("{0}")]
    Crypto(#[from] CryptoError),
    #[error("{0}")]
    Password(#[from] PasswordError),
}

/// A receiver that can receive files
pub struct Receiver {
    /// Receiver arguments
    args: ReceiverArgs,
    /// The connection to the sender
    conn: iroh::endpoint::Connection,
    /// The local endpoint
    endpoint: iroh::Endpoint,
    /// The sender wants a password
    password_required: bool,
    /// The password was checked
    authenticated: bool,
    /// Where the sender said it can be found again
    peer_identity: Option<iroh::EndpointAddr>,
    /// Turns away everyone who connects after the sender, when this side listened
    refuse_others: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for Receiver {
    fn drop(&mut self) {
        if let Some(task) = &self.refuse_others {
            task.abort();
        }
    }
}

/// Arguments for the receiver
pub struct ReceiverArgs {
    /// Resume interrupted transfers.
    /// If false, existing destinations are overwritten instead.
    pub resume: bool,
    /// The own address to tell the sender, so it can save this device as a peer.
    /// Only set together with the stable identity.
    pub announce: Option<iroh::EndpointAddr>,
}

impl Receiver {
    /// Connect to the sender at `addr`
    pub async fn connect(
        this_endpoint: iroh::Endpoint,
        addr: iroh::EndpointAddr,
        args: ReceiverArgs,
    ) -> Result<Self, ReceiveError> {
        let conn = this_endpoint
            .connect(addr, QS_ALPN)
            .await
            .map_err(|e| ReceiveError::Connect(e.to_string()))?;

        if let Err(e) = ensure_post_quantum(&conn) {
            conn.close(2u32.into(), b"post-quantum key exchange required");
            this_endpoint.close().await;
            return Err(e.into());
        }

        tracing::info!("receiver connected to sender");

        Self::welcome(this_endpoint, conn, args, None).await
    }

    /// Wait for the sender `expected` to connect, a saved peer.
    ///
    /// The other way round from [Receiver::connect]: the receiver listens and the sender
    /// dials. Everyone but `expected` is turned away.
    pub async fn accept(
        this_endpoint: iroh::Endpoint,
        expected: iroh::EndpointId,
        args: ReceiverArgs,
    ) -> Result<Self, ReceiveError> {
        let conn = loop {
            let Some(incoming) = this_endpoint.accept().await else {
                return Err(ReceiveError::Connect("the endpoint was closed".to_string()));
            };

            // A broken or hostile connection attempt must not end the wait for the sender
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

            if let Err(e) = ensure_post_quantum(&conn) {
                tracing::warn!("refused a connection: {e}");
                conn.close(2u32.into(), b"post-quantum key exchange required");
                continue;
            }

            if conn.remote_id() != expected {
                tracing::warn!(
                    "refused a connection from {}, expected {}",
                    conn.remote_id().fmt_short(),
                    expected.fmt_short()
                );
                conn.close(1u32.into(), b"unexpected peer");
                continue;
            }

            break conn;
        };

        // One sender per transfer: everybody else is refused from here on
        let refuse_others = crate::send::refuse_everyone(&this_endpoint);

        tracing::info!("sender connected to receiver");

        Self::welcome(this_endpoint, conn, args, Some(refuse_others)).await
    }

    /// Answer the connection request of the sender on a fresh connection
    async fn welcome(
        this_endpoint: iroh::Endpoint,
        conn: iroh::endpoint::Connection,
        args: ReceiverArgs,
        refuse_others: Option<tokio::task::JoinHandle<()>>,
    ) -> Result<Self, ReceiveError> {
        // Answer the connection request right away. The sender only waits a moment for
        // this, so that nobody can keep it busy without ever answering.
        let (password_required, peer_identity) =
            match receive_packet::<SenderToReceiver>(&conn).await? {
                SenderToReceiver::ConnRequest {
                    version_num,
                    password,
                    identity,
                } => {
                    if version_num != QS_PROTO_VERSION {
                        send_packet(
                            ReceiverToSender::WrongVersion {
                                expected: QS_PROTO_VERSION.to_string(),
                            },
                            &conn,
                        )
                        .await?;
                        return Err(ReceiveError::WrongVersion(
                            QS_PROTO_VERSION.to_string(),
                            version_num,
                        ));
                    }
                    send_packet(
                        ReceiverToSender::Ok {
                            identity: args.announce.clone(),
                        },
                        &conn,
                    )
                    .await?;

                    // An announced identity only counts if it is the one this connection
                    // is with
                    let identity = identity.filter(|addr| addr.id == conn.remote_id());
                    (password, identity)
                }
                p => return Err(ReceiveError::UnexpectedDataPacket(p)),
            };

        Ok(Self {
            args,
            conn,
            endpoint: this_endpoint,
            password_required,
            authenticated: false,
            peer_identity,
            refuse_others,
        })
    }

    /// Where the sender said it can be found again, if it uses its stable identity
    pub fn peer_identity(&self) -> Option<&iroh::EndpointAddr> {
        self.peer_identity.as_ref()
    }

    /// Whether the sender wants a password.
    ///
    /// The sender only waits a moment for the password. If the user has to be asked
    /// first, [Receiver::disconnect], ask, and connect again with the password at hand.
    pub fn password_required(&self) -> bool {
        self.password_required
    }

    /// Hang up without closing the endpoint, to connect again with it
    pub async fn disconnect(self) -> iroh::Endpoint {
        self.conn.close(0u32.into(), &[0]);
        self.endpoint.clone()
    }

    /// Prove to the sender that this side knows the password, and check that the sender
    /// knows it too. Has to be called before [Receiver::receive_files] if the sender wants
    /// a password, and with [None] it only checks that the sender wants none.
    pub async fn authenticate(&mut self, password: Option<&str>) -> Result<(), ReceiveError> {
        let password = match (self.password_required, password) {
            (false, None) => return Ok(()),
            (true, Some(password)) => password,
            (true, None) => {
                self.close().await;
                return Err(PasswordError::Required.into());
            }
            (false, Some(_)) => {
                send_packet(ReceiverToSender::PasswordExpected, &self.conn).await?;
                self.wait_for_close().await;
                return Err(PasswordError::NotExpected.into());
            }
        };

        let sender_message = match receive_packet::<SenderToReceiver>(&self.conn).await? {
            SenderToReceiver::Password { message } => message,
            p => return Err(ReceiveError::UnexpectedDataPacket(p)),
        };

        // A sender that sends no valid message does not know the password either
        let (key, message) =
            password::respond(password, &sender_message).map_err(|_| PasswordError::Wrong)?;
        let proof =
            password::proof(&self.conn, &key, Side::Receiver).ok_or(PasswordError::Wrong)?;
        send_packet(ReceiverToSender::Password { message, proof }, &self.conn).await?;

        match receive_packet::<SenderToReceiver>(&self.conn).await? {
            // The sender has to know the password as well
            SenderToReceiver::PasswordAccepted { proof }
                if password::verify(&self.conn, &key, Side::Sender, &proof) =>
            {
                self.authenticated = true;
                Ok(())
            }
            SenderToReceiver::PasswordAccepted { .. } | SenderToReceiver::PasswordRejected => {
                self.close().await;
                Err(PasswordError::Wrong.into())
            }
            p => Err(ReceiveError::UnexpectedDataPacket(p)),
        }
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

    /// The id of the sender. iroh only connects to the id that was dialed,
    /// so this is always the one from the ticket or the pairing.
    pub fn remote_id(&self) -> iroh::EndpointId {
        self.conn.remote_id()
    }

    /// Tell the sender that the files are not accepted and fail with `error`
    async fn reject<T>(&mut self, error: ReceiveError) -> Result<T, ReceiveError> {
        send_packet(ReceiverToSender::RejectFiles, &self.conn).await?;
        // Wait for the sender to acknowledge the rejection
        self.wait_for_close().await;
        Err(error)
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
        initial_progress_callback: impl FnMut(&[(String, u64, u64)]),
        accept_files_callback: impl FnMut(&[FilesAvailable]) -> Option<PathBuf>,
        destinations_callback: impl FnMut(&[FilesAvailable], &[Destination]),
        read_callback: &mut impl FnMut(u64),
        should_continue: &mut impl FnMut() -> bool,
    ) -> Result<bool, ReceiveError> {
        let result = self
            .receive_files_inner(
                initial_progress_callback,
                accept_files_callback,
                destinations_callback,
                read_callback,
                should_continue,
            )
            .await;

        // Whatever went wrong, hang up, so the sender knows at once
        if result.is_err() {
            self.close().await;
        }
        result
    }

    async fn receive_files_inner(
        &mut self,
        mut initial_progress_callback: impl FnMut(&[(String, u64, u64)]),
        mut accept_files_callback: impl FnMut(&[FilesAvailable]) -> Option<PathBuf>,
        mut destinations_callback: impl FnMut(&[FilesAvailable], &[Destination]),
        read_callback: &mut impl FnMut(u64),
        should_continue: &mut impl FnMut() -> bool,
    ) -> Result<bool, ReceiveError> {
        // A password has to be given with `authenticate` before anything is offered
        if self.password_required && !self.authenticated {
            self.close().await;
            return Err(PasswordError::Required.into());
        }

        let files_offered = match receive_packet::<SenderToReceiver>(&self.conn).await? {
            SenderToReceiver::FileInfo { files } => files,
            p => return Err(ReceiveError::UnexpectedDataPacket(p)),
        };

        // The offer is untrusted: check its shape and every name before it is shown
        let checked = check_offer(&files_offered)
            .map_err(ReceiveError::from)
            .and_then(|()| validate_offer(&files_offered).map_err(ReceiveError::from));
        if let Err(e) = checked {
            return self.reject(e).await;
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

        // Only what is not on disk yet has to fit
        let needed: u64 = files_offered
            .iter()
            .zip(&files_to_skip)
            .map(|(offered, skip)| {
                let skipped = skip.as_ref().map(|s| s.skip()).unwrap_or(0);
                offered.size().saturating_sub(skipped)
            })
            .sum();
        match fs4::available_space(&output_path) {
            Ok(available) => {
                if let Err(e) = check_space(needed, available) {
                    return self.reject(e.into()).await;
                }
            }
            // Not every file system can tell, the transfer then fails when the disk is full
            Err(e) => tracing::debug!("could not determine the free disk space: {e}"),
        }

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
