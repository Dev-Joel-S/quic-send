#![allow(clippy::suspicious_open_options)]

use crate::{
    common::{
        connection_path, get_files_available, receive_packet, send_packet, ConnectionPath,
        FileSendRecvTree, FilesAvailable, PacketRecvError,
    },
    crypto::{ensure_post_quantum, CryptoError},
    limits::{check_offer, LimitError},
    packets::{ReceiverToSender, SenderToReceiver},
    pairing::pake::Side,
    password::{self, PasswordError, MAX_ATTEMPTS},
    BUF_SIZE, QS_ALPN, QS_PROTO_VERSION,
};
use async_compression::tokio::write::GzipEncoder;
use iroh::EndpointAddr;
use std::path::PathBuf;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

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
    #[error("wrong version, the receiver expected: {0:?}, but got: {1:?}")]
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
    #[error("{0}")]
    Password(#[from] PasswordError),
    #[error("{0}")]
    Crypto(#[from] CryptoError),
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
    /// Where the receiver said it can be found again
    peer_identity: Option<EndpointAddr>,
}

/// Refuse every connection to `endpoint` from now on
pub(crate) fn refuse_everyone(endpoint: &iroh::Endpoint) -> tokio::task::JoinHandle<()> {
    let endpoint = endpoint.clone();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tracing::debug!("refused a connection");
            incoming.refuse();
        }
    })
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
    /// The receiver has to know this password, checked inside the connection.
    ///
    /// For direct mode. With a short code the password already went into the pairing
    /// and this stays [None].
    pub password: Option<Zeroizing<String>>,
    /// The own address to tell the receiver, so it can save this device as a peer.
    /// Only set together with the stable identity.
    pub announce: Option<EndpointAddr>,
}

/// How long a receiver has to answer the connection request and the password exchange
const GREETING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a receiver has to read that its password was wrong
const REJECTION_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

/// [greet] with a time limit. Saying hello needs no human on the other side, so it is
/// quick. Whoever takes longer is dropped, or one silent peer could keep everyone else out.
async fn greet_in_time(
    conn: &iroh::endpoint::Connection,
    hello: &Hello,
) -> Result<(Greeting, Option<EndpointAddr>), SendError> {
    tokio::time::timeout(GREETING_TIMEOUT, greet(conn, hello))
        .await
        .unwrap_or_else(|_| Err(SendError::Connect("the receiver did not answer".into())))
}

/// What a sender needs to say hello to whoever connects
struct Hello {
    expected_peer: Option<iroh::EndpointId>,
    password: Option<Zeroizing<String>>,
    announce: Option<EndpointAddr>,
}

impl Hello {
    fn new(args: &SenderArgs) -> Self {
        Self {
            expected_peer: args.expected_peer,
            password: args.password.clone(),
            announce: args.announce.clone(),
        }
    }
}

/// Most peers that may be saying hello at the same time, more are refused
const MAX_PENDING: usize = 16;

/// How the attempt of one peer to become the receiver ended
enum Attempt {
    /// This is the receiver, with the identity it announced
    Welcome(iroh::endpoint::Connection, Option<EndpointAddr>),
    WrongPassword,
    /// A receiver that cannot work with this sender. That is most likely the one the
    /// user is waiting for, so the user is told instead of waiting on.
    Incompatible(SendError),
    /// Not a receiver: a broken connection, a stranger, or somebody who said nothing
    Dropped,
}

/// Take one incoming connection as far as it gets. Runs in a task of its own, so a peer
/// that is slow or silent only holds up itself.
async fn attempt(incoming: iroh::endpoint::Incoming, hello: std::sync::Arc<Hello>) -> Attempt {
    // A broken or hostile connection attempt must not end the wait for the receiver
    let conn = match incoming.accept() {
        Ok(accepting) => match accepting.await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::debug!("incoming connection failed: {e}");
                return Attempt::Dropped;
            }
        },
        Err(e) => {
            tracing::debug!("incoming connection failed: {e}");
            return Attempt::Dropped;
        }
    };

    if let Err(e) = ensure_post_quantum(&conn) {
        tracing::warn!("refused a connection: {e}");
        conn.close(2u32.into(), b"post-quantum key exchange required");
        return Attempt::Dropped;
    }

    if let Some(expected) = hello.expected_peer {
        if conn.remote_id() != expected {
            tracing::warn!(
                "refused a connection from {}, expected {}",
                conn.remote_id().fmt_short(),
                expected.fmt_short()
            );
            conn.close(1u32.into(), b"unexpected peer");
            return Attempt::Dropped;
        }
    }

    match greet_in_time(&conn, &hello).await {
        Ok((Greeting::Welcome, identity)) => Attempt::Welcome(conn, identity),
        Ok((Greeting::WrongPassword, _)) => {
            // Give the receiver a moment to read the rejection, it hangs up then.
            // Closing right away could drop the packet that tells it why.
            let _ = tokio::time::timeout(REJECTION_GRACE, conn.closed()).await;
            conn.close(3u32.into(), b"wrong password");
            Attempt::WrongPassword
        }
        Err(e @ (SendError::WrongVersion(..) | SendError::Password(_))) => Attempt::Incompatible(e),
        // The connection broke while saying hello, somebody else may still come
        Err(e) => {
            tracing::debug!("lost a receiver before the transfer: {e}");
            conn.close(4u32.into(), b"no answer");
            Attempt::Dropped
        }
    }
}

/// How saying hello to a receiver went
enum Greeting {
    Welcome,
    WrongPassword,
}

/// Agree on the protocol version with a receiver and check its password if one is set.
/// Returns how it went and the identity the receiver announced.
async fn greet(
    conn: &iroh::endpoint::Connection,
    hello: &Hello,
) -> Result<(Greeting, Option<EndpointAddr>), SendError> {
    let password = hello.password.as_deref().map(String::as_str);

    send_packet(
        SenderToReceiver::ConnRequest {
            version_num: QS_PROTO_VERSION.to_string(),
            password: password.is_some(),
            identity: hello.announce.clone(),
        },
        conn,
    )
    .await?;

    let identity = match receive_packet::<ReceiverToSender>(conn).await? {
        // An announced identity only counts if it is the one this connection is with
        ReceiverToSender::Ok { identity } => identity.filter(|addr| addr.id == conn.remote_id()),
        ReceiverToSender::WrongVersion { expected } => {
            return Err(SendError::WrongVersion(
                expected,
                QS_PROTO_VERSION.to_string(),
            ));
        }
        p => return Err(SendError::UnexpectedDataPacket(p)),
    };

    let Some(password) = password else {
        return Ok((Greeting::Welcome, identity));
    };

    let (pake, message) = password::start(password).map_err(|_| PasswordError::Unavailable)?;
    send_packet(SenderToReceiver::Password { message }, conn).await?;

    let (message, proof) = match receive_packet::<ReceiverToSender>(conn).await? {
        ReceiverToSender::Password { message, proof } => (message, proof),
        p => return Err(SendError::UnexpectedDataPacket(p)),
    };

    // The receiver proves itself first. Only then does the sender show its own proof.
    let accepted = pake
        .finish(&message)
        .ok()
        .filter(|key| password::verify(conn, key, Side::Receiver, &proof))
        .and_then(|key| password::proof(conn, &key, Side::Sender));

    match accepted {
        Some(proof) => {
            send_packet(SenderToReceiver::PasswordAccepted { proof }, conn).await?;
            Ok((Greeting::Welcome, identity))
        }
        None => {
            send_packet(SenderToReceiver::PasswordRejected, conn).await?;
            Ok((Greeting::WrongPassword, None))
        }
    }
}

impl Sender {
    pub async fn connect(
        this_endpoint: iroh::Endpoint,
        args: SenderArgs,
    ) -> Result<Self, SendError> {
        let hello = std::sync::Arc::new(Hello::new(&args));
        let mut attempts = tokio::task::JoinSet::new();
        let mut wrong_passwords = 0;

        // Everyone who connects says hello at the same time. The first one that gets
        // through is the receiver. Taking them one after the other would let a single
        // silent peer keep the real receiver waiting.
        let (conn, peer_identity) = loop {
            tokio::select! {
                incoming = this_endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        return Err(SendError::Connect("the endpoint was closed".to_string()));
                    };
                    if attempts.len() >= MAX_PENDING {
                        incoming.refuse();
                    } else {
                        attempts.spawn(attempt(incoming, hello.clone()));
                    }
                }
                Some(finished) = attempts.join_next(), if !attempts.is_empty() => {
                    match finished {
                        Ok(Attempt::Welcome(conn, identity)) => break (conn, identity),
                        Ok(Attempt::WrongPassword) => {
                            wrong_passwords += 1;
                            if wrong_passwords >= MAX_ATTEMPTS {
                                attempts.shutdown().await;
                                this_endpoint.close().await;
                                return Err(PasswordError::TooManyAttempts.into());
                            }
                            tracing::warn!("a receiver used a wrong password");
                        }
                        Ok(Attempt::Incompatible(e)) => {
                            attempts.shutdown().await;
                            this_endpoint.close().await;
                            return Err(e);
                        }
                        Ok(Attempt::Dropped) | Err(_) => {}
                    }
                }
            }
        };

        // Everyone who is still saying hello is too late
        attempts.shutdown().await;

        // One receiver per transfer: everybody else is refused from here on
        let refuse_others = refuse_everyone(&this_endpoint);

        tracing::info!("receiver connected to sender");

        Ok(Self {
            args,
            conn,
            endpoint: this_endpoint,
            refuse_others,
            peer_identity,
        })
    }

    /// Connect to a receiver that waits for this device at `addr`, a saved peer.
    ///
    /// The other way round from [Sender::connect]: the receiver listens and the sender
    /// dials. iroh only completes a connection to the id in `addr`, so the receiver is
    /// the saved peer or nobody.
    pub async fn dial(
        this_endpoint: iroh::Endpoint,
        addr: EndpointAddr,
        args: SenderArgs,
    ) -> Result<Self, SendError> {
        let conn = this_endpoint
            .connect(addr, QS_ALPN)
            .await
            .map_err(|e| SendError::Connect(e.to_string()))?;

        if let Err(e) = ensure_post_quantum(&conn) {
            conn.close(2u32.into(), b"post-quantum key exchange required");
            this_endpoint.close().await;
            return Err(e.into());
        }

        let peer_identity = match greet_in_time(&conn, &Hello::new(&args)).await {
            Ok((Greeting::Welcome, identity)) => identity,
            Ok((Greeting::WrongPassword, _)) => {
                let _ = tokio::time::timeout(REJECTION_GRACE, conn.closed()).await;
                this_endpoint.close().await;
                return Err(PasswordError::Wrong.into());
            }
            Err(e) => {
                this_endpoint.close().await;
                return Err(e);
            }
        };

        // This endpoint called out, nobody has a reason to call in
        let refuse_others = refuse_everyone(&this_endpoint);

        Ok(Self {
            args,
            conn,
            endpoint: this_endpoint,
            refuse_others,
            peer_identity,
        })
    }

    /// Where the receiver said it can be found again, if it uses its stable identity
    pub fn peer_identity(&self) -> Option<&EndpointAddr> {
        self.peer_identity.as_ref()
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
        wait_for_other_peer_to_accept_files_callback: impl FnMut(),
        files_decision_callback: impl FnMut(bool),
        initial_progress_callback: impl FnMut(&[(String, u64, u64)]),
        write_callback: &mut impl FnMut(u64),
        should_continue: &mut impl FnMut() -> bool,
    ) -> Result<bool, SendError> {
        let result = self
            .send_files_inner(
                wait_for_other_peer_to_accept_files_callback,
                files_decision_callback,
                initial_progress_callback,
                write_callback,
                should_continue,
            )
            .await;

        // Whatever went wrong, hang up, so the receiver knows at once and does not
        // wait for a connection that will bring nothing
        if result.is_err() {
            self.close().await;
        }
        result
    }

    async fn send_files_inner(
        &mut self,
        mut wait_for_other_peer_to_accept_files_callback: impl FnMut(),
        mut files_decision_callback: impl FnMut(bool),
        mut initial_progress_callback: impl FnMut(&[(String, u64, u64)]),
        write_callback: &mut impl FnMut(u64),
        should_continue: &mut impl FnMut() -> bool,
    ) -> Result<bool, SendError> {
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
            ReceiverToSender::PasswordExpected => {
                self.close().await;
                return Err(PasswordError::ExpectedByReceiver.into());
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
