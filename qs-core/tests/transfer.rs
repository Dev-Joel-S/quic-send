//! End to end transfers between two local endpoints, without relay or discovery.

use iroh::{endpoint::presets, Endpoint, EndpointAddr, RelayMode};
use qs_core::{
    destination::{Destination, Placement},
    password::PasswordError,
    receive::{ReceiveError, Receiver, ReceiverArgs},
    send::{SendError, Sender, SenderArgs},
    QS_ALPN,
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime},
};

async fn endpoint() -> Endpoint {
    endpoint_with(qs_core::crypto::provider()).await
}

async fn endpoint_with(provider: Arc<rustls::crypto::CryptoProvider>) -> Endpoint {
    Endpoint::builder(presets::Empty)
        .crypto_provider(provider)
        .alpns(vec![QS_ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap()
}

fn local_addr(endpoint: &Endpoint) -> EndpointAddr {
    let v4 = endpoint
        .bound_sockets()
        .into_iter()
        .find(|a| a.is_ipv4())
        .unwrap();
    EndpointAddr::new(endpoint.id())
        .with_ip_addr(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), v4.port()))
}

/// Deterministic pseudo random content
fn content(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn write(path: &Path, data: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, data).unwrap();
}

struct Outcome {
    send: Result<bool, SendError>,
    receive: Result<bool, ReceiveError>,
    /// Payload bytes the receiver got over the wire
    received: u64,
    destinations: Vec<Destination>,
}

/// Transfer `files` into `output`.
/// The receiver stops after roughly `stop_after` bytes if given.
async fn transfer(
    files: Vec<PathBuf>,
    output: &Path,
    overwrite: bool,
    stop_after: Option<u64>,
) -> Outcome {
    let send_ep = endpoint().await;
    let recv_ep = endpoint().await;
    let addr = local_addr(&send_ep);

    let expected_peer = None;

    // Separate tasks, like two separate processes
    let send = tokio::spawn(async move {
        let mut sender = Sender::connect(
            send_ep,
            SenderArgs {
                files,
                expected_peer,
                password: None,
                announce: None,
            },
        )
        .await?;
        sender
            .send_files(|| {}, |_| {}, |_| {}, &mut |_| {}, &mut || true)
            .await
    });

    let output = output.to_path_buf();
    let received = Arc::new(AtomicU64::new(0));
    let destinations = Arc::new(Mutex::new(Vec::new()));
    let receive = tokio::spawn({
        let received = received.clone();
        let destinations = destinations.clone();
        async move {
            let mut receiver = Receiver::connect(
                recv_ep,
                addr,
                ReceiverArgs {
                    resume: !overwrite,
                    announce: None,
                },
            )
            .await?;
            receiver
                .receive_files(
                    |_| {},
                    |_| Some(output.clone()),
                    |_, chosen| *destinations.lock().unwrap() = chosen.to_vec(),
                    &mut |n| {
                        received.fetch_add(n, Ordering::Relaxed);
                    },
                    &mut || stop_after.is_none_or(|limit| received.load(Ordering::Relaxed) < limit),
                )
                .await
        }
    });

    let receive = receive.await.unwrap();
    let send = send.await.unwrap();
    let destinations = destinations.lock().unwrap().clone();
    Outcome {
        send,
        receive,
        received: received.load(Ordering::Relaxed),
        destinations,
    }
}

/// All file names below `dir`, relative and sorted
fn listing(dir: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            out.push(
                path.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
            if path.is_dir() {
                walk(root, &path, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn sends_files_and_directories() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();

    let a = content(1, 100_000);
    let b = content(2, 3);
    let single = content(3, 50_000);
    write(&src.path().join("dir/a.bin"), &a);
    write(&src.path().join("dir/sub/b.txt"), &b);
    write(&src.path().join("dir/empty.txt"), &[]);
    write(&src.path().join("single.bin"), &single);

    let outcome = transfer(
        vec![src.path().join("dir"), src.path().join("single.bin")],
        out.path(),
        false,
        None,
    )
    .await;

    assert!(outcome.receive.unwrap());
    assert!(outcome.send.unwrap());

    let out = out.path();
    assert_eq!(std::fs::read(out.join("dir/a.bin")).unwrap(), a);
    assert_eq!(std::fs::read(out.join("dir/sub/b.txt")).unwrap(), b);
    assert_eq!(std::fs::read(out.join("dir/empty.txt")).unwrap(), b"");
    assert_eq!(std::fs::read(out.join("single.bin")).unwrap(), single);

    // No .part files and no resume state left behind
    assert_eq!(
        listing(out),
        [
            "dir",
            "dir/a.bin",
            "dir/empty.txt",
            "dir/sub",
            "dir/sub/b.txt",
            "single.bin"
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn existing_folder_is_not_merged_into() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();

    let a = content(1, 1000);
    write(&src.path().join("dir/a.bin"), &a);
    write(&out.path().join("dir/a.bin"), b"mine");
    write(&out.path().join("a.bin"), b"mine too");

    let outcome = transfer(
        vec![src.path().join("dir"), src.path().join("dir/a.bin")],
        out.path(),
        false,
        None,
    )
    .await;
    assert!(outcome.receive.unwrap());

    let out = out.path();
    assert_eq!(std::fs::read(out.join("dir/a.bin")).unwrap(), b"mine");
    assert_eq!(std::fs::read(out.join("a.bin")).unwrap(), b"mine too");
    assert_eq!(std::fs::read(out.join("dir (1)/a.bin")).unwrap(), a);
    assert_eq!(std::fs::read(out.join("a (1).bin")).unwrap(), a);
    assert!(outcome
        .destinations
        .iter()
        .all(|d| d.placement == Placement::New));
}

#[tokio::test(flavor = "multi_thread")]
async fn overwrite_replaces_existing_files() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();

    let a = content(1, 1000);
    write(&src.path().join("dir/a.bin"), &a);
    write(&out.path().join("dir/a.bin"), b"old");
    write(&out.path().join("dir/other"), b"kept");

    let outcome = transfer(vec![src.path().join("dir")], out.path(), true, None).await;
    assert!(outcome.receive.unwrap());

    let out = out.path();
    assert_eq!(std::fs::read(out.join("dir/a.bin")).unwrap(), a);
    assert_eq!(listing(out), ["dir", "dir/a.bin", "dir/other"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn interrupted_folder_is_resumed() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();

    let a = content(1, 200_000);
    let b = content(2, 300_000);
    write(&src.path().join("dir/a.bin"), &a);
    write(&src.path().join("dir/b.bin"), &b);

    // Stop halfway through b.bin
    let first = transfer(
        vec![src.path().join("dir")],
        out.path(),
        false,
        Some(350_000),
    )
    .await;
    assert!(!first.receive.unwrap());

    let dir = out.path().join("dir");
    // Complete files are usable right away, the incomplete one is a .part file
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
    assert!(!dir.join("b.bin").exists());
    let partial = std::fs::metadata(dir.join("b.bin.part")).unwrap().len();
    assert!(partial > 0 && partial < b.len() as u64);
    assert!(out.path().join(".dir.qs-resume.json").exists());

    let second = transfer(vec![src.path().join("dir")], out.path(), false, None).await;
    assert!(second.receive.unwrap());
    assert_eq!(second.destinations[0].path, dir);
    assert_eq!(second.destinations[0].placement, Placement::Resume);
    // Only the missing part went over the wire
    assert_eq!(second.received, b.len() as u64 - partial);

    assert_eq!(std::fs::read(dir.join("b.bin")).unwrap(), b);
    assert_eq!(listing(out.path()), ["dir", "dir/a.bin", "dir/b.bin"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn interrupted_file_is_resumed() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();

    let data = content(7, 400_000);
    write(&src.path().join("big.bin"), &data);

    let first = transfer(
        vec![src.path().join("big.bin")],
        out.path(),
        false,
        Some(100_000),
    )
    .await;
    assert!(!first.receive.unwrap());
    assert!(!out.path().join("big.bin").exists());
    assert!(out.path().join("big.bin.part").exists());

    let second = transfer(vec![src.path().join("big.bin")], out.path(), false, None).await;
    assert!(second.receive.unwrap());
    assert_eq!(second.destinations[0].placement, Placement::Resume);
    assert!(second.received < data.len() as u64);
    assert_eq!(std::fs::read(out.path().join("big.bin")).unwrap(), data);
    assert_eq!(listing(out.path()), ["big.bin"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn changed_source_is_not_resumed() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();

    let file = src.path().join("big.bin");
    write(&file, &content(7, 400_000));

    let first = transfer(vec![file.clone()], out.path(), false, Some(100_000)).await;
    assert!(!first.receive.unwrap());

    // Same name and size, different content and modification time
    let changed = content(8, 400_000);
    write(&file, &changed);
    std::fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(SystemTime::now() + Duration::from_secs(10))
        .unwrap();

    let second = transfer(vec![file], out.path(), false, None).await;
    assert!(second.receive.unwrap());
    assert_eq!(second.destinations[0].placement, Placement::New);
    assert_eq!(second.destinations[0].path, out.path().join("big (1).bin"));
    assert_eq!(
        std::fs::read(out.path().join("big (1).bin")).unwrap(),
        changed
    );
}

/// Receive into `output` with default callbacks
async fn receive(
    endpoint: Endpoint,
    addr: EndpointAddr,
    output: &Path,
) -> Result<bool, ReceiveError> {
    let output = output.to_path_buf();
    let mut receiver = Receiver::connect(
        endpoint,
        addr,
        ReceiverArgs {
            resume: true,
            announce: None,
        },
    )
    .await?;
    receiver
        .receive_files(
            |_| {},
            |_| Some(output.clone()),
            |_, _| {},
            &mut |_| {},
            &mut || true,
        )
        .await
}

#[tokio::test(flavor = "multi_thread")]
async fn sender_only_serves_the_expected_receiver() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let stranger_out = tempfile::tempdir().unwrap();

    let data = content(4, 10_000);
    write(&src.path().join("secret.bin"), &data);

    let send_ep = endpoint().await;
    let good_ep = endpoint().await;
    let stranger_ep = endpoint().await;
    let addr = local_addr(&send_ep);

    let args = SenderArgs {
        files: vec![src.path().join("secret.bin")],
        expected_peer: Some(good_ep.id()),
        password: None,
        announce: None,
    };
    let send = tokio::spawn(async move {
        let mut sender = Sender::connect(send_ep, args).await?;
        sender
            .send_files(|| {}, |_| {}, |_| {}, &mut |_| {}, &mut || true)
            .await
    });

    // Somebody else who got hold of the address is turned away and gets nothing
    let stranger = tokio::time::timeout(
        Duration::from_secs(20),
        receive(stranger_ep, addr.clone(), stranger_out.path()),
    )
    .await
    .expect("the stranger must be refused, not left hanging");
    assert!(stranger.is_err());
    assert!(listing(stranger_out.path()).is_empty());

    // The sender is still waiting, and the expected receiver gets the file
    assert!(receive(good_ep, addr, out.path()).await.unwrap());
    assert!(send.await.unwrap().unwrap());
    assert_eq!(std::fs::read(out.path().join("secret.bin")).unwrap(), data);
}

#[tokio::test(flavor = "multi_thread")]
async fn second_receiver_is_refused() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let late_out = tempfile::tempdir().unwrap();

    write(&src.path().join("file.bin"), &content(5, 10_000));

    let send_ep = endpoint().await;
    let first_ep = endpoint().await;
    let late_ep = endpoint().await;
    let addr = local_addr(&send_ep);

    let args = SenderArgs {
        files: vec![src.path().join("file.bin")],
        expected_peer: None,
        password: None,
        announce: None,
    };
    let send = tokio::spawn(async move {
        let mut sender = Sender::connect(send_ep, args).await?;
        sender
            .send_files(|| {}, |_| {}, |_| {}, &mut |_| {}, &mut || true)
            .await
    });

    // The first receiver is connected, but has not accepted the files yet
    let mut first = Receiver::connect(
        first_ep,
        addr.clone(),
        ReceiverArgs {
            resume: true,
            announce: None,
        },
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // From now on nobody else gets in, even with the same ticket
    let late = tokio::time::timeout(
        Duration::from_secs(20),
        receive(late_ep, addr, late_out.path()),
    )
    .await
    .expect("the second receiver must be refused, not left hanging");
    assert!(late.is_err());

    let output = out.path().to_path_buf();
    let received = first
        .receive_files(
            |_| {},
            |_| Some(output.clone()),
            |_, _| {},
            &mut |_| {},
            &mut || true,
        )
        .await;
    assert!(received.unwrap());
    assert!(send.await.unwrap().unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn same_name_twice_is_refused_by_the_sender() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    write(&src.path().join("a/x.txt"), b"1");
    write(&src.path().join("b/x.txt"), b"2");

    let outcome = transfer(
        vec![src.path().join("a/x.txt"), src.path().join("b/x.txt")],
        out.path(),
        false,
        None,
    )
    .await;

    assert!(matches!(outcome.send, Err(SendError::DuplicateName(name)) if name == "x.txt"));
    assert!(outcome.receive.is_err());
    assert!(listing(out.path()).is_empty());
}

/// A provider like the real one, but without the post-quantum key exchange
fn classical_provider() -> Arc<rustls::crypto::CryptoProvider> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    Arc::new(provider)
}

#[tokio::test(flavor = "multi_thread")]
async fn connection_uses_the_hybrid_key_exchange() {
    let send_ep = endpoint().await;
    let recv_ep = endpoint().await;
    let addr = local_addr(&send_ep);

    let accept = tokio::spawn(async move {
        let incoming = send_ep.accept().await.unwrap();
        let conn = incoming.accept().unwrap().await.unwrap();
        let group = qs_core::crypto::key_exchange_group(&conn);
        conn.closed().await;
        group
    });

    let conn = recv_ep.connect(addr, QS_ALPN).await.unwrap();
    assert_eq!(
        qs_core::crypto::key_exchange_group(&conn),
        Some(rustls::NamedGroup::X25519MLKEM768)
    );
    assert_eq!(qs_core::crypto::ensure_post_quantum(&conn), Ok(()));
    conn.close(0u32.into(), b"done");

    assert_eq!(
        accept.await.unwrap(),
        Some(rustls::NamedGroup::X25519MLKEM768)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn classical_receiver_is_refused() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    write(&src.path().join("file.bin"), &content(6, 1000));

    let send_ep = endpoint().await;
    let addr = local_addr(&send_ep);
    let args = SenderArgs {
        files: vec![src.path().join("file.bin")],
        expected_peer: None,
        password: None,
        announce: None,
    };
    let send = tokio::spawn(async move {
        let mut sender = Sender::connect(send_ep, args).await?;
        sender.close().await;
        Ok::<_, SendError>(())
    });

    // A receiver that only offers X25519. It is not ours, so it does not check itself:
    // the sender has to turn it away.
    let classical = endpoint_with(classical_provider()).await;
    let conn = classical.connect(addr.clone(), QS_ALPN).await.unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(20), conn.closed())
        .await
        .expect("the sender must close a classical connection");
    assert!(closed.to_string().contains("post-quantum"), "{closed}");

    // The sender kept waiting and takes a proper receiver. It hangs up right after
    // connecting here, so there is nothing to receive.
    assert!(!send.is_finished());
    assert!(receive(endpoint().await, addr, out.path()).await.is_err());
    send.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn classical_sender_is_refused() {
    let out = tempfile::tempdir().unwrap();

    let send_ep = endpoint_with(classical_provider()).await;
    let addr = local_addr(&send_ep);
    let accept = tokio::spawn(async move {
        let incoming = send_ep.accept().await.unwrap();
        let conn = incoming.accept().unwrap().await.unwrap();
        conn.closed().await;
    });

    let result = receive(endpoint().await, addr, out.path()).await;
    assert!(matches!(result, Err(ReceiveError::Crypto(_))), "{result:?}");
    accept.await.unwrap();
}

/// Send one small file, asking for `password`. Returns the content and the running sender.
async fn password_sender(
    src: &Path,
    password: Option<&str>,
) -> (
    Vec<u8>,
    EndpointAddr,
    tokio::task::JoinHandle<Result<bool, SendError>>,
) {
    let data = content(9, 20_000);
    write(&src.join("file.bin"), &data);

    let send_ep = endpoint().await;
    let addr = local_addr(&send_ep);
    let args = SenderArgs {
        files: vec![src.join("file.bin")],
        expected_peer: None,
        password: password.map(|p| zeroize::Zeroizing::new(p.to_string())),
        announce: None,
    };
    let send = tokio::spawn(async move {
        let mut sender = Sender::connect(send_ep, args).await?;
        sender
            .send_files(|| {}, |_| {}, |_| {}, &mut |_| {}, &mut || true)
            .await
    });

    (data, addr, send)
}

/// Connect, give `password`, and receive into `output`
async fn receive_with_password(
    addr: EndpointAddr,
    output: &Path,
    password: Option<&str>,
) -> Result<bool, ReceiveError> {
    let output = output.to_path_buf();
    let mut receiver = Receiver::connect(
        endpoint().await,
        addr,
        ReceiverArgs {
            resume: true,
            announce: None,
        },
    )
    .await?;
    receiver.authenticate(password).await?;
    receiver
        .receive_files(
            |_| {},
            |_| Some(output.clone()),
            |_, _| {},
            &mut |_| {},
            &mut || true,
        )
        .await
}

fn is_password_error<T: std::fmt::Debug>(
    result: &Result<T, ReceiveError>,
    expected: PasswordError,
) -> bool {
    matches!(result, Err(ReceiveError::Password(e)) if *e == expected)
}

#[tokio::test(flavor = "multi_thread")]
async fn password_is_checked_in_direct_mode() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let (data, addr, send) = password_sender(src.path(), Some("hunter2")).await;

    let received = receive_with_password(addr, out.path(), Some("hunter2")).await;
    assert!(received.unwrap());
    assert!(send.await.unwrap().unwrap());
    assert_eq!(std::fs::read(out.path().join("file.bin")).unwrap(), data);
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_password_gets_nothing_and_the_sender_keeps_waiting() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let wrong_out = tempfile::tempdir().unwrap();
    let (data, addr, send) = password_sender(src.path(), Some("hunter2")).await;

    let wrong = receive_with_password(addr.clone(), wrong_out.path(), Some("hunter3")).await;
    assert!(is_password_error(&wrong, PasswordError::Wrong), "{wrong:?}");
    assert!(listing(wrong_out.path()).is_empty());

    // A typo does not end the transfer: the next attempt with the right password works
    assert!(!send.is_finished());
    let received = receive_with_password(addr, out.path(), Some("hunter2")).await;
    assert!(received.unwrap());
    assert!(send.await.unwrap().unwrap());
    assert_eq!(std::fs::read(out.path().join("file.bin")).unwrap(), data);
}

#[tokio::test(flavor = "multi_thread")]
async fn sender_gives_up_after_too_many_wrong_passwords() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let (_, addr, send) = password_sender(src.path(), Some("hunter2")).await;

    for guess in ["a", "b", "c"] {
        let wrong = receive_with_password(addr.clone(), out.path(), Some(guess)).await;
        assert!(is_password_error(&wrong, PasswordError::Wrong), "{wrong:?}");
    }

    let sent = send.await.unwrap();
    assert!(
        matches!(
            sent,
            Err(SendError::Password(PasswordError::TooManyAttempts))
        ),
        "{sent:?}"
    );
    // Now even the right password comes too late, the sender is gone
    let late = tokio::time::timeout(
        Duration::from_secs(3),
        receive_with_password(addr, out.path(), Some("hunter2")),
    )
    .await;
    assert!(!matches!(late, Ok(Ok(_))));
    assert!(listing(out.path()).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn nothing_is_offered_without_the_password() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let (data, addr, send) = password_sender(src.path(), Some("hunter2")).await;

    // A receiver that skips the password step is not shown what would be sent
    let output = out.path().to_path_buf();
    let mut receiver = Receiver::connect(
        endpoint().await,
        addr.clone(),
        ReceiverArgs {
            resume: true,
            announce: None,
        },
    )
    .await
    .unwrap();
    assert!(receiver.password_required());
    let mut offered = false;
    let skipped = receiver
        .receive_files(
            |_| {},
            |_| {
                offered = true;
                Some(output.clone())
            },
            |_, _| {},
            &mut |_| {},
            &mut || true,
        )
        .await;
    assert!(
        is_password_error(&skipped, PasswordError::Required),
        "{skipped:?}"
    );
    assert!(!offered);

    // Giving none at all is refused the same way
    let none = receive_with_password(addr.clone(), out.path(), None).await;
    assert!(
        is_password_error(&none, PasswordError::Required),
        "{none:?}"
    );
    assert!(listing(out.path()).is_empty());

    // Neither counts as a wrong guess, the sender still serves the right receiver
    let received = receive_with_password(addr, out.path(), Some("hunter2")).await;
    assert!(received.unwrap());
    assert!(send.await.unwrap().unwrap());
    assert_eq!(std::fs::read(out.path().join("file.bin")).unwrap(), data);
}

#[tokio::test(flavor = "multi_thread")]
async fn receiver_can_ask_for_the_password_and_come_back() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let (data, addr, send) = password_sender(src.path(), Some("hunter2")).await;

    // First contact: learn that a password is needed, hang up to ask the user
    let receiver = Receiver::connect(
        endpoint().await,
        addr.clone(),
        ReceiverArgs {
            resume: true,
            announce: None,
        },
    )
    .await
    .unwrap();
    assert!(receiver.password_required());
    let recv_ep = receiver.disconnect().await;

    // Second contact with the same endpoint and the password at hand
    let output = out.path().to_path_buf();
    let mut receiver = Receiver::connect(
        recv_ep,
        addr,
        ReceiverArgs {
            resume: true,
            announce: None,
        },
    )
    .await
    .unwrap();
    receiver.authenticate(Some("hunter2")).await.unwrap();
    let received = receiver
        .receive_files(
            |_| {},
            |_| Some(output.clone()),
            |_, _| {},
            &mut |_| {},
            &mut || true,
        )
        .await;

    assert!(received.unwrap());
    assert!(send.await.unwrap().unwrap());
    assert_eq!(std::fs::read(out.path().join("file.bin")).unwrap(), data);
}

#[tokio::test(flavor = "multi_thread")]
async fn password_without_one_on_the_sender_is_reported_on_both_sides() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let (_, addr, send) = password_sender(src.path(), None).await;

    let result = receive_with_password(addr, out.path(), Some("hunter2")).await;
    assert!(
        is_password_error(&result, PasswordError::NotExpected),
        "{result:?}"
    );

    let sent = send.await.unwrap();
    assert!(
        matches!(
            sent,
            Err(SendError::Password(PasswordError::ExpectedByReceiver))
        ),
        "{sent:?}"
    );
    assert!(listing(out.path()).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn silent_peer_does_not_keep_the_receiver_out() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let (data, addr, send) = password_sender(src.path(), None).await;

    // Somebody connects and then says nothing at all
    let silent = endpoint().await;
    let silent_conn = silent.connect(addr.clone(), QS_ALPN).await.unwrap();

    // The real receiver gets its turn once the sender has given up on the silent one
    let received = tokio::time::timeout(
        Duration::from_secs(40),
        receive_with_password(addr, out.path(), None),
    )
    .await
    .expect("the sender must not wait for a silent peer forever");
    assert!(received.unwrap());
    assert!(send.await.unwrap().unwrap());
    assert_eq!(std::fs::read(out.path().join("file.bin")).unwrap(), data);

    assert!(silent_conn.close_reason().is_some());
}

/// A sender that dials `addr` with one small file
fn dialing_sender(
    endpoint: Endpoint,
    addr: EndpointAddr,
    file: PathBuf,
    announce: Option<EndpointAddr>,
) -> tokio::task::JoinHandle<Result<(Option<EndpointAddr>, bool), SendError>> {
    tokio::spawn(async move {
        let args = SenderArgs {
            files: vec![file],
            expected_peer: None,
            password: None,
            announce,
        };
        let mut sender = Sender::dial(endpoint, addr, args).await?;
        let identity = sender.peer_identity().cloned();
        let sent = sender
            .send_files(|| {}, |_| {}, |_| {}, &mut |_| {}, &mut || true)
            .await?;
        Ok((identity, sent))
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn saved_peer_is_dialed_without_code_or_ticket() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let data = content(11, 30_000);
    write(&src.path().join("file.bin"), &data);

    // Both know each other from before: the sender has the receiver's address,
    // the receiver the sender's id
    let send_ep = endpoint().await;
    let recv_ep = endpoint().await;
    let send_addr = local_addr(&send_ep);
    let recv_addr = local_addr(&recv_ep);
    let send_id = send_ep.id();

    let output = out.path().to_path_buf();
    let announce = recv_addr.clone();
    let receive = tokio::spawn(async move {
        let args = ReceiverArgs {
            resume: true,
            announce: Some(announce),
        };
        let mut receiver = Receiver::accept(recv_ep, send_id, args).await?;
        let identity = receiver.peer_identity().cloned();
        let received = receiver
            .receive_files(
                |_| {},
                |_| Some(output.clone()),
                |_, _| {},
                &mut |_| {},
                &mut || true,
            )
            .await?;
        Ok::<_, ReceiveError>((identity, received))
    });

    let send = dialing_sender(
        send_ep,
        recv_addr.clone(),
        src.path().join("file.bin"),
        Some(send_addr.clone()),
    );

    let (receiver_saw, received) = receive.await.unwrap().unwrap();
    let (sender_saw, sent) = send.await.unwrap().unwrap();
    assert!(received && sent);
    assert_eq!(std::fs::read(out.path().join("file.bin")).unwrap(), data);

    // Each side learned where to find the other one again
    assert_eq!(receiver_saw, Some(send_addr));
    assert_eq!(sender_saw, Some(recv_addr));
}

#[tokio::test(flavor = "multi_thread")]
async fn listening_receiver_only_takes_the_saved_sender() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let data = content(12, 30_000);
    write(&src.path().join("file.bin"), &data);

    let send_ep = endpoint().await;
    let stranger_ep = endpoint().await;
    let recv_ep = endpoint().await;
    let recv_addr = local_addr(&recv_ep);
    let send_id = send_ep.id();

    let output = out.path().to_path_buf();
    let receive = tokio::spawn(async move {
        let args = ReceiverArgs {
            resume: true,
            announce: None,
        };
        let mut receiver = Receiver::accept(recv_ep, send_id, args).await?;
        receiver
            .receive_files(
                |_| {},
                |_| Some(output.clone()),
                |_, _| {},
                &mut |_| {},
                &mut || true,
            )
            .await
    });

    // Somebody else who knows the address cannot push files to the receiver
    let stranger = dialing_sender(
        stranger_ep,
        recv_addr.clone(),
        src.path().join("file.bin"),
        None,
    );
    let refused = tokio::time::timeout(Duration::from_secs(30), stranger)
        .await
        .expect("the stranger must be refused, not left hanging")
        .unwrap();
    assert!(refused.is_err());
    assert!(listing(out.path()).is_empty());

    // The receiver kept waiting for the saved sender
    assert!(!receive.is_finished());
    let send = dialing_sender(send_ep, recv_addr, src.path().join("file.bin"), None);
    assert!(receive.await.unwrap().unwrap());
    assert!(send.await.unwrap().unwrap().1);
    assert_eq!(std::fs::read(out.path().join("file.bin")).unwrap(), data);
}

#[tokio::test(flavor = "multi_thread")]
async fn announced_identity_has_to_be_the_own_one() {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    write(&src.path().join("file.bin"), &content(13, 1000));

    let send_ep = endpoint().await;
    let recv_ep = endpoint().await;
    let somebody_else = local_addr(&endpoint().await);
    let recv_addr = local_addr(&recv_ep);
    let send_id = send_ep.id();

    let output = out.path().to_path_buf();
    let receive = tokio::spawn(async move {
        let args = ReceiverArgs {
            resume: true,
            announce: None,
        };
        let mut receiver = Receiver::accept(recv_ep, send_id, args).await?;
        let identity = receiver.peer_identity().cloned();
        receiver
            .receive_files(
                |_| {},
                |_| Some(output.clone()),
                |_, _| {},
                &mut |_| {},
                &mut || true,
            )
            .await?;
        Ok::<_, ReceiveError>(identity)
    });

    // The sender claims to be found at an address with another key. Saving that would
    // pin the wrong device under this peer's name, so it is not taken.
    let send = dialing_sender(
        send_ep,
        recv_addr,
        src.path().join("file.bin"),
        Some(somebody_else),
    );

    assert_eq!(receive.await.unwrap().unwrap(), None);
    // The receiver announced nothing
    assert_eq!(send.await.unwrap().unwrap().0, None);
}
