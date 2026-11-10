//! End to end transfers between two local endpoints, without relay or discovery.

use iroh::{endpoint::presets, Endpoint, EndpointAddr, RelayMode};
use qs_core::{
    destination::{Destination, Placement},
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
            let mut receiver =
                Receiver::connect(recv_ep, addr, ReceiverArgs { resume: !overwrite }).await?;
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
    let mut receiver = Receiver::connect(endpoint, addr, ReceiverArgs { resume: true }).await?;
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
    };
    let send = tokio::spawn(async move {
        let mut sender = Sender::connect(send_ep, args).await?;
        sender
            .send_files(|| {}, |_| {}, |_| {}, &mut |_| {}, &mut || true)
            .await
    });

    // The first receiver is connected, but has not accepted the files yet
    let mut first = Receiver::connect(first_ep, addr.clone(), ReceiverArgs { resume: true })
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
