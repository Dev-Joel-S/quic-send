//! End to end transfers between two local endpoints, without relay or discovery.

use iroh::{Endpoint, NodeAddr, RelayMode};
use qs_core::{
    receive::{ReceiveError, Receiver, ReceiverArgs},
    send::{SendError, Sender, SenderArgs},
    QS_ALPN,
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

async fn endpoint() -> Endpoint {
    Endpoint::builder()
        .alpns(vec![QS_ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap()
}

fn local_addr(endpoint: &Endpoint) -> NodeAddr {
    let (v4, _) = endpoint.bound_sockets();
    NodeAddr::new(endpoint.node_id())
        .with_direct_addresses([SocketAddr::new(Ipv4Addr::LOCALHOST.into(), v4.port())])
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

    // Separate tasks, like two separate processes
    let send = tokio::spawn(async move {
        let mut sender = Sender::connect(send_ep, SenderArgs { files }).await?;
        sender
            .send_files(|| {}, |_| {}, |_| {}, &mut |_| {}, &mut || true)
            .await
    });

    let output = output.to_path_buf();
    let receive = tokio::spawn(async move {
        let received = AtomicU64::new(0);
        let mut receiver =
            Receiver::connect(recv_ep, addr, ReceiverArgs { resume: !overwrite }).await?;
        receiver
            .receive_files(
                |_| {},
                |_| Some(output.clone()),
                &mut |n| {
                    received.fetch_add(n, Ordering::Relaxed);
                },
                &mut || stop_after.is_none_or(|limit| received.load(Ordering::Relaxed) < limit),
            )
            .await
    });

    let receive = receive.await.unwrap();
    let send = send.await.unwrap();
    Outcome { send, receive }
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
}
