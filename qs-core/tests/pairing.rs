//! Pairing with a short code through a real rendezvous server, and a transfer on top.

use iroh::{endpoint::presets, Endpoint, EndpointAddr, RelayMode};
use qs_core::{
    pairing::{code::Code, rendezvous::Client, Claim, Offer, PairingError},
    receive::{Receiver, ReceiverArgs},
    send::{Sender, SenderArgs},
    QS_ALPN,
};
use qs_rendezvous::{serve, Config};
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

/// Start a rendezvous server on a free local port and return its url
async fn server(config: Config) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(serve(listener, config, std::future::pending()));
    url
}

async fn endpoint() -> Endpoint {
    Endpoint::builder(presets::Empty)
        .crypto_provider(qs_core::crypto::provider())
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

fn client(url: &str, endpoint: &Endpoint) -> Client {
    Client::new(url, endpoint.tls_config().clone()).unwrap()
}

/// The code as the receiver would type it after reading it off the sender's screen
fn typed(offer: &Offer) -> Code {
    offer.code().to_string().to_lowercase().parse().unwrap()
}

/// The same code with one character of the secret changed
fn mistyped(offer: &Offer) -> Code {
    let text = offer.code().to_string();
    let last = if text.ends_with('0') { '1' } else { '0' };
    format!("{}{last}", &text[..text.len() - 1])
        .parse()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn code_pairs_and_files_arrive() {
    let url = server(Config::default()).await;
    let send_ep = endpoint().await;
    let recv_ep = endpoint().await;
    let send_addr = local_addr(&send_ep);
    let recv_id = recv_ep.id();

    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("hello.txt"), b"hello over a short code").unwrap();

    // Sender: get a code, wait for the receiver, then only let that receiver in
    let offer = Offer::create(&client(&url, &send_ep), None).await.unwrap();
    let code = typed(&offer);
    assert_eq!(offer.code().to_string().len(), 9, "K7X4-M2QP");

    let files = vec![src.path().join("hello.txt")];
    let send = tokio::spawn(async move {
        let peer = offer.wait_for_receiver(&send_addr).await.unwrap();
        let args = SenderArgs {
            files,
            expected_peer: Some(peer),
            password: None,
        };
        let mut sender = Sender::connect(send_ep, args).await.unwrap();
        let sent = sender
            .send_files(|| {}, |_| {}, |_| {}, &mut |_| {}, &mut || true)
            .await
            .unwrap();
        (peer, sent)
    });

    // Receiver: type the code, learn the sender's address, connect
    let claim = Claim::new(&client(&url, &recv_ep), code).await.unwrap();
    assert!(!claim.password_required());
    let sender_addr = claim.complete(None, recv_id).await.unwrap();

    let output = out.path().to_path_buf();
    let mut receiver = Receiver::connect(recv_ep, sender_addr, ReceiverArgs { resume: true })
        .await
        .unwrap();
    let received = receiver
        .receive_files(
            |_| {},
            |_| Some(output.clone()),
            |_, _| {},
            &mut |_| {},
            &mut || true,
        )
        .await
        .unwrap();

    let (peer, sent) = send.await.unwrap();
    assert!(received && sent);
    assert_eq!(peer, recv_id);
    assert_eq!(
        std::fs::read(out.path().join("hello.txt")).unwrap(),
        b"hello over a short code"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_code_fails_on_both_sides_and_burns_the_code() {
    let url = server(Config::default()).await;
    let send_ep = endpoint().await;
    let recv_ep = endpoint().await;
    let send_addr = local_addr(&send_ep);

    let offer = Offer::create(&client(&url, &send_ep), None).await.unwrap();
    let right = typed(&offer);
    let wrong = mistyped(&offer);

    let send = tokio::spawn(async move { offer.wait_for_receiver(&send_addr).await });

    let claim = Claim::new(&client(&url, &recv_ep), wrong).await.unwrap();
    let receiver = claim.complete(None, recv_ep.id()).await;
    assert_eq!(receiver, Err(PairingError::Rejected));
    assert_eq!(send.await.unwrap(), Err(PairingError::ReceiverWrongCode));

    // One attempt per code: the right code no longer works either
    let again = Claim::new(&client(&url, &recv_ep), right).await;
    assert_eq!(again.err(), Some(PairingError::Used));
}

#[tokio::test(flavor = "multi_thread")]
async fn code_can_be_claimed_only_once() {
    let url = server(Config::default()).await;
    let send_ep = endpoint().await;
    let recv_ep = endpoint().await;
    let other_ep = endpoint().await;

    let offer = Offer::create(&client(&url, &send_ep), None).await.unwrap();

    let first = Claim::new(&client(&url, &recv_ep), typed(&offer)).await;
    assert!(first.is_ok());

    // Somebody who also knows the code, or guesses the slot, comes too late
    let second = Claim::new(&client(&url, &other_ep), typed(&offer)).await;
    assert_eq!(second.err(), Some(PairingError::Used));
}

#[tokio::test(flavor = "multi_thread")]
async fn password_protects_in_addition_to_the_code() {
    let url = server(Config::default()).await;

    // Right password: pairs
    let send_ep = endpoint().await;
    let recv_ep = endpoint().await;
    let send_addr = local_addr(&send_ep);
    let offer = Offer::create(&client(&url, &send_ep), Some("hunter2"))
        .await
        .unwrap();
    let code = typed(&offer);
    let expected_addr = send_addr.clone();
    let send = tokio::spawn(async move { offer.wait_for_receiver(&send_addr).await });

    let claim = Claim::new(&client(&url, &recv_ep), code).await.unwrap();
    assert!(claim.password_required());
    let addr = claim.complete(Some("hunter2"), recv_ep.id()).await;
    assert_eq!(addr, Ok(expected_addr));
    assert_eq!(send.await.unwrap(), Ok(recv_ep.id()));

    // Right code, wrong password: fails like a wrong code
    let send_ep = endpoint().await;
    let send_addr = local_addr(&send_ep);
    let offer = Offer::create(&client(&url, &send_ep), Some("hunter2"))
        .await
        .unwrap();
    let code = typed(&offer);
    let send = tokio::spawn(async move { offer.wait_for_receiver(&send_addr).await });

    let claim = Claim::new(&client(&url, &recv_ep), code).await.unwrap();
    let addr = claim.complete(Some("hunter3"), recv_ep.id()).await;
    assert_eq!(addr, Err(PairingError::Rejected));
    assert_eq!(send.await.unwrap(), Err(PairingError::ReceiverWrongCode));
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_password_is_noticed_before_guessing() {
    let url = server(Config::default()).await;
    let send_ep = endpoint().await;
    let recv_ep = endpoint().await;

    let offer = Offer::create(&client(&url, &send_ep), Some("hunter2"))
        .await
        .unwrap();
    let claim = Claim::new(&client(&url, &recv_ep), typed(&offer))
        .await
        .unwrap();

    // The frontend asks for the password when it sees this. Going on without one fails.
    assert!(claim.password_required());
    let result = claim.complete(None, recv_ep.id()).await;
    assert_eq!(result, Err(PairingError::PasswordRequired));
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_and_expired_codes_are_told_apart() {
    let url = server(Config {
        ttl: Duration::from_millis(300),
        ..Config::default()
    })
    .await;
    let send_ep = endpoint().await;
    let recv_ep = endpoint().await;
    let send_addr = local_addr(&send_ep);

    // Nobody ever had this slot
    let never = Claim::new(&client(&url, &recv_ep), "ZZZZ-ZZZZ".parse().unwrap()).await;
    assert_eq!(never.err(), Some(PairingError::Unknown));

    // This one runs out while the sender waits
    let offer = Offer::create(&client(&url, &send_ep), None).await.unwrap();
    let code = typed(&offer);
    let waited = offer.wait_for_receiver(&send_addr).await;
    assert_eq!(waited, Err(PairingError::NotClaimed));

    let late = Claim::new(&client(&url, &recv_ep), code).await;
    assert_eq!(late.err(), Some(PairingError::Expired));
}

#[tokio::test(flavor = "multi_thread")]
async fn giving_up_tells_the_other_side() {
    let url = server(Config::default()).await;
    let send_ep = endpoint().await;
    let recv_ep = endpoint().await;

    // The sender presses Ctrl+C before anyone used the code
    let offer = Offer::create(&client(&url, &send_ep), None).await.unwrap();
    let code = typed(&offer);
    offer.handle().cancel().await;
    let claim = Claim::new(&client(&url, &recv_ep), code).await;
    assert_eq!(claim.err(), Some(PairingError::Used));

    // The receiver gives up after claiming: the sender stops waiting
    let offer = Offer::create(&client(&url, &send_ep), None).await.unwrap();
    let claim = Claim::new(&client(&url, &recv_ep), typed(&offer))
        .await
        .unwrap();
    claim.handle().cancel().await;
    let send_addr = local_addr(&send_ep);
    let waited = tokio::time::timeout(Duration::from_secs(10), offer.wait_for_receiver(&send_addr))
        .await
        .expect("the sender must notice that the receiver gave up");
    assert_eq!(waited, Err(PairingError::ReceiverGaveUp));
}

#[tokio::test(flavor = "multi_thread")]
async fn server_problems_are_named() {
    let ep = endpoint().await;

    // Nothing listens there
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let result = Offer::create(&client(&dead, &ep), None).await;
    match result.err() {
        Some(PairingError::Unreachable { url, reason }) => {
            assert_eq!(url, dead);
            assert!(!reason.is_empty());
        }
        other => panic!("expected an unreachable server, got {other:?}"),
    }

    // Something listens, but it is not a rendezvous server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let other = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, axum::Router::new()).await });
    let result = Offer::create(&client(&other, &ep), None).await;
    assert!(matches!(result.err(), Some(PairingError::Protocol { .. })));

    // Not a url at all
    for bad in ["", "rendezvous.example.com", "ftp://example.com", "http://"] {
        let result = Client::new(bad, ep.tls_config().clone());
        assert!(
            matches!(result, Err(PairingError::InvalidUrl(_))),
            "{bad:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn stranger_who_grabs_the_slot_learns_nothing() {
    // Someone who only knows the nameplate (it is public) claims the slot before the
    // real receiver. They cannot answer correctly, the sender refuses them, and the
    // sender's address never leaves the sender.
    let url = server(Config::default()).await;
    let send_ep = endpoint().await;
    let stranger_ep = endpoint().await;
    let send_addr = local_addr(&send_ep);

    let offer = Offer::create(&client(&url, &send_ep), None).await.unwrap();
    let nameplate = offer.code().nameplate().to_string();
    let send = tokio::spawn(async move { offer.wait_for_receiver(&send_addr).await });

    let guess: Code = format!("{nameplate}000000").parse().unwrap();
    let claim = Claim::new(&client(&url, &stranger_ep), guess)
        .await
        .unwrap();
    let result = claim.complete(None, stranger_ep.id()).await;

    assert_eq!(result, Err(PairingError::Rejected));
    assert_eq!(send.await.unwrap(), Err(PairingError::ReceiverWrongCode));
}
