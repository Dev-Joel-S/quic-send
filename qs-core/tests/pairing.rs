//! Pairing with a short code through a real rendezvous server, and a transfer on top.

use iroh::{endpoint::presets, Endpoint, EndpointAddr, RelayMode};
use qs_core::{
    pairing::{code::Code, first_available, rendezvous::Client, Claim, Offer, PairingError},
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
    mistyped_from(offer.code())
}

fn mistyped_from(code: &Code) -> Code {
    let text = code.to_string();
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
            announce: None,
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
    let mut receiver = Receiver::connect(
        recv_ep,
        sender_addr,
        ReceiverArgs {
            resume: true,
            announce: None,
        },
    )
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
async fn looking_is_free_and_a_code_takes_one_reply() {
    let url = server(Config::default()).await;
    let send_ep = endpoint().await;
    let recv_ep = endpoint().await;
    let other_ep = endpoint().await;
    let send_addr = local_addr(&send_ep);

    let offer = Offer::create(&client(&url, &send_ep), None).await.unwrap();
    let code = typed(&offer);
    let send = tokio::spawn(async move { offer.wait_for_receiver(&send_addr).await });

    // Somebody who guesses the slot looks at it, again and again. That spends nothing.
    for _ in 0..3 {
        let stranger = Claim::new(&client(&url, &other_ep), mistyped_from(&code)).await;
        assert!(stranger.is_ok());
    }
    // Somebody who also knows the code looks as well, but is slower with the rest
    let second = Claim::new(&client(&url, &other_ep), code.clone())
        .await
        .unwrap();

    // The receiver is not disturbed by any of that
    let first = Claim::new(&client(&url, &recv_ep), code).await.unwrap();
    let addr = first.complete(None, recv_ep.id()).await.unwrap();
    assert_eq!(addr.id, send_ep.id());
    assert_eq!(send.await.unwrap(), Ok(recv_ep.id()));

    // One reply per code: whoever comes second is too late, even with the right code
    let late = second.complete(None, other_ep.id()).await;
    assert_eq!(late, Err(PairingError::Used));
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

    // Nothing was sent, so the code is not spent: with the password it still works
    let code = typed(&offer);
    let send_addr = local_addr(&send_ep);
    let send = tokio::spawn(async move { offer.wait_for_receiver(&send_addr).await });
    let claim = Claim::new(&client(&url, &recv_ep), code).await.unwrap();
    assert!(claim.complete(Some("hunter2"), recv_ep.id()).await.is_ok());
    assert_eq!(send.await.unwrap(), Ok(recv_ep.id()));
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

    // The receiver looks at the slot and walks away, for example at the password prompt.
    // Nothing was spent, the code still works.
    let offer = Offer::create(&client(&url, &send_ep), None).await.unwrap();
    let code = typed(&offer);
    let send_addr = local_addr(&send_ep);
    let send = tokio::spawn(async move { offer.wait_for_receiver(&send_addr).await });

    let claim = Claim::new(&client(&url, &recv_ep), code.clone()).await;
    assert!(claim.is_ok());
    drop(claim);

    let again = Claim::new(&client(&url, &recv_ep), code).await.unwrap();
    assert!(again.complete(None, recv_ep.id()).await.is_ok());
    assert_eq!(send.await.unwrap(), Ok(recv_ep.id()));
}

#[tokio::test(flavor = "multi_thread")]
async fn servers_are_tried_in_order() {
    let send_ep = endpoint().await;
    let recv_ep = endpoint().await;
    let send_addr = local_addr(&send_ep);

    // One server that is down, one that is no rendezvous server, two that work
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let foreign = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, axum::Router::new()).await });
    let empty = server(Config::default()).await;
    let url = server(Config::default()).await;

    // The sender takes the first one that answers as a rendezvous server
    let servers = [
        client(&dead, &send_ep),
        client(&foreign, &send_ep),
        client(&url, &send_ep),
        client(&empty, &send_ep),
    ];
    let chosen = first_available(&servers).await.unwrap();
    assert_eq!(chosen.url(), url);
    let offer = Offer::create(chosen, None).await.unwrap();
    let code = typed(&offer);
    let send = tokio::spawn(async move { offer.wait_for_receiver(&send_addr).await });

    // The receiver has another server in front that works but does not know the code
    let servers = [
        client(&dead, &recv_ep),
        client(&empty, &recv_ep),
        client(&url, &recv_ep),
    ];
    let claim = Claim::find(&servers, code.clone()).await.unwrap();
    assert!(claim.complete(None, recv_ep.id()).await.is_ok());
    assert_eq!(send.await.unwrap(), Ok(recv_ep.id()));

    // A code no server knows
    let unknown = Claim::find(&servers[..2], "ZZZZ-ZZZZ".parse().unwrap()).await;
    assert_eq!(unknown.err(), Some(PairingError::Unknown));

    // No server that can be used: every one is named with what is wrong with it
    let servers = [client(&dead, &send_ep), client(&foreign, &send_ep)];
    match first_available(&servers).await.err() {
        Some(PairingError::NoServer(text)) => {
            assert!(text.contains(&dead) && text.contains(&foreign), "{text}");
        }
        other => panic!("expected no usable server, got {other:?}"),
    }
    assert!(matches!(
        Claim::find(&servers, code).await.err(),
        Some(PairingError::NoServer(_))
    ));
    // With a single server the error is the one of that server
    assert!(matches!(
        first_available(&servers[..1]).await.err(),
        Some(PairingError::Unreachable { .. })
    ));
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

#[tokio::test(flavor = "multi_thread")]
async fn redirects_are_not_followed() {
    use axum::{response::Redirect, routing::post, Router};

    let real = server(Config::default()).await;
    let ep = endpoint().await;

    // A server that sends every client on to another one
    let target = format!("{real}/v1/slots");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redirecting = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().route(
        "/v1/slots",
        post(move || {
            let target = target.clone();
            async move { Redirect::temporary(&target) }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await });

    let result = Offer::create(&client(&redirecting, &ep), None).await;
    assert!(
        matches!(result.err(), Some(PairingError::Protocol { .. })),
        "a redirect must not be followed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn plain_http_over_a_network_is_pointed_out() {
    let ep = endpoint().await;
    let unprotected = |url: &str| client(url, &ep).is_unprotected();

    assert!(unprotected("http://rendezvous.example.com"));
    assert!(unprotected("http://192.168.1.5:8080"));
    assert!(!unprotected("https://rendezvous.example.com"));
    // On the same machine there is no network to listen on
    assert!(!unprotected("http://127.0.0.1:8080"));
    assert!(!unprotected("http://localhost:8080"));
    assert!(!unprotected("http://[::1]:8080"));
}
