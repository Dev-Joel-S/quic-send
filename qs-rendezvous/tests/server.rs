//! What a rendezvous server has to do, checked with plain HTTP requests like any client
//! could send them.
//!
//! By default the tests start the server of this crate. With `QS_RENDEZVOUS_URL` set they
//! run against the server at that url instead, which is how the Cloudflare Worker in
//! `rendezvous-worker/` is held to the same behavior (see `rendezvous-worker/test.sh`).
//! Such a server has to be started with its limits wide open, and the tests have to run
//! one after another (`--test-threads=1`), because they share it.
//! `QS_RENDEZVOUS_QUICK_URL` is a second instance where a slot expires after one second
//! without a reply and lives for a minute with one. Tests that need settings an outside
//! server cannot be given are skipped then.

use qs_rendezvous::{serve, Config};
use qs_rendezvous_api::{
    address_path, is_nameplate, reply_path, slot_path, ALPHABET, MAX_MESSAGE_BYTES, SLOTS_PATH,
};
use reqwest::{Client, Method, StatusCode};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};

/// Which server a test needs
enum Server {
    /// Limits wide open, everything else as it comes
    Open,
    /// Like [Server::Open], but a slot expires after a second without a reply
    Quick,
    /// Settings only the server of this crate can be given
    Only(Config),
}

/// Limits wide open, for tests that are about something else
fn open() -> Config {
    Config {
        creates_per_minute: 100_000,
        replies_per_minute: 100_000,
        looks_per_minute: 100_000,
        slots_per_address: 100_000,
        ..Config::default()
    }
}

/// Whether the tests run against a server that was started outside
fn outside() -> Option<String> {
    std::env::var("QS_RENDEZVOUS_URL")
        .ok()
        .filter(|url| !url.is_empty())
}

/// The base url of the server for a test, or [None] if the test cannot run against the
/// server that was given from outside
async fn start(server: Server) -> Option<String> {
    let config = match (server, outside()) {
        (Server::Open, Some(url)) => return Some(url),
        (Server::Quick, Some(_)) => {
            return std::env::var("QS_RENDEZVOUS_QUICK_URL")
                .ok()
                .filter(|url| !url.is_empty())
        }
        (Server::Only(_), Some(_)) => return None,
        (Server::Open, None) => open(),
        (Server::Quick, None) => Config {
            ttl: Duration::from_secs(1),
            reply_ttl: Duration::from_secs(60),
            ..open()
        },
        (Server::Only(config), None) => config,
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(serve(listener, config, std::future::pending()));
    Some(url)
}

/// The server for a test, or leave the test if it has none
macro_rules! server {
    ($server:expr) => {
        match start($server).await {
            Some(base) => base,
            None => {
                eprintln!("skipped: needs a server that cannot be set up from outside");
                return;
            }
        }
    };
}

fn client() -> Client {
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();

    Client::builder()
        .tls_backend_preconfigured(tls)
        .no_proxy()
        .build()
        .unwrap()
}

/// base64 (url safe, no padding) of a few known messages
const HELLO: &str = "aGVsbG8"; // hello
const REPLY: &str = "cmVwbHk"; // reply
const ADDRESS: &str = "YWRkcmVzcw"; // address

struct Answer {
    status: StatusCode,
    body: Value,
}

impl Answer {
    fn error(&self) -> &str {
        self.body["error"].as_str().unwrap_or_default()
    }

    fn str(&self, field: &str) -> String {
        self.body[field].as_str().unwrap_or_default().to_string()
    }
}

async fn call(
    client: &Client,
    method: Method,
    url: String,
    token: Option<&str>,
    body: Option<Value>,
) -> Answer {
    let mut request = client.request(method, url);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    if let Some(body) = body {
        request = request.json(&body);
    }

    let response = request.send().await.unwrap();
    let status = response.status();
    let body = response.json().await.unwrap_or(Value::Null);
    Answer { status, body }
}

async fn create_with(client: &Client, base: &str, message: &str) -> Answer {
    let url = format!("{base}{SLOTS_PATH}");
    let body = json!({ "message": message });
    call(client, Method::POST, url, None, Some(body)).await
}

async fn create(client: &Client, base: &str) -> Answer {
    create_with(client, base, HELLO).await
}

/// Look at a slot, which needs no token
async fn look(client: &Client, base: &str, nameplate: &str) -> Answer {
    let url = format!("{base}{}", slot_path(nameplate));
    call(client, Method::GET, url, None, None).await
}

/// Send the reply of the receiver, which needs no token and returns one
async fn reply_with(client: &Client, base: &str, nameplate: &str, message: &str) -> Answer {
    let url = format!("{base}{}", reply_path(nameplate));
    let body = json!({ "message": message });
    call(client, Method::PUT, url, None, Some(body)).await
}

async fn reply(client: &Client, base: &str, nameplate: &str) -> Answer {
    reply_with(client, base, nameplate, REPLY).await
}

async fn put(client: &Client, url: String, token: &str, message: &str) -> Answer {
    let body = json!({ "message": message });
    call(client, Method::PUT, url, Some(token), Some(body)).await
}

async fn get(client: &Client, url: String, token: &str) -> Answer {
    call(client, Method::GET, url, Some(token), None).await
}

async fn delete(client: &Client, base: &str, nameplate: &str, token: &str) -> Answer {
    let url = format!("{base}{}", slot_path(nameplate));
    call(client, Method::DELETE, url, Some(token), None).await
}

/// A slot that was created: (nameplate, sender token)
async fn created(client: &Client, base: &str) -> (String, String) {
    let created = create(client, base).await;
    assert_eq!(created.status, StatusCode::CREATED);
    (created.str("nameplate"), created.str("token"))
}

/// A slot that has its reply: (nameplate, sender token, receiver token)
async fn replied(client: &Client, base: &str) -> (String, String, String) {
    let (nameplate, sender) = created(client, base).await;
    let answer = reply(client, base, &nameplate).await;
    assert_eq!(answer.status, StatusCode::OK);
    (nameplate, sender, answer.str("token"))
}

#[tokio::test]
async fn messages_pass_through_a_slot() {
    let base = server!(Server::Open);
    let client = client();

    let created = create(&client, &base).await;
    assert_eq!(created.status, StatusCode::CREATED);
    let nameplate = created.str("nameplate");
    let sender = created.str("token");
    assert!(is_nameplate(&nameplate), "{nameplate}");
    assert!(sender.len() >= 16, "a token has to be hard to guess");
    let expires_in = created.body["expires_in"].as_u64().unwrap();
    assert!(expires_in > 0);

    let first = look(&client, &base, &nameplate).await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.str("message"), HELLO);
    assert!(first.body.get("token").is_none());

    let reply_url = format!("{base}{}", reply_path(&nameplate));
    let address_url = format!("{base}{}", address_path(&nameplate));

    let answer = reply(&client, &base, &nameplate).await;
    assert_eq!(answer.status, StatusCode::OK);
    let receiver = answer.str("token");
    assert!(receiver.len() >= 16);
    assert_ne!(sender, receiver);
    assert!(answer.body["expires_in"].as_u64().unwrap() > 0);

    let answer = get(&client, reply_url, &sender).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.str("message"), REPLY);

    let answer = put(&client, address_url.clone(), &sender, ADDRESS).await;
    assert_eq!(answer.status, StatusCode::NO_CONTENT);
    let answer = get(&client, address_url.clone(), &receiver).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.str("message"), ADDRESS);

    // Delivered once, then the slot is gone for good
    let again = get(&client, address_url, &receiver).await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.error(), "slot_used");
    assert_eq!(look(&client, &base, &nameplate).await.error(), "slot_used");
    assert_eq!(reply(&client, &base, &nameplate).await.error(), "slot_used");
}

#[tokio::test]
async fn looking_at_a_slot_does_not_use_it() {
    let base = server!(Server::Open);
    let client = client();
    let (nameplate, sender) = created(&client, &base).await;

    // Anyone can look, as often as they like, and always sees the same
    for _ in 0..5 {
        let answer = look(&client, &base, &nameplate).await;
        assert_eq!(answer.status, StatusCode::OK);
        assert_eq!(answer.str("message"), HELLO);
    }

    // The sender is not told about it, for it nothing has happened
    let reply_url = format!("{base}{}", reply_path(&nameplate));
    let nothing = get(&client, reply_url, &sender).await;
    assert_eq!(nothing.status, StatusCode::NO_CONTENT);

    // The receiver that comes after all that is the first to reply
    let answer = reply(&client, &base, &nameplate).await;
    assert_eq!(answer.status, StatusCode::OK);

    // Now the code is spent, and looking says so
    let late = look(&client, &base, &nameplate).await;
    assert_eq!(late.status, StatusCode::CONFLICT);
    assert_eq!(late.error(), "slot_used");
    assert!(late.body.get("message").is_none());
}

#[tokio::test]
async fn walking_through_every_nameplate_blocks_nobody() {
    let base = server!(Server::Open);
    let client = client();
    let (nameplate, sender) = created(&client, &base).await;

    // Somebody looks at all 1024 slots, to use up whatever codes are out there
    let mut found = 0;
    for a in ALPHABET {
        for b in ALPHABET {
            let name = String::from_utf8(vec![*a, *b]).unwrap();
            let answer = look(&client, &base, &name).await;
            assert_ne!(
                answer.status,
                StatusCode::TOO_MANY_REQUESTS,
                "limits not open"
            );
            found += usize::from(answer.status == StatusCode::OK);
        }
    }
    assert!(found >= 1);

    // The slot is as it was: the receiver replies, the sender gets the reply
    let answer = reply(&client, &base, &nameplate).await;
    assert_eq!(answer.status, StatusCode::OK);
    let reply_url = format!("{base}{}", reply_path(&nameplate));
    assert_eq!(get(&client, reply_url, &sender).await.str("message"), REPLY);
}

#[tokio::test]
async fn second_reply_is_refused() {
    let base = server!(Server::Open);
    let client = client();
    let (nameplate, sender, receiver) = replied(&client, &base).await;

    // Whoever comes second gets nothing, and changes nothing
    for _ in 0..3 {
        let second = reply_with(&client, &base, &nameplate, ADDRESS).await;
        assert_eq!(second.status, StatusCode::CONFLICT);
        assert_eq!(second.error(), "slot_used");
        assert!(second.body.get("token").is_none());
    }

    // The first one is not disturbed by that
    let reply_url = format!("{base}{}", reply_path(&nameplate));
    let address_url = format!("{base}{}", address_path(&nameplate));
    assert_eq!(get(&client, reply_url, &sender).await.str("message"), REPLY);
    let answer = put(&client, address_url.clone(), &sender, ADDRESS).await;
    assert_eq!(answer.status, StatusCode::NO_CONTENT);
    let answer = get(&client, address_url, &receiver).await;
    assert_eq!(answer.str("message"), ADDRESS);
}

#[tokio::test]
async fn unknown_nameplates() {
    let base = server!(Server::Open);
    let client = client();

    // Characters that are in no nameplate, and lengths no nameplate has
    for nameplate in ["zz", "K", "K7X4", "KI", "UU"] {
        let answer = look(&client, &base, nameplate).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{nameplate}");
        assert_eq!(answer.error(), "unknown_slot", "{nameplate}");

        let answer = reply(&client, &base, nameplate).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{nameplate}");
        assert_eq!(answer.error(), "unknown_slot", "{nameplate}");
    }

    // Path tricks lead nowhere. The client already resolves the dots, so this request
    // is for a path that does not exist.
    let dots = look(&client, &base, "%2E%2E").await;
    assert!(dots.status.is_client_error());
    assert!(dots.body.get("message").is_none());
}

#[tokio::test]
async fn slots_expire() {
    let base = server!(Server::Quick);
    let client = client();
    let (nameplate, sender) = created(&client, &base).await;

    // The sender is waiting for a reply and learns about the expiry without asking again
    let started = Instant::now();
    let url = format!("{base}{}?wait=20", reply_path(&nameplate));
    let waiting = get(&client, url, &sender).await;
    assert_eq!(waiting.status, StatusCode::GONE);
    assert_eq!(waiting.error(), "slot_expired");
    assert!(started.elapsed() < Duration::from_secs(8));

    for late in [
        look(&client, &base, &nameplate).await,
        reply(&client, &base, &nameplate).await,
    ] {
        assert_eq!(late.status, StatusCode::GONE);
        assert_eq!(late.error(), "slot_expired");
    }
}

#[tokio::test]
async fn a_reply_gives_time_to_finish() {
    let base = server!(Server::Quick);
    let client = client();
    let (nameplate, sender, _receiver) = replied(&client, &base).await;

    // Past the first deadline the slot is still there, because it has its reply
    tokio::time::sleep(Duration::from_millis(2000)).await;
    let reply_url = format!("{base}{}", reply_path(&nameplate));
    let answer = get(&client, reply_url, &sender).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.str("message"), REPLY);
}

#[tokio::test]
async fn tokens_are_required_and_bound_to_a_role() {
    let base = server!(Server::Open);
    let client = client();
    let (nameplate, sender) = created(&client, &base).await;
    let reply_url = format!("{base}{}", reply_path(&nameplate));
    let address_url = format!("{base}{}", address_path(&nameplate));

    let forbidden = |answer: Answer| {
        assert_eq!(answer.status, StatusCode::FORBIDDEN);
        assert_eq!(answer.error(), "forbidden");
    };

    // The address answers the reply, it cannot come first
    let early = put(&client, address_url.clone(), &sender, ADDRESS).await;
    assert_eq!(early.status, StatusCode::BAD_REQUEST);
    assert_eq!(early.error(), "bad_request");

    let answer = reply(&client, &base, &nameplate).await;
    let receiver = answer.str("token");

    // No token, a made up token, and the token of the other side
    forbidden(call(&client, Method::GET, reply_url.clone(), None, None).await);
    forbidden(
        get(
            &client,
            reply_url.clone(),
            "0123456789abcdef0123456789abcdef",
        )
        .await,
    );
    forbidden(get(&client, reply_url.clone(), &receiver).await);
    forbidden(put(&client, address_url.clone(), &receiver, ADDRESS).await);
    forbidden(put(&client, address_url.clone(), "nope", ADDRESS).await);
    forbidden(get(&client, address_url.clone(), &sender).await);
    forbidden(call(&client, Method::GET, address_url.clone(), None, None).await);
    forbidden(delete(&client, &base, &nameplate, "nope").await);

    // The address is set once
    let first = put(&client, address_url.clone(), &sender, ADDRESS).await;
    assert_eq!(first.status, StatusCode::NO_CONTENT);
    let twice = put(&client, address_url, &sender, REPLY).await;
    assert_eq!(twice.status, StatusCode::BAD_REQUEST);
    assert_eq!(twice.error(), "bad_request");
}

#[tokio::test]
async fn giving_up_closes_the_slot_for_the_other_side() {
    let base = server!(Server::Open);
    let client = client();
    let (nameplate, sender, receiver) = replied(&client, &base).await;

    // The receiver waits for the address while the sender gives up
    let waiting = tokio::spawn({
        let client = client.clone();
        let url = format!("{base}{}?wait=20", address_path(&nameplate));
        let receiver = receiver.clone();
        async move { get(&client, url, &receiver).await }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let started = Instant::now();
    let deleted = delete(&client, &base, &nameplate, &sender).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);

    let answer = waiting.await.unwrap();
    assert_eq!(answer.status, StatusCode::GONE);
    assert_eq!(answer.error(), "slot_closed");
    assert!(started.elapsed() < Duration::from_secs(5));

    // Deleting what is gone is fine, with any token
    let again = delete(&client, &base, &nameplate, "whatever").await;
    assert_eq!(again.status, StatusCode::NO_CONTENT);

    // A sender that gives up before anyone replied closes the slot as well
    let (nameplate, sender) = created(&client, &base).await;
    delete(&client, &base, &nameplate, &sender).await;
    for late in [
        look(&client, &base, &nameplate).await,
        reply(&client, &base, &nameplate).await,
    ] {
        assert_eq!(late.status, StatusCode::GONE);
        assert_eq!(late.error(), "slot_closed");
    }
}

#[tokio::test]
async fn waiting_returns_empty_or_as_soon_as_there_is_a_message() {
    let base = server!(Server::Open);
    let client = client();
    let (nameplate, sender) = created(&client, &base).await;
    let reply_url = format!("{base}{}", reply_path(&nameplate));

    // Nothing there: an empty answer, after the wait at the latest
    let started = Instant::now();
    let empty = get(&client, format!("{reply_url}?wait=1"), &sender).await;
    assert_eq!(empty.status, StatusCode::NO_CONTENT);
    assert!(started.elapsed() < Duration::from_secs(4));

    // Without `wait` the answer is immediate
    let started = Instant::now();
    let empty = get(&client, reply_url.clone(), &sender).await;
    assert_eq!(empty.status, StatusCode::NO_CONTENT);
    assert!(started.elapsed() < Duration::from_millis(900));

    // A message that arrives while waiting is delivered right away
    let waiting = tokio::spawn({
        let client = client.clone();
        let url = format!("{reply_url}?wait=20");
        async move { (get(&client, url, &sender).await, Instant::now()) }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let sent = Instant::now();
    reply(&client, &base, &nameplate).await;
    let (answer, arrived) = waiting.await.unwrap();
    assert_eq!(answer.str("message"), REPLY);
    assert!(arrived.duration_since(sent) < Duration::from_secs(3));
}

#[tokio::test]
async fn oversized_and_broken_bodies_are_refused() {
    let base = server!(Server::Open);
    let client = client();
    let url = format!("{base}{SLOTS_PATH}");

    // Exactly at the limit is fine, one byte more is not.
    // Three bytes are four characters of base64, MAX_MESSAGE_BYTES is not a multiple
    // of three, so one byte is left over and takes two more characters.
    assert_eq!(MAX_MESSAGE_BYTES % 3, 1);
    let at_limit = "A".repeat(MAX_MESSAGE_BYTES / 3 * 4 + 2);
    let over_limit = "A".repeat(MAX_MESSAGE_BYTES / 3 * 4 + 3);
    let ok = create_with(&client, &base, &at_limit).await;
    assert_eq!(ok.status, StatusCode::CREATED);
    let too_large = create_with(&client, &base, &over_limit).await;
    assert_eq!(too_large.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(too_large.error(), "too_large");

    // Far beyond the limit the body is not even read
    let huge = "A".repeat(MAX_MESSAGE_BYTES * 10);
    let refused = create_with(&client, &base, &huge).await;
    assert!(refused.status.is_client_error());

    let broken = [
        json!({}),
        json!({ "message": 5 }),
        json!({ "message": "not base64 !!" }),
        json!([1, 2]),
    ];
    for body in broken {
        let answer = call(&client, Method::POST, url.clone(), None, Some(body)).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    }
    let no_json = client.post(&url).body("hello").send().await.unwrap();
    assert_eq!(no_json.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn requests_per_address_are_limited() {
    let base = server!(Server::Only(Config {
        creates_per_minute: 3,
        replies_per_minute: 2,
        looks_per_minute: 4,
        ..open()
    }));
    let client = client();

    let mut nameplate = String::new();
    for _ in 0..3 {
        let created = create(&client, &base).await;
        assert_eq!(created.status, StatusCode::CREATED);
        nameplate = created.str("nameplate");
    }
    let limited = create(&client, &base).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.error(), "rate_limited");

    // Guessing with replies is limited too, also when the guesses lead nowhere
    assert_eq!(reply(&client, &base, "ZZ").await.error(), "unknown_slot");
    assert_eq!(reply(&client, &base, "ZY").await.error(), "unknown_slot");
    let limited = reply(&client, &base, &nameplate).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.error(), "rate_limited");

    // Looking has a limit of its own, which neither spends the slot nor the replies
    for _ in 0..4 {
        assert_eq!(
            look(&client, &base, &nameplate).await.status,
            StatusCode::OK
        );
    }
    let limited = look(&client, &base, &nameplate).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn open_slots_per_address_are_limited() {
    let base = server!(Server::Only(Config {
        slots_per_address: 2,
        ..open()
    }));
    let client = client();

    let first = create(&client, &base).await;
    assert_eq!(create(&client, &base).await.status, StatusCode::CREATED);
    let third = create(&client, &base).await;
    assert_eq!(third.status, StatusCode::TOO_MANY_REQUESTS);

    // Giving one back makes room again
    delete(&client, &base, &first.str("nameplate"), &first.str("token")).await;
    assert_eq!(create(&client, &base).await.status, StatusCode::CREATED);
}

#[tokio::test]
async fn a_nameplate_is_never_handed_out_twice() {
    let base = server!(Server::Open);
    let client = client();

    // Until the server has no slot left. A server may say so before every single
    // nameplate is taken, but not while most of them are free.
    let mut slots = Vec::new();
    let mut seen = HashSet::new();
    let full = loop {
        let created = create(&client, &base).await;
        if created.status != StatusCode::CREATED {
            break created;
        }
        let nameplate = created.str("nameplate");
        assert!(is_nameplate(&nameplate), "{nameplate}");
        assert!(seen.insert(nameplate.clone()), "nameplate handed out twice");
        slots.push((nameplate, created.str("token")));
        assert!(slots.len() <= 1024, "more slots than nameplates");
    };

    assert_eq!(full.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(full.error(), "no_free_slot");
    if outside().is_some() {
        assert!(slots.len() >= 512, "gave up after {} slots", slots.len());
    } else {
        assert_eq!(slots.len(), 1024);
    }

    // Leave the server as it was found, it may be shared with other tests
    for (nameplate, token) in slots {
        delete(&client, &base, &nameplate, &token).await;
    }
    assert_eq!(create(&client, &base).await.status, StatusCode::CREATED);
}

#[tokio::test]
async fn forwarded_address_counts_only_behind_a_proxy() {
    let limited = |behind_proxy| Config {
        creates_per_minute: 1,
        behind_proxy,
        ..open()
    };
    let client = client();
    let create_as = |base: String, forwarded: &'static str| {
        let client = client.clone();
        async move {
            client
                .post(format!("{base}{SLOTS_PATH}"))
                .header("x-forwarded-for", forwarded)
                .json(&json!({ "message": HELLO }))
                .send()
                .await
                .unwrap()
                .status()
        }
    };

    // Behind a proxy every forwarded address has its own limit
    let base = server!(Server::Only(limited(true)));
    let ok = StatusCode::CREATED;
    let limit = StatusCode::TOO_MANY_REQUESTS;
    assert_eq!(create_as(base.clone(), "203.0.113.1").await, ok);
    assert_eq!(create_as(base.clone(), "203.0.113.2").await, ok);
    assert_eq!(create_as(base.clone(), "203.0.113.1").await, limit);
    // Only the entry the proxy added counts, a client cannot put another one in front
    let spoofed = "198.51.100.9, 203.0.113.2";
    assert_eq!(create_as(base.clone(), spoofed).await, limit);

    // Without a proxy the header is ignored, a client cannot pick its own address
    let base = server!(Server::Only(limited(false)));
    assert_eq!(create_as(base.clone(), "203.0.113.1").await, ok);
    assert_eq!(create_as(base.clone(), "203.0.113.2").await, limit);
}

#[tokio::test]
async fn says_what_it_is() {
    let base = server!(Server::Open);
    let answer = call(&client(), Method::GET, format!("{base}/v1"), None, None).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.str("service"), "quic-send-rendezvous");
    assert_eq!(answer.body["api"], 1);

    // Anything else is not part of the API
    for path in ["/", "/v2", "/v1/nothing", "/v1/slots/K7/claim"] {
        let answer = call(&client(), Method::GET, format!("{base}{path}"), None, None).await;
        assert!(answer.status.is_client_error(), "{path}");
    }
}
