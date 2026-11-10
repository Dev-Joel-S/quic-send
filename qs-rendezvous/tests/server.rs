//! The server on its own, driven with plain HTTP requests like any client could send.

use qs_rendezvous::{serve, Config};
use qs_rendezvous_api::{
    address_path, claim_path, is_nameplate, reply_path, slot_path, MAX_MESSAGE_BYTES, SLOTS_PATH,
};
use reqwest::{Client, Method, StatusCode};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};

/// Start a server on a free local port and return its base url
async fn start(config: Config) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(serve(listener, config, std::future::pending()));
    url
}

/// Limits wide open, for tests that are about something else
fn open() -> Config {
    Config {
        creates_per_minute: 100_000,
        claims_per_minute: 100_000,
        slots_per_address: 100_000,
        ..Config::default()
    }
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

async fn claim(client: &Client, base: &str, nameplate: &str) -> Answer {
    let url = format!("{base}{}", claim_path(nameplate));
    call(client, Method::POST, url, None, None).await
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

/// A slot that was created and claimed: (nameplate, sender token, receiver token)
async fn claimed(client: &Client, base: &str) -> (String, String, String) {
    let created = create(client, base).await;
    assert_eq!(created.status, StatusCode::CREATED);
    let nameplate = created.str("nameplate");
    let claim = claim(client, base, &nameplate).await;
    assert_eq!(claim.status, StatusCode::OK);
    (nameplate, created.str("token"), claim.str("token"))
}

#[tokio::test]
async fn messages_pass_through_a_slot() {
    let base = start(open()).await;
    let client = client();

    let created = create(&client, &base).await;
    assert_eq!(created.status, StatusCode::CREATED);
    let nameplate = created.str("nameplate");
    let sender = created.str("token");
    assert!(is_nameplate(&nameplate), "{nameplate}");
    assert_eq!(created.body["expires_in"], 300);

    let claim_answer = claim(&client, &base, &nameplate).await;
    assert_eq!(claim_answer.status, StatusCode::OK);
    assert_eq!(claim_answer.str("message"), HELLO);
    let receiver = claim_answer.str("token");
    assert_ne!(sender, receiver);

    let reply_url = format!("{base}{}", reply_path(&nameplate));
    let address_url = format!("{base}{}", address_path(&nameplate));

    let answer = put(&client, reply_url.clone(), &receiver, REPLY).await;
    assert_eq!(answer.status, StatusCode::NO_CONTENT);
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
    assert_eq!(claim(&client, &base, &nameplate).await.error(), "slot_used");
}

#[tokio::test]
async fn second_claim_is_refused() {
    let base = start(open()).await;
    let client = client();
    let (nameplate, _sender, receiver) = claimed(&client, &base).await;

    // Whoever comes second gets nothing, not even the first message
    for _ in 0..3 {
        let second = claim(&client, &base, &nameplate).await;
        assert_eq!(second.status, StatusCode::CONFLICT);
        assert_eq!(second.error(), "slot_used");
        assert!(second.body.get("message").is_none());
        assert!(second.body.get("token").is_none());
    }

    // The first one is not disturbed by that
    let reply_url = format!("{base}{}", reply_path(&nameplate));
    let answer = put(&client, reply_url, &receiver, REPLY).await;
    assert_eq!(answer.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn unknown_nameplates() {
    let base = start(open()).await;
    let client = client();

    for nameplate in ["ZZ", "zz", "K", "K7X4", "KI"] {
        let answer = claim(&client, &base, nameplate).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{nameplate}");
        assert_eq!(answer.error(), "unknown_slot", "{nameplate}");
    }

    // Path tricks lead nowhere. The client already resolves the dots, so this request
    // is for a path that does not exist.
    let dots = claim(&client, &base, "%2E%2E").await;
    assert_eq!(dots.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn slots_expire() {
    let base = start(Config {
        ttl: Duration::from_millis(300),
        ..open()
    })
    .await;
    let client = client();

    let created = create(&client, &base).await;
    let nameplate = created.str("nameplate");
    let sender = created.str("token");

    // The sender is waiting for a reply and learns about the expiry without asking again
    let started = Instant::now();
    let url = format!("{base}{}?wait=20", reply_path(&nameplate));
    let waiting = get(&client, url, &sender).await;
    assert_eq!(waiting.status, StatusCode::GONE);
    assert_eq!(waiting.error(), "slot_expired");
    assert!(started.elapsed() < Duration::from_secs(5));

    let late = claim(&client, &base, &nameplate).await;
    assert_eq!(late.status, StatusCode::GONE);
    assert_eq!(late.error(), "slot_expired");
}

#[tokio::test]
async fn claiming_gives_time_to_finish() {
    let base = start(Config {
        ttl: Duration::from_millis(300),
        claimed_ttl: Duration::from_secs(60),
        ..open()
    })
    .await;
    let client = client();
    let (nameplate, _sender, receiver) = claimed(&client, &base).await;

    // Past the first deadline, for example while the receiver types a password
    tokio::time::sleep(Duration::from_millis(700)).await;
    let reply_url = format!("{base}{}", reply_path(&nameplate));
    let answer = put(&client, reply_url, &receiver, REPLY).await;
    assert_eq!(answer.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn tokens_are_required_and_bound_to_a_role() {
    let base = start(open()).await;
    let client = client();
    let (nameplate, sender, receiver) = claimed(&client, &base).await;
    let reply_url = format!("{base}{}", reply_path(&nameplate));
    let address_url = format!("{base}{}", address_path(&nameplate));

    let forbidden = |answer: Answer| {
        assert_eq!(answer.status, StatusCode::FORBIDDEN);
        assert_eq!(answer.error(), "forbidden");
    };

    // No token, a made up token, and the token of the other side
    forbidden(call(&client, Method::GET, reply_url.clone(), None, None).await);
    forbidden(get(&client, reply_url.clone(), "0123456789abcdef").await);
    forbidden(get(&client, reply_url.clone(), &receiver).await);
    forbidden(put(&client, reply_url.clone(), &sender, REPLY).await);
    forbidden(put(&client, address_url.clone(), &receiver, ADDRESS).await);
    forbidden(get(&client, address_url.clone(), &sender).await);
    forbidden(delete(&client, &base, &nameplate, "nope").await);

    // Out of order and repeated messages
    let early = put(&client, address_url, &sender, ADDRESS).await;
    assert_eq!(early.status, StatusCode::BAD_REQUEST);
    let first = put(&client, reply_url.clone(), &receiver, REPLY).await;
    assert_eq!(first.status, StatusCode::NO_CONTENT);
    let twice = put(&client, reply_url, &receiver, REPLY).await;
    assert_eq!(twice.status, StatusCode::BAD_REQUEST);
    assert_eq!(twice.error(), "bad_request");
}

#[tokio::test]
async fn giving_up_closes_the_slot_for_the_other_side() {
    let base = start(open()).await;
    let client = client();
    let (nameplate, sender, receiver) = claimed(&client, &base).await;

    // The receiver waits for the address while the sender gives up
    let waiting = tokio::spawn({
        let client = client.clone();
        let url = format!("{base}{}?wait=20", address_path(&nameplate));
        let receiver = receiver.clone();
        async move { get(&client, url, &receiver).await }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

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
}

#[tokio::test]
async fn waiting_returns_empty_or_as_soon_as_there_is_a_message() {
    let base = start(open()).await;
    let client = client();
    let (nameplate, sender, receiver) = claimed(&client, &base).await;
    let reply_url = format!("{base}{}", reply_path(&nameplate));

    // Nothing there: an empty answer after the wait
    let started = Instant::now();
    let empty = get(&client, format!("{reply_url}?wait=1"), &sender).await;
    assert_eq!(empty.status, StatusCode::NO_CONTENT);
    assert!(started.elapsed() >= Duration::from_millis(900));

    // Without `wait` the answer is immediate
    let started = Instant::now();
    let empty = get(&client, reply_url.clone(), &sender).await;
    assert_eq!(empty.status, StatusCode::NO_CONTENT);
    assert!(started.elapsed() < Duration::from_millis(500));

    // A message that arrives while waiting is delivered right away
    let waiting = tokio::spawn({
        let client = client.clone();
        let url = format!("{reply_url}?wait=20");
        async move { get(&client, url, &sender).await }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let started = Instant::now();
    put(&client, reply_url, &receiver, REPLY).await;
    let answer = waiting.await.unwrap();
    assert_eq!(answer.str("message"), REPLY);
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn oversized_and_broken_bodies_are_refused() {
    let base = start(open()).await;
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
    let base = start(Config {
        creates_per_minute: 3,
        claims_per_minute: 2,
        ..open()
    })
    .await;
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

    // Guessing nameplates is limited too, also when the guesses are wrong
    assert_eq!(claim(&client, &base, "ZZ").await.error(), "unknown_slot");
    assert_eq!(claim(&client, &base, "ZY").await.error(), "unknown_slot");
    let limited = claim(&client, &base, &nameplate).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn open_slots_per_address_are_limited() {
    let base = start(Config {
        slots_per_address: 2,
        ..open()
    })
    .await;
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
async fn every_nameplate_is_handed_out_once() {
    let base = start(open()).await;
    let client = client();

    let mut seen = HashSet::new();
    for _ in 0..1024 {
        let created = create(&client, &base).await;
        assert_eq!(created.status, StatusCode::CREATED);
        let nameplate = created.str("nameplate");
        assert!(seen.insert(nameplate), "nameplate handed out twice");
    }

    let full = create(&client, &base).await;
    assert_eq!(full.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(full.error(), "no_free_slot");
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
    let base = start(limited(true)).await;
    let ok = StatusCode::CREATED;
    let limit = StatusCode::TOO_MANY_REQUESTS;
    assert_eq!(create_as(base.clone(), "203.0.113.1").await, ok);
    assert_eq!(create_as(base.clone(), "203.0.113.2").await, ok);
    assert_eq!(create_as(base.clone(), "203.0.113.1").await, limit);
    // Only the entry the proxy added counts, a client cannot put another one in front
    let spoofed = "198.51.100.9, 203.0.113.2";
    assert_eq!(create_as(base.clone(), spoofed).await, limit);

    // Without a proxy the header is ignored, a client cannot pick its own address
    let base = start(limited(false)).await;
    assert_eq!(create_as(base.clone(), "203.0.113.1").await, ok);
    assert_eq!(create_as(base.clone(), "203.0.113.2").await, limit);
}

#[tokio::test]
async fn says_what_it_is() {
    let base = start(open()).await;
    let answer = call(&client(), Method::GET, format!("{base}/v1"), None, None).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.str("service"), "quic-send-rendezvous");
    assert_eq!(answer.body["api"], 1);
}
