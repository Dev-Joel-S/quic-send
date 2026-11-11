//! Rendezvous server for quic-send.
//!
//! An untrusted mailbox. It hands out slots and passes opaque messages between the two
//! peers of a pairing. It must not be able to do more than deny service, see
//! `qs_core::pairing` for what the clients assume, and `qs-rendezvous-api` for the wire
//! format.
//!
//! DONE: create slot: the server picks a free nameplate at random and returns it, so
//!       senders never collide.
//! DONE: messages are stored per slot and never interpreted: first message of the sender,
//!       reply of the receiver, sealed address of the sender.
//! DONE: a slot takes exactly one reply, a second one gets `slot_used` (test
//!       `second_reply_is_refused`). The reply is the guess at the code, so this is the
//!       defense against online guessing.
//! DONE: looking at a slot (`GET /v1/slots/{nameplate}`) is free: it changes nothing and
//!       does not count as an attempt, so nobody can use up codes by walking through the
//!       1024 nameplates (test `looking_at_a_slot_does_not_use_it`). The first message
//!       it returns is a PAKE message and a public key, which give away nothing.
//! DONE: a slot is removed when the address was fetched, on a delete request and when it
//!       expires. Ended slots are remembered for a while, so clients can be told `expired`,
//!       `used` and `closed` apart from a nameplate that never existed.
//! DONE: limits: message size, slots in total (the nameplate space) and per address,
//!       slot creations, replies and looks per address and minute. Everything is in
//!       memory.
//! DONE: `GET` requests wait up to 25 seconds for a message (long polling).
//! DONE: nothing is logged per slot, so slot names never end up next to IP addresses.
//! DONE: tests in `tests/server.rs`, including clients that behave badly.
//! DONE: TLS is the job of a reverse proxy, the README has an example configuration and
//!       `packaging/qs-rendezvous.service` an example systemd unit.
//! DONE: tokens are compared in constant time ([same_token]).
//! DONE (audit finding M3): the code stays 2 + 6 characters. What is left of the finding:
//!       anyone who can reach the server can still spend a code by sending a reply to its
//!       slot, because the sender closes the slot after one wrong reply. That one guess per
//!       code is the point of the design. The limit of replies per address slows it down.

use axum::{
    extract::{rejection::JsonRejection, ConnectInfo, DefaultBodyLimit, Path, Query, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use qs_rendezvous_api::{
    is_nameplate, ErrorBody, ErrorCode, Message, ServerInfo, SlotCreated, SlotReplied, ALPHABET,
    API_VERSION, MAX_MESSAGE_BYTES, MAX_WAIT_SECS, NAMEPLATE_LEN, SERVICE_NAME,
};
use serde::Deserialize;
use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Notify;

/// How the server behaves
#[derive(Debug, Clone)]
pub struct Config {
    /// How long a slot lives while nobody has replied to it
    pub ttl: Duration,
    /// How long the two peers have to finish once the reply is there
    pub reply_ttl: Duration,
    /// How long an ended slot is remembered, to tell why it is gone
    pub remember: Duration,
    /// Take the client address from `X-Forwarded-For` instead of the connection
    pub behind_proxy: bool,
    /// Slots one address may create per minute
    pub creates_per_minute: u32,
    /// Replies one address may send per minute. A reply is a guess at a code.
    pub replies_per_minute: u32,
    /// Looks at a slot one address may take per minute. They are free for the slot,
    /// the limit only keeps the load down.
    pub looks_per_minute: u32,
    /// Slots one address may have open at once
    pub slots_per_address: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(300),
            reply_ttl: Duration::from_secs(120),
            remember: Duration::from_secs(600),
            behind_proxy: false,
            creates_per_minute: 30,
            replies_per_minute: 30,
            looks_per_minute: 120,
            slots_per_address: 16,
        }
    }
}

/// A client address for rate limiting. IPv6 addresses are counted per /64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AddressKey(IpAddr);

impl AddressKey {
    fn new(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Self(ip),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => Self(IpAddr::V4(v4)),
                None => {
                    let prefix = u128::from(v6) & !u128::from(u64::MAX);
                    Self(IpAddr::V6(Ipv6Addr::from(prefix)))
                }
            },
        }
    }
}

struct Slot {
    expires: Instant,
    creator: AddressKey,
    sender_token: String,
    /// First message of the sender
    hello: Vec<u8>,
    /// Set once the reply is there
    receiver_token: Option<String>,
    /// Reply of the receiver
    reply: Option<Vec<u8>>,
    /// Sealed address of the sender
    address: Option<Vec<u8>>,
    /// Wakes requests that wait for a change of this slot
    changed: Arc<Notify>,
}

/// Why a slot is gone
#[derive(Debug, Clone, Copy)]
enum Gone {
    Used,
    Expired,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Limited {
    Create,
    Reply,
    Look,
}

#[derive(Default)]
struct Inner {
    slots: HashMap<String, Slot>,
    gone: HashMap<String, (Gone, Instant)>,
    /// Start of the current minute and requests in it, per address and kind
    windows: HashMap<(AddressKey, Limited), (Instant, u32)>,
}

impl Inner {
    /// Remove a slot and remember why. Wakes everyone waiting for it.
    fn end(&mut self, nameplate: &str, reason: Gone, config: &Config) {
        if let Some(slot) = self.slots.remove(nameplate) {
            slot.changed.notify_waiters();
            self.gone.insert(
                nameplate.to_string(),
                (reason, Instant::now() + config.remember),
            );
        }
    }

    /// Expire what is due
    fn sweep(&mut self, config: &Config) {
        let now = Instant::now();

        let expired: Vec<String> = self
            .slots
            .iter()
            .filter(|(_, slot)| slot.expires <= now)
            .map(|(nameplate, _)| nameplate.clone())
            .collect();
        for nameplate in expired {
            self.end(&nameplate, Gone::Expired, config);
        }

        self.gone.retain(|_, (_, until)| *until > now);
        self.windows
            .retain(|_, (start, _)| now.duration_since(*start) < Duration::from_secs(60));
    }

    /// The error for a slot that is not there
    fn missing(&self, nameplate: &str) -> ApiError {
        ApiError(match self.gone.get(nameplate) {
            Some((Gone::Used, _)) => ErrorCode::SlotUsed,
            Some((Gone::Expired, _)) => ErrorCode::SlotExpired,
            Some((Gone::Closed, _)) => ErrorCode::SlotClosed,
            None => ErrorCode::UnknownSlot,
        })
    }

    /// Count a request against the limit of its address
    fn allow(&mut self, address: AddressKey, kind: Limited, limit: u32) -> Result<(), ApiError> {
        let now = Instant::now();
        let window = self.windows.entry((address, kind)).or_insert((now, 0));

        if now.duration_since(window.0) >= Duration::from_secs(60) {
            *window = (now, 0);
        }
        if window.1 >= limit {
            return Err(ApiError(ErrorCode::RateLimited));
        }

        window.1 += 1;
        Ok(())
    }

    /// A random nameplate that is free. One that was not used recently if possible,
    /// so a late request for an ended slot does not meet a new one.
    fn free_nameplate(&self) -> Option<String> {
        let all = ALPHABET.iter().flat_map(|a| {
            ALPHABET
                .iter()
                .map(move |b| String::from_utf8_lossy(&[*a, *b]).into_owned())
        });
        let free: Vec<String> = all.filter(|n| !self.slots.contains_key(n)).collect();
        let fresh: Vec<&String> = free
            .iter()
            .filter(|n| !self.gone.contains_key(*n))
            .collect();

        let pick = |len: usize| random_u64().map(|r| (r % len as u64) as usize);
        if !fresh.is_empty() {
            return Some(fresh[pick(fresh.len())?].clone());
        }
        if !free.is_empty() {
            return Some(free[pick(free.len())?].clone());
        }
        None
    }
}

struct Shared {
    config: Config,
    inner: Mutex<Inner>,
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic while holding the lock leaves nothing half done that matters here
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.sweep(&self.config);
        inner
    }
}

/// An error answer
#[derive(Debug)]
struct ApiError(ErrorCode);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            ErrorCode::UnknownSlot => StatusCode::NOT_FOUND,
            ErrorCode::SlotUsed => StatusCode::CONFLICT,
            ErrorCode::SlotExpired | ErrorCode::SlotClosed => StatusCode::GONE,
            ErrorCode::Forbidden => StatusCode::FORBIDDEN,
            ErrorCode::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::NoFreeSlot => StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::BadRequest => StatusCode::BAD_REQUEST,
        };
        (status, Json(ErrorBody { error: self.0 })).into_response()
    }
}

fn random_u64() -> Option<u64> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).ok()?;
    Some(u64::from_le_bytes(bytes))
}

/// A token nobody can guess
fn new_token() -> Result<String, ApiError> {
    let mut bytes = [0u8; 16];
    // Without randomness there is no safe token, refuse rather than hand out a weak one
    getrandom::fill(&mut bytes).map_err(|_| ApiError(ErrorCode::NoFreeSlot))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// The token of a request
fn bearer(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ApiError(ErrorCode::Forbidden))
}

/// The address a request is counted against
fn client_address(shared: &Shared, peer: SocketAddr, headers: &HeaderMap) -> AddressKey {
    let forwarded = shared
        .config
        .behind_proxy
        .then(|| headers.get("x-forwarded-for"))
        .flatten()
        .and_then(|value| value.to_str().ok())
        // The last entry is the one the proxy itself added
        .and_then(|value| value.rsplit(',').next())
        .and_then(|ip| ip.trim().parse::<IpAddr>().ok());

    AddressKey::new(forwarded.unwrap_or(peer.ip()))
}

/// The message of a request body, checked for its size
fn message(body: Result<Json<Message>, JsonRejection>) -> Result<Vec<u8>, ApiError> {
    let Json(Message { message }) = body.map_err(|_| ApiError(ErrorCode::BadRequest))?;
    if message.len() > MAX_MESSAGE_BYTES {
        return Err(ApiError(ErrorCode::TooLarge));
    }
    Ok(message)
}

#[derive(Debug, Deserialize)]
struct Wait {
    /// Seconds to wait for the message
    #[serde(default)]
    wait: u64,
}

/// Tells a client that this is a rendezvous server, and which API it speaks
async fn info() -> Json<ServerInfo> {
    Json(ServerInfo {
        service: SERVICE_NAME.to_string(),
        api: API_VERSION,
    })
}

async fn create_slot(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Json<Message>, JsonRejection>,
) -> Result<(StatusCode, Json<SlotCreated>), ApiError> {
    let hello = message(body)?;
    let address = client_address(&shared, peer, &headers);
    let config = &shared.config;

    let mut inner = shared.lock();
    inner.allow(address, Limited::Create, config.creates_per_minute)?;

    let open = inner
        .slots
        .values()
        .filter(|s| s.creator == address)
        .count();
    if open >= config.slots_per_address {
        return Err(ApiError(ErrorCode::RateLimited));
    }

    let nameplate = inner
        .free_nameplate()
        .ok_or(ApiError(ErrorCode::NoFreeSlot))?;
    let token = new_token()?;

    inner.gone.remove(&nameplate);
    inner.slots.insert(
        nameplate.clone(),
        Slot {
            expires: Instant::now() + config.ttl,
            creator: address,
            sender_token: token.clone(),
            hello,
            receiver_token: None,
            reply: None,
            address: None,
            changed: Arc::new(Notify::new()),
        },
    );

    Ok((
        StatusCode::CREATED,
        Json(SlotCreated {
            nameplate,
            token,
            expires_in: config.ttl.as_secs(),
        }),
    ))
}

/// The first message of a slot. Free: it changes nothing and can be asked for again.
async fn get_slot(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(nameplate): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Message>, ApiError> {
    let address = client_address(&shared, peer, &headers);

    let mut inner = shared.lock();
    inner.allow(address, Limited::Look, shared.config.looks_per_minute)?;

    if !is_nameplate(&nameplate) {
        return Err(ApiError(ErrorCode::UnknownSlot));
    }
    let Some(slot) = inner.slots.get(&nameplate) else {
        return Err(inner.missing(&nameplate));
    };
    // Somebody else already answered, the code is spent
    if slot.reply.is_some() {
        return Err(ApiError(ErrorCode::SlotUsed));
    }

    Ok(Json(Message {
        message: slot.hello.clone(),
    }))
}

/// Who a token belongs to
#[derive(PartialEq)]
enum Party {
    Sender,
    Receiver,
}

/// Compare two tokens without stopping at the first difference, so the time it takes
/// says nothing about how much of a guessed token was right
fn same_token(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |difference, (x, y)| difference | (x ^ y))
            == 0
}

fn party(slot: &Slot, token: &str) -> Result<Party, ApiError> {
    let is_sender = same_token(&slot.sender_token, token);
    let is_receiver = slot
        .receiver_token
        .as_deref()
        .is_some_and(|receiver| same_token(receiver, token));

    if is_sender {
        Ok(Party::Sender)
    } else if is_receiver {
        Ok(Party::Receiver)
    } else {
        Err(ApiError(ErrorCode::Forbidden))
    }
}

async fn put_reply(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(nameplate): Path<String>,
    headers: HeaderMap,
    body: Result<Json<Message>, JsonRejection>,
) -> Result<Json<SlotReplied>, ApiError> {
    let reply = message(body)?;
    let address = client_address(&shared, peer, &headers);
    let config = &shared.config;

    let mut inner = shared.lock();
    inner.allow(address, Limited::Reply, config.replies_per_minute)?;

    if !is_nameplate(&nameplate) {
        return Err(ApiError(ErrorCode::UnknownSlot));
    }
    let Some(slot) = inner.slots.get_mut(&nameplate) else {
        return Err(inner.missing(&nameplate));
    };

    // One reply per slot. This is what limits guessing the code to one attempt.
    if slot.reply.is_some() {
        return Err(ApiError(ErrorCode::SlotUsed));
    }

    let token = new_token()?;
    slot.receiver_token = Some(token.clone());
    slot.reply = Some(reply);
    slot.expires = slot.expires.max(Instant::now() + config.reply_ttl);
    slot.changed.notify_waiters();

    Ok(Json(SlotReplied {
        token,
        expires_in: slot
            .expires
            .saturating_duration_since(Instant::now())
            .as_secs(),
    }))
}

async fn put_address(
    State(shared): State<Arc<Shared>>,
    Path(nameplate): Path<String>,
    headers: HeaderMap,
    body: Result<Json<Message>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let address = message(body)?;
    let token = bearer(&headers)?;

    let mut inner = shared.lock();
    let Some(slot) = inner.slots.get_mut(&nameplate) else {
        return Err(inner.missing(&nameplate));
    };
    if party(slot, token)? != Party::Sender {
        return Err(ApiError(ErrorCode::Forbidden));
    }
    // The address answers the reply, and is set once
    if slot.reply.is_none() || slot.address.is_some() {
        return Err(ApiError(ErrorCode::BadRequest));
    }

    slot.address = Some(address);
    slot.changed.notify_waiters();
    Ok(StatusCode::NO_CONTENT)
}

/// Wait until `ready` returns a message for the slot, or the time is up
async fn wait_for(
    shared: &Shared,
    nameplate: &str,
    wait: u64,
    mut ready: impl FnMut(&mut Inner) -> Result<Option<Vec<u8>>, ApiError>,
) -> Result<Response, ApiError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait.min(MAX_WAIT_SECS));

    loop {
        let changed = {
            let mut inner = shared.lock();
            if let Some(message) = ready(&mut inner)? {
                return Ok(Json(Message { message }).into_response());
            }
            match inner.slots.get(nameplate) {
                Some(slot) => slot.changed.clone(),
                None => return Err(inner.missing(nameplate)),
            }
        };

        // A change between the check above and here is not lost: the next round of the
        // loop checks again, at the latest when the short sleep below ends.
        tokio::select! {
            _ = changed.notified() => {}
            _ = tokio::time::sleep(Duration::from_millis(250)) => {}
            _ = tokio::time::sleep_until(deadline) => {
                return Ok(StatusCode::NO_CONTENT.into_response());
            }
        }
    }
}

async fn get_reply(
    State(shared): State<Arc<Shared>>,
    Path(nameplate): Path<String>,
    Query(Wait { wait }): Query<Wait>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let token = bearer(&headers)?.to_string();

    wait_for(&shared, &nameplate, wait, |inner| {
        let Some(slot) = inner.slots.get(&nameplate) else {
            return Err(inner.missing(&nameplate));
        };
        if party(slot, &token)? != Party::Sender {
            return Err(ApiError(ErrorCode::Forbidden));
        }
        Ok(slot.reply.clone())
    })
    .await
}

async fn get_address(
    State(shared): State<Arc<Shared>>,
    Path(nameplate): Path<String>,
    Query(Wait { wait }): Query<Wait>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let token = bearer(&headers)?.to_string();
    let config = shared.config.clone();

    wait_for(&shared, &nameplate, wait, |inner| {
        let Some(slot) = inner.slots.get(&nameplate) else {
            return Err(inner.missing(&nameplate));
        };
        if party(slot, &token)? != Party::Receiver {
            return Err(ApiError(ErrorCode::Forbidden));
        }
        let Some(address) = slot.address.clone() else {
            return Ok(None);
        };

        // Delivered: the slot has done its job
        inner.end(&nameplate, Gone::Used, &config);
        Ok(Some(address))
    })
    .await
}

async fn delete_slot(
    State(shared): State<Arc<Shared>>,
    Path(nameplate): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let token = bearer(&headers)?;

    let mut inner = shared.lock();
    let Some(slot) = inner.slots.get(&nameplate) else {
        // Already gone is what the caller wanted
        return Ok(StatusCode::NO_CONTENT);
    };
    party(slot, token)?;

    inner.end(&nameplate, Gone::Closed, &shared.config);
    Ok(StatusCode::NO_CONTENT)
}

/// The routes of the server
fn router(shared: Arc<Shared>) -> Router {
    Router::new()
        .route("/v1", get(info))
        .route("/v1/slots", post(create_slot))
        .route("/v1/slots/{nameplate}", get(get_slot).delete(delete_slot))
        .route("/v1/slots/{nameplate}/reply", get(get_reply).put(put_reply))
        .route(
            "/v1/slots/{nameplate}/address",
            get(get_address).put(put_address),
        )
        // Base64 and JSON around the largest message, with room to spare
        .layer(DefaultBodyLimit::max(MAX_MESSAGE_BYTES * 2))
        .with_state(shared)
}

/// Serve on `listener` until `shutdown` completes
pub async fn serve(
    listener: tokio::net::TcpListener,
    config: Config,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    debug_assert_eq!(
        NAMEPLATE_LEN, 2,
        "free_nameplate builds two character names"
    );

    let shared = Arc::new(Shared {
        config,
        inner: Mutex::new(Inner::default()),
    });

    // Slots also expire while nobody asks for them, so waiting requests get an answer
    let sweeper = tokio::spawn({
        let shared = shared.clone();
        async move {
            loop {
                tokio::time::sleep(Duration::from_millis(250)).await;
                drop(shared.lock());
            }
        }
    });

    let result = axum::serve(
        listener,
        router(shared).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await;

    sweeper.abort();
    result
}

#[cfg(test)]
mod tests {
    use super::same_token;

    #[test]
    fn tokens_are_compared_in_full() {
        assert!(same_token("0123abcd", "0123abcd"));
        assert!(!same_token("0123abcd", "0123abce"));
        assert!(!same_token("0123abcd", "1123abcd"));
        assert!(!same_token("0123abcd", "0123abc"));
        assert!(!same_token("", "0"));
        assert!(same_token("", ""));
    }
}
