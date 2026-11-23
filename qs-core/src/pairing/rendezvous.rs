//! Client side of the rendezvous protocol.
//!
//! The rendezvous server is an untrusted mailbox. It sees a slot name, a few
//! opaque messages and the IP addresses of the clients, and can deny service, nothing
//! else. The server lives in the `qs-rendezvous` crate, the wire format in
//! `qs-rendezvous-api`.
//!
//! Messages through one slot (a PAKE needs both sides before a key exists, so a
//! single upload is not enough):
//! 1. sender to server: its PAKE message and a KEM key
//! 2. receiver fetches that message (free, as often as it likes) and sends its PAKE
//!    message, the KEM ciphertext and its sealed id. A slot takes one such reply.
//! 3. sender to server: its sealed address, the receiver fetches it
//!
//! DONE: the wire format has a version in its path (`/v1`) and in the answer of the
//!       server to `GET /v1`, and lives in a small crate that client and server share.
//!       [Client::check] asks a server what it is before it is used.
//! DONE: HTTP client for the calls: create slot, look, reply, fetch, delete. It is the
//!       `reqwest` that iroh already uses, with TLS through the crypto provider of the
//!       endpoint, so it builds for static musl and Windows like the rest.
//! DONE: one reply per slot is enforced by the server and tested there and in
//!       `tests/pairing.rs` from the client side. Looking at a slot spends nothing.
//! DONE: a server that answers "nothing yet" at once is not asked again right away
//!       ([MIN_POLL_INTERVAL]), so it cannot make the client spin.
//! DONE: errors are told apart: wrong code, expired, already used, server unreachable,
//!       not a rendezvous server or another protocol version (see `super::PairingError`).
//! DONE: both sides delete the slot when a pairing fails ([Client::delete]).
//! DONE: redirects are not followed, and a server reached over plain `http` is pointed out
//!       ([Client::is_unprotected]).
//! DONE: timeouts for every request, an answer larger than expected is refused, and a
//!       slot can be given up from outside (`super::SlotHandle`), which the CLI does on
//!       Ctrl+C.

use qs_rendezvous_api::{
    address_path, reply_path, slot_path, ErrorBody, ErrorCode, Message, ServerInfo, SlotCreated,
    SlotReplied, API_VERSION, INFO_PATH, MAX_WAIT_SECS, SERVICE_NAME, SLOTS_PATH,
};
use reqwest::{RequestBuilder, StatusCode};
use serde::de::DeserializeOwned;
use std::time::{Duration, Instant};

/// How long a request may take that does not wait for the other peer
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// How long to wait for a connection to the server
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// A server may answer "nothing yet" before the wait is over. It is then not asked again
/// sooner than this.
const MIN_POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Largest answer the client reads. A message is at most 16 KiB before base64.
const MAX_ANSWER_BYTES: usize = 64 * 1024;

/// What can go wrong with a request, before it is put into words for the user
#[derive(Debug, PartialEq)]
pub(crate) enum ClientError {
    /// The server refused the request
    Api(ErrorCode),
    /// No answer from the server
    Unreachable(String),
    /// An answer that is not from a rendezvous server of this version
    Protocol(String),
    /// The url is not usable
    InvalidUrl,
}

/// Talks to one rendezvous server
#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
    /// Base url without a trailing slash
    base: String,
}

impl Client {
    /// A client for the server at `url`.
    ///
    /// `tls` is the TLS configuration for `https` urls, `Endpoint::tls_config` has one
    /// with the crypto provider of the endpoint.
    pub fn new(url: &str, tls: rustls::ClientConfig) -> Result<Self, super::PairingError> {
        Self::build(url, tls).map_err(|e| super::PairingError::from_client(e, url))
    }

    fn build(url: &str, tls: rustls::ClientConfig) -> Result<Self, ClientError> {
        let base = url.trim().trim_end_matches('/').to_string();

        let parsed = reqwest::Url::parse(&base).map_err(|_| ClientError::InvalidUrl)?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
            return Err(ClientError::InvalidUrl);
        }

        let http = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .user_agent(concat!("quic-send/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(CONNECT_TIMEOUT)
            // The server is not trusted to send this client anywhere else
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| ClientError::Protocol(e.to_string()))?;

        Ok(Self { http, base })
    }

    /// The url of the server
    pub fn url(&self) -> &str {
        &self.base
    }

    /// Whether the server is reached without TLS over a network.
    ///
    /// What is exchanged stays sealed either way, but without TLS anyone on the way sees
    /// the slot tokens and can disturb the pairing.
    pub fn is_unprotected(&self) -> bool {
        let Ok(url) = reqwest::Url::parse(&self.base) else {
            return false;
        };
        let local = match url.host_str() {
            Some("localhost") => true,
            Some(host) => host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback()),
            None => false,
        };
        url.scheme() == "http" && !local
    }

    fn url_for(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// Create a slot that holds the first message of the sender
    pub(crate) async fn create(&self, message: &[u8]) -> Result<SlotCreated, ClientError> {
        let request = self.http.post(self.url_for(SLOTS_PATH)).json(&Message {
            message: message.to_vec(),
        });
        expect_body(send(request, REQUEST_TIMEOUT).await?)
    }

    /// Ask the server what it is, and fail unless it is a rendezvous server that speaks
    /// the version of the API this client does
    pub(crate) async fn check(&self) -> Result<(), ClientError> {
        let request = self.http.get(self.url_for(INFO_PATH));
        let info: ServerInfo = expect_body(send(request, REQUEST_TIMEOUT).await?)?;

        if info.service != SERVICE_NAME {
            return Err(ClientError::Protocol(
                "this is not a quic-send rendezvous server".to_string(),
            ));
        }
        if info.api != API_VERSION {
            return Err(ClientError::Protocol(format!(
                "the server speaks version {} of the rendezvous protocol, this program \
                 version {API_VERSION}",
                info.api
            )));
        }
        Ok(())
    }

    /// The first message of a slot. Spends nothing, a slot can be looked at any number
    /// of times.
    pub(crate) async fn look(&self, nameplate: &str) -> Result<Vec<u8>, ClientError> {
        let request = self.http.get(self.url_for(&slot_path(nameplate)));
        let message: Message = expect_body(send(request, REQUEST_TIMEOUT).await?)?;
        Ok(message.message)
    }

    /// Store the reply of the receiver. Works once per slot, this is what spends a code.
    pub(crate) async fn put_reply(
        &self,
        nameplate: &str,
        message: &[u8],
    ) -> Result<SlotReplied, ClientError> {
        let request = self
            .http
            .put(self.url_for(&reply_path(nameplate)))
            .json(&Message {
                message: message.to_vec(),
            });
        expect_body(send(request, REQUEST_TIMEOUT).await?)
    }

    /// Store the sealed address of the sender
    pub(crate) async fn put_address(
        &self,
        nameplate: &str,
        token: &str,
        message: &[u8],
    ) -> Result<(), ClientError> {
        let request = self
            .http
            .put(self.url_for(&address_path(nameplate)))
            .bearer_auth(token)
            .json(&Message {
                message: message.to_vec(),
            });
        send::<serde::de::IgnoredAny>(request, REQUEST_TIMEOUT)
            .await
            .map(|_| ())
    }

    /// Wait a while for the reply of the receiver. [None] means: not yet, ask again.
    pub(crate) async fn poll_reply(
        &self,
        nameplate: &str,
        token: &str,
    ) -> Result<Option<Vec<u8>>, ClientError> {
        self.poll(&reply_path(nameplate), token).await
    }

    /// Wait a while for the address of the sender. [None] means: not yet, ask again.
    pub(crate) async fn poll_address(
        &self,
        nameplate: &str,
        token: &str,
    ) -> Result<Option<Vec<u8>>, ClientError> {
        self.poll(&address_path(nameplate), token).await
    }

    /// Give up a slot. Best effort: if the server cannot be reached the slot expires.
    pub(crate) async fn delete(&self, nameplate: &str, token: &str) {
        let request = self
            .http
            .delete(self.url_for(&slot_path(nameplate)))
            .bearer_auth(token);
        if let Err(e) = send::<serde::de::IgnoredAny>(request, REQUEST_TIMEOUT).await {
            tracing::debug!("could not delete the slot: {e:?}");
        }
    }

    async fn poll(&self, path: &str, token: &str) -> Result<Option<Vec<u8>>, ClientError> {
        let url = format!("{}?wait={MAX_WAIT_SECS}", self.url_for(path));
        let request = self.http.get(url).bearer_auth(token);
        // The server answers after the wait at the latest, give it some room on top
        let timeout = Duration::from_secs(MAX_WAIT_SECS) + REQUEST_TIMEOUT;

        let asked = Instant::now();
        let message = send::<Message>(request, timeout).await?;

        // Nothing yet, and the server did not wait: do that here instead
        if message.is_none() {
            if let Some(rest) = MIN_POLL_INTERVAL.checked_sub(asked.elapsed()) {
                tokio::time::sleep(rest).await;
            }
        }

        Ok(message.map(|message| message.message))
    }
}

fn expect_body<T>(body: Option<T>) -> Result<T, ClientError> {
    body.ok_or_else(|| ClientError::Protocol("the server sent an empty answer".to_string()))
}

/// Send a request. Returns the decoded body, or [None] for an answer without one.
async fn send<T: DeserializeOwned>(
    request: RequestBuilder,
    timeout: Duration,
) -> Result<Option<T>, ClientError> {
    let mut response = request
        .timeout(timeout)
        .send()
        .await
        .map_err(|e| ClientError::Unreachable(root_cause(&e)))?;
    let status = response.status();

    // Read the body with a limit, the server is not trusted to keep it small
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| ClientError::Unreachable(root_cause(&e)))?
    {
        if body.len() + chunk.len() > MAX_ANSWER_BYTES {
            return Err(ClientError::Protocol(
                "the server sent an answer that is too large".to_string(),
            ));
        }
        body.extend_from_slice(&chunk);
    }

    if status.is_success() {
        if status == StatusCode::NO_CONTENT || body.is_empty() {
            return Ok(None);
        }
        return serde_json::from_slice(&body).map(Some).map_err(|_| {
            ClientError::Protocol("the server sent an answer that cannot be read".to_string())
        });
    }

    match serde_json::from_slice::<ErrorBody>(&body) {
        Ok(error) => Err(ClientError::Api(error.error)),
        Err(_) => Err(ClientError::Protocol(format!(
            "unexpected answer (HTTP {})",
            status.as_u16()
        ))),
    }
}

/// The innermost cause of an error, which is the part that helps: "connection refused"
/// instead of "error sending request"
fn root_cause(error: &dyn std::error::Error) -> String {
    let mut cause = error;
    while let Some(source) = cause.source() {
        cause = source;
    }
    cause.to_string()
}
