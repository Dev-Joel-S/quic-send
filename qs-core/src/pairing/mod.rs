//! Pairing of two peers with a short code.
//!
//! The sender shows a short code, the receiver types it, and both end up knowing each
//! other's `EndpointId` without any third party being trusted.
//! Everything in here is independent of the CLI, so another frontend can reuse it.
//!
//! Flow, see the submodules for the details of each step:
//! 1. the sender creates a slot on the rendezvous server and gets a nameplate. Together
//!    with a secret it made up, that is the code ([code]).
//! 2. both sides run a PAKE with the secret and an ML-KEM exchange, and derive the same
//!    keys from both ([pake], [seal])
//! 3. the receiver's id and the sender's address are exchanged through the rendezvous
//!    server, sealed with those keys, so the server only ever sees opaque blobs
//!    ([rendezvous])
//! 4. the receiver connects with iroh to the sender's id, and the sender only accepts the
//!    receiver's id (`send::SenderArgs::expected_peer`). Both ids are pinned by the code.
//!
//! DONE: [PairingError] tells wrong code, expired, already used, unknown and server
//!       unreachable apart.
//! DONE: the result of a pairing is the `EndpointId` of the receiver for the sender
//!       ([Offer::wait_for_receiver]) and the `EndpointAddr` of the sender for the receiver
//!       ([Claim::complete]). No session key is handed on: the QUIC connection between the
//!       two pinned ids does the rest, with its own post-quantum key exchange.
//! DONE: the receiver learns from the first message whether the sender set a password
//!       ([Claim::password_required]), so it can ask for one before the code is spent.

pub mod code;
pub mod pake;
pub mod rendezvous;
pub mod seal;

use code::{Code, CodeError};
use iroh::{EndpointAddr, EndpointId};
use pake::{password_input, Pake, Side};
use qs_rendezvous_api::ErrorCode;
use rendezvous::{Client, ClientError};
use seal::{encapsulate, transcript, Direction, KemKey, SealError, SessionKeys};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use thiserror::Error;

/// What the PAKE of a pairing is for, also the version of the pairing
const CONTEXT: &[u8] = b"quic-send pairing v1";
/// Version of the messages below
const VERSION: u8 = 1;
/// How long a sender waits for a receiver at most, whatever the server says
const SENDER_PATIENCE: Duration = Duration::from_secs(60 * 60);
/// How long a receiver waits for the sender's answer at most
const RECEIVER_PATIENCE: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Error, PartialEq)]
pub enum PairingError {
    #[error("{0}")]
    Code(#[from] CodeError),
    #[error("wrong code or password. The code is used up now, the sender has to start again")]
    WrongCode,
    #[error(
        "the sender did not accept the code or password. \
         The code is used up now, the sender has to start again"
    )]
    Rejected,
    #[error(
        "the receiver entered a wrong code or password. \
         The code is used up now, start again to get a new one"
    )]
    ReceiverWrongCode,
    #[error("this code has expired, ask the sender for a new one")]
    Expired,
    #[error("this code was already used or the sender gave up, ask the sender for a new one")]
    Used,
    #[error(
        "no transfer is waiting under this code. \
         Check the first two characters, the code may also have expired"
    )]
    Unknown,
    #[error("nobody entered the code in time")]
    NotClaimed,
    #[error("the sender did not answer in time")]
    SenderGone,
    #[error("the rendezvous server {url} cannot be reached: {reason}")]
    Unreachable { url: String, reason: String },
    #[error(
        "the rendezvous server {url} answered in a way this version does not understand: \
         {message}"
    )]
    Protocol { url: String, message: String },
    #[error("the rendezvous server is busy, try again in a moment")]
    Busy,
    #[error("{0:?} is not a valid rendezvous url, it has to start with http:// or https://")]
    InvalidUrl(String),
    #[error("the sender protected this transfer with a password, but none was given")]
    PasswordRequired,
    #[error("a password was given, but the sender did not set one")]
    UnexpectedPassword,
    #[error("the other side uses a version of quic-send that pairs differently")]
    Version,
    #[error("the pairing failed: {0}")]
    Crypto(#[from] SealError),
}

/// What a request was for, which decides what a refusal means
#[derive(Clone, Copy, PartialEq)]
enum Stage {
    Creating,
    WaitingForReceiver,
    Claiming,
    WaitingForSender,
}

impl PairingError {
    /// An error for which the stage does not matter
    pub(crate) fn from_client(error: ClientError, url: &str) -> Self {
        Self::at(Stage::Creating, error, url)
    }

    fn at(stage: Stage, error: ClientError, url: &str) -> Self {
        let protocol = |message: String| Self::Protocol {
            url: url.to_string(),
            message,
        };

        match error {
            ClientError::Unreachable(reason) => Self::Unreachable {
                url: url.to_string(),
                reason,
            },
            ClientError::InvalidUrl => Self::InvalidUrl(url.to_string()),
            ClientError::Protocol(message) => protocol(message),
            ClientError::Api(ErrorCode::NoFreeSlot | ErrorCode::RateLimited) => Self::Busy,
            ClientError::Api(code) => match (stage, code) {
                (Stage::Claiming, ErrorCode::UnknownSlot) => Self::Unknown,
                (Stage::Claiming, ErrorCode::SlotExpired) => Self::Expired,
                (Stage::Claiming, ErrorCode::SlotUsed | ErrorCode::SlotClosed) => Self::Used,
                (Stage::WaitingForReceiver, ErrorCode::SlotExpired) => Self::NotClaimed,
                (Stage::WaitingForSender, ErrorCode::SlotClosed) => Self::Rejected,
                (Stage::WaitingForSender, ErrorCode::SlotExpired) => Self::SenderGone,
                (_, code) => protocol(format!("{code:?}")),
            },
        }
    }
}

/// First message, from the sender. Not secret, but covered by the transcript.
#[derive(Serialize, Deserialize)]
struct Hello {
    version: u8,
    /// Whether the sender mixed a password into the PAKE
    password: bool,
    pake: Vec<u8>,
    kem_key: Vec<u8>,
}

/// Second message, from the receiver
#[derive(Serialize, Deserialize)]
struct Reply {
    pake: Vec<u8>,
    kem_ciphertext: Vec<u8>,
    /// [ReceiverInfo], sealed for the sender
    sealed: Vec<u8>,
}

/// What the receiver tells the sender
#[derive(Serialize, Deserialize)]
struct ReceiverInfo {
    id: EndpointId,
}

/// What the sender tells the receiver, sealed, as the third message
#[derive(Serialize, Deserialize)]
struct SenderInfo {
    addr: EndpointAddr,
}

fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    // Serializing these plain structs into a Vec cannot fail
    postcard::to_stdvec(value).unwrap_or_default()
}

/// Everything both sides must agree on before any key is good for anything
fn pairing_transcript(nameplate: &str, hello: &[u8], reply: &Reply) -> [u8; 32] {
    transcript(&[
        CONTEXT,
        nameplate.as_bytes(),
        hello,
        &reply.pake,
        &reply.kem_ciphertext,
    ])
}

/// Sender, step one: start the exchange. Returns the state to keep and the first message.
fn sender_hello(
    secret: &str,
    password: Option<&str>,
) -> Result<(Pake, KemKey, Vec<u8>), SealError> {
    let (pake, pake_message) =
        Pake::start(Side::Sender, CONTEXT, &password_input(secret, password));
    let (kem, kem_key) = KemKey::generate()?;

    let hello = encode(&Hello {
        version: VERSION,
        password: password.is_some(),
        pake: pake_message,
        kem_key,
    });

    Ok((pake, kem, hello))
}

/// Receiver: answer the first message. Returns the keys to keep and the reply.
fn receiver_reply(
    code: &Code,
    password: Option<&str>,
    hello_bytes: &[u8],
    own_id: EndpointId,
) -> Result<(SessionKeys, Vec<u8>), PairingError> {
    let hello: Hello = postcard::from_bytes(hello_bytes).map_err(|_| PairingError::Version)?;
    if hello.version != VERSION {
        return Err(PairingError::Version);
    }
    match (hello.password, password) {
        (true, None) => return Err(PairingError::PasswordRequired),
        (false, Some(_)) => return Err(PairingError::UnexpectedPassword),
        _ => {}
    }

    let (pake, pake_message) = Pake::start(
        Side::Receiver,
        CONTEXT,
        &password_input(code.secret(), password),
    );
    // A first message that is not a valid PAKE message or KEM key did not come from
    // an honest sender. Nothing was revealed, the attempt is simply over.
    let pake_key = pake
        .finish(&hello.pake)
        .map_err(|_| PairingError::WrongCode)?;
    let (kem_ciphertext, kem_secret) =
        encapsulate(&hello.kem_key).map_err(|_| PairingError::WrongCode)?;

    let mut reply = Reply {
        pake: pake_message,
        kem_ciphertext,
        sealed: Vec::new(),
    };
    let transcript = pairing_transcript(code.nameplate(), hello_bytes, &reply);
    let keys = SessionKeys::derive(&pake_key, &kem_secret, &transcript)?;
    reply.sealed = keys.seal(Direction::ToSender, &encode(&ReceiverInfo { id: own_id }))?;

    Ok((keys, encode(&reply)))
}

/// Sender, step two: check the reply. Returns the receiver's id and the sealed address.
fn sender_finish(
    pake: Pake,
    kem: &KemKey,
    nameplate: &str,
    hello_bytes: &[u8],
    reply_bytes: &[u8],
    own_addr: &EndpointAddr,
) -> Result<(EndpointId, Vec<u8>), PairingError> {
    // Whatever is wrong with the reply, the one attempt this code had is spent
    let wrong = |_| PairingError::ReceiverWrongCode;

    let reply: Reply = postcard::from_bytes(reply_bytes).map_err(|_| wrong(()))?;
    let pake_key = pake.finish(&reply.pake).map_err(|_| wrong(()))?;
    let kem_secret = kem
        .decapsulate(&reply.kem_ciphertext)
        .map_err(|_| wrong(()))?;

    let transcript = pairing_transcript(nameplate, hello_bytes, &reply);
    let keys = SessionKeys::derive(&pake_key, &kem_secret, &transcript)?;

    let info = keys
        .open(Direction::ToSender, &reply.sealed)
        .map_err(|_| wrong(()))?;
    let info: ReceiverInfo = postcard::from_bytes(&info).map_err(|_| wrong(()))?;

    let sealed = keys.seal(
        Direction::ToReceiver,
        &encode(&SenderInfo {
            addr: own_addr.clone(),
        }),
    )?;

    Ok((info.id, sealed))
}

/// Receiver, last step: open the sender's address
fn receiver_finish(keys: &SessionKeys, sealed: &[u8]) -> Result<EndpointAddr, PairingError> {
    let info = keys
        .open(Direction::ToReceiver, sealed)
        .map_err(|_| PairingError::WrongCode)?;
    let info: SenderInfo = postcard::from_bytes(&info).map_err(|_| PairingError::WrongCode)?;
    Ok(info.addr)
}

/// A slot that can be given up, for example when the user presses Ctrl+C while waiting
#[derive(Debug, Clone)]
pub struct SlotHandle {
    client: Client,
    nameplate: String,
    token: String,
}

impl SlotHandle {
    /// Give up the slot. The other side is told that the code is no longer valid.
    pub async fn cancel(&self) {
        self.client.delete(&self.nameplate, &self.token).await;
    }
}

/// The sender's side of a pairing: a code that waits for its receiver
pub struct Offer {
    client: Client,
    code: Code,
    token: String,
    pake: Pake,
    kem: KemKey,
    hello: Vec<u8>,
}

impl Offer {
    /// Create a slot on the rendezvous server and make up a code for it.
    ///
    /// With a `password`, the receiver needs it in addition to the code.
    pub async fn create(client: &Client, password: Option<&str>) -> Result<Self, PairingError> {
        let secret = Code::generate_secret()?;
        let (pake, kem, hello) = sender_hello(&secret, password)?;

        let created = client
            .create(&hello)
            .await
            .map_err(|e| PairingError::at(Stage::Creating, e, client.url()))?;

        // The nameplate comes from the server and is checked like any other input
        let code = Code::new(&created.nameplate, secret).map_err(|_| PairingError::Protocol {
            url: client.url().to_string(),
            message: "the server handed out an invalid slot name".to_string(),
        })?;

        Ok(Self {
            client: client.clone(),
            code,
            token: created.token,
            pake,
            kem,
            hello,
        })
    }

    /// The code to show to the user
    pub fn code(&self) -> &Code {
        &self.code
    }

    /// A handle to give up the slot from elsewhere
    pub fn handle(&self) -> SlotHandle {
        SlotHandle {
            client: self.client.clone(),
            nameplate: self.code.nameplate().to_string(),
            token: self.token.clone(),
        }
    }

    /// Wait until a receiver used the code, check that it really knew the code, and
    /// tell it `own_addr`. Returns the id of the receiver, the only peer that may connect.
    pub async fn wait_for_receiver(
        self,
        own_addr: &EndpointAddr,
    ) -> Result<EndpointId, PairingError> {
        let nameplate = self.code.nameplate();
        let url = self.client.url();
        let deadline = Instant::now() + SENDER_PATIENCE;

        let reply = loop {
            match self.client.poll_reply(nameplate, &self.token).await {
                Ok(Some(reply)) => break reply,
                Ok(None) if Instant::now() < deadline => continue,
                Ok(None) => {
                    self.client.delete(nameplate, &self.token).await;
                    return Err(PairingError::NotClaimed);
                }
                Err(e) => return Err(PairingError::at(Stage::WaitingForReceiver, e, url)),
            }
        };

        match sender_finish(
            self.pake,
            &self.kem,
            nameplate,
            &self.hello,
            &reply,
            own_addr,
        ) {
            Ok((peer, sealed)) => {
                self.client
                    .put_address(nameplate, &self.token, &sealed)
                    .await
                    .map_err(|e| PairingError::at(Stage::WaitingForReceiver, e, url))?;
                Ok(peer)
            }
            Err(e) => {
                // One attempt per code: the slot is closed, the receiver is told
                self.client.delete(nameplate, &self.token).await;
                Err(e)
            }
        }
    }
}

/// The receiver's side of a pairing: a slot that was claimed with a code
pub struct Claim {
    client: Client,
    code: Code,
    token: String,
    hello: Vec<u8>,
    password_required: bool,
}

impl Claim {
    /// Claim the slot of `code`. This spends the code: a slot can be claimed once.
    pub async fn new(client: &Client, code: Code) -> Result<Self, PairingError> {
        let claimed = client
            .claim(code.nameplate())
            .await
            .map_err(|e| PairingError::at(Stage::Claiming, e, client.url()))?;

        let claim = Self {
            client: client.clone(),
            code,
            token: claimed.token,
            hello: claimed.message,
            password_required: false,
        };

        match postcard::from_bytes::<Hello>(&claim.hello) {
            Ok(hello) if hello.version == VERSION => Ok(Self {
                password_required: hello.password,
                ..claim
            }),
            _ => {
                claim.handle().cancel().await;
                Err(PairingError::Version)
            }
        }
    }

    /// Whether the sender set a password. Ask the user for it before [Claim::complete].
    pub fn password_required(&self) -> bool {
        self.password_required
    }

    /// A handle to give up the slot from elsewhere
    pub fn handle(&self) -> SlotHandle {
        SlotHandle {
            client: self.client.clone(),
            nameplate: self.code.nameplate().to_string(),
            token: self.token.clone(),
        }
    }

    /// Finish the pairing: prove knowledge of the code, tell the sender `own_id` and get
    /// its address. Only the endpoint with `own_id` will be let in by the sender.
    pub async fn complete(
        self,
        password: Option<&str>,
        own_id: EndpointId,
    ) -> Result<EndpointAddr, PairingError> {
        let nameplate = self.code.nameplate();
        let url = self.client.url();
        let at = |e| PairingError::at(Stage::WaitingForSender, e, url);

        let (keys, reply) = match receiver_reply(&self.code, password, &self.hello, own_id) {
            Ok(result) => result,
            Err(e) => {
                self.client.delete(nameplate, &self.token).await;
                return Err(e);
            }
        };

        self.client
            .put_reply(nameplate, &self.token, &reply)
            .await
            .map_err(at)?;

        let deadline = Instant::now() + RECEIVER_PATIENCE;
        let sealed = loop {
            match self.client.poll_address(nameplate, &self.token).await {
                Ok(Some(sealed)) => break sealed,
                Ok(None) if Instant::now() < deadline => continue,
                Ok(None) => {
                    self.client.delete(nameplate, &self.token).await;
                    return Err(PairingError::SenderGone);
                }
                Err(e) => return Err(at(e)),
            }
        };

        // The slot is already gone on the server once the address was fetched
        receiver_finish(&keys, &sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;
    use pretty_assertions::assert_eq;
    use zeroize::Zeroizing;

    fn id() -> EndpointId {
        SecretKey::generate().public()
    }

    fn addr() -> EndpointAddr {
        EndpointAddr::new(id()).with_ip_addr("192.168.1.5:4433".parse().unwrap())
    }

    fn code(text: &str) -> Code {
        text.parse().unwrap()
    }

    /// Run a whole pairing without a server. Returns what each side ends up with.
    fn pair(
        sender_code: &str,
        sender_password: Option<&str>,
        receiver_code: &str,
        receiver_password: Option<&str>,
    ) -> (
        Result<EndpointId, PairingError>,
        Result<EndpointAddr, PairingError>,
        EndpointId,
        EndpointAddr,
    ) {
        let sender_code = code(sender_code);
        let receiver_id = id();
        let sender_addr = addr();

        let (pake, kem, hello) = sender_hello(sender_code.secret(), sender_password).unwrap();
        let reply = receiver_reply(&code(receiver_code), receiver_password, &hello, receiver_id);
        let (keys, reply) = match reply {
            Ok(reply) => reply,
            Err(e) => {
                return (
                    Err(PairingError::NotClaimed),
                    Err(e),
                    receiver_id,
                    sender_addr,
                )
            }
        };

        let finished = sender_finish(
            pake,
            &kem,
            sender_code.nameplate(),
            &hello,
            &reply,
            &sender_addr,
        );
        match finished {
            Ok((peer, sealed)) => (
                Ok(peer),
                receiver_finish(&keys, &sealed),
                receiver_id,
                sender_addr,
            ),
            Err(e) => (
                Err(e),
                Err(PairingError::Rejected),
                receiver_id,
                sender_addr,
            ),
        }
    }

    #[test]
    fn right_code_pairs() {
        let (sender, receiver, receiver_id, sender_addr) =
            pair("K7X4-M2QP", None, "k7x4m2qp", None);
        assert_eq!(sender, Ok(receiver_id));
        assert_eq!(receiver, Ok(sender_addr));
    }

    #[test]
    fn wrong_secret_is_rejected_by_the_sender() {
        let (sender, _, _, _) = pair("K7X4-M2QP", None, "K7X4-M2QQ", None);
        assert_eq!(sender, Err(PairingError::ReceiverWrongCode));
    }

    #[test]
    fn right_secret_under_another_nameplate_is_rejected() {
        // The same secret reused in another slot must not open this one
        let (sender, _, _, _) = pair("K7X4-M2QP", None, "K8X4-M2QP", None);
        assert_eq!(sender, Err(PairingError::ReceiverWrongCode));
    }

    #[test]
    fn password_is_needed_in_addition_to_the_code() {
        let (sender, receiver, receiver_id, sender_addr) =
            pair("K7X4-M2QP", Some("hunter2"), "K7X4-M2QP", Some("hunter2"));
        assert_eq!(sender, Ok(receiver_id));
        assert_eq!(receiver, Ok(sender_addr));

        let (sender, _, _, _) = pair("K7X4-M2QP", Some("hunter2"), "K7X4-M2QP", Some("hunter3"));
        assert_eq!(sender, Err(PairingError::ReceiverWrongCode));
    }

    #[test]
    fn receiver_is_told_about_a_missing_or_surplus_password() {
        let (_, receiver, _, _) = pair("K7X4-M2QP", Some("hunter2"), "K7X4-M2QP", None);
        assert_eq!(receiver, Err(PairingError::PasswordRequired));

        let (_, receiver, _, _) = pair("K7X4-M2QP", None, "K7X4-M2QP", Some("hunter2"));
        assert_eq!(receiver, Err(PairingError::UnexpectedPassword));
    }

    #[test]
    fn sealed_address_cannot_be_opened_with_a_wrong_code() {
        // A receiver with a wrong code that somehow gets hold of the sealed address of a
        // pairing that went well cannot open it
        let right = code("K7X4-M2QP");
        let (pake, kem, hello) = sender_hello(right.secret(), None).unwrap();
        let (_, reply) = receiver_reply(&right, None, &hello, id()).unwrap();
        let (_, sealed) =
            sender_finish(pake, &kem, right.nameplate(), &hello, &reply, &addr()).unwrap();

        let (wrong_keys, _) = receiver_reply(&code("K7X4-M2QQ"), None, &hello, id()).unwrap();
        assert_eq!(
            receiver_finish(&wrong_keys, &sealed),
            Err(PairingError::WrongCode)
        );
    }

    #[test]
    fn server_cannot_swap_the_kem_key_or_the_password_flag() {
        let right = code("K7X4-M2QP");
        let (pake, kem, hello) = sender_hello(right.secret(), None).unwrap();

        // The server replaces the KEM key in the first message with its own
        let (_, own_key) = KemKey::generate().unwrap();
        let mut decoded: Hello = postcard::from_bytes(&hello).unwrap();
        decoded.kem_key = own_key;
        let forged = encode(&decoded);

        let (_, reply) = receiver_reply(&right, None, &forged, id()).unwrap();
        let finished = sender_finish(pake, &kem, right.nameplate(), &hello, &reply, &addr());
        assert_eq!(finished.err(), Some(PairingError::ReceiverWrongCode));

        // The server claims there is no password although the sender set one
        let (pake, kem, hello) = sender_hello(right.secret(), Some("hunter2")).unwrap();
        let mut decoded: Hello = postcard::from_bytes(&hello).unwrap();
        decoded.password = false;
        let forged = encode(&decoded);

        let (_, reply) = receiver_reply(&right, None, &forged, id()).unwrap();
        let finished = sender_finish(pake, &kem, right.nameplate(), &hello, &reply, &addr());
        assert_eq!(finished.err(), Some(PairingError::ReceiverWrongCode));
    }

    #[test]
    fn garbage_messages_are_errors_not_panics() {
        let right = code("K7X4-M2QP");
        for garbage in [&b""[..], b"hello", &[0xff; 2000]] {
            assert!(receiver_reply(&right, None, garbage, id()).is_err());

            let (pake, kem, hello) = sender_hello(right.secret(), None).unwrap();
            let finished = sender_finish(pake, &kem, right.nameplate(), &hello, garbage, &addr());
            assert_eq!(finished.err(), Some(PairingError::ReceiverWrongCode));
        }
    }

    #[test]
    fn other_version_is_reported() {
        let hello = encode(&Hello {
            version: VERSION + 1,
            password: false,
            pake: vec![],
            kem_key: vec![],
        });
        let result = receiver_reply(&code("K7X4-M2QP"), None, &hello, id());
        assert_eq!(result.err(), Some(PairingError::Version));
    }

    #[test]
    fn refusals_are_put_into_the_right_words() {
        let at = |stage, code| PairingError::at(stage, ClientError::Api(code), "http://rz");

        assert_eq!(
            at(Stage::Claiming, ErrorCode::UnknownSlot),
            PairingError::Unknown
        );
        assert_eq!(
            at(Stage::Claiming, ErrorCode::SlotExpired),
            PairingError::Expired
        );
        assert_eq!(at(Stage::Claiming, ErrorCode::SlotUsed), PairingError::Used);
        assert_eq!(
            at(Stage::Claiming, ErrorCode::SlotClosed),
            PairingError::Used
        );
        assert_eq!(
            at(Stage::WaitingForReceiver, ErrorCode::SlotExpired),
            PairingError::NotClaimed
        );
        assert_eq!(
            at(Stage::WaitingForSender, ErrorCode::SlotClosed),
            PairingError::Rejected
        );
        assert_eq!(
            at(Stage::WaitingForSender, ErrorCode::SlotExpired),
            PairingError::SenderGone
        );
        assert_eq!(
            at(Stage::Creating, ErrorCode::NoFreeSlot),
            PairingError::Busy
        );
        assert_eq!(
            at(Stage::Claiming, ErrorCode::RateLimited),
            PairingError::Busy
        );

        let unreachable = PairingError::at(
            Stage::Claiming,
            ClientError::Unreachable("connection refused".to_string()),
            "http://rz",
        );
        assert_eq!(
            unreachable.to_string(),
            "the rendezvous server http://rz cannot be reached: connection refused"
        );

        // All of these must read differently
        let messages: std::collections::HashSet<String> = [
            PairingError::WrongCode,
            PairingError::Expired,
            PairingError::Used,
            PairingError::Unknown,
            unreachable,
        ]
        .iter()
        .map(|e| e.to_string())
        .collect();
        assert_eq!(messages.len(), 5);
    }

    #[test]
    fn secret_is_not_in_the_first_message() {
        let secret = Zeroizing::new("X4M2QP".to_string());
        let (_, _, hello) = sender_hello(&secret, Some("hunter2")).unwrap();
        let contains = |needle: &[u8]| hello.windows(needle.len()).any(|w| w == needle);
        assert!(!contains(b"X4M2QP"));
        assert!(!contains(b"hunter2"));
    }
}
