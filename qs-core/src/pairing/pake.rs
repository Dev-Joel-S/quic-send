//! Password authenticated key exchange, the code is the password.
//!
//! Both sides prove knowledge of the code without sending it. A wrong guess
//! only fails the handshake, there is nothing an observer or the rendezvous
//! server could test offline.
//!
//! DONE: the PAKE is CPace on ristretto255, from the `pake-cpace` crate. The protocol is
//!       not implemented by hand here, this file is only the wiring.
//! DONE: CPace instead of SPAKE2, because SPAKE2 has two fixed group elements. Whoever
//!       computes their discrete logarithms once, with a quantum computer, can test
//!       passwords offline against every exchange he took part in. CPace has no such
//!       constants: the generator is hashed from the password, so every single guess
//!       costs a discrete logarithm of its own. It is still not a post-quantum PAKE,
//!       the post-quantum part of a pairing is the KEM in [super::seal].
//! DONE: the sender starts ([Pake::start]), the receiver answers its message
//!       ([Pake::respond]), the sender finishes ([Pake::finish]). The sender picks a random
//!       session id, it is part of its message.
//! DONE: the password input is the secret and the optional user password, each with its
//!       length in front, so the two parts cannot be shifted into each other
//!       ([password_input]). The user password is normalized to Unicode NFC.
//! DONE: the role of each side and the purpose of the exchange are bound into the PAKE
//!       (identities and associated data). The slot and the messages are bound in the key
//!       schedule, see [super::seal].
//! DONE: the result is a [SharedKey] that is wiped when dropped.
//! DONE: tests: same input gives the same key, another code, password or context does not,
//!       a damaged or misplaced message is refused or gives another key.
//! TODO: the `pake-cpace` crate does not wipe its own state (the secret scalar and its
//!       copy of the keys). Report or patch upstream.
//! TODO (decision, audit finding M4): `pake-cpace` has never had an independent audit,
//!       which the project asks for, and it is an early variant of CPace, not byte for byte
//!       the CFRG draft (draft-irtf-cfrg-cpace). No audited CPace crate exists. The
//!       security of a pairing against a server in the middle rests on it.

use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use pake_cpace::{CPace, Step1Out, STEP1_PACKET_BYTES, STEP2_PACKET_BYTES};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Error, PartialEq)]
pub enum PakeError {
    #[error("the key exchange message of the other side is invalid")]
    InvalidMessage,
    #[error("the key exchange could not be started, the system gave no random numbers")]
    Random,
}

/// Which side of an exchange this is
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Sender,
    Receiver,
}

impl Side {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Side::Sender => "sender",
            Side::Receiver => "receiver",
        }
    }
}

/// The secret both sides end up with if they used the same password
pub struct SharedKey(Zeroizing<Vec<u8>>);

impl SharedKey {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Take the keys out of the library's type, which is not wiped, into one that is
    fn new(mut keys: pake_cpace::SharedKeys) -> Self {
        let mut key = Zeroizing::new(Vec::with_capacity(keys.k1.len() + keys.k2.len()));
        key.extend_from_slice(&keys.k1);
        key.extend_from_slice(&keys.k2);
        keys.k1.zeroize();
        keys.k2.zeroize();
        Self(key)
    }
}

/// The library takes the password as text. The input here is bytes, so it is encoded,
/// which maps different inputs to different texts.
fn as_text(password: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(BASE64_URL_SAFE_NO_PAD.encode(password))
}

fn error(e: pake_cpace::Error) -> PakeError {
    match e {
        pake_cpace::Error::Random(_) => PakeError::Random,
        _ => PakeError::InvalidMessage,
    }
}

/// The sender's side of a key exchange that has sent its message and waits for the answer
pub struct Pake {
    state: Step1Out,
}

impl Pake {
    /// Start an exchange as the sender. Returns the state and the message for the receiver.
    ///
    /// `context` says what the exchange is for. Both sides have to use the same one,
    /// an exchange for one purpose cannot be finished with a message of another.
    pub fn start(context: &[u8], password: &[u8]) -> Result<(Self, Vec<u8>), PakeError> {
        let state = CPace::step1(
            &as_text(password),
            Side::Sender.label(),
            Side::Receiver.label(),
            Some(context),
        )
        .map_err(error)?;
        let message = state.packet().to_vec();

        Ok((Self { state }, message))
    }

    /// Answer the sender's message as the receiver. Returns the key and the message for
    /// the sender.
    ///
    /// This succeeds with any well formed message. Whether both sides used the same
    /// password only shows when the keys are used.
    pub fn respond(
        context: &[u8],
        password: &[u8],
        sender_message: &[u8],
    ) -> Result<(SharedKey, Vec<u8>), PakeError> {
        let sender_message: &[u8; STEP1_PACKET_BYTES] = sender_message
            .try_into()
            .map_err(|_| PakeError::InvalidMessage)?;

        let answer = CPace::step2(
            sender_message,
            &as_text(password),
            Side::Sender.label(),
            Side::Receiver.label(),
            Some(context),
        )
        .map_err(error)?;

        Ok((
            SharedKey::new(answer.shared_keys()),
            answer.packet().to_vec(),
        ))
    }

    /// Finish as the sender with the receiver's message.
    ///
    /// Like [Pake::respond], this succeeds with any well formed message.
    pub fn finish(self, receiver_message: &[u8]) -> Result<SharedKey, PakeError> {
        let receiver_message: &[u8; STEP2_PACKET_BYTES] = receiver_message
            .try_into()
            .map_err(|_| PakeError::InvalidMessage)?;

        self.state
            .step3(receiver_message)
            .map(SharedKey::new)
            .map_err(error)
    }
}

/// The user password in the form it goes into the key exchange: Unicode NFC, so the same
/// password typed on two systems gives the same bytes
pub fn normalize_password(password: &str) -> Zeroizing<String> {
    Zeroizing::new(password.nfc().collect())
}

/// The input of the key exchange: the secret part of the code and the optional password.
///
/// Each part has its length in front. Without that, the code `AB` with the password `C`
/// would give the same input as the code `A` with the password `BC`.
pub fn password_input(secret: &str, password: Option<&str>) -> Zeroizing<Vec<u8>> {
    let password = password.map(normalize_password);
    let password = password.as_ref().map(|p| p.as_bytes()).unwrap_or_default();

    let mut input = Zeroizing::new(Vec::with_capacity(8 + secret.len() + password.len()));
    for part in [secret.as_bytes(), password] {
        input.extend_from_slice(&(part.len() as u32).to_be_bytes());
        input.extend_from_slice(part);
    }
    input
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTEXT: &[u8] = b"test";

    /// Run an exchange and return the keys of both sides
    fn exchange(sender: &[u8], receiver: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (a, message_a) = Pake::start(CONTEXT, sender).unwrap();
        let (key_b, message_b) = Pake::respond(CONTEXT, receiver, &message_a).unwrap();
        let key_a = a.finish(&message_b).unwrap();
        (key_a.as_bytes().to_vec(), key_b.as_bytes().to_vec())
    }

    #[test]
    fn same_password_same_key() {
        let (a, b) = exchange(b"X4M2QP", b"X4M2QP");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn different_password_different_key() {
        let (a, b) = exchange(b"X4M2QP", b"X4M2QQ");
        assert_ne!(a, b);
    }

    #[test]
    fn every_exchange_has_its_own_key() {
        let (first, _) = exchange(b"X4M2QP", b"X4M2QP");
        let (second, _) = exchange(b"X4M2QP", b"X4M2QP");
        assert_ne!(first, second);
    }

    #[test]
    fn password_that_is_not_text() {
        // The input has length fields in it, any bytes have to work
        let password = [0u8, 0xff, 0x80, 0xc3, 0x28];
        let (a, b) = exchange(&password, &password);
        assert_eq!(a, b);
        let (a, b) = exchange(&password, &password[..4]);
        assert_ne!(a, b);
    }

    #[test]
    fn context_is_part_of_the_exchange() {
        let (a, message_a) = Pake::start(b"pairing", b"pw").unwrap();
        let (key_b, message_b) = Pake::respond(b"something else", b"pw", &message_a).unwrap();
        let key_a = a.finish(&message_b).unwrap();
        assert_ne!(key_a.as_bytes(), key_b.as_bytes());
    }

    #[test]
    fn invalid_messages_are_refused() {
        let start = || Pake::start(CONTEXT, b"pw").unwrap();

        // The own message reflected back, and the message of another sender
        let (state, own_message) = start();
        assert!(state.finish(&own_message).is_err());
        let (_, other_sender) = start();
        assert!(start().0.finish(&other_sender).is_err());

        // An answer where the first message belongs
        let (_, first) = start();
        let (_, answer) = Pake::respond(CONTEXT, b"pw", &first).unwrap();
        assert!(Pake::respond(CONTEXT, b"pw", &answer).is_err());

        // Too short, too long and empty
        assert!(start().0.finish(&answer[..answer.len() - 1]).is_err());
        assert!(start()
            .0
            .finish(&[answer.as_slice(), &[0]].concat())
            .is_err());
        assert!(start().0.finish(&[]).is_err());
        assert!(Pake::respond(CONTEXT, b"pw", &first[..first.len() - 1]).is_err());
        assert!(Pake::respond(CONTEXT, b"pw", &[]).is_err());

        // The neutral element, with it the key would not depend on the password
        assert!(start().0.finish(&[0; 32]).is_err());
        let mut neutral = first.clone();
        neutral[16..].fill(0);
        assert!(Pake::respond(CONTEXT, b"pw", &neutral).is_err());
    }

    #[test]
    fn changed_answer_never_gives_the_same_key() {
        // Every third bit keeps the test fast and still touches every byte
        for bit in (0..(32 * 8)).step_by(3) {
            let (a, message_a) = Pake::start(CONTEXT, b"pw").unwrap();
            let (key_b, message_b) = Pake::respond(CONTEXT, b"pw", &message_a).unwrap();

            // Flip one bit of the answer on its way to the sender
            let mut changed = message_b.clone();
            changed[bit / 8] ^= 1 << (bit % 8);

            // Either it is no longer a valid message, or the keys differ
            if let Ok(key_a) = a.finish(&changed) {
                assert_ne!(key_a.as_bytes(), key_b.as_bytes(), "bit {bit}");
            }
        }
    }

    #[test]
    fn changed_first_message_never_gives_the_same_key() {
        // The session id in front and the group element after it
        for bit in (0..(48 * 8)).step_by(3) {
            let (a, message_a) = Pake::start(CONTEXT, b"pw").unwrap();

            let mut changed = message_a.clone();
            changed[bit / 8] ^= 1 << (bit % 8);

            if let Ok((key_b, message_b)) = Pake::respond(CONTEXT, b"pw", &changed) {
                let key_a = a.finish(&message_b).unwrap();
                assert_ne!(key_a.as_bytes(), key_b.as_bytes(), "bit {bit}");
            }
        }
    }

    #[test]
    fn password_input_keeps_the_parts_apart() {
        assert_ne!(
            password_input("AB", Some("C")),
            password_input("A", Some("BC"))
        );
        assert_ne!(password_input("AB", None), password_input("A", Some("B")));
        assert_ne!(password_input("AB", None), password_input("AB", Some("x")));
        assert_eq!(
            password_input("AB", Some("C")),
            password_input("AB", Some("C"))
        );
    }

    #[test]
    fn password_is_normalized() {
        // "é" as one character and as "e" with a combining accent
        let composed = "caf\u{e9}";
        let decomposed = "cafe\u{301}";
        assert_ne!(composed, decomposed);
        assert_eq!(
            password_input("AB", Some(composed)),
            password_input("AB", Some(decomposed))
        );
    }

    #[test]
    fn optional_password_changes_the_key() {
        let with = password_input("X4M2QP", Some("hunter2"));
        let without = password_input("X4M2QP", None);
        let (a, b) = exchange(&with, &without);
        assert_ne!(a, b);
        let (a, b) = exchange(&with, &with);
        assert_eq!(a, b);
    }
}
