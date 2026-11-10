//! Password authenticated key exchange, the code is the password.
//!
//! Both sides prove knowledge of the code without sending it. A wrong guess
//! only fails the handshake, there is nothing an observer or the rendezvous
//! server could test offline.
//!
//! DONE: the PAKE is SPAKE2 from the RustCrypto `spake2` crate. There is no maintained
//!       CPace crate, and the protocol is not implemented by hand here.
//! DONE: the password input is the secret and the optional user password, each with its
//!       length in front, so the two parts cannot be shifted into each other
//!       ([password_input]). The user password is normalized to Unicode NFC.
//! DONE: the role of each side and the purpose of the exchange are bound into the PAKE as
//!       its identities ([Pake::start]). The slot and the messages are bound in the key
//!       schedule, see [super::seal].
//! DONE: the result is a [SharedKey] that is wiped when dropped.
//! DONE: tests: same input gives the same key, another code or password does not, a
//!       message of the wrong side or a damaged one is refused.
//! TODO: the `spake2` crate does not wipe its own state. Report or patch upstream.

use spake2::{Ed25519Group, Identity, Password, Spake2};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

#[derive(Debug, Error, PartialEq)]
pub enum PakeError {
    #[error("the key exchange message of the other side is invalid")]
    InvalidMessage,
}

/// Which side of an exchange this is
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Sender,
    Receiver,
}

impl Side {
    pub(crate) fn label(self) -> &'static [u8] {
        match self {
            Side::Sender => b"sender",
            Side::Receiver => b"receiver",
        }
    }
}

/// The secret both sides end up with if they used the same password
pub struct SharedKey(Zeroizing<Vec<u8>>);

impl SharedKey {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// One side of a key exchange that has sent its message and waits for the other one
pub struct Pake {
    state: Spake2<Ed25519Group>,
}

impl Pake {
    /// Start an exchange. Returns the state and the message for the other side.
    ///
    /// `context` says what the exchange is for. Both sides have to use the same one,
    /// an exchange for one purpose cannot be finished with a message of another.
    pub fn start(side: Side, context: &[u8], password: &[u8]) -> (Self, Vec<u8>) {
        let identity = |side: Side| Identity::new(&[context, b"/", side.label()].concat());
        let password = Password::new(password);

        let (state, message) = match side {
            Side::Sender => Spake2::<Ed25519Group>::start_a(
                &password,
                &identity(Side::Sender),
                &identity(Side::Receiver),
            ),
            Side::Receiver => Spake2::<Ed25519Group>::start_b(
                &password,
                &identity(Side::Sender),
                &identity(Side::Receiver),
            ),
        };

        (Self { state }, message)
    }

    /// Finish with the message of the other side.
    ///
    /// This succeeds with any well formed message. Whether both sides used the same
    /// password only shows when the keys are used.
    pub fn finish(self, peer_message: &[u8]) -> Result<SharedKey, PakeError> {
        self.state
            .finish(peer_message)
            .map(|key| SharedKey(Zeroizing::new(key)))
            .map_err(|_| PakeError::InvalidMessage)
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
        let (a, message_a) = Pake::start(Side::Sender, CONTEXT, sender);
        let (b, message_b) = Pake::start(Side::Receiver, CONTEXT, receiver);
        let key_a = a.finish(&message_b).unwrap();
        let key_b = b.finish(&message_a).unwrap();
        (key_a.as_bytes().to_vec(), key_b.as_bytes().to_vec())
    }

    #[test]
    fn same_password_same_key() {
        let (a, b) = exchange(b"X4M2QP", b"X4M2QP");
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
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
    fn context_is_part_of_the_exchange() {
        let (a, message_a) = Pake::start(Side::Sender, b"pairing", b"pw");
        let (b, message_b) = Pake::start(Side::Receiver, b"something else", b"pw");
        let key_a = a.finish(&message_b).unwrap();
        let key_b = b.finish(&message_a).unwrap();
        assert_ne!(key_a.as_bytes(), key_b.as_bytes());
    }

    #[test]
    fn invalid_messages_are_refused() {
        let start = || Pake::start(Side::Sender, CONTEXT, b"pw");

        // The own message reflected back
        let (state, own_message) = start();
        assert!(state.finish(&own_message).is_err());

        // Message of another sender
        let (_, other_sender) = start();
        assert!(start().0.finish(&other_sender).is_err());

        // Too short and empty
        let (_, valid) = Pake::start(Side::Receiver, CONTEXT, b"pw");
        assert!(start().0.finish(&valid[..valid.len() - 1]).is_err());
        assert!(start().0.finish(&[]).is_err());
    }

    #[test]
    fn changed_message_never_gives_the_same_key() {
        // Every seventh bit keeps the test fast and still touches every byte
        for bit in (8..(33 * 8)).step_by(7) {
            let (a, message_a) = Pake::start(Side::Sender, CONTEXT, b"pw");
            let (b, message_b) = Pake::start(Side::Receiver, CONTEXT, b"pw");
            let key_b = b.finish(&message_a).unwrap();

            // Flip one bit of the message on its way to the sender
            let mut changed = message_b.clone();
            changed[bit / 8] ^= 1 << (bit % 8);

            // Either it is no longer a valid message, or the keys differ
            if let Ok(key_a) = a.finish(&changed) {
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
