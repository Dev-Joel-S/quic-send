//! The optional password in direct mode.
//!
//! With a short code, the password goes into the pairing (see `pairing::pake`). With a
//! ticket there is no pairing, so the password is checked inside the QUIC connection:
//! both sides run a PAKE with it and prove to each other that they got the same key.
//! The password itself is never sent, and a wrong guess reveals nothing that could be
//! tested offline.
//!
//! The proofs are bound to the connection with keying material exported from its TLS
//! session, so a proof cannot be carried over to another connection.
//!
//! DONE: the sender allows a few attempts ([MAX_ATTEMPTS]) and keeps waiting after a wrong
//!       one, so a typo does not end the transfer and guessing stays slow.
//! DONE: both sides prove knowledge of the password, the receiver first.
//! DONE: tests in `tests/transfer.rs`: right password, wrong password, too many attempts,
//!       missing password, password where none was set.

use crate::pairing::{
    pake::{normalize_password, Pake, PakeError, SharedKey, Side},
    seal::{confirmation, verify_confirmation},
};
use thiserror::Error;

/// What the PAKE is for, also its version
const CONTEXT: &[u8] = b"quic-send password v1";
/// Label of the keying material exported from the TLS session
const EXPORTER_LABEL: &[u8] = b"quic-send password v1";
/// Wrong passwords a sender accepts before it gives up
pub const MAX_ATTEMPTS: usize = 3;

#[derive(Debug, Error, PartialEq)]
pub enum PasswordError {
    #[error("wrong password")]
    Wrong,
    #[error("the sender protected this transfer with a password, but none was given")]
    Required,
    #[error("a password was given, but the sender did not set one")]
    NotExpected,
    #[error("the receiver expected a password, but none was set. Run again with --password")]
    ExpectedByReceiver,
    #[error("wrong password entered {MAX_ATTEMPTS} times, giving up")]
    TooManyAttempts,
    #[error("the password check could not be started, the system gave no random numbers")]
    Unavailable,
}

/// Start the exchange as the sender. Returns the state and the message for the receiver.
pub(crate) fn start(password: &str) -> Result<(Pake, Vec<u8>), PakeError> {
    Pake::start(CONTEXT, normalize_password(password).as_bytes())
}

/// Answer the sender's message as the receiver. Returns the key and the message for the
/// sender.
pub(crate) fn respond(
    password: &str,
    sender_message: &[u8],
) -> Result<(SharedKey, Vec<u8>), PakeError> {
    Pake::respond(
        CONTEXT,
        normalize_password(password).as_bytes(),
        sender_message,
    )
}

/// Keying material only the two ends of `conn` can compute
fn exporter(conn: &iroh::endpoint::Connection) -> Option<[u8; 32]> {
    let mut material = [0u8; 32];
    conn.export_keying_material(&mut material, EXPORTER_LABEL, b"")
        .ok()?;
    Some(material)
}

/// Proof by `side` that it holds `key`, valid only on `conn`
pub(crate) fn proof(
    conn: &iroh::endpoint::Connection,
    key: &SharedKey,
    side: Side,
) -> Option<Vec<u8>> {
    Some(confirmation(key, &exporter(conn)?, side))
}

/// Check the proof of `side` for `conn`
pub(crate) fn verify(
    conn: &iroh::endpoint::Connection,
    key: &SharedKey,
    side: Side,
    proof: &[u8],
) -> bool {
    exporter(conn).is_some_and(|exporter| verify_confirmation(key, &exporter, side, proof))
}
