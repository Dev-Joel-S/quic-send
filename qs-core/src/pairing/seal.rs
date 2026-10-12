//! Key schedule and sealing of the sender's address.
//!
//! The sender's `EndpointAddr` is encrypted before it goes to the rendezvous
//! server. Only someone who finished the PAKE can open it.
//!
//! TODO: derive the keys with HKDF from the PAKE output, the transcript hash and,
//!       once the post-quantum step exists, the KEM secret (see `crate::crypto`).
//!       Breaking one of the inputs must not be enough.
//! TODO: seal and open with an AEAD from the same crypto provider as the QUIC
//!       handshake (ChaCha20-Poly1305 or AES-GCM). Fresh nonce per message,
//!       associated data covers the slot and the protocol version.
//! TODO: opening with a wrong key must fail cleanly and be reported as "wrong code".
//! TODO: confirm the session after connecting: a MAC over the QUIC exporter value
//!       (`Connection::export_keying_material`) proves both ends hold the same keys
//!       on this very connection.
//! TODO: tests: round trip, rejection on wrong key, tampered ciphertext, tampered
//!       associated data.
