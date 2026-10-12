//! Password authenticated key exchange, the code is the password.
//!
//! Both sides prove knowledge of the code without sending it. A wrong guess
//! only fails the handshake, there is nothing an observer or the rendezvous
//! server could test offline.
//!
//! TODO: pick the PAKE crate. There is no maintained CPace crate. Proposal: SPAKE2
//!       from RustCrypto/PAKEs. Do not implement the protocol ourselves.
//! TODO: password input is `secret || optional user password`, length prefixed so the
//!       two parts cannot be shifted into each other. Code uppercase, password in
//!       Unicode normalization form NFC.
//! TODO: bind the identities of both sides and the protocol version into the PAKE,
//!       so a transcript cannot be replayed against another pairing.
//! TODO: the output is the shared secret that [super::seal] turns into keys. Wrap it
//!       in a type that zeroizes on drop.
//! TODO: tests: same code gives the same key, wrong code or wrong password does not,
//!       the optional password changes the key.
