//! Pairing of two peers with a short code.
//!
//! The sender shows a short code, the receiver types it, and both end up with
//! an authenticated connection without any third party being trusted.
//! Everything in here is independent of the CLI, so another frontend can reuse it.
//!
//! Flow, see the submodules for the details of each step:
//! 1. the sender gets a nameplate and a secret ([code])
//! 2. both sides derive the same keys from the secret ([pake], [seal])
//! 3. the sender's address is exchanged through the rendezvous server,
//!    encrypted, so the server only ever sees opaque blobs ([rendezvous])
//! 4. the receiver connects with iroh and checks the sender's `EndpointId`
//!    against the one learned during pairing
//!
//! TODO: pairing errors must tell "wrong code", "slot expired", "slot already used"
//!       and "server unreachable" apart, see [rendezvous]. One shared error enum here.
//! TODO: decide how the pairing result is handed to `send::Sender` / `receive::Receiver`
//!       (probably the expected remote `EndpointId` plus the session key material).

pub mod code;
pub mod pake;
pub mod rendezvous;
pub mod seal;
