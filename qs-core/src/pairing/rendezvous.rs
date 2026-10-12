//! Client side of the rendezvous protocol.
//!
//! The rendezvous server is an untrusted mailbox. It sees a slot name, a few
//! opaque messages and IP addresses of the clients, and can deny service, nothing
//! else. The server lives in the `qs-rendezvous` crate.
//!
//! Messages through one slot (a PAKE needs both sides before a key exists, so a
//! single upload is not enough):
//! 1. sender to server: its PAKE message
//! 2. receiver claims the slot (only once) and sends its PAKE message
//! 3. sender to server: its sealed address, receiver fetches it
//!
//! TODO: define the wire format and a protocol version, shared with `qs-rendezvous`.
//!       Consider moving the message types into a small crate both depend on.
//! TODO: HTTP client for the calls: create slot, upload, claim, fetch, delete.
//!       Pick a client that works in the static musl build and on Windows.
//! TODO: enforce one claim per slot on the server and test it. This is the whole
//!       defense against online guessing.
//! TODO: error mapping: wrong code, slot expired, slot already used, server
//!       unreachable, server speaks another protocol version.
//! TODO: the receiver deletes the slot after a failed attempt, both sides after success.
//! TODO: timeouts and a way to cancel from the CLI (Ctrl+C removes the slot).
