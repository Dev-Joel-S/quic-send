//! Rendezvous server for quic-send.
//!
//! An untrusted mailbox. It hands out slots and passes opaque messages between the two
//! peers of a pairing. It must not be able to do more than deny service, see
//! `qs_core::pairing::rendezvous` for the messages and what the clients assume.
//!
//! TODO: create slot: the server picks the nameplate and returns it, so senders never collide.
//! TODO: store messages per slot: PAKE message of the sender, claim with the PAKE message
//!       of the receiver, sealed address. Never interpret them.
//! TODO: a slot can be claimed exactly once. A second attempt gets "already used". This
//!       is the defense against online guessing and needs a test.
//! TODO: remove a slot on first successful fetch, on a delete request, and after a few
//!       minutes. Keep a short list of used and expired slot names so the clients can be
//!       told "expired" and "already used" apart.
//! TODO: limits: size of every message, number of slots per IP and in total, slot
//!       creation rate. Everything in memory, nothing written to disk.
//! TODO: long polling or a similar way for the sender to wait for the receiver.
//! TODO: TLS is the job of a reverse proxy, document an example configuration. The
//!       server has no secrets, but the clients' IP addresses should not travel in clear.
//! TODO: no logging of slot names together with IP addresses.
//! TODO: tests for the points above, including a client that behaves badly.
