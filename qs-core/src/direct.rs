//! Serverless mode: address and public key exchanged directly, no rendezvous.
//!
//! The ticket contains the sender's `EndpointAddr`, which includes its
//! `EndpointId`. That is the pin, so no PAKE is needed. This is what the CLI
//! prints today (see `ticket` handling in `qs-cli/src/main.rs`).
//!
//! TODO: move encoding and decoding of the ticket out of the CLI into this module
//!       (postcard, then base64), so other frontends can use it.
//! TODO: put a version byte and a prefix in front, so a ticket is recognizable and
//!       future formats can be told apart. Reject unknown versions with a clear error.
//! TODO: with the optional password, run a PAKE inside the QUIC connection and bind it
//!       to the connection with the exporter value (see [crate::pairing::seal]).
//! TODO: this mode has to work with nothing but an IP address: no rendezvous, no relay, no
//!       hole punching. `qs send --direct --relay disabled` and `qs receive --direct <blob>`
//!       connect straight to `ip:port`. The blob then holds the address(es) and the
//!       `EndpointId`. An IP without the key cannot be authenticated, so it is not accepted.
//! TODO: accept the blob in a human typable form too, for example `192.168.1.5:4433/<key>`,
//!       next to the encoded ticket.
//! TODO: a fixed port for the sender (`--port`), otherwise there is nothing to give out.
//!       Print every usable address (LAN, and public if known), the receiver tries them all.
//! TODO: document clearly that without a relay and without hole punching the sender must be
//!       reachable by the receiver: same network, a forwarded port, or a public IP.
//! TODO: tests: round trip, garbage input, wrong version, truncated ticket.
