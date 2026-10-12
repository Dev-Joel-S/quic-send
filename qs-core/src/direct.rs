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
//! TODO: document that one side has to be reachable when the relay is disabled.
//! TODO: tests: round trip, garbage input, wrong version, truncated ticket.
