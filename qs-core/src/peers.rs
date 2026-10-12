//! A stable identity and pinned peers, so repeat transfers need no code.
//!
//! Today every run uses a fresh key, so the `EndpointId` of a sender changes each
//! time and nothing about a peer can be remembered. That also keeps resume state
//! from being tied to a peer (see `destination::ResumeState::peer`).
//!
//! TODO: decide about privacy first. A stable id can be recognized by relays and
//!       address lookup. Proposal: keep the ephemeral key as the default, use a stored
//!       key only when a peer is saved or used.
//! TODO: store the secret key in a file in the config directory, permissions 0600 on
//!       Unix, a private location on Windows. Never print it.
//! TODO: `known_peers`: alias to `EndpointId`, saved after a successful pairing and
//!       used by `qs send --to <alias>`. The pin is the public key, so this stays
//!       zero trust.
//! TODO: decide how a pinned peer is found again: address lookup, a stored address,
//!       or direct mode.
//! TODO: the sender accepts only the expected `EndpointId`. Today
//!       `send::Sender::connect` takes the first connection of anyone.
//! TODO: tests: alias lookup, unknown alias, a changed key for a known alias is a loud
//!       error and not silently replaced.
