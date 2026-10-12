//! The short code: generation, display and parsing.
//!
//! Crockford Base32 (no I, L, O, U), 8 characters, 40 bits, shown as `K7X4-M2QP`.
//! The code is split into a public part and a secret part:
//! - the nameplate selects a slot on the rendezvous server and is sent to it
//! - the secret is the PAKE password and never leaves the machine
//!
//! The split matters. If the slot were derived from the whole code, a hostile
//! server could try all 2^40 codes offline and recover the secret.
//!
//! TODO: generate the code with the OS random number generator.
//! TODO: decide the split. Proposal: 2 characters nameplate (1024 slots at once),
//!       6 characters secret (30 bits per online guess). Ideally the server hands
//!       out the nameplate, so two senders never collide.
//! TODO: parse input case insensitive, with or without the dash, and apply
//!       Crockford's substitutions (I and L become 1, O becomes 0) before decoding.
//! TODO: reject codes of the wrong length or with invalid characters with a clear error.
//! TODO: tests: round trip, substitutions, dash and case handling, wrong length.
