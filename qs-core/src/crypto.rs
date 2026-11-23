//! TLS configuration of the QUIC connection: crypto provider and post-quantum key exchange.
//!
//! iroh lets the application set the rustls crypto provider
//! (`Endpoint::builder(..).crypto_provider(..)`), so the hybrid X25519MLKEM768
//! key exchange can be switched on without touching iroh. A recorded transfer then
//! stays confidential even if X25519 alone is broken later.
//!
//! DONE: [provider] builds a provider from aws-lc-rs that puts X25519MLKEM768 first.
//!       The CLI and the tests give it to the endpoint builder.
//! DONE: iroh is built with `tls-aws-lc-rs` instead of `tls-ring`. `ring` is no longer
//!       compiled at all (`cargo tree -i ring` is empty).
//! DONE: the same provider also does the HTTPS connections to the relay, so the classical
//!       groups stay in the list as a fallback for servers without the hybrid group.
//!       What is enforced instead is the result: [ensure_post_quantum] reads the group
//!       that was really negotiated on a connection, and `send::Sender::connect` and
//!       `receive::Receiver::connect` refuse a connection that fell back to a classical one.
//! DONE: tests in `tests/transfer.rs`: two endpoints negotiate the hybrid group, a peer
//!       that only offers X25519 is refused in both directions.
//! DONE: the static musl build and the Windows GNU build compile with aws-lc-rs (checked
//!       locally). `prebuilt-nasm` is enabled so the MSVC build needs no assembler.
//! DONE: the MSVC build is confirmed in CI: the checks and the release workflow build with
//!       it on Windows and run the tests there.

use rustls::{
    crypto::{aws_lc_rs, CryptoProvider},
    NamedGroup,
};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum CryptoError {
    #[error(
        "the connection does not use the post-quantum key exchange (negotiated: {0}), \
         the other side probably runs an old or modified version"
    )]
    NotPostQuantum(String),
}

/// The crypto provider for every endpoint: aws-lc-rs, hybrid post-quantum key exchange first.
///
/// The classical groups stay available, because the same provider is used for the HTTPS
/// connection to a relay server, which may not support the hybrid group. A connection
/// between two peers is checked with [ensure_post_quantum] afterwards.
pub fn provider() -> Arc<CryptoProvider> {
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = vec![
        aws_lc_rs::kx_group::X25519MLKEM768,
        aws_lc_rs::kx_group::X25519,
        aws_lc_rs::kx_group::SECP256R1,
        aws_lc_rs::kx_group::SECP384R1,
    ];
    Arc::new(provider)
}

/// The key exchange group that was negotiated for `conn`
pub fn key_exchange_group(conn: &iroh::endpoint::Connection) -> Option<NamedGroup> {
    conn.handshake_data()?
        .downcast::<noq::crypto::rustls::HandshakeData>()
        .ok()?
        .negotiated_key_exchange_group
}

/// Fail unless `conn` was set up with the hybrid post-quantum key exchange
pub fn ensure_post_quantum(conn: &iroh::endpoint::Connection) -> Result<(), CryptoError> {
    match key_exchange_group(conn) {
        Some(NamedGroup::X25519MLKEM768) => Ok(()),
        Some(other) => Err(CryptoError::NotPostQuantum(format!("{other:?}"))),
        None => Err(CryptoError::NotPostQuantum("unknown".to_string())),
    }
}
