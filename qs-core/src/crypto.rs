//! TLS configuration of the QUIC connection: crypto provider and post-quantum key exchange.
//!
//! iroh lets the application set the rustls crypto provider
//! (`Endpoint::builder(..).crypto_provider(..)`), so the hybrid X25519MLKEM768
//! key exchange can be switched on without touching iroh.
//!
//! TODO: build a provider from aws-lc-rs whose key exchange groups put
//!       X25519MLKEM768 first, and give it to the endpoint builder in the CLI.
//! TODO: enable the `tls-aws-lc-rs` feature of iroh instead of `tls-ring` and check
//!       the whole dependency tree for leftover assumptions about `ring`.
//! TODO: check that the static musl build and the Windows MSVC build still compile
//!       with aws-lc-rs, in CI.
//! TODO: the same provider is used for the HTTPS connections to the relay. Check that
//!       a hybrid-only list of groups does not break them, keep a classical fallback there.
//! TODO: test that two endpoints really negotiate the hybrid group, and not silently
//!       fall back to X25519.
//! TODO: only if iroh turns out not to give enough control: add an ML-KEM-768 exchange
//!       during pairing and mix its secret into the key schedule in
//!       [crate::pairing::seal]. Do not patch iroh.
