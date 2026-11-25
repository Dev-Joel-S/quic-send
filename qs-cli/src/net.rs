//! Setting up the iroh endpoint from the settings in effect.
//!
//! PLANNED (branch claude-direct-connect, not started): make a direct connection work in
//! more networks, without any relay.
//! Ground rule for all of these: no server ever carries file data, not even encrypted.
//! Servers may only help the two peers find each other.
//! TODO: IPv6 first. Bind dual stack and make sure every global IPv6 address of the
//!       machine is in the address that is shared. Most mobile networks hand out IPv6,
//!       and there is no NAT on it, only stateful firewalls, which open when both sides
//!       send at the same time (see `qs_core::send`).
//! TODO: check that the port mapping of the router (UPnP, PCP, NAT-PMP, iroh's
//!       `portmapper`, on by default) still runs with `presets::Empty` and no relay, and
//!       that the mapped address ends up in the address that is shared. Add a test.
//! TODO: add the public IPv4 address the rendezvous server saw (`observed_ip`, see
//!       `qs_rendezvous_api`) together with the local UDP port as one more candidate.
//!       Many home routers keep the port, then this is the address seen from outside.
//!       Needs the port of the endpoint to be known, so bind it before pairing.

use crate::config::{RelaySetting, Settings};
use iroh::{endpoint::presets, Endpoint, EndpointAddr, RelayMap, RelayMode, SecretKey};
use qs_core::QS_ALPN;
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

/// How long to wait for a relay before going on with only local addresses
const ONLINE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to wait for any address after that
const ADDR_TIMEOUT: Duration = Duration::from_secs(5);

/// Bind an endpoint with the relay mode and port from `settings`.
///
/// Every endpoint uses the crypto provider with the post-quantum key exchange.
pub async fn bind(settings: &Settings, secret_key: SecretKey) -> Result<Endpoint, String> {
    let builder = |fixed_v6: bool| -> Result<_, String> {
        let mut builder = Endpoint::builder(presets::Empty)
            .crypto_provider(qs_core::crypto::provider())
            .secret_key(secret_key.clone())
            .alpns(vec![QS_ALPN.to_vec()])
            .relay_mode(match &settings.relay {
                RelaySetting::Disabled => RelayMode::Disabled,
                RelaySetting::Custom(url) => RelayMode::Custom(RelayMap::from(url.clone())),
            });

        if let Some(port) = settings.port {
            builder = builder
                .bind_addr((Ipv4Addr::UNSPECIFIED, port))
                .map_err(|e| e.to_string())?;
            if fixed_v6 {
                builder = builder
                    .bind_addr((Ipv6Addr::UNSPECIFIED, port))
                    .map_err(|e| e.to_string())?;
            }
        }

        Ok(builder)
    };

    match builder(settings.port.is_some())?.bind().await {
        Ok(endpoint) => Ok(endpoint),
        // A machine without IPv6 cannot bind the fixed port there. IPv4 alone is enough.
        Err(e) if settings.port.is_some() => {
            tracing::debug!("could not bind the fixed port on IPv4 and IPv6: {e}");
            builder(false)?.bind().await.map_err(|e| e.to_string())
        }
        Err(e) => Err(e.to_string()),
    }
}

/// The address other peers can reach this endpoint at.
///
/// With a relay this waits until the relay is connected, so the address works across the
/// internet. Without a network that never happens, the local addresses are used then.
pub async fn own_addr(endpoint: &Endpoint, relay: &RelaySetting) -> Result<EndpointAddr, String> {
    if *relay != RelaySetting::Disabled
        && tokio::time::timeout(ONLINE_TIMEOUT, endpoint.online())
            .await
            .is_err()
    {
        tracing::warn!("no relay reachable, only local addresses are available");
    }

    // Local addresses can show up a moment after binding
    let mut addr = endpoint.addr();
    let deadline = tokio::time::Instant::now() + ADDR_TIMEOUT;
    while addr.is_empty() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
        addr = endpoint.addr();
    }

    if addr.is_empty() {
        return Err("neither a relay nor a local network address is available".to_string());
    }

    Ok(addr)
}
