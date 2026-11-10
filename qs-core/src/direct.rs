//! Serverless mode: address and public key exchanged directly, no rendezvous.
//!
//! The ticket contains the sender's `EndpointAddr`, which includes its
//! `EndpointId`. That is the pin, so no PAKE is needed: the receiver only completes
//! a connection to the holder of that key.
//!
//! DONE: encoding and decoding of the ticket live here ([Ticket]), the CLI only prints
//!       and parses it.
//! DONE: an encoded ticket starts with `qs1:`. An unknown version is reported as such
//!       ([TicketError::UnknownVersion]) instead of as garbage.
//! DONE: this mode works with nothing but an IP address: no rendezvous, no relay, no hole
//!       punching (`qs send --relay disabled`, covered by the end to end tests, which run
//!       without a relay). An IP without the key is not accepted, it could not be
//!       authenticated.
//! DONE: a form that can be typed, `192.168.1.5:4433/<key>` ([Ticket::typable] to print,
//!       the same [FromStr] to read). Several addresses are separated by commas.
//! DONE: the sender can bind a fixed port (`--port`, `port` in the config file), and the
//!       CLI prints every usable address when no relay is in use.
//! DONE: with the optional password a PAKE runs inside the QUIC connection, bound to it
//!       with the exporter value, see `crate::password`.
//! DONE: the README says clearly that without a relay the sender must be reachable
//!       by the receiver (same network, a forwarded port, or a public IP).

use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use iroh::{EndpointAddr, EndpointId};
use std::{fmt, net::SocketAddr, str::FromStr};
use thiserror::Error;

/// Prefix of an encoded ticket, with the version of the format
const PREFIX: &str = "qs1:";

#[derive(Debug, Error, PartialEq)]
pub enum TicketError {
    #[error("this is not a valid ticket")]
    Invalid,
    #[error("this ticket was made by a newer version of quic-send (ticket format {0})")]
    UnknownVersion(String),
    #[error("the ticket contains no address to connect to")]
    NoAddress,
}

/// Everything a receiver needs to connect to a sender without a rendezvous server
#[derive(Debug, Clone, PartialEq)]
pub struct Ticket {
    addr: EndpointAddr,
}

impl Ticket {
    /// A ticket for `addr`. Fails if `addr` has neither an IP address nor a relay.
    pub fn new(addr: EndpointAddr) -> Result<Self, TicketError> {
        if addr.is_empty() {
            return Err(TicketError::NoAddress);
        }
        Ok(Self { addr })
    }

    /// The address to connect to
    pub fn addr(&self) -> &EndpointAddr {
        &self.addr
    }

    /// The address to connect to
    pub fn into_addr(self) -> EndpointAddr {
        self.addr
    }

    /// The ticket in the form a human can type, one line per IP address:
    /// `192.168.1.5:4433/<key>`. Empty if the ticket has no IP address.
    pub fn typable(&self) -> Vec<String> {
        self.addr
            .ip_addrs()
            .map(|ip| format!("{ip}/{}", self.addr.id))
            .collect()
    }
}

impl fmt::Display for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Encoding an address into a Vec cannot fail
        let bytes = postcard::to_stdvec(&self.addr).map_err(|_| fmt::Error)?;
        write!(f, "{PREFIX}{}", BASE64_URL_SAFE_NO_PAD.encode(bytes))
    }
}

impl FromStr for Ticket {
    type Err = TicketError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        if let Some(encoded) = s.strip_prefix(PREFIX) {
            let bytes = BASE64_URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| TicketError::Invalid)?;
            let addr: EndpointAddr =
                postcard::from_bytes(&bytes).map_err(|_| TicketError::Invalid)?;
            return Self::new(addr);
        }

        // `qs<number>:` with another number is a format this version does not know
        if let Some((version, _)) = s.strip_prefix("qs").and_then(|rest| rest.split_once(':')) {
            if !version.is_empty() && version.chars().all(|c| c.is_ascii_digit()) {
                return Err(TicketError::UnknownVersion(version.to_string()));
            }
        }

        // `ip:port[,ip:port...]/key`
        let (addrs, key) = s.rsplit_once('/').ok_or(TicketError::Invalid)?;
        let id = EndpointId::from_str(key.trim()).map_err(|_| TicketError::Invalid)?;

        let mut addr = EndpointAddr::new(id);
        for ip in addrs.split(',') {
            let ip = SocketAddr::from_str(ip.trim()).map_err(|_| TicketError::Invalid)?;
            addr = addr.with_ip_addr(ip);
        }

        Self::new(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::{RelayUrl, SecretKey};
    use pretty_assertions::assert_eq;

    fn id() -> EndpointId {
        SecretKey::generate().public()
    }

    fn sample() -> Ticket {
        let addr = EndpointAddr::new(id())
            .with_relay_url(RelayUrl::from_str("https://relay.example.com").unwrap())
            .with_ip_addr("192.168.1.5:4433".parse().unwrap())
            .with_ip_addr("[2001:db8::1]:4433".parse().unwrap());
        Ticket::new(addr).unwrap()
    }

    #[test]
    fn round_trip() {
        let ticket = sample();
        let text = ticket.to_string();
        assert!(text.starts_with("qs1:"));
        assert_eq!(Ticket::from_str(&text), Ok(ticket.clone()));
        // Whitespace from copy and paste does not matter
        assert_eq!(Ticket::from_str(&format!("  {text}\n")), Ok(ticket));
    }

    #[test]
    fn typable_form() {
        let ticket = sample();
        let lines = ticket.typable();
        assert_eq!(lines.len(), 2);
        assert!(lines.iter().any(|l| l.starts_with("192.168.1.5:4433/")));
        assert!(lines.iter().any(|l| l.starts_with("[2001:db8::1]:4433/")));

        // Every line alone is a ticket for that address and the same key
        for line in &lines {
            let parsed = Ticket::from_str(line).unwrap();
            assert_eq!(parsed.addr().id, ticket.addr().id);
            assert_eq!(parsed.addr().ip_addrs().count(), 1);
            assert_eq!(parsed.addr().relay_urls().count(), 0);
        }
    }

    #[test]
    fn typable_with_several_addresses() {
        let key = id();
        let ticket = Ticket::from_str(&format!("10.0.0.1:1, [::1]:2 / {key}")).unwrap();
        assert_eq!(ticket.addr().id, key);
        assert_eq!(ticket.addr().ip_addrs().count(), 2);
    }

    #[test]
    fn address_without_key_is_refused() {
        assert_eq!(
            Ticket::from_str("192.168.1.5:4433"),
            Err(TicketError::Invalid)
        );
        assert_eq!(
            Ticket::from_str("192.168.1.5:4433/"),
            Err(TicketError::Invalid)
        );
        assert_eq!(
            Ticket::from_str("192.168.1.5:4433/not-a-key"),
            Err(TicketError::Invalid)
        );
    }

    #[test]
    fn key_without_address_is_refused() {
        assert_eq!(
            Ticket::new(EndpointAddr::new(id())),
            Err(TicketError::NoAddress)
        );
        assert_eq!(
            Ticket::from_str(&format!("/{}", id())),
            Err(TicketError::Invalid)
        );
    }

    #[test]
    fn garbage_and_truncation() {
        for bad in ["", "hello", "qs1:", "qs1:!!!", "qs1:AAAA", "K7X4-M2QP"] {
            assert!(Ticket::from_str(bad).is_err(), "{bad:?}");
        }

        let text = sample().to_string();
        assert!(Ticket::from_str(&text[..text.len() - 5]).is_err());
    }

    #[test]
    fn unknown_version() {
        assert_eq!(
            Ticket::from_str("qs2:AAAA"),
            Err(TicketError::UnknownVersion("2".to_string()))
        );
        assert_eq!(
            Ticket::from_str("qs17:AAAA"),
            Err(TicketError::UnknownVersion("17".to_string()))
        );
    }
}
