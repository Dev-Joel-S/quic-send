//! Wire format of the quic-send rendezvous server, shared by the server
//! (`qs-rendezvous`) and the client (`qs_core::pairing::rendezvous`).
//!
//! The server is an untrusted mailbox. Two peers that share a short code exchange
//! three opaque messages through one slot:
//!
//! | Step | Request | Who | Body |
//! |------|---------|-----|------|
//! | 1 | `POST /v1/slots` | sender | its first message, gets a nameplate and a token |
//! | 2 | `POST /v1/slots/{nameplate}/claim` | receiver | gets the first message and a token, only once per slot |
//! | 3 | `PUT /v1/slots/{nameplate}/reply` | receiver | its reply |
//! | 4 | `GET /v1/slots/{nameplate}/reply` | sender | waits for the reply |
//! | 5 | `PUT /v1/slots/{nameplate}/address` | sender | its sealed address |
//! | 6 | `GET /v1/slots/{nameplate}/address` | receiver | waits for the address, the slot is gone afterwards |
//! | any | `DELETE /v1/slots/{nameplate}` | either | gives up |
//!
//! Requests after the first carry `Authorization: Bearer <token>`. `GET` requests take
//! `?wait=<seconds>` and answer `204 No Content` if nothing arrived in that time.
//! Bodies are JSON, binary messages are base64 (url safe, no padding).
//! Errors are a JSON [ErrorBody] with a fitting HTTP status.

use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The alphabet of codes and nameplates: Crockford Base32, without I, L, O and U
pub const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Characters of a nameplate. With the alphabet above that is 1024 slots at once.
/// Changing this also means changing `SECRET_LEN` in `qs_core::pairing::code`, the two
/// add up to the length of a code.
pub const NAMEPLATE_LEN: usize = 2;
/// Largest message a slot stores, before base64
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;
/// Longest a `GET` may wait for a message
pub const MAX_WAIT_SECS: u64 = 25;

/// Path of the slot collection
pub const SLOTS_PATH: &str = "/v1/slots";
/// Path that tells what the server is
pub const INFO_PATH: &str = "/v1";
/// What [ServerInfo::service] has to say
pub const SERVICE_NAME: &str = "quic-send-rendezvous";
/// The version of this API
pub const API_VERSION: u32 = 1;

/// Path of a slot
pub fn slot_path(nameplate: &str) -> String {
    format!("{SLOTS_PATH}/{nameplate}")
}

/// Path to claim a slot
pub fn claim_path(nameplate: &str) -> String {
    format!("{SLOTS_PATH}/{nameplate}/claim")
}

/// Path of the reply of the receiver
pub fn reply_path(nameplate: &str) -> String {
    format!("{SLOTS_PATH}/{nameplate}/reply")
}

/// Path of the sealed address of the sender
pub fn address_path(nameplate: &str) -> String {
    format!("{SLOTS_PATH}/{nameplate}/address")
}

/// Whether `nameplate` has the right length and only characters of the [ALPHABET]
pub fn is_nameplate(nameplate: &str) -> bool {
    nameplate.len() == NAMEPLATE_LEN && nameplate.bytes().all(|b| ALPHABET.contains(&b))
}

/// An opaque message, the server never looks inside
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    #[serde(with = "base64_bytes")]
    pub message: Vec<u8>,
}

/// Answer to creating a slot
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlotCreated {
    pub nameplate: String,
    /// Authorizes the sender's later requests for this slot
    pub token: String,
    /// Seconds until the slot expires if nobody claims it
    pub expires_in: u64,
}

/// Answer to claiming a slot
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlotClaimed {
    /// The first message of the sender
    #[serde(with = "base64_bytes")]
    pub message: Vec<u8>,
    /// Authorizes the receiver's later requests for this slot
    pub token: String,
    /// Seconds until the slot expires
    pub expires_in: u64,
}

/// Answer to asking the server what it is
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerInfo {
    pub service: String,
    pub api: u32,
}

/// Why a request failed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// No slot with this nameplate, and none that ended recently
    UnknownSlot,
    /// The slot was already claimed or completed
    SlotUsed,
    /// Nobody claimed the slot in time
    SlotExpired,
    /// One side gave up
    SlotClosed,
    /// Missing or wrong token
    Forbidden,
    /// The message is larger than [MAX_MESSAGE_BYTES]
    TooLarge,
    /// Every nameplate is taken
    NoFreeSlot,
    /// Too many requests from this address
    RateLimited,
    /// The request makes no sense at this point
    BadRequest,
}

/// Body of an error response
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ErrorCode,
}

mod base64_bytes {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64_URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        BASE64_URL_SAFE_NO_PAD
            .decode(text)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_is_base64_in_json() {
        let message = Message {
            message: vec![0, 255, 16],
        };
        let json = serde_json::to_string(&message).unwrap();
        assert_eq!(json, r#"{"message":"AP8Q"}"#);
        assert_eq!(serde_json::from_str::<Message>(&json).unwrap(), message);
        assert!(serde_json::from_str::<Message>(r#"{"message":"***"}"#).is_err());
    }

    #[test]
    fn error_codes_are_snake_case() {
        let body = ErrorBody {
            error: ErrorCode::SlotUsed,
        };
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"error":"slot_used"}"#
        );
    }

    #[test]
    fn nameplates() {
        assert!(is_nameplate("K7"));
        assert!(is_nameplate("00"));
        for bad in ["", "K", "K7X", "k7", "KI", "KO", "K-", "ÄÄ"] {
            assert!(!is_nameplate(bad), "{bad:?}");
        }
    }
}
