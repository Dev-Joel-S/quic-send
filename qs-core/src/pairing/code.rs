//! The short code: generation, display and parsing.
//!
//! Crockford Base32 (no I, L, O, U), 8 characters, shown as `K7X4-M2QP`.
//! The code is split into a public part and a secret part:
//! - the nameplate (first 2 characters) selects a slot on the rendezvous server and is
//!   sent to it
//! - the secret (last 6 characters, 30 bits) is the PAKE password and never leaves the
//!   machine
//!
//! The split matters. If the slot were derived from the whole code, a hostile
//! server could try all 2^40 codes offline and recover the secret.
//!
//! DONE: the secret is generated with the random number generator of the operating system
//!       ([Code::generate_secret]).
//! DONE: the split is 2 + 6. The server hands out the nameplate, so two senders never
//!       collide. An attacker gets one guess per code, with a chance of one in a billion.
//!       Changing the split means changing [SECRET_LEN] here and `NAMEPLATE_LEN` in
//!       `qs-rendezvous-api`.
//! DONE: input is parsed case insensitive, with or without the dash, and with Crockford's
//!       substitutions (I and L become 1, O becomes 0).
//! DONE: wrong length and invalid characters are separate errors ([CodeError]).
//! DONE: tests: round trip, substitutions, dash and case handling, wrong length.

use qs_rendezvous_api::{is_nameplate, ALPHABET, NAMEPLATE_LEN};
use std::{fmt, str::FromStr};
use thiserror::Error;
use zeroize::Zeroizing;

/// Characters of the secret part of a code
pub const SECRET_LEN: usize = 6;
/// Characters of a whole code
pub const CODE_LEN: usize = NAMEPLATE_LEN + SECRET_LEN;

#[derive(Debug, Error, PartialEq)]
pub enum CodeError {
    #[error("a code has {CODE_LEN} characters, this one has {0}")]
    WrongLength(usize),
    #[error("the character {0:?} cannot be part of a code")]
    InvalidCharacter(char),
    #[error("no secure random numbers are available on this system")]
    Random,
}

/// A short code that pairs a sender with a receiver
#[derive(Clone, PartialEq)]
pub struct Code {
    nameplate: String,
    secret: Zeroizing<String>,
}

impl Code {
    /// A fresh random secret part
    pub fn generate_secret() -> Result<Zeroizing<String>, CodeError> {
        let mut random = Zeroizing::new([0u8; SECRET_LEN]);
        aws_lc_rs::rand::fill(random.as_mut()).map_err(|_| CodeError::Random)?;

        // 256 is a multiple of 32, so every character is equally likely
        let secret = random
            .iter()
            .map(|byte| ALPHABET[(byte % 32) as usize] as char)
            .collect();
        Ok(Zeroizing::new(secret))
    }

    /// Put a code together from the nameplate the server handed out and a secret
    pub fn new(nameplate: &str, secret: Zeroizing<String>) -> Result<Self, CodeError> {
        let mut code = String::with_capacity(CODE_LEN);
        code.push_str(nameplate);
        code.push_str(&secret);
        code.parse()
    }

    /// The public part, which selects the slot on the rendezvous server
    pub fn nameplate(&self) -> &str {
        &self.nameplate
    }

    /// The secret part, which only the two peers may know
    pub fn secret(&self) -> &str {
        &self.secret
    }
}

/// Whether `input` is short and plain enough to be meant as a code, valid or not.
/// A ticket is much longer and has punctuation.
pub fn looks_like_code(input: &str) -> bool {
    let relevant = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .count();

    relevant <= CODE_LEN * 2
        && input
            .chars()
            .all(|c| c.is_alphanumeric() || c.is_whitespace() || c == '-')
}

/// `K7X4-M2QP`
impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (first, second) = self.secret.split_at(CODE_LEN / 2 - NAMEPLATE_LEN);
        write!(f, "{}{first}-{second}", self.nameplate)
    }
}

/// Never shows the secret, so a code can end up in a log without harm
impl fmt::Debug for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Code({}******)", self.nameplate)
    }
}

impl FromStr for Code {
    type Err = CodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut code = Zeroizing::new(String::with_capacity(CODE_LEN));

        for c in s.chars() {
            if c.is_whitespace() || c == '-' {
                continue;
            }

            // Characters that are easily confused when read or typed
            let normalized = match c.to_ascii_uppercase() {
                'I' | 'L' => '1',
                'O' => '0',
                other => other,
            };

            if !normalized.is_ascii() || !ALPHABET.contains(&(normalized as u8)) {
                return Err(CodeError::InvalidCharacter(c));
            }
            code.push(normalized);
        }

        if code.len() != CODE_LEN {
            return Err(CodeError::WrongLength(code.len()));
        }

        let (nameplate, secret) = code.split_at(NAMEPLATE_LEN);
        debug_assert!(is_nameplate(nameplate));

        Ok(Self {
            nameplate: nameplate.to_string(),
            secret: Zeroizing::new(secret.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn code(s: &str) -> Code {
        s.parse().unwrap()
    }

    #[test]
    fn round_trip() {
        let parsed = code("K7X4-M2QP");
        assert_eq!(parsed.nameplate(), "K7");
        assert_eq!(parsed.secret(), "X4M2QP");
        assert_eq!(parsed.to_string(), "K7X4-M2QP");
        assert_eq!(code(&parsed.to_string()), parsed);
    }

    #[test]
    fn dash_case_and_spaces_do_not_matter() {
        let expected = code("K7X4-M2QP");
        for input in ["K7X4M2QP", "k7x4-m2qp", " k7x4 m2qp\n", "K-7-X-4-M-2-Q-P"] {
            assert_eq!(code(input), expected, "{input:?}");
        }
    }

    #[test]
    fn confusable_characters_are_substituted() {
        assert_eq!(code("ILOilo11"), code("11011011"));
        assert_eq!(code("O0O0-L1L1").to_string(), "0000-1111");
    }

    #[test]
    fn wrong_length() {
        assert_eq!("".parse::<Code>(), Err(CodeError::WrongLength(0)));
        assert_eq!("K7X4-M2Q".parse::<Code>(), Err(CodeError::WrongLength(7)));
        assert_eq!("K7X4-M2QPP".parse::<Code>(), Err(CodeError::WrongLength(9)));
    }

    #[test]
    fn invalid_characters() {
        // U is not in the alphabet and has no substitute
        assert_eq!(
            "K7X4-M2QU".parse::<Code>(),
            Err(CodeError::InvalidCharacter('U'))
        );
        assert_eq!(
            "K7X4_M2QP".parse::<Code>(),
            Err(CodeError::InvalidCharacter('_'))
        );
        assert_eq!(
            "K7X4-M2QÄ".parse::<Code>(),
            Err(CodeError::InvalidCharacter('Ä'))
        );
    }

    #[test]
    fn generated_secrets_are_valid_and_differ() {
        let a = Code::generate_secret().unwrap();
        let b = Code::generate_secret().unwrap();
        assert_eq!(a.len(), SECRET_LEN);
        assert!(a.bytes().all(|c| ALPHABET.contains(&c)));
        // Equal with a chance of one in a billion
        assert_ne!(a, b);

        let code = Code::new("K7", a.clone()).unwrap();
        assert_eq!(code.nameplate(), "K7");
        assert_eq!(code.secret(), a.as_str());
    }

    #[test]
    fn invalid_nameplate_from_the_server_is_refused() {
        let secret = || Zeroizing::new("X4M2QP".to_string());
        assert!(Code::new("K", secret()).is_err());
        assert!(Code::new("K7X", secret()).is_err());
        assert!(Code::new("K!", secret()).is_err());
    }

    #[test]
    fn debug_hides_the_secret() {
        let debug = format!("{:?}", code("K7X4-M2QP"));
        assert!(debug.contains("K7"));
        assert!(!debug.contains("X4"));
        assert!(!debug.contains("M2QP"));
    }

    #[test]
    fn telling_codes_from_tickets() {
        for input in ["K7X4-M2QP", "k7x4m2qp", "K7X4-M2Q", "K7X4 M2QP1", "hello"] {
            assert!(looks_like_code(input), "{input:?}");
        }
        for input in [
            "qs1:TYXpn-lm8ladLNDYvhrI_nKROlu2vy2HvxDI6Ync2pIBAQDAAAICme8C",
            "192.168.1.5:4433/4d85e99fe966f2569d2cd0d8be1ac8fe72913a5bb6bf2d87bf10c8e989dcda92",
            "4d85e99fe966f2569d2cd0d8be1ac8fe72913a5bb6bf2d87bf10c8e989dcda92",
        ] {
            assert!(!looks_like_code(input), "{input:?}");
        }
    }
}
