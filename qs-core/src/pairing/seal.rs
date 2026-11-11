//! Key schedule and sealing of what the peers tell each other during pairing.
//!
//! The sender's `EndpointAddr` and the receiver's `EndpointId` are encrypted before they
//! go to the rendezvous server. Only someone who finished the PAKE can open them.
//!
//! DONE: the keys are derived with HKDF-SHA256 from the PAKE output, an ML-KEM-768 shared
//!       secret and a hash of the transcript ([SessionKeys::derive]). An attacker has to
//!       break both the PAKE and the KEM, a recorded pairing stays sealed if only the
//!       classical one falls later.
//! DONE: sealing and opening use ChaCha20-Poly1305 from aws-lc-rs, the provider that also
//!       does the QUIC handshake. Every message has a fresh random nonce, each direction
//!       has its own key, and the transcript is the associated data, so a message cannot
//!       be replayed into another pairing or sent back to its author.
//! DONE: opening with a wrong key fails cleanly ([SealError::Open]), `pairing` reports it
//!       as a wrong code.
//! DONE: [confirmation] proves knowledge of a PAKE key on one specific QUIC connection,
//!       by a MAC over its exporter value. Used for the password in direct mode.
//! DONE: tests: round trip, wrong key, tampered ciphertext, tampered transcript, wrong
//!       direction, KEM round trip and a foreign KEM ciphertext.

use super::pake::{SharedKey, Side};
use aws_lc_rs::{aead, digest, hkdf, hmac, kem};
use thiserror::Error;
use zeroize::Zeroizing;

/// Salt of the key derivation, also the version of the key schedule
const SALT: &[u8] = b"quic-send pairing v1";
/// What the confirmation MAC is computed for
const CONFIRMATION: &[u8] = b"quic-send password confirmation v1";

#[derive(Debug, Error, PartialEq)]
pub enum SealError {
    /// The message was not sealed with this key, or was changed on the way
    #[error("the message could not be opened")]
    Open,
    /// The crypto library refused an operation, for example an invalid public key
    #[error("a cryptographic operation failed")]
    Crypto,
}

/// The secret of a KEM exchange
pub struct KemSecret(Zeroizing<Vec<u8>>);

/// The private half of a KEM key pair, made for one pairing
pub struct KemKey {
    key: kem::DecapsulationKey,
}

impl KemKey {
    /// A fresh key pair. Returns the private half and the public key to send.
    pub fn generate() -> Result<(Self, Vec<u8>), SealError> {
        let key =
            kem::DecapsulationKey::generate(&kem::ML_KEM_768).map_err(|_| SealError::Crypto)?;
        let public = key
            .encapsulation_key()
            .and_then(|public| public.key_bytes())
            .map_err(|_| SealError::Crypto)?;

        Ok((Self { key }, public.as_ref().to_vec()))
    }

    /// The secret the other side put into `ciphertext`.
    ///
    /// A ciphertext that was made for another key does not fail here. It gives a
    /// secret nobody else has, so the keys derived from it open nothing.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<KemSecret, SealError> {
        self.key
            .decapsulate(ciphertext.into())
            .map(|secret| KemSecret(Zeroizing::new(secret.as_ref().to_vec())))
            .map_err(|_| SealError::Crypto)
    }
}

/// Make a secret for the holder of `public`. Returns the ciphertext to send and the secret.
pub fn encapsulate(public: &[u8]) -> Result<(Vec<u8>, KemSecret), SealError> {
    let key =
        kem::EncapsulationKey::new(&kem::ML_KEM_768, public).map_err(|_| SealError::Crypto)?;
    let (ciphertext, secret) = key.encapsulate().map_err(|_| SealError::Crypto)?;

    Ok((
        ciphertext.as_ref().to_vec(),
        KemSecret(Zeroizing::new(secret.as_ref().to_vec())),
    ))
}

/// A hash over everything both sides have to agree on.
///
/// Every part has its length in front, so parts cannot be shifted into each other.
pub fn transcript(parts: &[&[u8]]) -> [u8; 32] {
    let mut context = digest::Context::new(&digest::SHA256);
    for part in parts {
        context.update(&(part.len() as u64).to_be_bytes());
        context.update(part);
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(context.finish().as_ref());
    hash
}

/// Who a sealed message is for
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ToSender,
    ToReceiver,
}

impl Direction {
    fn label(self) -> &'static [u8] {
        match self {
            Direction::ToSender => b"to sender",
            Direction::ToReceiver => b"to receiver",
        }
    }
}

/// Output length for HKDF
struct Length(usize);

impl hkdf::KeyType for Length {
    fn len(&self) -> usize {
        self.0
    }
}

/// The keys of one pairing
pub struct SessionKeys {
    to_sender: Zeroizing<[u8; 32]>,
    to_receiver: Zeroizing<[u8; 32]>,
    transcript: [u8; 32],
}

impl SessionKeys {
    /// Derive the keys. Both secrets and the transcript go in: with a wrong code, a
    /// substituted KEM key or any changed message, the two sides get different keys.
    pub fn derive(
        pake: &SharedKey,
        kem: &KemSecret,
        transcript: &[u8; 32],
    ) -> Result<Self, SealError> {
        let mut secret = Zeroizing::new(Vec::with_capacity(pake.as_bytes().len() + kem.0.len()));
        secret.extend_from_slice(pake.as_bytes());
        secret.extend_from_slice(&kem.0);

        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, SALT).extract(&secret);
        let key = |direction: Direction| -> Result<Zeroizing<[u8; 32]>, SealError> {
            let mut key = Zeroizing::new([0u8; 32]);
            prk.expand(&[direction.label(), transcript], Length(32))
                .and_then(|okm| okm.fill(key.as_mut()))
                .map_err(|_| SealError::Crypto)?;
            Ok(key)
        };

        Ok(Self {
            to_sender: key(Direction::ToSender)?,
            to_receiver: key(Direction::ToReceiver)?,
            transcript: *transcript,
        })
    }

    fn key(&self, direction: Direction) -> Result<aead::LessSafeKey, SealError> {
        let bytes = match direction {
            Direction::ToSender => &self.to_sender,
            Direction::ToReceiver => &self.to_receiver,
        };
        aead::UnboundKey::new(&aead::CHACHA20_POLY1305, bytes.as_ref())
            .map(aead::LessSafeKey::new)
            .map_err(|_| SealError::Crypto)
    }

    /// Encrypt `plaintext` for one direction. The result starts with the nonce.
    pub fn seal(&self, direction: Direction, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        let mut nonce = [0u8; aead::NONCE_LEN];
        aws_lc_rs::rand::fill(&mut nonce).map_err(|_| SealError::Crypto)?;

        let mut sealed = plaintext.to_vec();
        self.key(direction)?
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(self.transcript),
                &mut sealed,
            )
            .map_err(|_| SealError::Crypto)?;

        let mut out = nonce.to_vec();
        out.append(&mut sealed);
        Ok(out)
    }

    /// Decrypt a message that was sealed for `direction`
    pub fn open(&self, direction: Direction, sealed: &[u8]) -> Result<Vec<u8>, SealError> {
        if sealed.len() < aead::NONCE_LEN {
            return Err(SealError::Open);
        }
        let (nonce, ciphertext) = sealed.split_at(aead::NONCE_LEN);
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| SealError::Open)?;

        let mut buffer = ciphertext.to_vec();
        let plaintext = self
            .key(direction)?
            .open_in_place(nonce, aead::Aad::from(self.transcript), &mut buffer)
            .map_err(|_| SealError::Open)?;

        Ok(plaintext.to_vec())
    }
}

fn confirmation_key(key: &SharedKey) -> hmac::Key {
    hmac::Key::new(hmac::HMAC_SHA256, key.as_bytes())
}

fn confirmation_message(exporter: &[u8], side: Side) -> Vec<u8> {
    [CONFIRMATION, b"/", side.label().as_bytes(), b"/", exporter].concat()
}

/// Proof by `side` that it holds `key`, valid only on the connection that `exporter`
/// belongs to. `exporter` is keying material exported from the TLS session, which both
/// ends of one connection share and nobody else can compute.
pub fn confirmation(key: &SharedKey, exporter: &[u8], side: Side) -> Vec<u8> {
    hmac::sign(
        &confirmation_key(key),
        &confirmation_message(exporter, side),
    )
    .as_ref()
    .to_vec()
}

/// Check a [confirmation] of the other side, in constant time
pub fn verify_confirmation(key: &SharedKey, exporter: &[u8], side: Side, proof: &[u8]) -> bool {
    hmac::verify(
        &confirmation_key(key),
        &confirmation_message(exporter, side),
        proof,
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::super::pake::Pake;
    use super::*;

    /// The shared key of a finished exchange, as both sides have it
    fn shared(password: &[u8]) -> (SharedKey, SharedKey) {
        let (a, message_a) = Pake::start(b"test", password).unwrap();
        let (key_b, message_b) = Pake::respond(b"test", password, &message_a).unwrap();
        (a.finish(&message_b).unwrap(), key_b)
    }

    /// The KEM secret as both sides have it
    fn kem_pair() -> (KemSecret, KemSecret) {
        let (key, public) = KemKey::generate().unwrap();
        let (ciphertext, theirs) = encapsulate(&public).unwrap();
        (key.decapsulate(&ciphertext).unwrap(), theirs)
    }

    /// Keys of both sides for a pairing that went well
    fn keys() -> (SessionKeys, SessionKeys) {
        let (pake_a, pake_b) = shared(b"code");
        let (kem_a, kem_b) = kem_pair();
        let transcript = transcript(&[b"slot", b"messages"]);
        (
            SessionKeys::derive(&pake_a, &kem_a, &transcript).unwrap(),
            SessionKeys::derive(&pake_b, &kem_b, &transcript).unwrap(),
        )
    }

    #[test]
    fn kem_round_trip() {
        let (key, public) = KemKey::generate().unwrap();
        // Sizes of ML-KEM-768
        assert_eq!(public.len(), 1184);
        let (ciphertext, theirs) = encapsulate(&public).unwrap();
        assert_eq!(ciphertext.len(), 1088);
        assert_eq!(key.decapsulate(&ciphertext).unwrap().0, theirs.0);
    }

    #[test]
    fn kem_ciphertext_for_another_key_gives_another_secret() {
        let (key, _) = KemKey::generate().unwrap();
        let (_, other_public) = KemKey::generate().unwrap();
        let (ciphertext, theirs) = encapsulate(&other_public).unwrap();
        assert_ne!(key.decapsulate(&ciphertext).unwrap().0, theirs.0);
    }

    #[test]
    fn invalid_kem_input_is_refused() {
        assert_eq!(encapsulate(b"too short").err(), Some(SealError::Crypto));
        let (key, _) = KemKey::generate().unwrap();
        assert!(key.decapsulate(b"too short").is_err());
    }

    #[test]
    fn seal_round_trip() {
        let (sender, receiver) = keys();
        let sealed = receiver.seal(Direction::ToSender, b"receiver id").unwrap();
        assert_eq!(
            sender.open(Direction::ToSender, &sealed).unwrap(),
            b"receiver id"
        );

        let sealed = sender
            .seal(Direction::ToReceiver, b"sender address")
            .unwrap();
        assert_eq!(
            receiver.open(Direction::ToReceiver, &sealed).unwrap(),
            b"sender address"
        );
    }

    #[test]
    fn sealing_twice_gives_different_ciphertexts() {
        let (sender, _) = keys();
        let first = sender.seal(Direction::ToReceiver, b"same").unwrap();
        let second = sender.seal(Direction::ToReceiver, b"same").unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn wrong_code_cannot_open() {
        let (pake_a, _) = shared(b"right code");
        let (_, pake_b) = shared(b"wrong code");
        let (kem_a, kem_b) = kem_pair();
        let transcript = transcript(&[b"slot"]);
        let sender = SessionKeys::derive(&pake_a, &kem_a, &transcript).unwrap();
        let receiver = SessionKeys::derive(&pake_b, &kem_b, &transcript).unwrap();

        let sealed = receiver.seal(Direction::ToSender, b"receiver id").unwrap();
        assert_eq!(
            sender.open(Direction::ToSender, &sealed),
            Err(SealError::Open)
        );
    }

    #[test]
    fn substituted_kem_key_cannot_open() {
        // The PAKE went well, but someone in the middle replaced the KEM key and so
        // the two sides have different KEM secrets
        let (pake_a, pake_b) = shared(b"code");
        let (kem_a, _) = kem_pair();
        let (_, kem_b) = kem_pair();
        let transcript = transcript(&[b"slot"]);
        let sender = SessionKeys::derive(&pake_a, &kem_a, &transcript).unwrap();
        let receiver = SessionKeys::derive(&pake_b, &kem_b, &transcript).unwrap();

        let sealed = receiver.seal(Direction::ToSender, b"receiver id").unwrap();
        assert_eq!(
            sender.open(Direction::ToSender, &sealed),
            Err(SealError::Open)
        );
    }

    #[test]
    fn changed_transcript_cannot_open() {
        let (pake_a, pake_b) = shared(b"code");
        let (kem_a, kem_b) = kem_pair();
        let sender = SessionKeys::derive(&pake_a, &kem_a, &transcript(&[b"slot A"])).unwrap();
        let receiver = SessionKeys::derive(&pake_b, &kem_b, &transcript(&[b"slot B"])).unwrap();

        let sealed = receiver.seal(Direction::ToSender, b"receiver id").unwrap();
        assert_eq!(
            sender.open(Direction::ToSender, &sealed),
            Err(SealError::Open)
        );
    }

    #[test]
    fn tampered_or_truncated_message_cannot_open() {
        let (sender, receiver) = keys();
        let sealed = receiver.seal(Direction::ToSender, b"receiver id").unwrap();

        for index in [0, aead::NONCE_LEN, sealed.len() - 1] {
            let mut tampered = sealed.clone();
            tampered[index] ^= 1;
            assert_eq!(
                sender.open(Direction::ToSender, &tampered),
                Err(SealError::Open),
                "byte {index}"
            );
        }

        assert_eq!(
            sender.open(Direction::ToSender, &sealed[..sealed.len() - 1]),
            Err(SealError::Open)
        );
        assert_eq!(sender.open(Direction::ToSender, &[]), Err(SealError::Open));
        assert_eq!(
            sender.open(Direction::ToSender, &[0; 5]),
            Err(SealError::Open)
        );
    }

    #[test]
    fn message_cannot_be_reflected() {
        // What the receiver sealed for the sender does not open as a message to the receiver
        let (_, receiver) = keys();
        let sealed = receiver.seal(Direction::ToSender, b"receiver id").unwrap();
        assert_eq!(
            receiver.open(Direction::ToReceiver, &sealed),
            Err(SealError::Open)
        );
    }

    #[test]
    fn transcript_keeps_parts_apart() {
        assert_ne!(transcript(&[b"ab", b"c"]), transcript(&[b"a", b"bc"]));
        assert_ne!(transcript(&[b"abc"]), transcript(&[b"abc", b""]));
        assert_eq!(transcript(&[b"ab", b"c"]), transcript(&[b"ab", b"c"]));
    }

    #[test]
    fn confirmation_is_bound_to_key_connection_and_side() {
        let (key_a, key_b) = shared(b"password");
        let (other, _) = shared(b"other password");
        let exporter = b"exported from this connection";

        let proof = confirmation(&key_a, exporter, Side::Receiver);
        assert!(verify_confirmation(
            &key_b,
            exporter,
            Side::Receiver,
            &proof
        ));

        // Wrong password, another connection, the other side's label, a damaged proof
        assert!(!verify_confirmation(
            &other,
            exporter,
            Side::Receiver,
            &proof
        ));
        assert!(!verify_confirmation(
            &key_b,
            b"another connection",
            Side::Receiver,
            &proof
        ));
        assert!(!verify_confirmation(&key_b, exporter, Side::Sender, &proof));
        assert!(!verify_confirmation(
            &key_b,
            exporter,
            Side::Receiver,
            &proof[1..]
        ));
        assert!(!verify_confirmation(&key_b, exporter, Side::Receiver, &[]));
    }
}
