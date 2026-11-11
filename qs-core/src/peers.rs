//! A stable identity and pinned peers, so repeat transfers need no code.
//!
//! Normally every run uses a fresh key, so nothing links two transfers of the same
//! machine. To recognize a peer again both sides need a key that stays: the identity
//! in this module. It is only used when a peer is saved or a saved peer is used.
//!
//! DONE: privacy: the ephemeral key stays the default. The stored key is only used with
//!       `--save-peer`, `--to` and `--from`. A stable id can be recognized by the relay,
//!       which is the price of not needing a code.
//! DONE: the secret key is kept in `identity.key` in the config directory, readable only
//!       for the user: mode 0600 on Unix, an access list with the own user as its only
//!       entry on Windows (`crate::private_file`). A file that has more access is
//!       tightened when it is loaded. The key is never printed, and an unreadable file is
//!       an error, never silently replaced by a new key.
//! DONE: the identity can be sealed with a passphrase ([set_identity_passphrase]), for
//!       everything file permissions do not stop: an administrator, a backup, a disk that
//!       is read from another system. The key for that comes from the passphrase with
//!       PBKDF2-HMAC-SHA256, the file is sealed with ChaCha20-Poly1305, both from
//!       aws-lc-rs. The settings of the key derivation are part of what is sealed.
//! DONE: known peers: alias to id and last known address, saved after a transfer where
//!       both sides asked for it ([PeerStore]). The pin is the public key, so this stays
//!       zero trust: no server is involved in recognizing the peer.
//! DONE: a pinned peer is found again at the address it announced when it was saved:
//!       its relay and its IP addresses. If it moved, pair once more with a code or
//!       ticket and `--save-peer` to refresh it.
//! DONE: the sender accepts only the expected `EndpointId` when it knows one
//!       (`send::SenderArgs::expected_peer`), refuses everyone else, and refuses every
//!       further connection once its receiver is in. A receiver that waits for a saved
//!       peer does the same (`receive::Receiver::accept`).
//! DONE: tests: alias lookup, unknown alias, a changed key for a known alias is a loud
//!       error and not silently replaced, the identity survives a restart.
//! TODO: PBKDF2 is the password hash aws-lc-rs has. A memory-hard one (Argon2id, scrypt)
//!       would slow down guessing on graphics cards more, but would come from a crate
//!       without an audit.
//! TODO: a receiver that keeps listening for several transfers (a daemon for a homelab).
//! TODO: address lookup for a peer whose relay or address changed.

use crate::{pairing::pake::normalize_password, private_file};
use aws_lc_rs::{aead, pbkdf2};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use iroh::{EndpointAddr, EndpointId, RelayUrl, SecretKey};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io,
    net::SocketAddr,
    num::NonZeroU32,
    path::{Path, PathBuf},
    str::FromStr,
};
use thiserror::Error;
use zeroize::Zeroizing;

/// File with the secret key of the stable identity
const IDENTITY_FILE: &str = "identity.key";
/// File with the saved peers
const PEERS_FILE: &str = "known_peers.json";
/// What a sealed identity file says it is, also the version of its format
const SEALED_FORMAT: &str = "quic-send identity v1";
/// The only key derivation there is so far
const SEALED_KDF: &str = "pbkdf2-hmac-sha256";
/// Rounds of the key derivation for a new file. What OWASP recommends for this function.
const KDF_ROUNDS: u32 = 600_000;
/// Rounds a file may ask for. Fewer would make guessing cheap, more is a file that only
/// wants to keep this program busy.
const KDF_ROUNDS_ALLOWED: std::ops::RangeInclusive<u32> = 100_000..=10_000_000;

#[derive(Debug, Error)]
pub enum PeerError {
    #[error("{}: {source}", path.display())]
    Io { path: PathBuf, source: io::Error },
    #[error(
        "the identity file {} is damaged. Fix or remove it, a new identity means every \
         peer that saved this device has to save it again",
        .0.display()
    )]
    DamagedIdentity(PathBuf),
    #[error("the identity is protected with a passphrase, which is needed to use it")]
    PassphraseRequired,
    #[error("wrong passphrase for the identity")]
    WrongPassphrase,
    #[error("the identity could not be sealed, the system gave no random numbers")]
    Random,
    #[error("the file with the saved peers, {}, is damaged: {message}", path.display())]
    DamagedStore { path: PathBuf, message: String },
    #[error("no peer is saved as {0:?}. `qsend peers` lists the saved ones")]
    Unknown(String),
    #[error(
        "{alias:?} is already saved with another identity ({saved}), this one is {offered}. \
         If that is intended, remove it first with `qsend peers remove {alias}`"
    )]
    Changed {
        alias: String,
        saved: String,
        offered: String,
    },
    #[error("{0:?} is not a valid name for a peer: use letters, digits, `-` and `_`")]
    InvalidAlias(String),
    #[error("no address is known for {0:?}. Pair once with a code or ticket and --save-peer")]
    NoAddress(String),
}

fn io_error(path: &Path) -> impl FnOnce(io::Error) -> PeerError + '_ {
    move |source| PeerError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// What is in the identity file
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityState {
    /// There is no identity yet
    Missing,
    /// The key is stored as it is, protected by the access rights of the file
    Plain,
    /// The key is sealed with a passphrase
    Sealed,
}

/// An identity file that is sealed with a passphrase. Binary fields are base64.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedIdentity {
    format: String,
    kdf: String,
    rounds: u32,
    salt: String,
    nonce: String,
    key: String,
}

impl SealedIdentity {
    /// Everything about the file that is not the sealed key itself. It is authenticated
    /// together with the key, so nobody can lower the rounds of a file unnoticed.
    fn header(&self) -> Vec<u8> {
        format!(
            "{}\n{}\n{}\n{}",
            self.format, self.kdf, self.rounds, self.salt
        )
        .into_bytes()
    }

    /// The key that seals the file, from the passphrase
    fn sealing_key(&self, passphrase: &str) -> Option<aead::LessSafeKey> {
        let salt = BASE64_URL_SAFE_NO_PAD.decode(&self.salt).ok()?;
        let passphrase = normalize_password(passphrase);

        let mut key = Zeroizing::new([0u8; 32]);
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(self.rounds)?,
            &salt,
            passphrase.as_bytes(),
            key.as_mut(),
        );

        let key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key.as_ref()).ok()?;
        Some(aead::LessSafeKey::new(key))
    }

    fn seal(secret: &SecretKey, passphrase: &str) -> Result<Self, PeerError> {
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; aead::NONCE_LEN];
        aws_lc_rs::rand::fill(&mut salt).map_err(|_| PeerError::Random)?;
        aws_lc_rs::rand::fill(&mut nonce).map_err(|_| PeerError::Random)?;

        let mut sealed = Self {
            format: SEALED_FORMAT.to_string(),
            kdf: SEALED_KDF.to_string(),
            rounds: KDF_ROUNDS,
            salt: BASE64_URL_SAFE_NO_PAD.encode(salt),
            nonce: BASE64_URL_SAFE_NO_PAD.encode(nonce),
            key: String::new(),
        };

        let mut bytes = Zeroizing::new(secret.to_bytes().to_vec());
        sealed
            .sealing_key(passphrase)
            .ok_or(PeerError::Random)?
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(sealed.header()),
                &mut *bytes,
            )
            .map_err(|_| PeerError::Random)?;
        sealed.key = BASE64_URL_SAFE_NO_PAD.encode(&*bytes);

        Ok(sealed)
    }

    /// The key, if `passphrase` is the right one. [None] for a file that makes no sense.
    fn open(&self, passphrase: &str) -> Option<Result<SecretKey, PeerError>> {
        if self.format != SEALED_FORMAT
            || self.kdf != SEALED_KDF
            || !KDF_ROUNDS_ALLOWED.contains(&self.rounds)
        {
            return None;
        }
        let nonce = BASE64_URL_SAFE_NO_PAD.decode(&self.nonce).ok()?;
        let nonce = aead::Nonce::try_assume_unique_for_key(&nonce).ok()?;
        let mut bytes = Zeroizing::new(BASE64_URL_SAFE_NO_PAD.decode(&self.key).ok()?);
        let key = self.sealing_key(passphrase)?;

        let Ok(plain) = key.open_in_place(nonce, aead::Aad::from(self.header()), &mut bytes) else {
            return Some(Err(PeerError::WrongPassphrase));
        };
        let plain: &[u8; 32] = (&*plain).try_into().ok()?;
        Some(Ok(SecretKey::from_bytes(plain)))
    }
}

/// The identity file as text, or [None] if there is none
fn read_identity(path: &Path) -> Result<Option<Zeroizing<String>>, PeerError> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            // A file from before the access rights were set, or one that was copied
            // around: tighten it. If that fails the key is still usable.
            if !private_file::is_private(path).unwrap_or(true) {
                if let Err(e) = private_file::restrict(path) {
                    tracing::debug!("could not restrict access to the identity file: {e}");
                }
            }
            Ok(Some(Zeroizing::new(text)))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_error(path)(e)),
    }
}

fn write_identity(
    path: &Path,
    secret: &SecretKey,
    passphrase: Option<&str>,
) -> Result<(), PeerError> {
    // The copies made for writing are wiped, the key itself wipes on drop
    let text = match passphrase {
        Some(passphrase) => {
            let sealed = SealedIdentity::seal(secret, passphrase)?;
            Zeroizing::new(serde_json::to_string_pretty(&sealed).unwrap_or_default())
        }
        None => {
            let bytes = Zeroizing::new(secret.to_bytes());
            let mut text = Zeroizing::new(String::with_capacity(bytes.len() * 2));
            for byte in bytes.iter() {
                text.push_str(&format!("{byte:02x}"));
            }
            text
        }
    };

    private_file::write(path, text.as_bytes()).map_err(io_error(path))
}

/// Whether `dir` has an identity, and whether a passphrase is needed for it
pub fn identity_state(dir: &Path) -> Result<IdentityState, PeerError> {
    Ok(match read_identity(&dir.join(IDENTITY_FILE))? {
        None => IdentityState::Missing,
        Some(text) if text.trim_start().starts_with('{') => IdentityState::Sealed,
        Some(_) => IdentityState::Plain,
    })
}

/// The secret key of this device's stable identity, from `dir`. Made up on first use.
///
/// `passphrase` is needed for an identity that is sealed with one, see [identity_state].
/// A new identity is not sealed, [set_identity_passphrase] does that.
pub fn load_or_create_identity(
    dir: &Path,
    passphrase: Option<&str>,
) -> Result<SecretKey, PeerError> {
    let path = dir.join(IDENTITY_FILE);

    let Some(text) = read_identity(&path)? else {
        let key = SecretKey::generate();
        write_identity(&path, &key, None)?;
        return Ok(key);
    };

    if !text.trim_start().starts_with('{') {
        return SecretKey::from_str(text.trim()).map_err(|_| PeerError::DamagedIdentity(path));
    }

    let Ok(sealed) = serde_json::from_str::<SealedIdentity>(&text) else {
        return Err(PeerError::DamagedIdentity(path));
    };
    let passphrase = passphrase.ok_or(PeerError::PassphraseRequired)?;
    sealed
        .open(passphrase)
        .unwrap_or(Err(PeerError::DamagedIdentity(path)))
}

/// Store the identity `secret` in `dir` sealed with `passphrase`, or as it is with [None].
///
/// `secret` is the key from [load_or_create_identity], so the caller has shown that it
/// may use the identity before it changes how it is kept.
pub fn set_identity_passphrase(
    dir: &Path,
    secret: &SecretKey,
    passphrase: Option<&str>,
) -> Result<(), PeerError> {
    write_identity(&dir.join(IDENTITY_FILE), secret, passphrase)
}

/// A peer that was saved under an alias
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KnownPeer {
    /// The pin: only the holder of this key is this peer
    pub id: EndpointId,
    /// The relay it was reachable through when it was saved
    #[serde(default)]
    pub relay: Option<RelayUrl>,
    /// The IP addresses it had when it was saved
    #[serde(default)]
    pub addresses: Vec<SocketAddr>,
}

impl KnownPeer {
    /// A peer of which only the id is known
    pub fn from_id(id: EndpointId) -> Self {
        Self {
            id,
            relay: None,
            addresses: Vec::new(),
        }
    }

    /// The address to reach the peer at
    pub fn addr(&self) -> EndpointAddr {
        let mut addr = EndpointAddr::new(self.id);
        if let Some(relay) = &self.relay {
            addr = addr.with_relay_url(relay.clone());
        }
        for ip in &self.addresses {
            addr = addr.with_ip_addr(*ip);
        }
        addr
    }
}

impl From<&EndpointAddr> for KnownPeer {
    fn from(addr: &EndpointAddr) -> Self {
        Self {
            id: addr.id,
            relay: addr.relay_urls().next().cloned(),
            addresses: addr.ip_addrs().copied().collect(),
        }
    }
}

/// Aliases are typed on the command line and shown in messages, so they are kept simple
fn check_alias(alias: &str) -> Result<(), PeerError> {
    let valid = !alias.is_empty()
        && alias.len() <= 64
        && alias
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_');
    if valid {
        Ok(())
    } else {
        Err(PeerError::InvalidAlias(alias.to_string()))
    }
}

/// The saved peers of this device
#[derive(Debug)]
pub struct PeerStore {
    path: PathBuf,
    peers: BTreeMap<String, KnownPeer>,
}

impl PeerStore {
    /// Load the saved peers from `dir`. No file means no peers.
    pub fn load(dir: &Path) -> Result<Self, PeerError> {
        let path = dir.join(PEERS_FILE);

        let peers = match std::fs::read(&path) {
            Ok(data) => serde_json::from_slice(&data).map_err(|e| PeerError::DamagedStore {
                path: path.clone(),
                message: e.to_string(),
            })?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(io_error(&path)(e)),
        };

        Ok(Self { path, peers })
    }

    /// All saved peers by alias
    pub fn peers(&self) -> &BTreeMap<String, KnownPeer> {
        &self.peers
    }

    /// The peer saved as `alias`
    pub fn get(&self, alias: &str) -> Result<&KnownPeer, PeerError> {
        self.peers
            .get(alias)
            .ok_or_else(|| PeerError::Unknown(alias.to_string()))
    }

    /// Save `peer` as `alias`.
    ///
    /// An alias that is already taken by another identity is not overwritten: that is
    /// either a mistake or somebody posing as the peer, and has to be resolved by hand.
    /// For the same identity the address is brought up to date.
    pub fn save(&mut self, alias: &str, peer: KnownPeer) -> Result<(), PeerError> {
        check_alias(alias)?;

        if let Some(saved) = self.peers.get(alias) {
            if saved.id != peer.id {
                return Err(PeerError::Changed {
                    alias: alias.to_string(),
                    saved: saved.id.fmt_short().to_string(),
                    offered: peer.id.fmt_short().to_string(),
                });
            }
        }

        self.peers.insert(alias.to_string(), peer);
        self.write()
    }

    /// Forget the peer saved as `alias`
    pub fn remove(&mut self, alias: &str) -> Result<(), PeerError> {
        if self.peers.remove(alias).is_none() {
            return Err(PeerError::Unknown(alias.to_string()));
        }
        self.write()
    }

    fn write(&self) -> Result<(), PeerError> {
        let data = serde_json::to_vec_pretty(&self.peers).map_err(|e| PeerError::DamagedStore {
            path: self.path.clone(),
            message: e.to_string(),
        })?;
        private_file::write(&self.path, &data).map_err(io_error(&self.path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn peer() -> KnownPeer {
        KnownPeer {
            id: SecretKey::generate().public(),
            relay: Some(RelayUrl::from_str("https://relay.example.com").unwrap()),
            addresses: vec!["192.168.1.5:4433".parse().unwrap()],
        }
    }

    #[test]
    fn identity_is_created_once_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let first = load_or_create_identity(dir.path(), None).unwrap();
        let second = load_or_create_identity(dir.path(), None).unwrap();
        assert_eq!(first.public(), second.public());

        // Another directory is another device
        let other = tempfile::tempdir().unwrap();
        let third = load_or_create_identity(other.path(), None).unwrap();
        assert_ne!(first.public(), third.public());
    }

    #[cfg(unix)]
    #[test]
    fn identity_file_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        load_or_create_identity(dir.path(), None).unwrap();
        let mode = std::fs::metadata(dir.path().join(IDENTITY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn identity_file_is_only_for_the_user() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(IDENTITY_FILE);

        load_or_create_identity(dir.path(), None).unwrap();
        assert!(!private_file::can_check() || private_file::is_private(&path).unwrap());

        // A file that somebody opened up is closed again when it is used
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(!private_file::is_private(&path).unwrap());
            load_or_create_identity(dir.path(), None).unwrap();
            assert!(private_file::is_private(&path).unwrap());
        }
    }

    #[test]
    fn identity_can_be_sealed_with_a_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(IDENTITY_FILE);
        assert_eq!(identity_state(dir.path()).unwrap(), IdentityState::Missing);

        let key = load_or_create_identity(dir.path(), None).unwrap();
        assert_eq!(identity_state(dir.path()).unwrap(), IdentityState::Plain);
        let plain = std::fs::read_to_string(&path).unwrap();

        set_identity_passphrase(dir.path(), &key, Some("correct horse")).unwrap();
        assert_eq!(identity_state(dir.path()).unwrap(), IdentityState::Sealed);
        assert!(!private_file::can_check() || private_file::is_private(&path).unwrap());
        // The key is no longer in the file
        let sealed = std::fs::read_to_string(&path).unwrap();
        assert!(!sealed.contains(plain.trim()));

        // Without the passphrase, and with a wrong one, there is no key and no new identity
        assert!(matches!(
            load_or_create_identity(dir.path(), None),
            Err(PeerError::PassphraseRequired)
        ));
        assert!(matches!(
            load_or_create_identity(dir.path(), Some("correct horse ")),
            Err(PeerError::WrongPassphrase)
        ));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), sealed);

        let again = load_or_create_identity(dir.path(), Some("correct horse")).unwrap();
        assert_eq!(again.public(), key.public());

        // Sealing twice with the same passphrase gives another file: fresh salt and nonce
        set_identity_passphrase(dir.path(), &key, Some("correct horse")).unwrap();
        assert_ne!(std::fs::read_to_string(&path).unwrap(), sealed);

        // And back to a file without a passphrase
        set_identity_passphrase(dir.path(), &key, None).unwrap();
        assert_eq!(identity_state(dir.path()).unwrap(), IdentityState::Plain);
        let again = load_or_create_identity(dir.path(), None).unwrap();
        assert_eq!(again.public(), key.public());
    }

    #[test]
    fn passphrase_is_normalized() {
        let dir = tempfile::tempdir().unwrap();
        let key = load_or_create_identity(dir.path(), None).unwrap();

        // "é" as one character, and as "e" with a combining accent
        set_identity_passphrase(dir.path(), &key, Some("caf\u{e9}")).unwrap();
        let again = load_or_create_identity(dir.path(), Some("cafe\u{301}")).unwrap();
        assert_eq!(again.public(), key.public());
    }

    #[test]
    fn changed_sealed_identity_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(IDENTITY_FILE);
        let key = load_or_create_identity(dir.path(), None).unwrap();
        set_identity_passphrase(dir.path(), &key, Some("pw")).unwrap();
        let sealed = std::fs::read_to_string(&path).unwrap();
        let load = || load_or_create_identity(dir.path(), Some("pw"));
        let rounds = format!("\"rounds\": {KDF_ROUNDS}");
        assert!(sealed.contains(&rounds), "{sealed}");

        // Fewer rounds, to make the passphrase cheaper to guess: the file no longer opens,
        // not even with the right passphrase
        std::fs::write(&path, sealed.replace(&rounds, "\"rounds\": 100000")).unwrap();
        assert!(matches!(load(), Err(PeerError::WrongPassphrase)));

        // Rounds that make no sense are not even tried
        for rounds_now in ["1", "0", "4000000000"] {
            let changed = sealed.replace(&rounds, &format!("\"rounds\": {rounds_now}"));
            std::fs::write(&path, changed).unwrap();
            assert!(matches!(load(), Err(PeerError::DamagedIdentity(_))));
        }

        // Another format, something that is not the format at all, a cut off file
        for changed in [
            sealed.replace(SEALED_FORMAT, "quic-send identity v2"),
            sealed.replace(SEALED_KDF, "md5"),
            "{}".to_string(),
            sealed[..sealed.len() / 2].to_string(),
        ] {
            std::fs::write(&path, changed).unwrap();
            assert!(matches!(load(), Err(PeerError::DamagedIdentity(_))));
        }

        // The untouched file still opens
        std::fs::write(&path, &sealed).unwrap();
        assert_eq!(load().unwrap().public(), key.public());
    }

    #[test]
    fn damaged_identity_is_not_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(IDENTITY_FILE);
        std::fs::write(&path, "not a key").unwrap();

        assert!(matches!(
            load_or_create_identity(dir.path(), None),
            Err(PeerError::DamagedIdentity(_))
        ));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "not a key");
    }

    #[test]
    fn peers_are_saved_and_found_again() {
        let dir = tempfile::tempdir().unwrap();
        let homelab = peer();

        let mut store = PeerStore::load(dir.path()).unwrap();
        assert!(store.peers().is_empty());
        store.save("homelab", homelab.clone()).unwrap();

        let store = PeerStore::load(dir.path()).unwrap();
        assert_eq!(store.get("homelab").unwrap(), &homelab);

        // The address a saved peer is dialed at has everything that was saved
        let addr = homelab.addr();
        assert_eq!(addr.id, homelab.id);
        assert_eq!(addr.relay_urls().count(), 1);
        assert_eq!(addr.ip_addrs().count(), 1);
        assert_eq!(KnownPeer::from(&addr), homelab);
    }

    #[test]
    fn unknown_alias() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = PeerStore::load(dir.path()).unwrap();
        assert!(matches!(store.get("nobody"), Err(PeerError::Unknown(_))));
        assert!(matches!(store.remove("nobody"), Err(PeerError::Unknown(_))));
    }

    #[test]
    fn changed_key_for_a_known_alias_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let original = peer();
        let mut store = PeerStore::load(dir.path()).unwrap();
        store.save("homelab", original.clone()).unwrap();

        let result = store.save("homelab", peer());
        assert!(
            matches!(result, Err(PeerError::Changed { .. })),
            "{result:?}"
        );
        // Nothing changed, in memory and on disk
        assert_eq!(store.get("homelab").unwrap(), &original);
        let reloaded = PeerStore::load(dir.path()).unwrap();
        assert_eq!(reloaded.get("homelab").unwrap(), &original);

        // After removing it by hand, the new identity can be saved
        store.remove("homelab").unwrap();
        assert!(store.save("homelab", peer()).is_ok());
    }

    #[test]
    fn same_key_updates_the_address() {
        let dir = tempfile::tempdir().unwrap();
        let mut moved = peer();
        let mut store = PeerStore::load(dir.path()).unwrap();
        store.save("homelab", moved.clone()).unwrap();

        moved.addresses = vec!["10.0.0.9:4433".parse().unwrap()];
        store.save("homelab", moved.clone()).unwrap();
        assert_eq!(store.get("homelab").unwrap(), &moved);
    }

    #[test]
    fn aliases_are_kept_simple() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = PeerStore::load(dir.path()).unwrap();
        for bad in ["", "two words", "a/b", "../x", &"x".repeat(65)] {
            assert!(
                matches!(store.save(bad, peer()), Err(PeerError::InvalidAlias(_))),
                "{bad:?}"
            );
        }
        for good in ["homelab", "büro-pc", "laptop_2"] {
            assert!(store.save(good, peer()).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn damaged_store_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(PEERS_FILE), "{ not json").unwrap();
        assert!(matches!(
            PeerStore::load(dir.path()),
            Err(PeerError::DamagedStore { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn store_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let mut store = PeerStore::load(dir.path()).unwrap();
        store.save("homelab", peer()).unwrap();
        let mode = std::fs::metadata(dir.path().join(PEERS_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
