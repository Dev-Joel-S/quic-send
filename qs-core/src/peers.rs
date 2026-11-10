//! A stable identity and pinned peers, so repeat transfers need no code.
//!
//! Normally every run uses a fresh key, so nothing links two transfers of the same
//! machine. To recognize a peer again both sides need a key that stays: the identity
//! in this module. It is only used when a peer is saved or a saved peer is used.
//!
//! DONE: privacy: the ephemeral key stays the default. The stored key is only used with
//!       `--save-peer`, `--to` and `--from`. A stable id can be recognized by the relay,
//!       which is the price of not needing a code.
//! DONE: the secret key is kept in `identity.key` in the config directory, created with
//!       permissions 0600 on Unix ([load_or_create_identity]). It is never printed, and an
//!       unreadable file is an error, never silently replaced by a new key.
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
//! TODO: a receiver that keeps listening for several transfers (a daemon for a homelab).
//! TODO: address lookup for a peer whose relay or address changed.

use iroh::{EndpointAddr, EndpointId, RelayUrl, SecretKey};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{self, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
};
use thiserror::Error;

/// File with the secret key of the stable identity
const IDENTITY_FILE: &str = "identity.key";
/// File with the saved peers
const PEERS_FILE: &str = "known_peers.json";

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
    #[error("the file with the saved peers, {}, is damaged: {message}", path.display())]
    DamagedStore { path: PathBuf, message: String },
    #[error("no peer is saved as {0:?}. `qs peers` lists the saved ones")]
    Unknown(String),
    #[error(
        "{alias:?} is already saved with another identity ({saved}), this one is {offered}. \
         If that is intended, remove it first with `qs peers remove {alias}`"
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

/// Write `data` to `path` so that only the user can read it, replacing the file in one step
fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }

    let temporary = path.with_extension("tmp");
    let _ = std::fs::remove_file(&temporary);

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(&temporary)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);

    std::fs::rename(&temporary, path)
}

/// The secret key of this device's stable identity, from `dir`. Made up on first use.
pub fn load_or_create_identity(dir: &Path) -> Result<SecretKey, PeerError> {
    let path = dir.join(IDENTITY_FILE);

    match std::fs::read_to_string(&path) {
        Ok(text) => SecretKey::from_str(text.trim()).map_err(|_| PeerError::DamagedIdentity(path)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let key = SecretKey::generate();
            let text = key
                .to_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            write_private(&path, text.as_bytes()).map_err(io_error(&path))?;
            Ok(key)
        }
        Err(e) => Err(io_error(&path)(e)),
    }
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
        write_private(&self.path, &data).map_err(io_error(&self.path))
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
        let first = load_or_create_identity(dir.path()).unwrap();
        let second = load_or_create_identity(dir.path()).unwrap();
        assert_eq!(first.public(), second.public());

        // Another directory is another device
        let other = tempfile::tempdir().unwrap();
        let third = load_or_create_identity(other.path()).unwrap();
        assert_ne!(first.public(), third.public());
    }

    #[cfg(unix)]
    #[test]
    fn identity_file_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        load_or_create_identity(dir.path()).unwrap();
        let mode = std::fs::metadata(dir.path().join(IDENTITY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn damaged_identity_is_not_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(IDENTITY_FILE);
        std::fs::write(&path, "not a key").unwrap();

        assert!(matches!(
            load_or_create_identity(dir.path()),
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
