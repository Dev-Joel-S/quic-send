//! Saved peers in the CLI: where they are kept, looking them up, saving and listing them.
//!
//! The logic is in `qs_core::peers`. Peers saved with `--save-peer` are kept in
//! `known_peers.json` next to the config file. Entries of `[known_peers]` in the config
//! file are read as well, they only have an id and are never written by qsend.

use crate::config::{config_dir, RelaySetting, Settings};
use colored::Colorize;
use iroh::{EndpointAddr, EndpointId, SecretKey};
use qs_core::peers::{
    create_identity, identity_is_exposed, identity_state, load_or_create_identity,
    set_identity_passphrase, IdentityState, KnownPeer, PeerError, PeerStore,
};
use std::{
    io::IsTerminal,
    path::{Path, PathBuf},
    str::FromStr,
};

type Failure = Box<dyn std::error::Error>;

/// The directory with the identity and the saved peers: next to the config file
pub fn state_dir(explicit_config: Option<&Path>) -> Result<PathBuf, Failure> {
    let dir = match explicit_config {
        Some(config) => config.parent().map(Path::to_path_buf),
        None => config_dir(),
    };
    dir.ok_or_else(|| "there is no config directory on this system to keep peers in".into())
}

/// Wrong passphrases before giving up
const PASSPHRASE_ATTEMPTS: usize = 3;

/// The stable identity of this device. Asks for the passphrase if it is sealed with one.
pub fn identity(dir: &Path) -> Result<SecretKey, Failure> {
    if identity_is_exposed(dir) {
        eprintln!(
            "{} the identity file in {} could be read by other users of this computer. \
             That is closed now, but the key may have been copied before. To be safe, \
             remove the file and save your peers again.",
            "warning:".yellow().bold(),
            dir.display()
        );
    }

    match identity_state(dir)? {
        IdentityState::Plain => Ok(load_or_create_identity(dir, None)?),
        IdentityState::Missing => {
            let key = load_or_create_identity(dir, None)?;
            eprintln!(
                "{} this device now has an identity that stays, kept in {}. Only you can \
                 read that file. `qsend peers passphrase` seals it with a passphrase as well.",
                "note:".yellow().bold(),
                dir.display()
            );
            Ok(key)
        }
        IdentityState::Sealed => {
            for attempt in 1..=PASSPHRASE_ATTEMPTS {
                let passphrase = crate::password::ask_passphrase()?;
                match load_or_create_identity(dir, Some(&passphrase)) {
                    Err(PeerError::WrongPassphrase) if attempt < PASSPHRASE_ATTEMPTS => {
                        eprintln!("{} wrong passphrase, try again", "error:".red().bold());
                    }
                    result => return Ok(result?),
                }
            }
            Err(PeerError::WrongPassphrase.into())
        }
    }
}

/// Set, change or remove the passphrase the identity is sealed with
pub fn passphrase(dir: &Path) -> Result<(), Failure> {
    // No identity yet: make one that is sealed from the start, so the key never touches
    // the disk without the passphrase
    if identity_state(dir)? == IdentityState::Missing {
        let new = crate::password::ask_new_passphrase()?;
        create_identity(dir, (!new.is_empty()).then_some(new.as_str()))?;
        println!(
            "This device now has an identity that stays, kept in {}.",
            dir.display()
        );
        if !new.is_empty() {
            println!(
                "It is sealed with the passphrase and was never stored without it. You are \
                 asked for it whenever a saved peer is used. There is no way to recover it."
            );
        }
        return Ok(());
    }

    // Whoever changes how the key is kept has to be able to use it, so this asks for the
    // current passphrase first if there is one
    let was_plain = identity_state(dir)? == IdentityState::Plain;
    let key = identity(dir)?;

    let new = crate::password::ask_new_passphrase()?;
    if new.is_empty() {
        set_identity_passphrase(dir, &key, None)?;
        println!("The identity is stored without a passphrase. Only you can read the file.");
    } else {
        set_identity_passphrase(dir, &key, Some(&new))?;
        println!(
            "The identity is sealed with the passphrase. You are asked for it whenever a \
             saved peer is used. There is no way to recover it."
        );
        if was_plain {
            println!(
                "{} this key was stored without a passphrase until now, and replacing a file \
                 does not erase what it held. Somebody who reads the disk itself may still \
                 find the old copy. For a key that was never stored unsealed, remove the \
                 identity file, run this command again and save your peers again.",
                "note:".yellow().bold()
            );
        }
    }
    Ok(())
}

/// The peer known as `alias`: saved with `--save-peer`, or listed in the config file
pub fn lookup(dir: &Path, settings: &Settings, alias: &str) -> Result<KnownPeer, Failure> {
    let store = PeerStore::load(dir)?;
    if let Ok(peer) = store.get(alias) {
        return Ok(peer.clone());
    }

    let Some(id) = settings.known_peers.get(alias) else {
        return Err(PeerError::Unknown(alias.to_string()).into());
    };
    let id = EndpointId::from_str(id.trim())
        .map_err(|_| format!("the id of {alias:?} in the config file is not a valid id"))?;

    // Only the id is known. With an own relay that both sides use, that is enough.
    let mut peer = KnownPeer::from_id(id);
    if let RelaySetting::Custom(relay) = &settings.relay {
        peer.relay = Some(relay.clone());
    }
    Ok(peer)
}

/// The address to dial `alias` at
pub fn address(dir: &Path, settings: &Settings, alias: &str) -> Result<EndpointAddr, Failure> {
    let addr = lookup(dir, settings, alias)?.addr();
    if addr.is_empty() {
        return Err(PeerError::NoAddress(alias.to_string()).into());
    }
    Ok(addr)
}

/// A fingerprint of `id` that is long enough to compare by eye: `07f4-a0d8-aa35-b216`
pub fn fingerprint(id: &EndpointId) -> String {
    let hex = id.to_string();
    let groups: Vec<&str> = (0..4).map(|i| &hex[i * 4..i * 4 + 4]).collect();
    groups.join("-")
}

/// Ask whether to save a peer that nothing has vouched for.
///
/// With a plain ticket the receiver is whoever had the ticket first. Saving it would
/// turn a ticket that leaked once into a peer that is trusted from then on, so the user
/// has to compare the fingerprint and say yes.
fn confirm_unverified(alias: &str, id: &EndpointId) -> Result<bool, Failure> {
    eprintln!(
        "{} this receiver was not checked by a code or a password. \
         Anyone who got hold of the ticket could be it.",
        "warning:".yellow().bold()
    );
    println!(
        "Its fingerprint is {}. Compare it with `This device` on the other side.",
        fingerprint(id).bright_white()
    );

    if !std::io::stdin().is_terminal() {
        println!("Not saved: this has to be confirmed in a terminal.");
        return Ok(false);
    }

    Ok(dialoguer::Confirm::new()
        .with_prompt(format!("Is it the same, save it as {alias}?"))
        .default(false)
        .interact()?)
}

/// Save the peer of this transfer as `alias`, if it told where to find it again.
///
/// `verified` says whether something vouches for the peer: the code, a password, or
/// the key in the ticket it was dialed with.
pub fn remember(
    dir: &Path,
    alias: &str,
    peer: Option<&EndpointAddr>,
    verified: bool,
) -> Result<(), Failure> {
    let Some(peer) = peer else {
        eprintln!(
            "{} the other side did not use --save-peer, so it has no identity that \
             stays. Nothing was saved.",
            "warning:".yellow().bold()
        );
        return Ok(());
    };

    if !verified && !confirm_unverified(alias, &peer.id)? {
        println!("Not saved.");
        return Ok(());
    }

    let mut store = PeerStore::load(dir)?;
    store.save(alias, KnownPeer::from(peer))?;
    println!(
        "Saved this peer as {}. Next time no code is needed: {} or {}",
        alias.bright_white(),
        format!("qsend send --to {alias}").yellow(),
        format!("qsend receive --from {alias}").yellow()
    );
    Ok(())
}

/// Print the saved peers
pub fn list(dir: &Path, settings: &Settings) -> Result<(), Failure> {
    let store = PeerStore::load(dir)?;

    if store.peers().is_empty() && settings.known_peers.is_empty() {
        println!("No peers saved. Use --save-peer <name> on both sides of a transfer.");
        return Ok(());
    }

    for (alias, peer) in store.peers() {
        println!("{}  {}", alias.bright_white(), peer.id);
        if let Some(relay) = &peer.relay {
            println!("    relay   {relay}");
        }
        for address in &peer.addresses {
            println!("    address {address}");
        }
    }
    for (alias, id) in &settings.known_peers {
        if !store.peers().contains_key(alias) {
            println!("{}  {id}  (from the config file)", alias.bright_white());
        }
    }
    Ok(())
}

/// Forget a saved peer
pub fn remove(dir: &Path, alias: &str) -> Result<(), Failure> {
    let mut store = PeerStore::load(dir)?;
    store.remove(alias)?;
    println!("Removed {alias}.");
    Ok(())
}
