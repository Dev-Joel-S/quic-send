//! Prompt for the optional password.
//!
//! The password is an addition to the code or ticket, never a replacement. It is never
//! accepted as a command line argument or an environment variable, because both show up
//! in the process list and the shell history.
//!
//! DONE: prompted without echo, the sender types it twice ([ask_new]).
//! DONE: normalized to Unicode NFC in `qs_core`, where it goes into the key exchange.
//! DONE: `--password` is a flag without a value that only turns the prompt on.
//! DONE: without a terminal the prompt fails with a clear message instead of reading the
//!       password from a pipe by accident.
//! DONE: the receiver is asked on its own when the sender set a password and the flag was
//!       not given, and is told when it gave one although the sender set none.

use std::io::{self, IsTerminal};
use zeroize::Zeroizing;

fn require_terminal() -> io::Result<()> {
    if io::stdin().is_terminal() {
        return Ok(());
    }
    Err(io::Error::other(
        "a password can only be entered in a terminal, not through a pipe",
    ))
}

/// Ask for a new password, twice
pub fn ask_new() -> io::Result<Zeroizing<String>> {
    require_terminal()?;
    dialoguer::Password::new()
        .with_prompt("Password for this transfer")
        .with_confirmation("Repeat the password", "The passwords do not match")
        .interact()
        .map(Zeroizing::new)
        .map_err(io::Error::other)
}

/// Ask for the password the sender set
pub fn ask() -> io::Result<Zeroizing<String>> {
    require_terminal()?;
    dialoguer::Password::new()
        .with_prompt("Password")
        .interact()
        .map(Zeroizing::new)
        .map_err(io::Error::other)
}

/// Ask whether to go on without the password that was given but is not needed
pub fn confirm_without() -> io::Result<bool> {
    if !io::stdin().is_terminal() {
        return Ok(false);
    }
    dialoguer::Confirm::new()
        .with_prompt("The sender did not set a password. Receive without one?")
        .default(false)
        .interact()
        .map_err(io::Error::other)
}

/// Ask for the passphrase the identity is sealed with
pub fn ask_passphrase() -> io::Result<Zeroizing<String>> {
    require_terminal()?;
    dialoguer::Password::new()
        .with_prompt("Passphrase for the identity of this device")
        .interact()
        .map(Zeroizing::new)
        .map_err(io::Error::other)
}

/// Ask for a new passphrase for the identity, twice. Empty means none.
pub fn ask_new_passphrase() -> io::Result<Zeroizing<String>> {
    require_terminal()?;
    dialoguer::Password::new()
        .with_prompt("New passphrase (leave empty to store the identity without one)")
        .with_confirmation("Repeat the passphrase", "The passphrases do not match")
        .allow_empty_password(true)
        .interact()
        .map(Zeroizing::new)
        .map_err(io::Error::other)
}
