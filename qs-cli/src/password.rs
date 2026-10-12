//! Prompt for the optional password.
//!
//! The password is mixed into the PAKE on top of the code. It is never accepted as a
//! command line argument or an environment variable, because both show up in the
//! process list and the shell history.
//!
//! TODO: prompt without echo (dialoguer has `Password`), ask twice when sending.
//! TODO: normalize to Unicode NFC before it is handed to `qs_core::pairing`.
//! TODO: `--password` is a flag without a value that only turns the prompt on.
//! TODO: not a terminal on stdin: fail with a clear message instead of reading it from
//!       a pipe by accident.
//! TODO: tell the user if the other side used no password and the pairing failed
//!       because of it, if the protocol can tell that apart from a wrong code.
