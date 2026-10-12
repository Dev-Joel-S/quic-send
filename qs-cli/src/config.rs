//! Configuration file of the CLI.
//!
//! Lives in the platform config directory (`dirs::config_dir()`), flags on the
//! command line override it.
//!
//! Settings:
//! - `rendezvous_url`: empty means no rendezvous, so only direct mode works
//! - `relay`: `default`, `custom <url>` or `disabled`
//! - `output_dir`: replaces the Downloads default
//! - `known_peers`: alias to `EndpointId`, see `qs_core::peers`
//!
//! TODO: choose the format (TOML proposed) and add the parser dependency to qs-cli.
//! TODO: a missing file is fine and means all defaults. A broken file is an error that
//!       names the file and the line, it is never silently ignored.
//! TODO: precedence: flag, then config file, then built-in default. Test it.
//! TODO: `qs config` prints the path of the file and the values in effect.
//! TODO: write the file only on request, never in the background, and never put a
//!       password or a secret key in it.
//! TODO: replace the relay mode that is hard coded in `main.rs` and the Downloads
//!       lookup in `resolve_output_dir` with the values from here.
