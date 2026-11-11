//! Configuration file of the CLI.
//!
//! Lives in the platform config directory (`dirs::config_dir()`), as
//! `quic-send/config.toml`. Flags on the command line override it.
//!
//! ```toml
//! # Rendezvous server for short codes. Without one, qsend prints a ticket instead.
//! rendezvous_url = "https://rendezvous.example.com"
//! # "default", "disabled" or the URL of your own relay
//! relay = "default"
//! # Where received files go. "." is the directory qsend is started in.
//! output_dir = "/home/me/Downloads"
//! # Fixed UDP port instead of a random one
//! port = 4433
//! # Copy codes and tickets to the clipboard, on by default
//! clipboard = true
//!
//! [known_peers]
//! homelab = "<endpoint id>"
//! ```
//!
//! DONE: TOML, parsed with the `toml` crate.
//! DONE: a missing file means all defaults. A broken file is an error that names the file,
//!       the line and the problem, also for an unknown setting (typos are not ignored).
//! DONE: precedence flag, then config file, then built-in default ([Settings::resolve]),
//!       with tests.
//! DONE: `qsend config` prints the path of the file and the values in effect.
//! DONE: the file is never written by qsend, and no password or secret key belongs in it.
//! DONE: the relay mode and the Downloads lookup in `main.rs` use the values from here.
//! DONE: `output_dir = "."` means the directory qsend is started in, like `-o .` and `--here`.
//! DONE: `known_peers` entries are used by `--to` and `--from`, next to the peers saved
//!       with `--save-peer` (see `peers.rs`). They only carry an id, so sending to one needs
//!       an own relay that both sides use.

use iroh::RelayUrl;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fmt,
    path::{Path, PathBuf},
    str::FromStr,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not read the config file {}: {source}", path.display())]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("the config file {} is not valid:\n{message}", path.display())]
    Parse { path: PathBuf, message: String },
}

/// Which relay servers an endpoint uses
#[derive(Debug, Clone, PartialEq, Default)]
pub enum RelaySetting {
    /// The public relay servers run by the iroh project
    #[default]
    Default,
    /// No relay at all. Peers have to reach each other directly.
    Disabled,
    /// Your own relay server
    Custom(RelayUrl),
}

impl FromStr for RelaySetting {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        // `custom <url>` and the bare url both work
        let url = s.strip_prefix("custom").map(str::trim).unwrap_or(s);

        match s {
            "default" => Ok(Self::Default),
            "disabled" => Ok(Self::Disabled),
            _ if url.starts_with("http://") || url.starts_with("https://") => {
                RelayUrl::from_str(url)
                    .map(Self::Custom)
                    .map_err(|e| format!("invalid relay url {url:?}: {e}"))
            }
            _ => Err(format!(
                "invalid relay setting {s:?}: expected \"default\", \"disabled\" or a http(s) url"
            )),
        }
    }
}

impl fmt::Display for RelaySetting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => write!(f, "default"),
            Self::Disabled => write!(f, "disabled"),
            Self::Custom(url) => write!(f, "{url}"),
        }
    }
}

impl<'de> Deserialize<'de> for RelaySetting {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// The config file as written by the user
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub rendezvous_url: Option<String>,
    pub relay: Option<RelaySetting>,
    pub output_dir: Option<PathBuf>,
    pub port: Option<u16>,
    /// Copy codes and tickets to the clipboard
    pub clipboard: Option<bool>,
    /// Alias to endpoint id
    #[serde(default)]
    pub known_peers: BTreeMap<String, String>,
}

impl Config {
    /// Where the config file is looked for by default
    pub fn default_path() -> Option<PathBuf> {
        Some(config_dir()?.join("config.toml"))
    }

    /// Parse the contents of a config file
    pub fn parse(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|e| e.to_string())
    }

    /// Load the config file.
    ///
    /// With an `explicit` path the file has to exist. The default file may be missing,
    /// which means all defaults. Returns the config and the path it was looked for at.
    pub fn load(explicit: Option<&Path>) -> Result<(Self, Option<PathBuf>), ConfigError> {
        let Some(path) = explicit.map(Path::to_path_buf).or_else(Self::default_path) else {
            return Ok((Self::default(), None));
        };

        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && explicit.is_none() => {
                return Ok((Self::default(), Some(path)));
            }
            Err(source) => return Err(ConfigError::Read { path, source }),
        };

        match Self::parse(&text) {
            Ok(config) => Ok((config, Some(path))),
            Err(message) => Err(ConfigError::Parse { path, message }),
        }
    }
}

/// The directory quic-send keeps its files in
pub fn config_dir() -> Option<PathBuf> {
    Some(dirs::config_dir()?.join("quic-send"))
}

/// Settings given on the command line, each overrides the config file
#[derive(Debug, Default, Clone, clap::Args)]
pub struct NetworkArgs {
    /// Rendezvous server for short codes [default: from the config file, else none]
    #[clap(long, value_name = "URL", global = true)]
    pub rendezvous: Option<String>,

    /// Relay server: "default", "disabled" or the URL of your own [default: default]
    #[clap(long, value_name = "RELAY", global = true)]
    pub relay: Option<RelaySetting>,

    /// Fixed UDP port instead of a random one
    #[clap(long, global = true)]
    pub port: Option<u16>,

    /// Do not copy the code or ticket to the clipboard
    #[clap(long, global = true)]
    pub no_clipboard: bool,
}

/// The settings in effect: command line, then config file, then defaults
#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    /// [None] means no rendezvous server: tickets instead of short codes
    pub rendezvous_url: Option<String>,
    pub relay: RelaySetting,
    /// [None] means the Downloads folder
    pub output_dir: Option<PathBuf>,
    /// [None] means a random port
    pub port: Option<u16>,
    /// Whether codes and tickets are copied to the clipboard
    pub clipboard: bool,
    pub known_peers: BTreeMap<String, String>,
}

impl Settings {
    pub fn resolve(args: &NetworkArgs, output: Option<PathBuf>, config: Config) -> Self {
        let rendezvous_url = args
            .rendezvous
            .clone()
            .or(config.rendezvous_url)
            .map(|url| url.trim().to_string())
            // An empty value switches the rendezvous off, also from the command line
            .filter(|url| !url.is_empty());

        Self {
            rendezvous_url,
            relay: args.relay.clone().or(config.relay).unwrap_or_default(),
            output_dir: output.or(config.output_dir),
            port: args.port.or(config.port),
            // The flag can only switch it off, like the setting in the file
            clipboard: !args.no_clipboard && config.clipboard.unwrap_or(true),
            known_peers: config.known_peers,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn empty_file_is_all_defaults() {
        assert_eq!(Config::parse("").unwrap(), Config::default());
        let settings = Settings::resolve(&NetworkArgs::default(), None, Config::default());
        assert_eq!(settings.rendezvous_url, None);
        assert_eq!(settings.relay, RelaySetting::Default);
        assert_eq!(settings.output_dir, None);
        assert_eq!(settings.port, None);
    }

    #[test]
    fn full_file() {
        let config = Config::parse(
            r#"
            rendezvous_url = "https://rz.example.com"
            relay = "disabled"
            output_dir = "."
            port = 4433

            [known_peers]
            homelab = "abc"
            "#,
        )
        .unwrap();

        assert_eq!(
            config.rendezvous_url.as_deref(),
            Some("https://rz.example.com")
        );
        assert_eq!(config.relay, Some(RelaySetting::Disabled));
        assert_eq!(config.output_dir, Some(PathBuf::from(".")));
        assert_eq!(config.port, Some(4433));
        assert_eq!(
            config.known_peers.get("homelab").map(String::as_str),
            Some("abc")
        );
    }

    #[test]
    fn relay_setting_forms() {
        let url = RelayUrl::from_str("https://relay.example.com").unwrap();
        assert_eq!("default".parse(), Ok(RelaySetting::Default));
        assert_eq!(" disabled ".parse(), Ok(RelaySetting::Disabled));
        assert_eq!(
            "https://relay.example.com".parse(),
            Ok(RelaySetting::Custom(url.clone()))
        );
        assert_eq!(
            "custom https://relay.example.com".parse(),
            Ok(RelaySetting::Custom(url))
        );
        assert!("off".parse::<RelaySetting>().is_err());
        assert!("custom".parse::<RelaySetting>().is_err());
    }

    #[test]
    fn mistakes_are_errors_with_a_position() {
        // Unknown setting, most likely a typo
        let err = Config::parse("rendevouz_url = \"x\"").unwrap_err();
        assert!(err.contains("rendevouz_url"), "{err}");
        assert!(err.contains("line 1"), "{err}");

        let err = Config::parse("\nrelay = \"sometimes\"").unwrap_err();
        assert!(err.contains("invalid relay setting"), "{err}");
        assert!(err.contains("line 2"), "{err}");

        assert!(Config::parse("port = 70000").is_err());
        assert!(Config::parse("port = ").is_err());
    }

    #[test]
    fn flags_override_the_file() {
        let config = || {
            Config::parse(
                "rendezvous_url = \"https://file\"\nrelay = \"disabled\"\noutput_dir = \"/file\"\nport = 1",
            )
            .unwrap()
        };

        // Nothing on the command line: the file counts
        let settings = Settings::resolve(&NetworkArgs::default(), None, config());
        assert_eq!(settings.rendezvous_url.as_deref(), Some("https://file"));
        assert_eq!(settings.relay, RelaySetting::Disabled);
        assert_eq!(settings.output_dir, Some(PathBuf::from("/file")));
        assert_eq!(settings.port, Some(1));

        // Everything on the command line: the file is overridden
        let args = NetworkArgs {
            rendezvous: Some("https://flag".to_string()),
            relay: Some(RelaySetting::Default),
            port: Some(2),
            no_clipboard: false,
        };
        let settings = Settings::resolve(&args, Some(PathBuf::from(".")), config());
        assert_eq!(settings.rendezvous_url.as_deref(), Some("https://flag"));
        assert_eq!(settings.relay, RelaySetting::Default);
        assert_eq!(settings.output_dir, Some(PathBuf::from(".")));
        assert_eq!(settings.port, Some(2));
    }

    #[test]
    fn clipboard_is_on_unless_switched_off() {
        let resolve = |no_clipboard, file: &str| {
            let args = NetworkArgs {
                no_clipboard,
                ..Default::default()
            };
            Settings::resolve(&args, None, Config::parse(file).unwrap()).clipboard
        };

        assert!(resolve(false, ""));
        assert!(resolve(false, "clipboard = true"));
        assert!(!resolve(false, "clipboard = false"));
        assert!(!resolve(true, ""));
        // The flag wins over a file that switches it on
        assert!(!resolve(true, "clipboard = true"));
    }

    #[test]
    fn empty_rendezvous_switches_it_off() {
        let config = Config::parse("rendezvous_url = \"https://file\"").unwrap();
        let args = NetworkArgs {
            rendezvous: Some(String::new()),
            ..Default::default()
        };
        assert_eq!(Settings::resolve(&args, None, config).rendezvous_url, None);

        let config = Config::parse("rendezvous_url = \"\"").unwrap();
        let settings = Settings::resolve(&NetworkArgs::default(), None, config);
        assert_eq!(settings.rendezvous_url, None);
    }

    #[test]
    fn missing_default_file_is_fine_missing_explicit_file_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.toml");
        assert!(matches!(
            Config::load(Some(&missing)),
            Err(ConfigError::Read { .. })
        ));

        let broken = dir.path().join("broken.toml");
        std::fs::write(&broken, "port = \"many\"").unwrap();
        let err = Config::load(Some(&broken)).unwrap_err().to_string();
        assert!(err.contains("broken.toml"), "{err}");
        assert!(err.contains("line 1"), "{err}");
    }
}
