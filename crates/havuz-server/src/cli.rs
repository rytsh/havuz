//! Argument parsing.
//!
//! Hand-rolled rather than pulled from a crate: the surface is four
//! subcommands and one flag, and a dependency here would cost more in compile
//! time than it saves in code.

use std::path::PathBuf;

use anyhow::{bail, Result};

pub const USAGE: &str = "\
havuz - PostgreSQL connection pooler

USAGE:
    havuz [run] [--config <path>]   Start the pooler and the admin API
    havuz check [--config <path>]   Validate the configuration and exit
    havuz keygen                    Generate a master key for the secret store
    havuz --help | --version

OPTIONS:
    -c, --config <path>   Configuration file (default: havuz.toml)

ENVIRONMENT:
    HAVUZ_MASTER_KEY      Required to run. Seals stored credentials.
    HAVUZ_UI_DIR          Serve dashboard assets from this directory.
    RUST_LOG              Overrides the configured log filter.
";

const DEFAULT_CONFIG: &str = "havuz.toml";

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Run { config: PathBuf },
    Check { config: PathBuf },
    Keygen,
    Help,
    Version,
}

pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Command> {
    let args: Vec<String> = args.into_iter().collect();
    let mut config: Option<PathBuf> = None;
    let mut subcommand: Option<String> = None;

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "-V" | "--version" => return Ok(Command::Version),
            "-c" | "--config" => {
                let Some(value) = iter.next() else {
                    bail!("--config needs a path");
                };
                config = Some(PathBuf::from(value));
            }
            other if other.starts_with('-') => bail!("unknown option '{other}'\n\n{USAGE}"),
            other => {
                if subcommand.is_some() {
                    bail!("unexpected argument '{other}'\n\n{USAGE}");
                }
                subcommand = Some(other.to_string());
            }
        }
    }

    let config = config.unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG));

    match subcommand.as_deref() {
        None | Some("run") => Ok(Command::Run { config }),
        Some("check") => Ok(Command::Check { config }),
        Some("keygen") => Ok(Command::Keygen),
        Some(other) => bail!("unknown command '{other}'\n\n{USAGE}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(args: &[&str]) -> Result<Command> {
        parse(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn no_arguments_runs_with_the_default_config() {
        assert_eq!(parse_args(&[]).unwrap(), Command::Run { config: PathBuf::from("havuz.toml") });
    }

    #[test]
    fn subcommands_are_recognised() {
        assert_eq!(parse_args(&["keygen"]).unwrap(), Command::Keygen);
        assert_eq!(parse_args(&["check"]).unwrap(), Command::Check { config: PathBuf::from("havuz.toml") });
        assert_eq!(parse_args(&["run"]).unwrap(), Command::Run { config: PathBuf::from("havuz.toml") });
    }

    #[test]
    fn the_config_flag_works_before_and_after_the_subcommand() {
        let expected = Command::Check { config: PathBuf::from("/etc/havuz.toml") };
        assert_eq!(parse_args(&["check", "--config", "/etc/havuz.toml"]).unwrap(), expected);
        assert_eq!(parse_args(&["--config", "/etc/havuz.toml", "check"]).unwrap(), expected);
        assert_eq!(parse_args(&["-c", "/etc/havuz.toml", "check"]).unwrap(), expected);
    }

    #[test]
    fn help_and_version_short_circuit() {
        assert_eq!(parse_args(&["--help"]).unwrap(), Command::Help);
        assert_eq!(parse_args(&["-h"]).unwrap(), Command::Help);
        assert_eq!(parse_args(&["--version"]).unwrap(), Command::Version);
        // Even when combined with something else.
        assert_eq!(parse_args(&["check", "--help"]).unwrap(), Command::Help);
    }

    #[test]
    fn bad_input_is_rejected_with_the_usage_text() {
        let err = parse_args(&["frobnicate"]).unwrap_err().to_string();
        assert!(err.contains("unknown command"));
        assert!(err.contains("USAGE"));

        assert!(parse_args(&["--config"]).unwrap_err().to_string().contains("needs a path"));
        assert!(parse_args(&["--nope"]).unwrap_err().to_string().contains("unknown option"));
        assert!(parse_args(&["run", "extra"]).unwrap_err().to_string().contains("unexpected argument"));
    }

    #[test]
    fn usage_documents_the_required_environment() {
        // Forgetting the master key is the most likely first-run failure, so it
        // has to be discoverable from --help.
        assert!(USAGE.contains("HAVUZ_MASTER_KEY"));
        assert!(USAGE.contains("keygen"));
    }
}
