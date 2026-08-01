//! Bootstrap configuration.
//!
//! Read once at startup from TOML. Everything here requires a restart to change
//! because it decides which sockets we bind and where state is persisted.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("cannot read config file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse config file {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error(
        "admin listener is bound to {addr} but no authentication is configured; \
         set admin.auth or bind to localhost"
    )]
    UnauthenticatedRemoteAdmin { addr: SocketAddr },
    #[error("server.bind {bind} and the admin listener {admin} would collide on every pool port")]
    ListenerCollision { bind: IpAddr, admin: SocketAddr },
    #[error("server.tls.cert is set but server.tls.key is not (or vice versa)")]
    IncompleteTls,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Bootstrap {
    pub server: ServerConfig,
    pub admin: AdminConfig,
    pub state: StatePaths,
    pub log: LogConfig,
}

impl Bootstrap {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, BootstrapError> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .map_err(|source| BootstrapError::Read { path: path.to_path_buf(), source })?;
        let config: Bootstrap =
            toml::from_str(&raw).map_err(|source| BootstrapError::Parse { path: path.to_path_buf(), source })?;
        config.validate()?;
        Ok(config)
    }

    /// Fail fast on configurations that are dangerous rather than merely wrong.
    pub fn validate(&self) -> Result<(), BootstrapError> {
        // An unauthenticated admin API on a routable address hands out the
        // ability to repoint pools at an attacker's database. Refuse to start.
        if !is_loopback(&self.admin.listen) && matches!(self.admin.auth, AdminAuth::None) {
            return Err(BootstrapError::UnauthenticatedRemoteAdmin { addr: self.admin.listen });
        }

        if self.server.tls.cert.is_some() != self.server.tls.key.is_some() {
            return Err(BootstrapError::IncompleteTls);
        }
        Ok(())
    }
}

fn is_loopback(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerConfig {
    /// Interface every pool port is bound on.
    ///
    /// Only the address: there is no process-wide client port. A pool declares
    /// the port clients reach it on, which is the one piece of routing an
    /// operator actually thinks about, and it can change without a restart.
    pub bind: IpAddr,
    /// Worker threads. `0` means one per core.
    pub workers: usize,
    /// Hard ceiling across every pool port. Protects the process from fd
    /// exhaustion before per-pool limits get a chance to apply.
    pub max_client_connections: u32,
    pub tls: ServerTls,
}

impl ServerConfig {
    /// Ports this process must never hand to a pool.
    ///
    /// Only the admin listener, and only when it shares our bind address or one
    /// of the two is a wildcard — otherwise the sockets cannot collide.
    pub fn reserved_port(&self, admin: SocketAddr) -> Option<u16> {
        let overlaps = self.bind == admin.ip() || self.bind.is_unspecified() || admin.ip().is_unspecified();
        overlaps.then_some(admin.port())
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0".parse().expect("valid default"),
            workers: 0,
            max_client_connections: 1000,
            tls: ServerTls::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerTls {
    /// PEM certificate chain presented to clients.
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    /// Require clients to present a certificate. Off by default; SCRAM is the
    /// primary client authentication mechanism.
    pub require_client_cert: bool,
}

impl ServerTls {
    pub fn is_enabled(&self) -> bool {
        self.cert.is_some() && self.key.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AdminConfig {
    /// HTTP API and dashboard. Loopback by default on purpose.
    pub listen: SocketAddr,
    pub auth: AdminAuth,
    /// Serve the embedded dashboard. Disable for headless deployments.
    pub ui: bool,
    /// Origins allowed to call the API from a browser. Empty means same-origin
    /// only, which is what the embedded UI needs.
    pub cors_origins: Vec<String>,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:7432".parse().expect("valid default"),
            auth: AdminAuth::None,
            ui: true,
            cors_origins: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdminAuth {
    /// Only permitted when the admin listener is on loopback.
    #[default]
    None,
    /// Bearer token read from an environment variable, so it never sits in the
    /// config file.
    Bearer { token_env: String },
}

impl AdminAuth {
    /// Resolve the expected token, if any.
    pub fn expected_token(&self) -> Result<Option<String>, BootstrapError> {
        match self {
            AdminAuth::None => Ok(None),
            AdminAuth::Bearer { token_env } => Ok(std::env::var(token_env).ok().filter(|t| !t.is_empty())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct StatePaths {
    /// Directory holding `state.json`. Contains sealed secrets, so it should
    /// not be world readable.
    pub dir: PathBuf,
}

impl Default for StatePaths {
    fn default() -> Self {
        Self { dir: PathBuf::from("./data") }
    }
}

impl StatePaths {
    pub fn state_file(&self) -> PathBuf {
        self.dir.join("state.json")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LogConfig {
    /// `tracing` filter directive, e.g. `info,havuz_pg=debug`.
    pub filter: String,
    pub json: bool,
    /// Log every accepted connection. Noisy under load; off by default.
    pub log_connections: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self { filter: "info".into(), json: false, log_connections: false }
    }
}

/// Shared default used by both bootstrap and per-pool settings.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml_src: &str) -> Result<Bootstrap, BootstrapError> {
        let config: Bootstrap = toml::from_str(toml_src).unwrap();
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn defaults_are_safe() {
        let config = Bootstrap::default();
        config.validate().expect("defaults must be valid");
        assert!(config.server.bind.is_unspecified(), "pool ports default to every interface");
        assert_eq!(config.admin.listen.port(), 7432);
        assert!(is_loopback(&config.admin.listen), "admin must default to loopback");
    }

    #[test]
    fn remote_admin_without_auth_refuses_to_start() {
        let err = parse(
            r#"
            [admin]
            listen = "0.0.0.0:7432"
            "#,
        )
        .unwrap_err();
        assert!(matches!(err, BootstrapError::UnauthenticatedRemoteAdmin { .. }));
    }

    #[test]
    fn remote_admin_with_bearer_auth_is_allowed() {
        parse(
            r#"
            [admin]
            listen = "0.0.0.0:7432"
            auth = { type = "bearer", token_env = "HAVUZ_ADMIN_TOKEN" }
            "#,
        )
        .expect("bearer auth unlocks a remote admin listener");
    }

    #[test]
    fn loopback_admin_without_auth_is_fine() {
        parse(
            r#"
            [admin]
            listen = "127.0.0.1:9999"
            "#,
        )
        .expect("loopback needs no token");
    }

    #[test]
    fn the_admin_port_is_reserved_only_when_the_sockets_could_collide() {
        // The admin port is reserved against pool ports, and only when the two
        // bind addresses can actually overlap.
        let same = parse(
            r#"
            [server]
            bind = "127.0.0.1"
            [admin]
            listen = "127.0.0.1:7432"
            "#,
        )
        .unwrap();
        assert_eq!(same.server.reserved_port(same.admin.listen), Some(7432));

        let wildcard = parse(
            r#"
            [server]
            bind = "0.0.0.0"
            [admin]
            listen = "127.0.0.1:7432"
            "#,
        )
        .unwrap();
        assert_eq!(wildcard.server.reserved_port(wildcard.admin.listen), Some(7432), "a wildcard bind covers loopback");

        let separate = parse(
            r#"
            [server]
            bind = "10.0.0.5"
            [admin]
            listen = "127.0.0.1:7432"
            "#,
        )
        .unwrap();
        assert_eq!(separate.server.reserved_port(separate.admin.listen), None, "different interfaces cannot collide");
    }

    #[test]
    fn half_configured_tls_is_rejected() {
        let err = parse(
            r#"
            [server.tls]
            cert = "/etc/havuz/server.crt"
            "#,
        )
        .unwrap_err();
        assert!(matches!(err, BootstrapError::IncompleteTls));
    }

    #[test]
    fn unknown_keys_are_rejected_so_typos_do_not_silently_disable_settings() {
        let err = toml::from_str::<Bootstrap>(
            r#"
            [server]
            lisen = "0.0.0.0:5432"
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("lisen"), "got: {err}");
    }

    #[test]
    fn state_file_path_is_derived_from_the_directory() {
        let paths = StatePaths { dir: PathBuf::from("/var/lib/havuz") };
        assert_eq!(paths.state_file(), PathBuf::from("/var/lib/havuz/state.json"));
    }

    #[test]
    fn bearer_token_comes_from_the_environment_not_the_file() {
        let auth = AdminAuth::Bearer { token_env: "HAVUZ_TEST_TOKEN_UNSET".into() };
        assert_eq!(auth.expected_token().unwrap(), None);
        assert_eq!(AdminAuth::None.expected_token().unwrap(), None);
    }
}
