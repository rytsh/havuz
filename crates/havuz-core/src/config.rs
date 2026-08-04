//! Bootstrap configuration.
//!
//! Read once at startup from TOML. Everything here requires a restart to change
//! because it decides which sockets we bind and where state is persisted.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use havuz_secrets::MasterKey;
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
    #[error("secrets.master_key and secrets.master_key_file are both set; pick one")]
    AmbiguousMasterKey,
}

/// Something went wrong finding, reading or creating the master key.
///
/// Separate from [`BootstrapError`] because this happens at startup rather than
/// at parse time, and because a bad key is a different kind of problem from a
/// bad config: the config can be fixed, whereas the wrong key means the stored
/// secrets are already unreadable.
#[derive(Debug, thiserror::Error)]
pub enum MasterKeyError {
    #[error("{source_name} does not contain a usable master key: {source}")]
    Unusable {
        source_name: String,
        #[source]
        source: havuz_secrets::MasterKeyError,
    },
    #[error("cannot read master key from {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot write a generated master key to {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "no master key: set ${env}, secrets.master_key, or secrets.master_key_file, \
         or turn secrets.auto_generate back on"
    )]
    Missing { env: &'static str },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Bootstrap {
    pub server: ServerConfig,
    pub admin: AdminConfig,
    pub state: StatePaths,
    pub log: LogConfig,
    pub secrets: SecretsConfig,
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

        // Two keys in one file is not a merge to resolve, it is a mistake to
        // report: picking one silently would mean every secret sealed under the
        // other becomes unreadable without anything saying so.
        if self.secrets.master_key.is_some() && self.secrets.master_key_file.is_some() {
            return Err(BootstrapError::AmbiguousMasterKey);
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

/// Where the key that seals stored credentials comes from.
///
/// Everything havuz keeps that is worth stealing — backend passwords, client
/// SCRAM verifiers — is sealed under one AES-256 key that lives outside the
/// state file. The key used to be mandatory and environment-only, which is the
/// right default for a deployment with a secret manager and a needless obstacle
/// for one without: it makes `docker run havuz` fail on the first line.
///
/// So there are now four ways to supply it and one way to not bother, tried in
/// this order:
///
/// 1. `$HAVUZ_MASTER_KEY`. Still first, because a secret manager that injects
///    an environment variable should not have to know what havuz's config file
///    looks like.
/// 2. [`master_key`](Self::master_key), inline in the config file.
/// 3. [`master_key_file`](Self::master_key_file), a path the config points at.
/// 4. `master.key` beside the state file, if a previous run left one there.
/// 5. Otherwise, with [`auto_generate`](Self::auto_generate) on, a fresh key
///    written to that same path.
///
/// A key present but unreadable at any step is a hard error rather than a
/// fallthrough to the next one. Falling through would generate a *second* key
/// and quietly orphan everything sealed under the first.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SecretsConfig {
    /// Base64 master key, written straight into the config file.
    ///
    /// Convenient, and it puts the key in the same file as everything else —
    /// which is fine when that file is itself a managed secret and bad when it
    /// is checked into a repository. havuz cannot tell the difference, so it
    /// takes the value and says nothing.
    pub master_key: Option<String>,
    /// Path to a file containing the base64 master key, whitespace ignored.
    ///
    /// The middle ground: the config file can be public, the key file separate
    /// and mounted. Warned about if its permissions let anyone else read it.
    pub master_key_file: Option<PathBuf>,
    /// Create a key and keep it beside the state file when nothing supplies
    /// one.
    ///
    /// On by default so havuz starts without ceremony. Note what it costs:
    /// the key then sits in the same directory as the ciphertext it opens, so
    /// it protects against a stolen state file and not against a stolen state
    /// *directory*. Turn it off to make a missing key fail loudly, which is the
    /// right setting anywhere the key is supposed to come from elsewhere.
    pub auto_generate: bool,
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self { master_key: None, master_key_file: None, auto_generate: true }
    }
}

/// Which of [`SecretsConfig`]'s sources actually produced the key.
///
/// Logged at startup alongside the key id. With five possible sources, "which
/// one won" is the first question asked when havuz cannot open its own secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MasterKeySource {
    Environment,
    ConfigInline,
    ConfigFile,
    StateDirectory,
    Generated,
}

impl MasterKeySource {
    pub fn as_str(self) -> &'static str {
        match self {
            MasterKeySource::Environment => "environment",
            MasterKeySource::ConfigInline => "config file",
            MasterKeySource::ConfigFile => "key file named by the config",
            MasterKeySource::StateDirectory => "key file in the state directory",
            MasterKeySource::Generated => "generated",
        }
    }
}

impl SecretsConfig {
    /// The file a generated key is written to, and read back from next time.
    pub fn generated_key_file(state: &StatePaths) -> PathBuf {
        state.dir.join("master.key")
    }

    /// Find the master key, or make one. See the type-level documentation for
    /// the order and why a broken source never falls through to the next.
    pub fn resolve(&self, state: &StatePaths) -> Result<(MasterKey, MasterKeySource), MasterKeyError> {
        self.resolve_with_env(state, std::env::var(MasterKey::ENV_VAR).ok())
    }

    /// The same, with the environment passed in rather than read.
    ///
    /// Exists so the order can be tested without `set_var`, which is global to
    /// the process and races every other test in the binary.
    fn resolve_with_env(
        &self,
        state: &StatePaths,
        from_env: Option<String>,
    ) -> Result<(MasterKey, MasterKeySource), MasterKeyError> {
        let env = MasterKey::ENV_VAR;
        if let Some(raw) = from_env.filter(|v| !v.trim().is_empty()) {
            return Ok((parse(&raw, env)?, MasterKeySource::Environment));
        }

        if let Some(inline) = self.master_key.as_deref().filter(|v| !v.trim().is_empty()) {
            return Ok((parse(inline, "secrets.master_key")?, MasterKeySource::ConfigInline));
        }

        if let Some(path) = &self.master_key_file {
            let raw = read_key_file(path)?;
            return Ok((parse(&raw, &path.display().to_string())?, MasterKeySource::ConfigFile));
        }

        let generated = Self::generated_key_file(state);
        if generated.exists() {
            let raw = read_key_file(&generated)?;
            return Ok((parse(&raw, &generated.display().to_string())?, MasterKeySource::StateDirectory));
        }

        if !self.auto_generate {
            return Err(MasterKeyError::Missing { env });
        }

        let key = MasterKey::generate();
        write_key_file(&generated, &key.to_base64())?;
        tracing::warn!(
            path = %generated.display(),
            key_id = %key.id(),
            "no master key was configured, so one was generated and written next to the state file; \
             it protects a stolen state file but not a stolen state directory, and losing it makes \
             every stored credential unrecoverable"
        );
        Ok((key, MasterKeySource::Generated))
    }
}

fn parse(raw: &str, source_name: &str) -> Result<MasterKey, MasterKeyError> {
    MasterKey::from_base64(raw)
        .map_err(|source| MasterKeyError::Unusable { source_name: source_name.to_string(), source })
}

fn read_key_file(path: &Path) -> Result<String, MasterKeyError> {
    let raw =
        std::fs::read_to_string(path).map_err(|source| MasterKeyError::Read { path: path.to_path_buf(), source })?;
    warn_if_world_readable(path);
    Ok(raw)
}

/// Write the key so that only this user can read it back.
///
/// The permissions are set before the bytes are written, not after: the gap
/// between the two is short, but it is a window in which the key is on disk and
/// readable by anyone on the machine.
fn write_key_file(path: &Path, contents: &str) -> Result<(), MasterKeyError> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|source| MasterKeyError::Write { path: dir.to_path_buf(), source })?;
    }

    let write = || -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
            file.write_all(contents.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()
        }
        #[cfg(not(unix))]
        {
            std::fs::write(path, format!("{contents}\n"))
        }
    };

    write().map_err(|source| MasterKeyError::Write { path: path.to_path_buf(), source })
}

#[cfg(unix)]
fn warn_if_world_readable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let Ok(meta) = std::fs::metadata(path) else { return };
    let mode = meta.permissions().mode() & 0o077;
    if mode != 0 {
        tracing::warn!(
            path = %path.display(),
            mode = format!("{:o}", meta.permissions().mode() & 0o777),
            "master key file is readable by others; chmod 600 it"
        );
    }
}

#[cfg(not(unix))]
fn warn_if_world_readable(_path: &Path) {}

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

    // --- master key ---

    fn state_dir() -> (tempfile::TempDir, StatePaths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = StatePaths { dir: dir.path().to_path_buf() };
        (dir, paths)
    }

    #[test]
    fn a_missing_key_is_generated_and_then_reused() {
        // The reason this used to be a fatal error was that a key per run
        // orphans the previous run's secrets. Persisting it is what makes
        // starting without one defensible at all, so it is the property to
        // pin down.
        let (_dir, paths) = state_dir();
        let config = SecretsConfig::default();

        let (first, source) = config.resolve_with_env(&paths, None).unwrap();
        assert_eq!(source, MasterKeySource::Generated);
        assert!(SecretsConfig::generated_key_file(&paths).exists());

        let (second, source) = config.resolve_with_env(&paths, None).unwrap();
        assert_eq!(source, MasterKeySource::StateDirectory);
        assert_eq!(second.id(), first.id(), "a restart must not orphan what the first run sealed");
    }

    #[test]
    #[cfg(unix)]
    fn a_generated_key_is_not_readable_by_anyone_else() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_dir, paths) = state_dir();
        SecretsConfig::default().resolve_with_env(&paths, None).unwrap();

        let mode = std::fs::metadata(SecretsConfig::generated_key_file(&paths)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "it sits next to the ciphertext it opens");
    }

    #[test]
    fn auto_generate_off_restores_the_old_hard_failure() {
        let (_dir, paths) = state_dir();
        let config = SecretsConfig { auto_generate: false, ..Default::default() };

        let err = config.resolve_with_env(&paths, None).unwrap_err();
        assert!(matches!(err, MasterKeyError::Missing { .. }), "got {err:?}");
        assert!(!SecretsConfig::generated_key_file(&paths).exists(), "nothing may be written on the failing path");
    }

    #[test]
    fn the_environment_wins_over_the_config_file() {
        // A secret manager injecting a variable should not have to know what
        // the config file happens to say.
        let (_dir, paths) = state_dir();
        let from_config = MasterKey::generate();
        let from_env = MasterKey::generate();
        let config = SecretsConfig { master_key: Some(from_config.to_base64()), ..Default::default() };

        let (key, source) = config.resolve_with_env(&paths, Some(from_env.to_base64())).unwrap();
        assert_eq!(source, MasterKeySource::Environment);
        assert_eq!(key.id(), from_env.id());

        let (key, source) = config.resolve_with_env(&paths, None).unwrap();
        assert_eq!(source, MasterKeySource::ConfigInline);
        assert_eq!(key.id(), from_config.id());
    }

    #[test]
    fn a_key_file_named_by_the_config_beats_the_state_directory() {
        let (_dir, paths) = state_dir();
        let named = MasterKey::generate();
        let path = paths.dir.join("elsewhere.key");
        // Trailing whitespace is what `echo "$KEY" > file` leaves behind.
        std::fs::write(&path, format!("{}\n", named.to_base64())).unwrap();
        // A leftover from an earlier run, which must not win.
        std::fs::write(SecretsConfig::generated_key_file(&paths), MasterKey::generate().to_base64()).unwrap();

        let config = SecretsConfig { master_key_file: Some(path), ..Default::default() };
        let (key, source) = config.resolve_with_env(&paths, None).unwrap();
        assert_eq!(source, MasterKeySource::ConfigFile);
        assert_eq!(key.id(), named.id());
    }

    #[test]
    fn a_broken_source_fails_instead_of_falling_through_to_the_next() {
        // This is the whole safety argument for auto-generation. Treating a
        // corrupt key as "no key" would generate a second one and silently
        // orphan every secret sealed under the first.
        let (_dir, paths) = state_dir();

        let config = SecretsConfig { master_key: Some("not base64 at all".into()), ..Default::default() };
        let err = config.resolve_with_env(&paths, None).unwrap_err();
        assert!(matches!(err, MasterKeyError::Unusable { .. }), "got {err:?}");
        assert!(!SecretsConfig::generated_key_file(&paths).exists());

        let err = SecretsConfig::default().resolve_with_env(&paths, Some("c2hvcnQ=".into())).unwrap_err();
        assert!(matches!(err, MasterKeyError::Unusable { .. }), "a short key is not a missing key: {err:?}");

        let config = SecretsConfig { master_key_file: Some(paths.dir.join("absent.key")), ..Default::default() };
        let err = config.resolve_with_env(&paths, None).unwrap_err();
        assert!(matches!(err, MasterKeyError::Read { .. }), "got {err:?}");
    }

    #[test]
    fn an_empty_environment_variable_is_treated_as_absent() {
        // `export HAVUZ_MASTER_KEY=` in a wrapper script is common enough that
        // failing on it would be unkind, and it carries no key to orphan.
        let (_dir, paths) = state_dir();
        let (_, source) = SecretsConfig::default().resolve_with_env(&paths, Some("   ".into())).unwrap();
        assert_eq!(source, MasterKeySource::Generated);
    }

    #[test]
    fn two_configured_keys_are_a_config_error_rather_than_a_silent_choice() {
        let err = parse(
            r#"
            [secrets]
            master_key = "aGF2dXogaXMgYSBjb25uZWN0aW9uIHBvb2xlciEh"
            master_key_file = "/etc/havuz/master.key"
            "#,
        )
        .unwrap_err();
        assert!(matches!(err, BootstrapError::AmbiguousMasterKey));
    }
}
