//! An agent session, as the pool sees it.
//!
//! `havuz-pool` counts connections, queues clients behind `max_size` and
//! retires connections at `max_lifetime`. None of that cares what a connection
//! *is*, which is why a JDBC session slots in without the pool knowing.
//!
//! Deliberately one JDBC connection per session, and no pool inside the agent.
//! A second layer of limits under havuz would make the number an operator
//! configured stop being the number the database sees, which is the one
//! promise a pooler exists to keep.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use havuz_proto::{BackendConn, BackendConnector, ProtoError, ProtoResult, ResetOutcome};
use serde_json::{json, Value};

use crate::agent::{Agent, AgentCommand};

/// Where and as whom to open JDBC connections.
#[derive(Debug, Clone)]
pub struct JdbcConfig {
    pub url: String,
    pub user: String,
    pub password: String,
    /// Fully qualified driver class. Optional: a JAR that declares itself
    /// through `META-INF/services` is discovered without one.
    pub driver_class: Option<String>,
    /// JARs to load the driver from. Empty means the agent's own classpath,
    /// which has no drivers in it, so in practice this is always set.
    pub driver_paths: Vec<String>,
    pub connect_timeout_ms: u64,
    /// Run when a connection returns to the pool.
    ///
    /// `None` means the connection is closed instead. JDBC offers no portable
    /// way to clear session state, and reusing a connection that might still
    /// hold a temporary table or a changed `search_path` would hand one
    /// client's state to the next — which is a correctness bug, not a tuning
    /// choice, so it is not the default.
    pub reset_query: Option<String>,
    /// For metrics and logs. Not the URL, which carries credentials in some
    /// dialects.
    pub label: String,
}

/// One JDBC connection, held open by the agent.
pub struct JdbcBackend {
    agent: Arc<Agent>,
    handle: String,
    opened_at: Instant,
    broken: bool,
    server_version: String,
    reset_query: Option<String>,
}

impl JdbcBackend {
    pub fn handle(&self) -> &str {
        &self.handle
    }

    pub fn agent(&self) -> &Arc<Agent> {
        &self.agent
    }

    pub fn server_version(&self) -> &str {
        &self.server_version
    }

    /// Mark the connection unusable so the pool retires rather than reuses it.
    pub fn poison(&mut self) {
        self.broken = true;
    }
}

#[async_trait]
impl BackendConn for JdbcBackend {
    fn is_broken(&self) -> bool {
        // Includes the agent itself: when the JVM dies every session on it went
        // with it, and handing one out would fail on first use.
        self.broken || !self.agent.is_alive()
    }

    fn opened_at(&self) -> Instant {
        self.opened_at
    }

    /// JDBC exposes no backend process id, and inventing one would put a
    /// number in the dashboard that matches nothing an operator can look up.
    fn backend_pid(&self) -> Option<u32> {
        None
    }

    async fn reset(&mut self) -> ProtoResult<ResetOutcome> {
        let Some(reset_query) = self.reset_query.clone() else {
            // Nothing was configured to clean this connection with, so it is
            // not safe to give to anyone else.
            return Ok(ResetOutcome::Discard);
        };

        match self.agent.call("reset", json!({ "session": self.handle, "sql": reset_query })).await {
            Ok(result) => {
                let valid = result.get("valid").and_then(Value::as_bool).unwrap_or(true);
                if valid {
                    Ok(ResetOutcome::Cleaned)
                } else {
                    // The driver says the connection is no longer usable. Better
                    // to open a new one than to hand this to the next client.
                    self.broken = true;
                    Ok(ResetOutcome::Discard)
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "resetting a jdbc session failed");
                self.broken = true;
                Ok(ResetOutcome::Discard)
            }
        }
    }

    async fn close(&mut self) {
        if let Err(e) = self.agent.call("close_session", json!({ "session": self.handle })).await {
            // The agent may already be gone, which is the usual reason and not
            // worth a warning.
            tracing::debug!(error = %e, "closing a jdbc session failed");
        }
    }
}

/// Opens JDBC connections for one pool, through one shared JVM.
pub struct JdbcConnector {
    agent: Arc<Agent>,
    config: JdbcConfig,
}

impl JdbcConnector {
    pub fn new(agent: Arc<Agent>, config: JdbcConfig) -> Self {
        Self { agent, config }
    }

    /// Start a JVM and check it can reach the database.
    ///
    /// Opening one connection up front turns "the driver class is wrong" from
    /// something the first client discovers into something the operator does.
    pub async fn probe(agent: &Arc<Agent>, config: &JdbcConfig) -> ProtoResult<String> {
        let connector = JdbcConnector::new(agent.clone(), config.clone());
        let mut backend = connector.connect().await?;
        let version = backend.server_version.clone();
        backend.close().await;
        Ok(version)
    }

    pub fn agent(&self) -> &Arc<Agent> {
        &self.agent
    }
}

#[async_trait]
impl BackendConnector for JdbcConnector {
    type Conn = JdbcBackend;

    async fn connect(&self) -> ProtoResult<Self::Conn> {
        let result = self
            .agent
            .call(
                "open_session",
                json!({
                    "url": self.config.url,
                    "user": self.config.user,
                    "password": self.config.password,
                    "driverClass": self.config.driver_class,
                    "driverPaths": self.config.driver_paths,
                    "connectTimeoutMs": self.config.connect_timeout_ms,
                }),
            )
            .await
            .map_err(ProtoError::from)?;

        let handle = result
            .get("session")
            .and_then(Value::as_str)
            .ok_or_else(|| ProtoError::backend("the agent opened a session without naming it"))?
            .to_string();

        Ok(JdbcBackend {
            agent: self.agent.clone(),
            handle,
            opened_at: Instant::now(),
            broken: false,
            reset_query: self.config.reset_query.clone(),
            server_version: format!(
                "{} {}",
                result.get("serverName").and_then(Value::as_str).unwrap_or("unknown"),
                result.get("serverVersion").and_then(Value::as_str).unwrap_or(""),
            )
            .trim()
            .to_string(),
        })
    }

    fn target_label(&self) -> String {
        self.config.label.clone()
    }
}

/// Where the agent JAR is, and what runs it.
///
/// Resolved once at startup so a missing runtime is a startup error rather than
/// a failure on the first connection to reach the pool.
pub fn agent_command(jar: Option<&str>, java: Option<&str>) -> Result<AgentCommand, String> {
    let jar = match jar {
        Some(path) => std::path::PathBuf::from(path),
        None => default_jar().ok_or_else(|| {
            "no JDBC agent JAR found; build it with agent/build.sh or set the agent_jar setting".to_string()
        })?,
    };
    if !jar.exists() {
        return Err(format!("the JDBC agent JAR {} does not exist; build it with agent/build.sh", jar.display()));
    }
    Ok(AgentCommand::new(java.unwrap_or("java"), jar))
}

/// Look where the JAR would be for a build from source and for an install.
fn default_jar() -> Option<std::path::PathBuf> {
    let candidates = [
        std::path::PathBuf::from("agent/build/havuz-agent.jar"),
        std::path::PathBuf::from("/usr/share/havuz/havuz-agent.jar"),
        std::path::PathBuf::from("/opt/havuz/havuz-agent.jar"),
    ];
    candidates.into_iter().find(|path| path.exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_jar_is_a_startup_error_with_a_fix_in_it() {
        let error = agent_command(Some("/nonexistent/havuz-agent.jar"), None).unwrap_err();
        assert!(error.contains("does not exist"), "got: {error}");
        assert!(error.contains("agent/build.sh"), "the message must say how to fix it: {error}");
    }

    #[test]
    fn an_explicit_runtime_overrides_the_one_on_path() {
        // Operators pin a JVM when the one on PATH is the wrong version.
        let jar = std::env::temp_dir().join("havuz-agent-test.jar");
        std::fs::write(&jar, b"not really a jar").unwrap();
        let command = agent_command(jar.to_str(), Some("/opt/jdk21/bin/java")).unwrap();
        assert_eq!(command.java, "/opt/jdk21/bin/java");
        std::fs::remove_file(&jar).ok();
    }

    #[test]
    fn the_default_jvm_options_favour_startup_over_peak_throughput() {
        // The agent marshals JSON and waits; it never gets hot enough for the
        // optimising compiler to pay for the time it costs to start.
        let command = AgentCommand::new("java", "/tmp/x.jar");
        assert!(command.java_options.iter().any(|option| option.contains("TieredStopAtLevel")));
    }
}
