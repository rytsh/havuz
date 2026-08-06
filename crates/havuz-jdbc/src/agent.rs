//! Driving the JVM sidecar.
//!
//! One process serves every session for one pool. A JVM costs tens of megabytes
//! and hundreds of milliseconds to start; paying that per backend connection
//! would make the bridge slower than not pooling at all.
//!
//! The transport is newline-delimited JSON-RPC over stdin and stdout, which is
//! not glamorous but has two properties that matter more than elegance: the
//! child dies when the pipe closes, so a crashed havuz cannot leave orphaned
//! JVMs holding database connections, and there is no port to collide with, no
//! socket file to clean up and nothing for anyone else on the host to connect
//! to.
//!
//! Requests carry an id and responses are matched to it rather than assumed to
//! arrive in order, because they are explicitly allowed not to.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use havuz_proto::ProtoError;
use serde_json::{json, Map, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::oneshot;

/// The protocol version this build speaks. The agent refuses anything else.
const PROTOCOL: i64 = 1;

/// How long to wait for the readiness line. Generous: a cold JVM on a loaded
/// host is slow, and failing early here means failing every connection.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

/// A single request's ceiling. A query that runs longer is the database's
/// problem to report, not ours to guess about, so this is only a backstop
/// against a wedged JVM.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

/// Lines of the agent's stderr kept for diagnostics.
///
/// Bounded because a driver that logs on every row would otherwise use the
/// error buffer as unbounded memory.
const STDERR_LINES: usize = 20;

/// How to start the sidecar.
#[derive(Debug, Clone)]
pub struct AgentCommand {
    /// `java`, or an absolute path when the operator pinned a runtime.
    pub java: String,
    pub jar: PathBuf,
    /// Extra JVM flags. Startup latency matters here far more than peak
    /// throughput, so the defaults ask for a fast start rather than a fast
    /// steady state.
    pub java_options: Vec<String>,
}

impl AgentCommand {
    pub fn new(java: impl Into<String>, jar: impl Into<PathBuf>) -> Self {
        Self {
            java: java.into(),
            jar: jar.into(),
            java_options: vec![
                // The agent marshals JSON and waits on a socket; it never gets
                // hot enough for C2 to pay for itself, and tiered compilation
                // costs startup time we do pay for.
                "-XX:TieredStopAtLevel=1".into(),
                "-XX:+UseSerialGC".into(),
                "-Xss512k".into(),
                "-Dfile.encoding=UTF-8".into(),
            ],
        }
    }
}

/// Requests waiting for an answer, keyed by the id they were sent with.
type Waiting = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, AgentError>>>>>;

/// A running sidecar.
pub struct Agent {
    stdin: tokio::sync::Mutex<ChildStdin>,
    pending: Waiting,
    stderr: Arc<Mutex<Vec<String>>>,
    next_id: AtomicU64,
    /// Set once the child's stdout closes; every later request fails fast
    /// rather than waiting out the timeout.
    dead: Arc<Mutex<Option<String>>>,
    child: Mutex<Option<Child>>,
    /// Filled by the handshake, which needs a live agent to run against and so
    /// cannot happen before construction.
    info: std::sync::OnceLock<AgentInfo>,
}

#[derive(Debug, Clone)]
pub struct AgentInfo {
    pub java: String,
    pub vendor: String,
}

/// What went wrong, kept apart from [`ProtoError`] so the SQLSTATE a driver
/// supplied survives all the way to the client that caused it.
#[derive(Debug, Clone, thiserror::Error)]
pub enum AgentError {
    #[error("{message}")]
    Database { sql_state: Option<String>, message: String },
    #[error("the JDBC agent is gone: {0}")]
    Gone(String),
    #[error("the JDBC agent did not answer within {0:?}")]
    Timeout(Duration),
    #[error("cannot talk to the JDBC agent: {0}")]
    Transport(String),
    /// No connection was free to run the statement on.
    ///
    /// Carried here rather than folded into `Transport` because the two send an
    /// operator to opposite places: a transport failure means the JVM stopped
    /// answering, this means the pool is at `max_size` and the client should
    /// try again. The SQLSTATE has to say which.
    #[error("{0}")]
    Exhausted(String),
}

impl From<AgentError> for ProtoError {
    fn from(error: AgentError) -> Self {
        match error {
            AgentError::Database { message, .. } => ProtoError::backend(message),
            other => ProtoError::backend(other.to_string()),
        }
    }
}

impl AgentError {
    /// The SQLSTATE to report, defaulting to a generic internal error.
    pub fn sql_state(&self) -> &str {
        match self {
            AgentError::Database { sql_state: Some(state), .. } if state.len() == 5 => state,
            AgentError::Database { .. } => "XX000",
            AgentError::Timeout(_) => "57014",
            // What PostgreSQL sends when it is out of connection slots, which
            // is what this is, so a client with a retry policy for that code
            // already handles it.
            AgentError::Exhausted(_) => "53300",
            _ => "08006",
        }
    }
}

impl std::fmt::Debug for Agent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agent").field("alive", &self.is_alive()).field("java", &self.info().java).finish()
    }
}

impl Agent {
    /// Start a JVM and wait for it to say it is up.
    pub async fn start(command: &AgentCommand) -> Result<Arc<Self>, AgentError> {
        let mut child = Command::new(&command.java)
            .args(&command.java_options)
            .arg("-jar")
            .arg(&command.jar)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // The JVM must not outlive us holding database connections.
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                AgentError::Transport(format!(
                    "cannot start '{}': {e}; the JDBC bridge needs a Java runtime on PATH",
                    command.java
                ))
            })?;

        let stdin = child.stdin.take().expect("stdin was piped");
        let stdout = child.stdout.take().expect("stdout was piped");
        let child_stderr = child.stderr.take().expect("stderr was piped");

        let stderr = Arc::new(Mutex::new(Vec::new()));
        spawn_stderr_reader(child_stderr, stderr.clone());

        let mut lines = BufReader::new(stdout).lines();
        let ready = tokio::time::timeout(STARTUP_TIMEOUT, read_ready(&mut lines))
            .await
            .map_err(|_| AgentError::Timeout(STARTUP_TIMEOUT))?
            .map_err(|e| AgentError::Transport(with_stderr(e, &stderr)))?;

        if ready != PROTOCOL {
            return Err(AgentError::Transport(format!(
                "agent speaks protocol {ready}, this build speaks {PROTOCOL}; rebuild agent/build.sh"
            )));
        }

        let pending: Waiting = Arc::default();
        let dead: Arc<Mutex<Option<String>>> = Arc::default();
        spawn_reader(lines, pending.clone(), dead.clone(), stderr.clone());

        let agent = Arc::new(Self {
            stdin: tokio::sync::Mutex::new(stdin),
            pending,
            stderr,
            next_id: AtomicU64::new(1),
            dead,
            child: Mutex::new(Some(child)),
            info: std::sync::OnceLock::new(),
        });

        let handshake = agent.call("handshake", json!({})).await?;
        let info = AgentInfo {
            java: handshake.get("java").and_then(Value::as_str).unwrap_or("unknown").to_string(),
            vendor: handshake.get("vendor").and_then(Value::as_str).unwrap_or("unknown").to_string(),
        };
        tracing::info!(java = %info.java, vendor = %info.vendor, "jdbc agent ready");
        let _ = agent.info.set(info);
        Ok(agent)
    }

    /// What the JVM said it was. Empty until the handshake has run.
    pub fn info(&self) -> AgentInfo {
        self.info.get().cloned().unwrap_or(AgentInfo { java: "unknown".into(), vendor: "unknown".into() })
    }

    /// Issue one request and wait for its answer.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, AgentError> {
        if let Some(reason) = self.dead.lock().expect("liveness flag poisoned").clone() {
            return Err(AgentError::Gone(reason));
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().expect("pending map poisoned").insert(id, tx);

        let line = format!("{}\n", json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        if let Err(e) = self.stdin.lock().await.write_all(line.as_bytes()).await {
            self.pending.lock().expect("pending map poisoned").remove(&id);
            return Err(AgentError::Transport(with_stderr(e.to_string(), &self.stderr)));
        }

        match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(result)) => result,
            // The reader dropped the sender, which only happens when stdout
            // closed and every pending request was failed at once.
            Ok(Err(_)) => Err(AgentError::Gone(self.reason())),
            Err(_) => {
                self.pending.lock().expect("pending map poisoned").remove(&id);
                Err(AgentError::Timeout(REQUEST_TIMEOUT))
            }
        }
    }

    pub fn is_alive(&self) -> bool {
        self.dead.lock().expect("liveness flag poisoned").is_none()
    }

    fn reason(&self) -> String {
        self.dead.lock().expect("liveness flag poisoned").clone().unwrap_or_else(|| "agent stopped".into())
    }

    /// Ask the JVM to exit, then stop waiting for it.
    ///
    /// Best effort on purpose: a wedged agent must not be able to hold up
    /// shutdown, and `kill_on_drop` collects it either way.
    pub async fn shutdown(&self) {
        let _ = tokio::time::timeout(Duration::from_secs(5), self.call("shutdown", json!({}))).await;
        if let Some(mut child) = self.child.lock().expect("child slot poisoned").take() {
            let _ = child.start_kill();
        }
    }
}

/// Read lines until the agent announces itself, returning its protocol version.
///
/// Non-JSON lines are skipped rather than treated as fatal: a JVM will happily
/// print a warning about an obsolete flag before running any of our code, and
/// refusing to start over that would be maddening.
async fn read_ready<R>(lines: &mut tokio::io::Lines<BufReader<R>>) -> Result<i64, String>
where
    R: tokio::io::AsyncRead + Unpin,
{
    while let Some(line) = lines.next_line().await.map_err(|e| e.to_string())? {
        let Ok(Value::Object(document)) = serde_json::from_str::<Value>(&line) else {
            tracing::debug!(%line, "ignoring non-JSON output from the jdbc agent");
            continue;
        };
        if document.get("ready").and_then(Value::as_bool) == Some(true) {
            return Ok(document.get("protocol").and_then(Value::as_i64).unwrap_or(0));
        }
    }
    Err("the agent exited before it was ready".into())
}

fn spawn_reader<R>(
    mut lines: tokio::io::Lines<BufReader<R>>,
    pending: Waiting,
    dead: Arc<Mutex<Option<String>>>,
    stderr: Arc<Mutex<Vec<String>>>,
) where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => dispatch(&line, &pending),
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!(error = %e, "jdbc agent stdout failed");
                    break;
                }
            }
        }

        // stdout closed: the JVM is gone. Failing everything at once beats
        // leaving each caller to time out separately.
        let reason = with_stderr("the JDBC agent exited".into(), &stderr);
        *dead.lock().expect("liveness flag poisoned") = Some(reason.clone());
        let waiting: Vec<_> = pending.lock().expect("pending map poisoned").drain().map(|(_, tx)| tx).collect();
        for tx in waiting {
            let _ = tx.send(Err(AgentError::Gone(reason.clone())));
        }
    });
}

fn dispatch(line: &str, pending: &Waiting) {
    let Ok(Value::Object(document)) = serde_json::from_str::<Value>(line) else {
        tracing::debug!(%line, "ignoring unparseable line from the jdbc agent");
        return;
    };
    let Some(id) = document.get("id").and_then(Value::as_u64) else {
        return;
    };
    let Some(tx) = pending.lock().expect("pending map poisoned").remove(&id) else {
        tracing::debug!(id, "answer for a request nobody is waiting on");
        return;
    };
    let _ = tx.send(outcome(document));
}

fn outcome(mut document: Map<String, Value>) -> Result<Value, AgentError> {
    if let Some(Value::Object(error)) = document.remove("error") {
        return Err(AgentError::Database {
            sql_state: error.get("sqlState").and_then(Value::as_str).map(str::to_string),
            message: strip_severity(
                error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("the JDBC agent reported an error with no message"),
            ),
        });
    }
    Ok(document.remove("result").unwrap_or(Value::Object(Map::new())))
}

/// Drop a severity the driver already prefixed.
///
/// The wire format carries severity as its own field, so a message that starts
/// with one produces `ERROR:  ERROR: relation "t" does not exist` in the
/// client. pgjdbc includes it; other drivers do not.
fn strip_severity(message: &str) -> String {
    for prefix in ["ERROR: ", "FATAL: ", "PANIC: ", "WARNING: "] {
        if let Some(rest) = message.strip_prefix(prefix) {
            return rest.trim_start().to_string();
        }
    }
    message.to_string()
}

fn spawn_stderr_reader<R>(stream: R, buffer: Arc<Mutex<Vec<String>>>)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(stream).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            tracing::debug!(target: "havuz_jdbc::agent", "{line}");
            let mut buffer = buffer.lock().expect("stderr buffer poisoned");
            if buffer.len() == STDERR_LINES {
                buffer.remove(0);
            }
            buffer.push(line);
        }
    });
}

/// Attach whatever the JVM said to an otherwise contentless failure.
///
/// "the agent exited" is useless on its own; "the agent exited: Error:
/// LinkageError occurred while loading main class" is a fix.
fn with_stderr(message: String, stderr: &Arc<Mutex<Vec<String>>>) -> String {
    let lines = stderr.lock().expect("stderr buffer poisoned");
    if lines.is_empty() {
        return message;
    }
    format!("{message}: {}", lines.join(" | "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_database_error_keeps_the_sqlstate_the_driver_supplied() {
        // It is the only part of a JDBC error with an agreed meaning, and the
        // client is going to branch on it.
        let mut document = Map::new();
        document.insert("error".into(), json!({ "message": "relation \"t\" does not exist", "sqlState": "42P01" }));
        let error = outcome(document).unwrap_err();
        assert_eq!(error.sql_state(), "42P01");
        assert!(error.to_string().contains("does not exist"));
    }

    #[test]
    fn a_severity_the_driver_already_added_is_not_repeated() {
        // The wire format has a severity field of its own, so leaving it in
        // the message produces "ERROR:  ERROR: relation ..." in the client.
        let mut document = Map::new();
        document
            .insert("error".into(), json!({ "message": "ERROR: relation \"t\" does not exist", "sqlState": "42P01" }));
        assert_eq!(outcome(document).unwrap_err().to_string(), "relation \"t\" does not exist");

        // A message that merely mentions an error is left alone.
        assert_eq!(strip_severity("the ERROR: was elsewhere"), "the ERROR: was elsewhere");
    }

    #[test]
    fn an_error_without_a_sqlstate_reports_a_generic_one() {
        let mut document = Map::new();
        document.insert("error".into(), json!({ "message": "NullPointerException" }));
        assert_eq!(outcome(document).unwrap_err().sql_state(), "XX000");
    }

    #[test]
    fn a_malformed_sqlstate_is_not_passed_through() {
        // A five-character code is what the wire format allows; anything else
        // would produce a message clients cannot parse.
        let mut document = Map::new();
        document.insert("error".into(), json!({ "message": "x", "sqlState": "oops" }));
        assert_eq!(outcome(document).unwrap_err().sql_state(), "XX000");
    }

    #[test]
    fn a_result_without_a_body_is_an_empty_object_not_a_failure() {
        let mut document = Map::new();
        document.insert("id".into(), json!(1));
        assert_eq!(outcome(document).unwrap(), json!({}));
    }

    #[tokio::test]
    async fn the_readiness_line_survives_jvm_chatter_before_it() {
        // A JVM prints warnings about obsolete flags before running any of our
        // code; refusing to start over that would be maddening.
        let input = "OpenJDK 64-Bit Server VM warning: ignoring option\n{\"ready\":true,\"protocol\":1}\n";
        let mut lines = BufReader::new(input.as_bytes()).lines();
        assert_eq!(read_ready(&mut lines).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn an_agent_that_exits_before_announcing_is_reported_as_such() {
        let mut lines = BufReader::new("".as_bytes()).lines();
        assert!(read_ready(&mut lines).await.unwrap_err().contains("before it was ready"));
    }

    #[tokio::test]
    async fn responses_are_matched_by_id_not_by_arrival_order() {
        let pending: Waiting = Arc::default();
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        pending.lock().unwrap().insert(1, tx1);
        pending.lock().unwrap().insert(2, tx2);

        dispatch(r#"{"jsonrpc":"2.0","id":2,"result":{"second":true}}"#, &pending);
        dispatch(r#"{"jsonrpc":"2.0","id":1,"result":{"first":true}}"#, &pending);

        assert_eq!(rx1.await.unwrap().unwrap(), json!({"first": true}));
        assert_eq!(rx2.await.unwrap().unwrap(), json!({"second": true}));
        assert!(pending.lock().unwrap().is_empty());
    }

    #[test]
    fn an_answer_nobody_awaits_is_dropped_rather_than_panicking() {
        let pending: Waiting = Arc::default();
        dispatch(r#"{"jsonrpc":"2.0","id":99,"result":{}}"#, &pending);
        dispatch("not json at all", &pending);
        dispatch(r#"{"no":"id"}"#, &pending);
    }

    #[test]
    fn stderr_is_attached_to_failures_and_stays_bounded() {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        assert_eq!(with_stderr("bare".into(), &buffer), "bare");

        buffer.lock().unwrap().push("Error: LinkageError".to_string());
        assert!(with_stderr("the agent exited".into(), &buffer).contains("LinkageError"));
    }
}
