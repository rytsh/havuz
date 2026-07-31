//! Errors that cross the protocol boundary.

use std::io;

pub type ProtoResult<T> = Result<T, ProtoError>;

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("io: {0}")]
    Io(#[from] io::Error),

    /// The peer sent something that is not valid for this protocol. Always a
    /// client bug or a port mix-up, never a transient condition.
    #[error("protocol violation: {0}")]
    Protocol(String),

    #[error("authentication failed: {0}")]
    Auth(String),

    /// The client asked for a pool that does not exist or is not granted.
    #[error("no route: {0}")]
    NoRoute(String),

    #[error("backend unavailable: {0}")]
    Backend(String),

    /// Waited longer than `queue_timeout` for a backend.
    #[error("pool '{pool}' exhausted: no backend available within {waited_ms}ms")]
    PoolExhausted { pool: String, waited_ms: u64 },

    #[error("connection limit reached for {scope}")]
    TooManyConnections { scope: String },

    #[error("timed out after {0}ms")]
    Timeout(u64),

    /// TLS was mandatory but the peer refused or failed the handshake.
    #[error("tls: {0}")]
    Tls(String),

    #[error("shutting down")]
    ShuttingDown,

    #[error("{0} is not implemented yet")]
    Unsupported(&'static str),
}

impl ProtoError {
    pub fn protocol(msg: impl Into<String>) -> Self {
        ProtoError::Protocol(msg.into())
    }

    pub fn backend(msg: impl Into<String>) -> Self {
        ProtoError::Backend(msg.into())
    }

    pub fn auth(msg: impl Into<String>) -> Self {
        ProtoError::Auth(msg.into())
    }

    /// Whether retrying on a different backend could plausibly succeed.
    ///
    /// Used by the pool to decide between failing the client and picking
    /// another target. Client-side faults are never retryable.
    pub fn is_retryable(&self) -> bool {
        match self {
            ProtoError::Io(e) => matches!(
                e.kind(),
                io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::TimedOut
            ),
            ProtoError::Backend(_) | ProtoError::Timeout(_) => true,
            ProtoError::Protocol(_)
            | ProtoError::Auth(_)
            | ProtoError::NoRoute(_)
            | ProtoError::PoolExhausted { .. }
            | ProtoError::TooManyConnections { .. }
            | ProtoError::Tls(_)
            | ProtoError::ShuttingDown
            | ProtoError::Unsupported(_) => false,
        }
    }

    /// Short, stable label for metrics. Must not embed dynamic values or the
    /// cardinality explodes.
    pub fn kind(&self) -> &'static str {
        match self {
            ProtoError::Io(_) => "io",
            ProtoError::Protocol(_) => "protocol",
            ProtoError::Auth(_) => "auth",
            ProtoError::NoRoute(_) => "no_route",
            ProtoError::Backend(_) => "backend",
            ProtoError::PoolExhausted { .. } => "pool_exhausted",
            ProtoError::TooManyConnections { .. } => "too_many_connections",
            ProtoError::Timeout(_) => "timeout",
            ProtoError::Tls(_) => "tls",
            ProtoError::ShuttingDown => "shutting_down",
            ProtoError::Unsupported(_) => "unsupported",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_backend_faults_are_retryable() {
        assert!(ProtoError::backend("connection reset").is_retryable());
        assert!(ProtoError::Timeout(5000).is_retryable());
        assert!(ProtoError::Io(io::Error::from(io::ErrorKind::ConnectionRefused)).is_retryable());
    }

    #[test]
    fn client_faults_are_never_retried_against_another_backend() {
        assert!(!ProtoError::auth("bad password").is_retryable());
        assert!(!ProtoError::protocol("bad startup packet").is_retryable());
        assert!(!ProtoError::NoRoute("app_main".into()).is_retryable());
        // Retrying an exhausted pool on another target just moves the problem.
        assert!(!ProtoError::PoolExhausted { pool: "app_main".into(), waited_ms: 5000 }.is_retryable());
        assert!(!ProtoError::Io(io::Error::from(io::ErrorKind::InvalidData)).is_retryable());
    }

    #[test]
    fn metric_labels_are_bounded() {
        // Every variant must map to a fixed label; dynamic content in a metric
        // label is how you kill a Prometheus server.
        let samples = [
            ProtoError::Io(io::Error::from(io::ErrorKind::Other)),
            ProtoError::protocol("x"),
            ProtoError::auth("x"),
            ProtoError::NoRoute("x".into()),
            ProtoError::backend("x"),
            ProtoError::PoolExhausted { pool: "x".into(), waited_ms: 1 },
            ProtoError::TooManyConnections { scope: "x".into() },
            ProtoError::Timeout(1),
            ProtoError::Tls("x".into()),
            ProtoError::ShuttingDown,
            ProtoError::Unsupported("x"),
        ];
        for e in &samples {
            let kind = e.kind();
            assert!(!kind.is_empty());
            assert!(kind.chars().all(|c| c.is_ascii_lowercase() || c == '_'), "bad label: {kind}");
        }
    }

    #[test]
    fn pool_exhaustion_message_tells_the_operator_what_to_tune() {
        let e = ProtoError::PoolExhausted { pool: "app_main".into(), waited_ms: 5000 };
        let msg = e.to_string();
        assert!(msg.contains("app_main"));
        assert!(msg.contains("5000ms"));
    }
}
