//! Backend connections.
//!
//! One service account per pool, shared by every client. That sharing is not a
//! simplification — it is the mechanism that makes a backend connection
//! reusable at all. If each client's own database role were carried through,
//! havuz would need a separate pool per role and the fan-in would collapse to
//! the number of roles.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use havuz_core::SslMode;
use havuz_proto::{BackendConn, BackendConnector, ProtoError, ProtoResult, ResetOutcome};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::cancel::CancelTarget;
use crate::prepared::BackendStatements;
use crate::protocol::{Message, StartupPacket, TransactionStatus};
use crate::scram::ScramClient;
use crate::stream::MaybeTls;

/// Everything needed to open one backend connection.
#[derive(Debug, Clone)]
pub struct BackendConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    /// The pool's service account.
    pub user: String,
    pub password: String,
    pub ssl_mode: SslMode,
    pub tls: Option<Arc<rustls::ClientConfig>>,
    /// Sent as `application_name` so the backend shows something meaningful
    /// even before a client identity is attached.
    pub application_name: String,
    /// Whether `DISCARD ALL` is understood. Redshift, for one, does not.
    pub supports_discard_all: bool,
}

/// A live backend connection.
pub struct PgBackend {
    stream: MaybeTls,
    opened_at: Instant,
    /// Where this connection was opened. Carried on the connection rather than
    /// looked up from configuration at cancellation time: a `CancelRequest`
    /// must reach the server that is actually running the query, and the pool's
    /// configuration may have been edited since — or the checkout may have come
    /// from a replica while the pool now points somewhere else.
    host: String,
    port: u16,
    backend_pid: Option<u32>,
    secret_key: Option<i32>,
    /// `ParameterStatus` values the backend reported during startup. Replayed
    /// to each client so they see a coherent session.
    parameters: Vec<(String, String)>,
    broken: bool,
    supports_discard_all: bool,
    /// Global prepared statement names this connection has parsed. Lives with
    /// the connection because that is exactly what it describes.
    statements: BackendStatements,
    /// Session parameters currently in force, as the statements that produced
    /// them. Lives with the connection for the same reason: it describes this
    /// backend, not the client that happens to be holding it.
    applied_params: BTreeMap<String, String>,
}

impl std::fmt::Debug for PgBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgBackend")
            .field("backend_pid", &self.backend_pid)
            .field("encrypted", &self.stream.is_encrypted())
            .field("broken", &self.broken)
            .finish()
    }
}

impl PgBackend {
    pub fn stream_mut(&mut self) -> &mut MaybeTls {
        &mut self.stream
    }

    pub fn statements(&self) -> &BackendStatements {
        &self.statements
    }

    pub fn statements_mut(&mut self) -> &mut BackendStatements {
        &mut self.statements
    }

    pub fn parameters(&self) -> &[(String, String)] {
        &self.parameters
    }

    /// Session parameters this connection currently has, keyed by name.
    ///
    /// Empty means "the backend defaults", which is what a freshly opened or
    /// freshly reset connection has.
    pub fn applied_params(&self) -> &BTreeMap<String, String> {
        &self.applied_params
    }

    /// Record the parameters now in force, after applying a delta or after
    /// watching a client's own `SET` succeed.
    pub fn set_applied_params(&mut self, params: BTreeMap<String, String>) {
        self.applied_params = params;
    }

    pub fn secret_key(&self) -> Option<i32> {
        self.secret_key
    }

    /// Where a `CancelRequest` for this connection has to be sent.
    ///
    /// `None` when the server never sent a `BackendKeyData` — some proxies and
    /// PostgreSQL-compatible engines do not. Cancellation is impossible then,
    /// and saying so beats sending a key pair of zeroes to a server that would
    /// either ignore it or, worse, match it against something.
    pub fn cancel_target(&self) -> Option<CancelTarget> {
        Some(CancelTarget {
            host: self.host.clone(),
            port: self.port,
            backend_pid: self.backend_pid? as i32,
            backend_secret: self.secret_key?,
        })
    }

    pub fn is_encrypted(&self) -> bool {
        self.stream.is_encrypted()
    }

    /// Mark unusable. Called when a relay fails partway through a message and
    /// the framing can no longer be trusted.
    pub fn mark_broken(&mut self) {
        self.broken = true;
    }

    /// Run a query and return the first column of the first row.
    ///
    /// Control plane only: health probes and "Test Connection". Never called
    /// while a client is attached, so the extra round trip costs nothing on the
    /// data path.
    ///
    /// `None` means the query returned no rows, or a SQL NULL.
    pub async fn query_scalar(&mut self, sql: &str) -> ProtoResult<Option<String>> {
        if self.broken {
            return Err(ProtoError::backend("connection is broken"));
        }

        let mut body = Vec::with_capacity(sql.len() + 1);
        body.extend_from_slice(sql.as_bytes());
        body.push(0);

        Message::new(b'Q', Bytes::from(body)).write(&mut self.stream).await.map_err(|e| {
            self.broken = true;
            ProtoError::backend(format!("sending query: {e}"))
        })?;

        let mut value = None;
        loop {
            let msg = Message::read(&mut self.stream).await.map_err(|e| {
                self.broken = true;
                ProtoError::backend(format!("reading query result: {e}"))
            })?;

            match msg.tag {
                // DataRow. Keep only the first one.
                b'D' if value.is_none() => {
                    value = Some(first_column(&msg.body));
                }
                b'E' => {
                    let detail = msg
                        .error_fields()
                        .into_iter()
                        .find(|(f, _)| *f == b'M')
                        .map(|(_, v)| v)
                        .unwrap_or_else(|| "query failed".into());
                    // Drain to ReadyForQuery so the connection stays usable.
                    while let Ok(m) = Message::read(&mut self.stream).await {
                        if m.tag == b'Z' {
                            break;
                        }
                    }
                    return Err(ProtoError::backend(detail));
                }
                b'Z' => break,
                _ => continue,
            }
        }

        Ok(value.flatten())
    }

    /// Run one simple query and drain to `ReadyForQuery`.
    ///
    /// Used only on the recycling path, never while a client is attached.
    async fn simple_query(&mut self, sql: &str) -> ProtoResult<()> {
        if self.broken {
            return Ok(());
        }

        let mut body = Vec::with_capacity(sql.len() + 1);
        body.extend_from_slice(sql.as_bytes());
        body.push(0);

        if let Err(e) = Message::new(b'Q', Bytes::from(body)).write(&mut self.stream).await {
            tracing::debug!(sql, error = %e, "reset statement failed to send");
            self.broken = true;
            return Ok(());
        }

        loop {
            match Message::read(&mut self.stream).await {
                Ok(msg) if msg.tag == b'Z' => return Ok(()),
                // An error here means the connection is in a state we do not
                // understand; recycling it would leak that state to the next
                // client.
                Ok(msg) if msg.tag == b'E' => {
                    tracing::debug!(sql, fields = ?msg.error_fields(), "reset statement failed");
                    self.broken = true;
                    return Ok(());
                }
                Ok(_) => continue,
                Err(e) => {
                    tracing::debug!(sql, error = %e, "reset lost the connection");
                    self.broken = true;
                    return Ok(());
                }
            }
        }
    }
}

#[async_trait]
impl BackendConn for PgBackend {
    fn is_broken(&self) -> bool {
        self.broken
    }

    fn opened_at(&self) -> Instant {
        self.opened_at
    }

    fn backend_pid(&self) -> Option<u32> {
        self.backend_pid
    }

    async fn reset(&mut self) -> ProtoResult<ResetOutcome> {
        if self.broken {
            return Ok(ResetOutcome::Discard);
        }
        // Two separate statements, in this order, and never combined.
        //
        // A client that vanished mid-transaction leaves one open, and
        // `DISCARD ALL` is rejected inside a transaction block. Sending
        // "ROLLBACK; DISCARD ALL" as one simple query does not help either:
        // multi-statement simple queries run in an implicit transaction, so
        // DISCARD would still be refused.
        self.simple_query("ROLLBACK").await?;

        let discard = if self.supports_discard_all {
            "DISCARD ALL"
        } else {
            // Redshift and other old forks reject DISCARD ALL. This covers the
            // portable subset; anything else is why the profile caps its
            // pooling mode.
            "RESET ALL"
        };
        self.simple_query(discard).await?;

        // DISCARD ALL includes DEALLOCATE ALL, so the server has forgotten every
        // prepared statement. Keeping the cache would make us skip replays the
        // backend can no longer honour.
        self.statements.clear();

        // Both DISCARD ALL and RESET ALL return every session parameter to its
        // default, so this connection now matches a freshly opened one.
        self.applied_params.clear();

        Ok(if self.broken { ResetOutcome::Discard } else { ResetOutcome::Cleaned })
    }

    async fn close(&mut self) {
        // Best effort: a backend that is already gone does not need a goodbye.
        let _ = Message::terminate().write(&mut self.stream).await;
        let _ = self.stream.shutdown().await;
    }
}

/// Opens backend connections for one pool.
pub struct PgConnector {
    config: BackendConfig,
}

impl PgConnector {
    pub fn new(config: BackendConfig) -> Self {
        Self { config }
    }

    async fn negotiate_tls(&self, mut socket: TcpStream) -> ProtoResult<MaybeTls> {
        if !self.config.ssl_mode.wants_tls() {
            return Ok(MaybeTls::Plain(socket));
        }

        StartupPacket::SslRequest
            .write(&mut socket)
            .await
            .map_err(|e| ProtoError::backend(format!("ssl request failed: {e}")))?;

        let mut answer = [0u8; 1];
        socket
            .read_exact(&mut answer)
            .await
            .map_err(|e| ProtoError::backend(format!("no answer to ssl request: {e}")))?;

        match answer[0] {
            b'S' => {
                let tls = self
                    .config
                    .tls
                    .clone()
                    .ok_or_else(|| ProtoError::Tls("server offered TLS but no client config was built".into()))?;
                let server_name = ServerName::try_from(self.config.host.clone())
                    .map_err(|_| ProtoError::Tls(format!("'{}' is not a valid TLS server name", self.config.host)))?;
                let connector = tokio_rustls::TlsConnector::from(tls);
                let stream = connector
                    .connect(server_name, socket)
                    .await
                    .map_err(|e| ProtoError::Tls(format!("handshake failed: {e}")))?;
                Ok(MaybeTls::ClientTls(Box::new(stream)))
            }
            b'N' => {
                // The server declined. Only `prefer` may continue in the clear.
                if self.config.ssl_mode.requires_tls() {
                    Err(ProtoError::Tls(format!(
                        "server refused TLS but sslmode={} requires it",
                        self.config.ssl_mode.as_str()
                    )))
                } else {
                    Ok(MaybeTls::Plain(socket))
                }
            }
            // An 'E' here means the server is too old to understand SSLRequest.
            other => Err(ProtoError::backend(format!("unexpected answer to ssl request: {:?}", other as char))),
        }
    }

    async fn authenticate(&self, stream: &mut MaybeTls) -> ProtoResult<Startup> {
        let mut startup = Startup::default();
        let mut scram: Option<ScramClient> = None;

        loop {
            let msg = Message::read(stream)
                .await
                .map_err(|e| ProtoError::backend(format!("reading startup response: {e}")))?;

            match msg.tag {
                b'R' => {
                    let mut body = msg.body.clone();
                    if body.len() < 4 {
                        return Err(ProtoError::backend("truncated authentication request"));
                    }
                    let kind = body.get_i32();
                    match kind {
                        // AuthenticationOk
                        0 => continue,
                        // Cleartext password. Only sane over TLS, but the
                        // backend chose it, so honour it.
                        3 => {
                            let mut payload = self.config.password.clone().into_bytes();
                            payload.push(0);
                            Message::new(b'p', Bytes::from(payload))
                                .write(stream)
                                .await
                                .map_err(|e| ProtoError::backend(format!("sending password: {e}")))?;
                        }
                        // MD5 is deprecated and removed in modern Postgres; we
                        // refuse it rather than implement a broken hash.
                        5 => {
                            return Err(ProtoError::auth(
                                "backend requested md5 authentication, which havuz does not implement; \
                                 switch the account to scram-sha-256",
                            ))
                        }
                        // SASL
                        10 => {
                            let mechanisms = parse_mechanisms(&body);
                            if !mechanisms.iter().any(|m| m == "SCRAM-SHA-256") {
                                return Err(ProtoError::auth(format!(
                                    "backend offers no supported SASL mechanism (got {mechanisms:?})"
                                )));
                            }
                            let mut client = ScramClient::new(self.config.password.clone());
                            let first = client.client_first().map_err(|e| ProtoError::auth(format!("scram: {e}")))?;

                            let mut payload = Vec::new();
                            payload.extend_from_slice(b"SCRAM-SHA-256\0");
                            payload.extend_from_slice(&(first.len() as i32).to_be_bytes());
                            payload.extend_from_slice(&first);
                            Message::new(b'p', Bytes::from(payload))
                                .write(stream)
                                .await
                                .map_err(|e| ProtoError::backend(format!("sending sasl initial: {e}")))?;
                            scram = Some(client);
                        }
                        // SASLContinue
                        11 => {
                            let client = scram.as_mut().ok_or_else(|| ProtoError::auth("unexpected SASLContinue"))?;
                            let final_msg =
                                client.client_final(&body).map_err(|e| ProtoError::auth(format!("scram: {e}")))?;
                            Message::new(b'p', Bytes::from(final_msg))
                                .write(stream)
                                .await
                                .map_err(|e| ProtoError::backend(format!("sending sasl response: {e}")))?;
                        }
                        // SASLFinal
                        12 => {
                            let client = scram.as_mut().ok_or_else(|| ProtoError::auth("unexpected SASLFinal"))?;
                            // Verifying this is what proves the backend also
                            // knows the password rather than just accepting
                            // whatever we sent.
                            client.verify_server_final(&body).map_err(|e| ProtoError::auth(format!("scram: {e}")))?;
                        }
                        other => {
                            return Err(ProtoError::auth(format!(
                                "backend requested unsupported authentication method {other}"
                            )))
                        }
                    }
                }
                b'S' => {
                    if let Some((k, v)) = parse_parameter_status(&msg.body) {
                        startup.parameters.push((k, v));
                    }
                }
                b'K' => {
                    if msg.body.len() >= 8 {
                        let mut body = msg.body.clone();
                        startup.backend_pid = Some(body.get_i32() as u32);
                        startup.secret_key = Some(body.get_i32());
                    }
                }
                b'Z' => {
                    // ReadyForQuery: startup is complete.
                    if msg.transaction_status() == Some(TransactionStatus::Idle) || msg.body.len() == 1 {
                        return Ok(startup);
                    }
                    return Ok(startup);
                }
                b'E' => {
                    let fields = msg.error_fields();
                    let message = fields
                        .iter()
                        .find(|(f, _)| *f == b'M')
                        .map(|(_, v)| v.clone())
                        .unwrap_or_else(|| "unknown error".into());
                    let code = fields.iter().find(|(f, _)| *f == b'C').map(|(_, v)| v.clone()).unwrap_or_default();
                    // 28P01 and friends are credential problems, not transient
                    // faults, so they must not be retried against a replica.
                    return Err(if code.starts_with("28") {
                        ProtoError::auth(message)
                    } else {
                        ProtoError::backend(format!("{code}: {message}"))
                    });
                }
                // NoticeResponse and anything else during startup is noise.
                _ => continue,
            }
        }
    }
}

#[derive(Debug, Default)]
struct Startup {
    parameters: Vec<(String, String)>,
    backend_pid: Option<u32>,
    secret_key: Option<i32>,
}

#[async_trait]
impl BackendConnector for PgConnector {
    type Conn = PgBackend;

    async fn connect(&self) -> ProtoResult<PgBackend> {
        let socket = TcpStream::connect((self.config.host.as_str(), self.config.port))
            .await
            .map_err(|e| ProtoError::backend(format!("connecting to {}: {e}", self.target_label())))?;
        socket.set_nodelay(true).ok();

        let mut stream = self.negotiate_tls(socket).await?;

        let packet = StartupPacket::Startup {
            params: vec![
                ("user".into(), self.config.user.clone()),
                ("database".into(), self.config.database.clone()),
                ("application_name".into(), self.config.application_name.clone()),
                // A pooler must never be handed a binary-only session it cannot
                // interpret; leave the client encoding at the default.
                ("client_encoding".into(), "UTF8".into()),
            ],
        };
        packet.write(&mut stream).await.map_err(|e| ProtoError::backend(format!("sending startup: {e}")))?;

        let startup = self.authenticate(&mut stream).await?;

        Ok(PgBackend {
            stream,
            opened_at: Instant::now(),
            host: self.config.host.clone(),
            port: self.config.port,
            backend_pid: startup.backend_pid,
            secret_key: startup.secret_key,
            parameters: startup.parameters,
            broken: false,
            supports_discard_all: self.config.supports_discard_all,
            statements: BackendStatements::new(),
            applied_params: BTreeMap::new(),
        })
    }

    fn target_label(&self) -> String {
        format!("{}:{}", self.config.host, self.config.port)
    }
}

/// First column of a `DataRow`, or `None` for SQL NULL.
///
/// Layout: `Int16 column_count`, then per column `Int32 length` (-1 for NULL)
/// followed by that many bytes.
fn first_column(body: &[u8]) -> Option<String> {
    if body.len() < 6 {
        return None;
    }
    let columns = i16::from_be_bytes([body[0], body[1]]);
    if columns < 1 {
        return None;
    }
    let len = i32::from_be_bytes([body[2], body[3], body[4], body[5]]);
    if len < 0 {
        return None;
    }
    let start = 6;
    let end = start + len as usize;
    if end > body.len() {
        return None;
    }
    Some(String::from_utf8_lossy(&body[start..end]).into_owned())
}

fn parse_mechanisms(body: &[u8]) -> Vec<String> {
    body.split(|b| *b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

fn parse_parameter_status(body: &[u8]) -> Option<(String, String)> {
    let mut parts = body.split(|b| *b == 0);
    let key = parts.next()?;
    let value = parts.next()?;
    Some((String::from_utf8_lossy(key).into_owned(), String::from_utf8_lossy(value).into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> BackendConfig {
        BackendConfig {
            host: "pg-primary.internal".into(),
            port: 5432,
            database: "appdb".into(),
            user: "app".into(),
            password: "hunter2".into(),
            ssl_mode: SslMode::Disable,
            tls: None,
            application_name: "havuz".into(),
            supports_discard_all: true,
        }
    }

    #[test]
    fn target_label_is_stable_for_metrics() {
        assert_eq!(PgConnector::new(config()).target_label(), "pg-primary.internal:5432");
    }

    #[test]
    fn sasl_mechanism_list_is_parsed() {
        // AuthenticationSASL body after the subtype: mechanisms, then a final
        // empty string.
        assert_eq!(parse_mechanisms(b"SCRAM-SHA-256\0\0"), vec!["SCRAM-SHA-256"]);
        assert_eq!(
            parse_mechanisms(b"SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0"),
            vec!["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"]
        );
        assert!(parse_mechanisms(b"\0").is_empty());
    }

    #[test]
    fn parameter_status_is_parsed_into_a_pair() {
        let body = [b"server_version".as_slice(), &[0], b"16.2", &[0]].concat();
        assert_eq!(parse_parameter_status(&body), Some(("server_version".into(), "16.2".into())));
        assert_eq!(parse_parameter_status(b"incomplete"), None);
    }

    #[tokio::test]
    async fn connecting_to_a_dead_address_reports_a_retryable_backend_error() {
        let mut cfg = config();
        cfg.host = "127.0.0.1".into();
        // Port 1 is reserved and nothing listens there.
        cfg.port = 1;

        let err = PgConnector::new(cfg).connect().await.unwrap_err();
        assert!(matches!(err, ProtoError::Backend(_)), "got {err:?}");
        assert!(err.is_retryable(), "a refused connection should let the pool try another target");
    }

    #[test]
    fn data_row_parsing_handles_nulls_and_truncation() {
        // "hello" in a single column.
        let mut body = vec![0, 1];
        body.extend_from_slice(&5i32.to_be_bytes());
        body.extend_from_slice(b"hello");
        assert_eq!(first_column(&body), Some("hello".into()));

        // SQL NULL is length -1, and must not read as an empty string: for a
        // lag probe those mean very different things.
        let mut null_row = vec![0, 1];
        null_row.extend_from_slice(&(-1i32).to_be_bytes());
        assert_eq!(first_column(&null_row), None);

        // No columns.
        assert_eq!(first_column(&[0, 0, 0, 0, 0, 0]), None);

        // A length that runs past the end must not panic.
        let mut truncated = vec![0, 1];
        truncated.extend_from_slice(&999i32.to_be_bytes());
        truncated.extend_from_slice(b"ab");
        assert_eq!(first_column(&truncated), None);

        assert_eq!(first_column(&[]), None);
        assert_eq!(first_column(&[0, 1]), None);
    }

    #[test]
    fn redshift_style_backends_get_a_portable_reset_statement() {
        let mut cfg = config();
        cfg.supports_discard_all = false;
        // The flag is what selects the fallback; assert it survives into the
        // connector so the profile quirk actually reaches the reset path.
        let connector = PgConnector::new(cfg);
        assert!(!connector.config.supports_discard_all);
    }
}
