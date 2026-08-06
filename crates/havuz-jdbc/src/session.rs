//! Serving one client, as PostgreSQL would.
//!
//! This is the part that makes the bridge a server rather than a pooler. There
//! is no backend sending frames to copy, so every `RowDescription`, `DataRow`
//! and `CommandComplete` is composed here from what the agent reported.
//!
//! Both query protocols are supported, because supporting only the simple one
//! would be a demo: JDBC, pgx, asyncpg and Npgsql all use the extended
//! protocol, and a bridge whose whole purpose is to be reached by real
//! applications has to speak what real applications send.
//!
//! ## Where the backend is held
//!
//! A session borrows a JDBC connection from the moment the client asks for work
//! until the driver reports no transaction open, which is the same rule
//! `havuz-pg` follows and for the same reason. Three things make it work here:
//!
//! **The transaction boundary is a fact, not a guess.** The agent answers with
//! `inTransaction` read from `Connection.getAutoCommit()`. That is the JDBC
//! equivalent of the `ReadyForQuery` status byte, and it means transaction
//! boundaries are never inferred by looking for `COMMIT`.
//!
//! **What dirties a session is the product's answer, not ours.** The bridge
//! sees SQL in a dialect it was not told the name of, so it cannot decide
//! whether `ALTER SESSION` matters. [`SessionRules`] on the driver profile
//! says, and anything it does not recognise pins — see
//! [`havuz_registry::SessionRules::shareable`].
//!
//! **Prepared statements move with the client for free.** The agent creates and
//! closes a `PreparedStatement` per call, so nothing on the Java side is bound
//! to the connection this client happened to borrow. The metadata cached here
//! describes the SQL, not the socket, and survives a handover untouched.

use std::collections::HashMap;
use std::time::Duration;

use bytes::{Buf, Bytes};
use havuz_control::{HolderHandle, KickSignal};
use havuz_pg::protocol::sqlstate;
use havuz_pg::{FieldDescription, MaybeTls, Message, TransactionStatus};
use havuz_pool::{Checkout, Pool};
use havuz_proto::{FlowEvent, PinReason, ProtoError, ProtoResult, SessionState as FlowState};
use havuz_registry::{PoolMode, SessionRules};
use serde_json::{json, Value};

use crate::agent::{Agent, AgentError};
use crate::conn::JdbcConnector;
use crate::rewrite::{self, Rewritten};
use crate::types::{command_tag, pg_type};

/// Parameter values a client is told about at startup.
///
/// PostgreSQL sends these and clients act on them: `libpq` refuses to run
/// without `client_encoding`, and pgjdbc reads `standard_conforming_strings` to
/// decide how to escape. Reporting the truth about *this* endpoint matters more
/// than reporting the database behind it, because these describe how the two
/// sides will talk to each other.
pub fn startup_parameters(server_version: &str) -> Vec<(String, String)> {
    vec![
        // Named for what it is. A client that logs the server version should
        // not be told it is talking to PostgreSQL when it is not.
        ("server_version".into(), format!("16.0 (havuz jdbc bridge; {server_version})")),
        ("server_encoding".into(), "UTF8".into()),
        ("client_encoding".into(), "UTF8".into()),
        ("DateStyle".into(), "ISO, MDY".into()),
        ("integer_datetimes".into(), "on".into()),
        // Every value crosses as text, so backslashes are literal.
        ("standard_conforming_strings".into(), "on".into()),
        ("TimeZone".into(), "UTC".into()),
    ]
}

/// A statement the client parsed but has not run.
#[derive(Debug, Clone)]
struct Prepared {
    rewritten: Rewritten,
    original: String,
    /// What `Describe` should answer, when the driver would say.
    columns: Vec<FieldDescription>,
    params: usize,
}

/// A bound statement, ready to execute.
#[derive(Debug, Clone)]
struct Portal {
    statement: String,
    /// In the order the rewritten SQL wants them, which is not the order the
    /// client sent them when placeholders repeat or are out of order.
    values: Vec<Value>,
}

/// How the session ended.
#[derive(Debug, Default)]
pub struct SessionStats {
    pub exchanges: u64,
    pub rows: u64,
}

/// How a session is allowed to behave, beyond what its statements ask for.
pub struct SessionPolicy {
    /// How long a client may sit inside an open transaction before the session
    /// is ended. Zero disables it.
    ///
    /// Only meaningful in a multiplexing mode: in session mode the client owns
    /// its backend anyway, so ending it early frees nothing that disconnecting
    /// would not. `State::warnings` says so rather than letting the setting
    /// look like it applies everywhere.
    pub idle_in_transaction: Duration,
    /// Fires when an operator kills this session from the admin API.
    pub kick: KickSignal,
}

/// Relay a client through the agent until one side hangs up.
pub struct Session<'a> {
    agent: &'a Agent,
    pool: &'a Pool<JdbcConnector>,
    /// The JDBC connection this client is holding, if it is holding one.
    ///
    /// `None` between transactions in a multiplexing mode, and that absence is
    /// the entire source of the fan-in.
    held: Option<Checkout<JdbcConnector>>,
    /// The agent's handle for [`Session::held`]. Empty when nothing is held.
    ///
    /// Kept beside the checkout rather than read through it so an agent call
    /// does not have to borrow `held` for the length of a round trip into the
    /// JVM.
    handle: String,
    flow: FlowState,
    rules: SessionRules,
    policy: SessionPolicy,
    holder: &'a HolderHandle,
    /// What the dashboard calls the thing this session is holding.
    target: String,
    statements: HashMap<String, Prepared>,
    portals: HashMap<String, Portal>,
    /// Set when a message failed and everything until `Sync` must be skipped,
    /// which is what the extended protocol requires and what stops a client
    /// from acting on the results of statements that never ran.
    failed: bool,
    stats: SessionStats,
}

impl<'a> Session<'a> {
    /// Start a session that already holds `checkout`.
    ///
    /// The caller acquires the first backend before the handshake completes,
    /// which is what turns an exhausted pool into an error the client gets at
    /// connect time instead of one it discovers on its first query. In a
    /// multiplexing mode that backend is handed straight back: from here the
    /// client holds nothing while it is idle.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        agent: &'a Agent,
        pool: &'a Pool<JdbcConnector>,
        checkout: Checkout<JdbcConnector>,
        mode: PoolMode,
        rules: SessionRules,
        policy: SessionPolicy,
        holder: &'a HolderHandle,
        target: String,
    ) -> Self {
        let mut session = Self {
            agent,
            pool,
            handle: checkout.handle().to_string(),
            held: Some(checkout),
            flow: FlowState::new(mode),
            rules,
            policy,
            holder,
            target,
            statements: HashMap::new(),
            portals: HashMap::new(),
            failed: false,
            stats: SessionStats::default(),
        };
        session.release_if_idle();
        session.report_holder();
        session
    }

    pub fn stats(&self) -> &SessionStats {
        &self.stats
    }

    /// Why this session stopped being shareable, if it did.
    ///
    /// Always `None` in session mode, where nothing was ever shared and a
    /// verdict would only flatter the pin rate.
    pub fn pin(&self) -> Option<PinReason> {
        self.flow.mode().multiplexes().then(|| self.flow.pin()).flatten()
    }

    /// The backend this session is still holding, for the caller to clean up.
    pub fn into_checkout(self) -> Option<Checkout<JdbcConnector>> {
        self.held
    }

    /// Read and answer client messages until it disconnects.
    pub async fn run(&mut self, client: &mut MaybeTls) -> ProtoResult<()> {
        loop {
            // Between two client messages is the only moment at which ending a
            // session cannot leave a statement half-run, so both ways of ending
            // one early live here. The idle timer runs only while a transaction
            // is open: outside one this wait holds nothing and is exactly what
            // transaction mode is for.
            let idle_limit = self.policy.idle_in_transaction;
            let ticking = !idle_limit.is_zero() && self.flow.in_transaction() && self.held.is_some();

            let message = tokio::select! {
                biased;
                _ = self.policy.kick.kicked() => {
                    let _ = Message::fatal(
                        sqlstate::ADMIN_SHUTDOWN,
                        "terminating connection due to administrator command",
                    )
                    .write(client)
                    .await;
                    return Ok(());
                }
                _ = tokio::time::sleep(idle_limit), if ticking => {
                    // PostgreSQL's own code and wording, because it is the same
                    // event and a client that already handles it from the
                    // database should not have to learn a second spelling.
                    let _ = Message::fatal(
                        sqlstate::IDLE_IN_TRANSACTION_SESSION_TIMEOUT,
                        "terminating connection due to idle-in-transaction timeout",
                    )
                    .write(client)
                    .await;
                    // The transaction is abandoned, not committed: the client
                    // never said commit and guessing that it meant to would be
                    // inventing a write nobody asked for.
                    self.abandon().await;
                    tracing::info!(
                        pool = %self.pool.name(),
                        timeout_ms = idle_limit.as_millis() as u64,
                        "ended a jdbc session idle inside an open transaction"
                    );
                    return Ok(());
                }
                read = Message::read(client) => match read {
                    Ok(message) => message,
                    // A client that vanishes mid-session is ordinary, not an
                    // error: connection pools close idle connections all the
                    // time.
                    Err(_) => return Ok(()),
                },
            };

            match message.tag {
                b'Q' => self.simple_query(client, &message.body).await?,
                b'P' => self.parse(client, &message.body).await?,
                b'B' => self.bind(client, &message.body).await?,
                b'D' => self.describe(client, &message.body).await?,
                b'E' => self.execute(client, &message.body).await?,
                b'C' => self.close(client, &message.body).await?,
                b'S' => self.sync(client).await?,
                b'H' => {}
                b'X' => return Ok(()),
                other => {
                    self.fail(
                        client,
                        sqlstate::PROTOCOL_VIOLATION,
                        &format!("unsupported message '{}'", other as char),
                    )
                    .await?;
                    self.sync(client).await?;
                }
            }
        }
    }

    // --- holding a backend ---

    /// The agent handle for this client's connection, borrowing one if the
    /// client is not currently holding any.
    async fn backend(&mut self) -> Result<String, AgentError> {
        if self.held.is_some() {
            return Ok(self.handle.clone());
        }

        let checkout = self.pool.acquire().await.map_err(|e| AgentError::Exhausted(e.to_string()))?;
        self.handle = checkout.handle().to_string();
        self.held = Some(checkout);
        self.report_holder();
        Ok(self.handle.clone())
    }

    /// Give the backend back if the client is between transactions.
    ///
    /// No reset on the way out, deliberately. Recycling after every transaction
    /// would add a round trip into the JVM to every single one and undo most of
    /// the benefit; it is unnecessary because anything that dirties the
    /// connection was classified as a pin, and a pinned connection is never
    /// released. The reset happens once, when the client finally goes away.
    fn release_if_idle(&mut self) {
        if !self.flow.is_releasable() {
            self.report_holder();
            return;
        }
        if self.held.take().is_some() {
            self.handle.clear();
            self.flow.released();
        }
        self.holder.clear();
    }

    /// Roll back and drop whatever this session is holding.
    ///
    /// Used when the session is ended from outside rather than by the client.
    async fn abandon(&mut self) {
        if self.held.is_none() {
            return;
        }
        let handle = self.handle.clone();
        if let Err(e) = self.agent.call("rollback", json!({ "session": handle })).await {
            tracing::debug!(error = %e, "rolling back an abandoned jdbc transaction failed");
            if let Some(checkout) = self.held.as_mut() {
                checkout.poison();
            }
        }
        self.flow.observe(FlowEvent::Idle);
    }

    /// Tell the dashboard what this session is doing with a backend.
    fn report_holder(&self) {
        match self.flow.pin() {
            Some(reason) if self.held.is_some() => self.holder.pinned(reason, self.target.clone(), None),
            _ if self.held.is_none() => self.holder.clear(),
            _ if self.flow.in_transaction() => self.holder.idle_in_transaction(self.target.clone(), None),
            _ => self.holder.session_reserved(self.target.clone(), None),
        }
    }

    /// Fold one statement's outcome into the release decision.
    fn observe(&mut self, sql: &str, in_transaction: bool) {
        // Classification is skipped outside a multiplexing mode. In session
        // mode the connection is never shared, so every statement would be
        // reported as a pin and the pin breakdown — the one number that tells
        // an operator why transaction mode is not paying off — would be noise.
        if self.flow.mode().multiplexes() {
            if let Some(reason) = self.rules.classify(sql) {
                self.flow.observe(FlowEvent::MustPin(reason));
            }
        }
        self.flow.observe(if in_transaction { FlowEvent::InTransaction } else { FlowEvent::Idle });
    }

    /// Record what an agent failure means for the connection underneath it.
    ///
    /// A database error is the statement's problem and leaves the connection
    /// usable; anything else means the JVM stopped answering and what the
    /// driver is doing is unknown. Unknown is not shareable.
    fn observe_error(&mut self, error: &AgentError) {
        if matches!(error, AgentError::Database { .. }) {
            return;
        }
        self.flow.observe(FlowEvent::Broken);
        if let Some(checkout) = self.held.as_mut() {
            checkout.poison();
        }
    }

    // --- simple query ---

    async fn simple_query(&mut self, client: &mut MaybeTls, body: &Bytes) -> ProtoResult<()> {
        let sql = cstring(body);
        self.stats.exchanges += 1;

        if sql.trim().is_empty() {
            Message::empty_query_response().write(client).await.map_err(protocol)?;
            return self.ready(client).await;
        }

        // The client drives transactions with SQL here, so BEGIN and COMMIT
        // have to become explicit calls: JDBC tracks autocommit itself and
        // letting a raw BEGIN through would leave the two disagreeing about
        // whether a transaction is open.
        if let Some(control) = TransactionControl::of(&sql) {
            return match self.control(control).await {
                Ok(()) => {
                    Message::command_complete(control.tag()).write(client).await.map_err(protocol)?;
                    self.ready(client).await
                }
                Err(e) => {
                    self.report(client, &e).await?;
                    self.ready(client).await
                }
            };
        }

        let rewritten = rewrite::to_jdbc(&sql);
        match self.run_sql(&rewritten.sql, &[]).await {
            Ok(outcome) => {
                self.emit(client, &sql, &outcome, true).await?;
            }
            Err(e) => self.report(client, &e).await?,
        }
        self.ready(client).await
    }

    // --- extended query ---

    async fn parse(&mut self, client: &mut MaybeTls, body: &Bytes) -> ProtoResult<()> {
        if self.failed {
            return Ok(());
        }
        let mut rest = &body[..];
        let name = take_cstring(&mut rest);
        let sql = take_cstring(&mut rest);
        // Parameter type hints follow. They are advisory and the driver knows
        // better, so they are read past rather than used.

        let rewritten = rewrite::to_jdbc(&sql);
        let described = self.agent_describe(&rewritten.sql).await;

        let (columns, params) = match described {
            Ok((columns, params)) => (columns, params),
            Err(e) => {
                self.fail(client, e.sql_state(), &e.to_string()).await?;
                return Ok(());
            }
        };

        self.statements.insert(
            name,
            Prepared {
                params: if params > 0 { params } else { rewritten.highest as usize },
                rewritten,
                original: sql,
                columns,
            },
        );
        Message::parse_complete().write(client).await.map_err(protocol)
    }

    async fn bind(&mut self, client: &mut MaybeTls, body: &Bytes) -> ProtoResult<()> {
        if self.failed {
            return Ok(());
        }
        let mut rest = &body[..];
        let portal = take_cstring(&mut rest);
        let statement = take_cstring(&mut rest);

        let formats = take_i16_list(&mut rest);
        let count = take_i16(&mut rest).max(0) as usize;
        let mut sent = Vec::with_capacity(count);
        for index in 0..count {
            let length = take_i32(&mut rest);
            if length < 0 {
                sent.push(Value::Null);
                continue;
            }
            let bytes = take_bytes(&mut rest, length as usize);
            // Format 1 is binary. The bridge cannot interpret a binary
            // parameter without knowing its type, so it goes to the driver as
            // bytes and the database decides.
            let binary = matches!(formats.len(), 1 if formats[0] == 1) || formats.get(index) == Some(&1);
            sent.push(if binary { json!({ "binary": hex(&bytes) }) } else { json!(String::from_utf8_lossy(&bytes)) });
        }

        let Some(prepared) = self.statements.get(&statement) else {
            self.fail(
                client,
                sqlstate::PROTOCOL_VIOLATION,
                &format!("prepared statement \"{statement}\" does not exist"),
            )
            .await?;
            return Ok(());
        };

        // A repeated `$1` needs the value twice, and `$2, $1` needs them
        // swapped: JDBC is positional and has no way to say "that one again".
        let mut values = Vec::with_capacity(prepared.rewritten.order.len());
        for slot in &prepared.rewritten.order {
            values.push(sent.get(*slot as usize).cloned().unwrap_or(Value::Null));
        }

        self.portals.insert(portal, Portal { statement, values });
        Message::bind_complete().write(client).await.map_err(protocol)
    }

    async fn describe(&mut self, client: &mut MaybeTls, body: &Bytes) -> ProtoResult<()> {
        if self.failed {
            return Ok(());
        }
        let mut rest = &body[..];
        let kind = take_u8(&mut rest);
        let name = take_cstring(&mut rest);

        let statement = match kind {
            b'S' => self.statements.get(&name),
            _ => self.portals.get(&name).and_then(|portal| self.statements.get(&portal.statement)),
        };

        let Some(prepared) = statement else {
            self.fail(client, sqlstate::PROTOCOL_VIOLATION, &format!("\"{name}\" does not exist")).await?;
            return Ok(());
        };
        let columns = prepared.columns.clone();
        let params = prepared.params;

        if kind == b'S' {
            // Zero means "you decide", which is the honest answer: the driver
            // would not say, and inventing an OID would make the client encode
            // the value wrongly.
            Message::parameter_description(&vec![0i32; params]).write(client).await.map_err(protocol)?;
        }

        if columns.is_empty() {
            Message::no_data().write(client).await.map_err(protocol)
        } else {
            Message::row_description(&columns).write(client).await.map_err(protocol)
        }
    }

    async fn execute(&mut self, client: &mut MaybeTls, body: &Bytes) -> ProtoResult<()> {
        if self.failed {
            return Ok(());
        }
        let mut rest = &body[..];
        let name = take_cstring(&mut rest);

        let Some(portal) = self.portals.get(&name).cloned() else {
            self.fail(client, sqlstate::PROTOCOL_VIOLATION, &format!("portal \"{name}\" does not exist")).await?;
            return Ok(());
        };
        let Some(prepared) = self.statements.get(&portal.statement).cloned() else {
            self.fail(client, sqlstate::PROTOCOL_VIOLATION, "the portal's statement is gone").await?;
            return Ok(());
        };

        self.stats.exchanges += 1;

        if let Some(control) = TransactionControl::of(&prepared.original) {
            return match self.control(control).await {
                Ok(()) => Message::command_complete(control.tag()).write(client).await.map_err(protocol),
                Err(e) => self.fail(client, e.sql_state(), &e.to_string()).await,
            };
        }

        match self.run_sql(&prepared.rewritten.sql, &portal.values).await {
            // No RowDescription: the client already asked for it with Describe,
            // and sending it twice makes some drivers treat the second one as a
            // new result set.
            Ok(outcome) => self.emit(client, &prepared.original, &outcome, false).await,
            Err(e) => self.fail(client, e.sql_state(), &e.to_string()).await,
        }
    }

    async fn close(&mut self, client: &mut MaybeTls, body: &Bytes) -> ProtoResult<()> {
        let mut rest = &body[..];
        let kind = take_u8(&mut rest);
        let name = take_cstring(&mut rest);
        match kind {
            b'S' => {
                self.statements.remove(&name);
                self.portals.retain(|_, portal| portal.statement != name);
            }
            _ => {
                self.portals.remove(&name);
            }
        }
        Message::close_complete().write(client).await.map_err(protocol)
    }

    async fn sync(&mut self, client: &mut MaybeTls) -> ProtoResult<()> {
        self.failed = false;
        self.ready(client).await
    }

    // --- shared ---

    async fn run_sql(&mut self, sql: &str, values: &[Value]) -> Result<Outcome, AgentError> {
        let handle = self.backend().await?;
        let result = match self.agent.call("execute", json!({ "session": handle, "sql": sql, "params": values })).await
        {
            Ok(result) => result,
            Err(e) => {
                self.observe_error(&e);
                return Err(e);
            }
        };
        let outcome = Outcome::from(&result);
        self.observe(sql, outcome.in_transaction);
        Ok(outcome)
    }

    async fn agent_describe(&mut self, sql: &str) -> Result<(Vec<FieldDescription>, usize), AgentError> {
        // Describing needs a live connection even though it runs nothing, so a
        // `Parse` is where a multiplexing session starts holding one. That is
        // the same point `havuz-pg` starts holding: the client asked for work.
        let handle = self.backend().await?;
        let result = match self.agent.call("describe", json!({ "session": handle, "sql": sql })).await {
            Ok(result) => result,
            Err(e) => {
                self.observe_error(&e);
                return Err(e);
            }
        };
        let columns = fields(result.get("columns"));
        let params = result.get("paramCount").and_then(Value::as_i64).unwrap_or(-1);
        Ok((columns, if params > 0 { params as usize } else { 0 }))
    }

    async fn control(&mut self, control: TransactionControl) -> Result<(), AgentError> {
        // Ending a transaction nobody started needs no backend. PostgreSQL
        // answers this with a warning and the tag, and borrowing a connection
        // to tell a driver's idle `COMMIT` the same thing would spend a
        // checkout on nothing.
        if self.held.is_none() && control != TransactionControl::Begin {
            self.flow.observe(FlowEvent::Idle);
            return Ok(());
        }

        let handle = self.backend().await?;
        let result = match self.agent.call(control.method(), json!({ "session": handle })).await {
            Ok(result) => result,
            Err(e) => {
                self.observe_error(&e);
                return Err(e);
            }
        };
        let in_transaction = result.get("inTransaction").and_then(Value::as_bool).unwrap_or(false);
        self.flow.observe(if in_transaction { FlowEvent::InTransaction } else { FlowEvent::Idle });
        Ok(())
    }

    /// Write a result set the way PostgreSQL would.
    async fn emit(&mut self, client: &mut MaybeTls, sql: &str, outcome: &Outcome, describe: bool) -> ProtoResult<()> {
        if !outcome.columns.is_empty() && describe {
            Message::row_description(&outcome.columns).write(client).await.map_err(protocol)?;
        }
        for row in &outcome.rows {
            Message::data_row(row).write(client).await.map_err(protocol)?;
        }
        self.stats.rows += outcome.rows.len() as u64;
        let tag = command_tag(sql, outcome.rows.len() as u64, outcome.update_count);
        Message::command_complete(&tag).write(client).await.map_err(protocol)
    }

    /// End an exchange: hand the backend back if the client owes us nothing,
    /// then tell it we are ready.
    ///
    /// Released before the `ReadyForQuery` rather than after, so the connection
    /// is already available to whoever is queued behind this client by the time
    /// this one is told it may send more.
    async fn ready(&mut self, client: &mut MaybeTls) -> ProtoResult<()> {
        let status =
            if self.flow.in_transaction() { TransactionStatus::InTransaction } else { TransactionStatus::Idle };
        self.release_if_idle();
        Message::ready_for_query(status).write(client).await.map_err(protocol)
    }

    /// Report an error and stop processing until the client synchronises.
    async fn fail(&mut self, client: &mut MaybeTls, code: &str, message: &str) -> ProtoResult<()> {
        self.failed = true;
        Message::error_response("ERROR", code, message).write(client).await.map_err(protocol)
    }

    async fn report(&mut self, client: &mut MaybeTls, error: &AgentError) -> ProtoResult<()> {
        Message::error_response("ERROR", error.sql_state(), &error.to_string()).write(client).await.map_err(protocol)
    }
}

/// What the agent said about one statement.
struct Outcome {
    columns: Vec<FieldDescription>,
    rows: Vec<Vec<Option<Vec<u8>>>>,
    update_count: i64,
    in_transaction: bool,
}

impl Outcome {
    fn from(result: &Value) -> Self {
        let columns = fields(result.get("columns"));
        // Re-encoded here rather than in the agent: whether a boolean is `t`
        // and whether binary carries a `\x` are facts about the PostgreSQL wire
        // format, and the agent does not know which protocol it is feeding.
        let encodings: Vec<_> = column_types(result.get("columns"));

        let rows = result
            .get("rows")
            .and_then(Value::as_array)
            .map(|rows| {
                rows.iter()
                    .map(|row| {
                        row.as_array()
                            .map(|values| {
                                values
                                    .iter()
                                    .enumerate()
                                    .map(|(index, value)| {
                                        value.as_str().map(|text| match encodings.get(index) {
                                            Some(pg) => pg.encode(text),
                                            None => text.as_bytes().to_vec(),
                                        })
                                    })
                                    .collect()
                            })
                            .unwrap_or_default()
                    })
                    .collect()
            })
            .unwrap_or_default();

        Self {
            columns,
            rows,
            update_count: result.get("updateCount").and_then(Value::as_i64).unwrap_or(-1),
            in_transaction: result.get("inTransaction").and_then(Value::as_bool).unwrap_or(false),
        }
    }
}

fn column_types(columns: Option<&Value>) -> Vec<crate::types::PgType> {
    columns
        .and_then(Value::as_array)
        .map(|columns| {
            columns
                .iter()
                .map(|column| {
                    pg_type(
                        column.get("jdbcType").and_then(Value::as_i64).unwrap_or(0) as i32,
                        column.get("typeName").and_then(Value::as_str).unwrap_or(""),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn fields(columns: Option<&Value>) -> Vec<FieldDescription> {
    columns
        .and_then(Value::as_array)
        .map(|columns| {
            columns
                .iter()
                .map(|column| {
                    let pg = pg_type(
                        column.get("jdbcType").and_then(Value::as_i64).unwrap_or(0) as i32,
                        column.get("typeName").and_then(Value::as_str).unwrap_or(""),
                    );
                    FieldDescription {
                        name: column.get("name").and_then(Value::as_str).unwrap_or("?column?").to_string(),
                        type_oid: pg.oid,
                        type_size: pg.size,
                        type_modifier: -1,
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `BEGIN`, `COMMIT` or `ROLLBACK`, which the bridge performs rather than
/// forwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransactionControl {
    Begin,
    Commit,
    Rollback,
}

impl TransactionControl {
    fn of(sql: &str) -> Option<Self> {
        let mut words = sql
            .trim_start()
            .split(|c: char| c.is_whitespace() || c == ';')
            .filter(|word| !word.is_empty())
            .map(|word| word.to_ascii_uppercase());

        let first = words.next()?;
        let second = words.next();

        match first.as_str() {
            // `BEGIN` opens a transaction in PostgreSQL and an anonymous block
            // in Oracle and Db2, and the client speaks PostgreSQL while the
            // database may not. The two are told apart by what follows: a
            // transaction start is either bare or carries one of the
            // characteristics `BEGIN` accepts, and a block carries a statement.
            //
            // Getting this wrong is not cosmetic. A block treated as `BEGIN`
            // would leave the client believing its PL/SQL ran when nothing but
            // `setAutoCommit(false)` did.
            "BEGIN" => matches!(
                second.as_deref(),
                None | Some("WORK")
                    | Some("TRANSACTION")
                    | Some("ISOLATION")
                    | Some("READ")
                    | Some("DEFERRABLE")
                    | Some("NOT")
            )
            .then_some(Self::Begin),
            // Only ever `START TRANSACTION`; anything else is a procedure a
            // driver happened to name that way.
            "START" => (second.as_deref() == Some("TRANSACTION")).then_some(Self::Begin),
            "COMMIT" => Some(Self::Commit),
            // PostgreSQL's synonym for COMMIT, and the terminator of a PL/SQL
            // block. A bare `END` is the former; `END LOOP` and friends only
            // ever arrive inside a block, which the `BEGIN` arm already refused
            // to treat as control.
            "END" => matches!(second.as_deref(), None | Some("WORK") | Some("TRANSACTION")).then_some(Self::Commit),
            "ROLLBACK" | "ABORT" => Some(Self::Rollback),
            _ => None,
        }
    }

    fn method(self) -> &'static str {
        match self {
            Self::Begin => "begin",
            Self::Commit => "commit",
            Self::Rollback => "rollback",
        }
    }

    /// PostgreSQL's own tags, which clients compare against.
    fn tag(self) -> &'static str {
        match self {
            Self::Begin => "BEGIN",
            Self::Commit => "COMMIT",
            Self::Rollback => "ROLLBACK",
        }
    }
}

fn protocol(e: impl std::fmt::Display) -> ProtoError {
    ProtoError::protocol(e.to_string())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// --- wire decoding helpers ---

fn cstring(body: &Bytes) -> String {
    let end = body.iter().position(|byte| *byte == 0).unwrap_or(body.len());
    String::from_utf8_lossy(&body[..end]).into_owned()
}

fn take_cstring(rest: &mut &[u8]) -> String {
    let end = rest.iter().position(|byte| *byte == 0).unwrap_or(rest.len());
    let text = String::from_utf8_lossy(&rest[..end]).into_owned();
    *rest = &rest[(end + 1).min(rest.len())..];
    text
}

fn take_u8(rest: &mut &[u8]) -> u8 {
    if rest.is_empty() {
        return 0;
    }
    let value = rest[0];
    *rest = &rest[1..];
    value
}

fn take_i16(rest: &mut &[u8]) -> i16 {
    if rest.len() < 2 {
        *rest = &[];
        return 0;
    }
    let value = i16::from_be_bytes([rest[0], rest[1]]);
    rest.advance(2);
    value
}

fn take_i32(rest: &mut &[u8]) -> i32 {
    if rest.len() < 4 {
        *rest = &[];
        return -1;
    }
    let value = i32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
    rest.advance(4);
    value
}

fn take_i16_list(rest: &mut &[u8]) -> Vec<i16> {
    let count = take_i16(rest).max(0) as usize;
    (0..count).map(|_| take_i16(rest)).collect()
}

fn take_bytes(rest: &mut &[u8], length: usize) -> Vec<u8> {
    let length = length.min(rest.len());
    let value = rest[..length].to_vec();
    *rest = &rest[length..];
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_control_is_performed_not_forwarded() {
        // JDBC tracks autocommit itself; a raw BEGIN would leave the two
        // disagreeing about whether a transaction is open.
        assert_eq!(TransactionControl::of("begin"), Some(TransactionControl::Begin));
        assert_eq!(TransactionControl::of("  BEGIN;"), Some(TransactionControl::Begin));
        assert_eq!(TransactionControl::of("BEGIN WORK"), Some(TransactionControl::Begin));
        assert_eq!(TransactionControl::of("BEGIN ISOLATION LEVEL SERIALIZABLE"), Some(TransactionControl::Begin));
        assert_eq!(TransactionControl::of("start transaction"), Some(TransactionControl::Begin));
        assert_eq!(TransactionControl::of("COMMIT"), Some(TransactionControl::Commit));
        assert_eq!(TransactionControl::of("end"), Some(TransactionControl::Commit));
        assert_eq!(TransactionControl::of("rollback"), Some(TransactionControl::Rollback));
        assert_eq!(TransactionControl::of("abort"), Some(TransactionControl::Rollback));

        assert_eq!(TransactionControl::of("select 1"), None);
        assert_eq!(TransactionControl::of(""), None);
        // Not a transaction control statement, despite the prefix.
        assert_eq!(TransactionControl::of("beginning"), None);
    }

    #[test]
    fn a_plsql_block_is_not_a_transaction_start() {
        // The whole reason this bridge exists is databases that are not
        // PostgreSQL, and in Oracle and Db2 `BEGIN` opens an anonymous block.
        // Treating one as transaction control would answer the client with a
        // `BEGIN` tag while nothing but setAutoCommit(false) had happened —
        // the client's procedure would silently never run.
        assert_eq!(TransactionControl::of("BEGIN DBMS_OUTPUT.PUT_LINE('x'); END;"), None);
        assert_eq!(TransactionControl::of("begin\n  null;\nend;"), None);
        assert_eq!(TransactionControl::of("BEGIN ATOMIC SET x = 1; END"), None);

        // And `START` only ever means a transaction as `START TRANSACTION`.
        assert_eq!(TransactionControl::of("START JOB 'nightly'"), None);
    }

    #[test]
    fn startup_parameters_say_what_this_endpoint_is() {
        let params = startup_parameters("PostgreSQL 16.2");
        let version = params.iter().find(|(k, _)| k == "server_version").unwrap();
        assert!(version.1.contains("havuz jdbc bridge"), "a client must not be told it reached PostgreSQL directly");
        assert!(version.1.contains("PostgreSQL 16.2"), "and must still learn what is actually behind it");
        assert!(params.iter().any(|(k, v)| k == "client_encoding" && v == "UTF8"));
        assert!(params.iter().any(|(k, v)| k == "standard_conforming_strings" && v == "on"));
    }

    #[test]
    fn a_result_set_is_re_encoded_for_the_wire() {
        let result = json!({
            "columns": [
                {"name": "flag", "jdbcType": 16, "typeName": "bool"},
                {"name": "blob", "jdbcType": -2, "typeName": "bytea"},
                {"name": "note", "jdbcType": 12, "typeName": "text"},
            ],
            "rows": [["true", "00ff", "hi"], ["false", null, null]],
            "updateCount": -1,
            "inTransaction": false,
        });
        let outcome = Outcome::from(&result);

        assert_eq!(outcome.columns.len(), 3);
        assert_eq!(outcome.columns[0].type_oid, 16);
        assert_eq!(outcome.rows[0][0], Some(b"t".to_vec()));
        assert_eq!(outcome.rows[0][1], Some(b"\\x00ff".to_vec()));
        assert_eq!(outcome.rows[0][2], Some(b"hi".to_vec()));
        assert_eq!(outcome.rows[1][0], Some(b"f".to_vec()));
        assert_eq!(outcome.rows[1][1], None, "a null must not become an empty blob");
    }

    #[test]
    fn a_result_with_no_rows_is_not_a_failure() {
        let outcome = Outcome::from(&json!({ "columns": [], "rows": [], "updateCount": 3 }));
        assert!(outcome.rows.is_empty());
        assert_eq!(outcome.update_count, 3);
    }

    #[test]
    fn a_malformed_agent_reply_degrades_rather_than_panicking() {
        let outcome = Outcome::from(&json!({}));
        assert!(outcome.columns.is_empty());
        assert_eq!(outcome.update_count, -1);
    }

    #[test]
    fn a_column_without_a_name_still_describes() {
        let outcome = Outcome::from(&json!({ "columns": [{"jdbcType": 4, "typeName": "int4"}], "rows": [] }));
        assert_eq!(outcome.columns[0].name, "?column?", "what PostgreSQL calls an unnamed column");
    }

    #[test]
    fn cstrings_are_read_without_their_terminator() {
        let mut rest: &[u8] = b"stmt\0select 1\0extra";
        assert_eq!(take_cstring(&mut rest), "stmt");
        assert_eq!(take_cstring(&mut rest), "select 1");
        assert_eq!(rest, b"extra");
    }

    #[test]
    fn truncated_messages_do_not_panic() {
        // A malformed frame is a client bug; it must produce an error, not
        // take the whole process down.
        let mut rest: &[u8] = b"\x00";
        assert_eq!(take_i16(&mut rest), 0);
        let mut rest: &[u8] = b"\x00\x01";
        assert_eq!(take_i32(&mut rest), -1);
        let mut rest: &[u8] = b"no terminator";
        assert_eq!(take_cstring(&mut rest), "no terminator");
        let mut rest: &[u8] = b"ab";
        assert_eq!(take_bytes(&mut rest, 99), b"ab");
    }

    #[test]
    fn parameter_formats_decide_text_from_binary() {
        // Format 1 means binary, and a single format applies to every value.
        let mut rest: &[u8] = &[0, 1, 0, 1];
        assert_eq!(take_i16_list(&mut rest), [1]);
    }
}
