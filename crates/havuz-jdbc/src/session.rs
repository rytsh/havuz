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

use std::collections::HashMap;

use bytes::{Buf, Bytes};
use havuz_pg::protocol::sqlstate;
use havuz_pg::{FieldDescription, MaybeTls, Message, TransactionStatus};
use havuz_proto::{ProtoError, ProtoResult};
use serde_json::{json, Value};

use crate::agent::{Agent, AgentError};
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

/// Relay a client through the agent until one side hangs up.
pub struct Session<'a> {
    agent: &'a Agent,
    /// The agent's handle for this client's JDBC connection.
    handle: &'a str,
    statements: HashMap<String, Prepared>,
    portals: HashMap<String, Portal>,
    in_transaction: bool,
    /// Set when a message failed and everything until `Sync` must be skipped,
    /// which is what the extended protocol requires and what stops a client
    /// from acting on the results of statements that never ran.
    failed: bool,
    stats: SessionStats,
}

impl<'a> Session<'a> {
    pub fn new(agent: &'a Agent, handle: &'a str) -> Self {
        Self {
            agent,
            handle,
            statements: HashMap::new(),
            portals: HashMap::new(),
            in_transaction: false,
            failed: false,
            stats: SessionStats::default(),
        }
    }

    pub fn stats(&self) -> &SessionStats {
        &self.stats
    }

    /// Read and answer client messages until it disconnects.
    pub async fn run(&mut self, client: &mut MaybeTls) -> ProtoResult<()> {
        loop {
            let message = match Message::read(client).await {
                Ok(message) => message,
                // A client that vanishes mid-session is ordinary, not an error:
                // connection pools close idle connections all the time.
                Err(_) => return Ok(()),
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
        let result =
            self.agent.call("execute", json!({ "session": self.handle, "sql": sql, "params": values })).await?;
        let outcome = Outcome::from(&result);
        self.in_transaction = outcome.in_transaction;
        Ok(outcome)
    }

    async fn agent_describe(&self, sql: &str) -> Result<(Vec<FieldDescription>, usize), AgentError> {
        let result = self.agent.call("describe", json!({ "session": self.handle, "sql": sql })).await?;
        let columns = fields(result.get("columns"));
        let params = result.get("paramCount").and_then(Value::as_i64).unwrap_or(-1);
        Ok((columns, if params > 0 { params as usize } else { 0 }))
    }

    async fn control(&mut self, control: TransactionControl) -> Result<(), AgentError> {
        let result = self.agent.call(control.method(), json!({ "session": self.handle })).await?;
        self.in_transaction = result.get("inTransaction").and_then(Value::as_bool).unwrap_or(false);
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

    async fn ready(&mut self, client: &mut MaybeTls) -> ProtoResult<()> {
        let status = if self.in_transaction { TransactionStatus::InTransaction } else { TransactionStatus::Idle };
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
        let word = sql.trim_start().split(|c: char| c.is_whitespace() || c == ';').next()?.to_ascii_uppercase();
        match word.as_str() {
            "BEGIN" | "START" => Some(Self::Begin),
            "COMMIT" | "END" => Some(Self::Commit),
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
