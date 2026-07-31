//! Prepared statement rewriting.
//!
//! Without this, transaction mode is quietly broken for every serious client.
//!
//! The extended query protocol lets a client `Parse` a statement under a name
//! and `Bind` to it later. asyncpg, JDBC, Npgsql and pgx all do this by
//! default. In transaction mode the `Bind` can land on a different backend from
//! the `Parse`, and the client gets `prepared statement "s1" does not exist` —
//! intermittently, under load, in production.
//!
//! There are two honest ways out. Pin any session that uses a named statement,
//! which is safe but hands back almost all of the multiplexing. Or rewrite the
//! names so a statement can be replayed onto whichever backend the client
//! reaches. This module does the second.
//!
//! The mechanism:
//!
//! 1. A client's `Parse` name is replaced with a global name derived from the
//!    statement text, so identical SQL from different clients shares one
//!    server-side statement.
//! 2. Each backend remembers which global names it has parsed.
//! 3. When a `Bind`, `Describe` or `Close` reaches a backend that has never
//!    seen the statement, the `Parse` is replayed first.
//!
//! Step 3 is where a bug would be catastrophic rather than merely annoying: get
//! the mapping wrong and one client's statement executes with another client's
//! parameters. Everything here is therefore pure, total, and tested against
//! malformed input rather than only against well-formed input.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use sha2::{Digest, Sha256};

use crate::protocol::Message;

/// Per-backend cache ceiling. Each entry costs a plan on the server, so this is
/// a real resource, not just memory.
pub const MAX_STATEMENTS_PER_BACKEND: usize = 256;

/// The unnamed statement. Scoped to a single extended-query exchange, so it
/// never needs rewriting.
const UNNAMED: &str = "";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PreparedError {
    #[error("malformed {message} message: {detail}")]
    Malformed { message: &'static str, detail: &'static str },
    #[error("client bound to unknown prepared statement '{0}'")]
    UnknownStatement(String),
}

/// A statement the client parsed, ready to be replayed onto any backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedStatement {
    /// Stable name derived from the statement text and parameter types.
    pub global_name: String,
    /// A complete `Parse` message using `global_name`.
    pub parse_message: Bytes,
    pub sql: String,
}

/// What the relay should do with a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rewrite {
    /// Forward unchanged.
    Unchanged,
    /// Forward this instead.
    Replace(Message),
    /// Replay `parse` first, then forward `message`.
    ReplayThen { parse: Bytes, global_name: String, message: Message },
    /// A renamed `Parse`.
    ///
    /// Handled separately from [`Rewrite::Replace`] because the backend may
    /// already hold this name, and PostgreSQL rejects a second `Parse` under an
    /// existing name rather than replacing it.
    Parse { global_name: String, message: Message },
    /// A `Close` of a statement; the backend cache must forget it too.
    CloseStatement { global_name: String, client_name: String, message: Message },
}

/// Per-client-session view of prepared statements.
#[derive(Debug, Default)]
pub struct ClientStatements {
    by_name: HashMap<String, Arc<PreparedStatement>>,
}

impl ClientStatements {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    pub fn get(&self, client_name: &str) -> Option<&Arc<PreparedStatement>> {
        self.by_name.get(client_name)
    }

    /// Handle a `Parse` from the client.
    ///
    /// The unnamed statement is passed through: it lives only until the next
    /// `Parse` on the same connection, and the whole exchange happens inside
    /// one checkout.
    pub fn on_parse(&mut self, msg: &Message) -> Result<Rewrite, PreparedError> {
        let parsed = ParseParts::decode(&msg.body)?;
        if parsed.name == UNNAMED {
            return Ok(Rewrite::Unchanged);
        }

        let global_name = global_name(parsed.sql, parsed.param_types);
        let parse_message = build_parse(&global_name, parsed.sql, parsed.param_types);

        self.by_name.insert(
            parsed.name.to_string(),
            Arc::new(PreparedStatement {
                global_name: global_name.clone(),
                parse_message: parse_message.clone(),
                sql: parsed.sql.to_string(),
            }),
        );

        Ok(Rewrite::Parse { global_name, message: Message::new(b'P', parse_message) })
    }

    /// Handle a `Bind`, whose second field names the statement.
    pub fn on_bind(&self, msg: &Message, backend: &BackendStatements) -> Result<Rewrite, PreparedError> {
        let name = bind_statement_name(&msg.body)?;
        self.redirect(msg, name, 1, backend)
    }

    /// Handle `Describe`/`Close`, which name either a statement or a portal.
    pub fn on_describe_or_close(&self, msg: &Message, backend: &BackendStatements) -> Result<Rewrite, PreparedError> {
        let (kind, name) = describe_target(&msg.body)?;
        // Portals are per-transaction and never need rewriting.
        if kind != b'S' {
            return Ok(Rewrite::Unchanged);
        }
        let rewritten = self.redirect(msg, name, 0, backend)?;

        // A Close must also drop the name from the backend cache, or the next
        // Bind would skip a replay the backend can no longer honour.
        if msg.tag == b'C' {
            if let Some(statement) = self.by_name.get(name) {
                let message = match rewritten {
                    Rewrite::Replace(m) | Rewrite::ReplayThen { message: m, .. } => m,
                    Rewrite::Unchanged => msg.clone(),
                    other => return Ok(other),
                };
                return Ok(Rewrite::CloseStatement {
                    global_name: statement.global_name.clone(),
                    client_name: name.to_string(),
                    message,
                });
            }
        }
        Ok(rewritten)
    }

    /// Common path: map the client's name onto the global one, replaying the
    /// `Parse` first when this backend has not seen it.
    fn redirect(
        &self,
        msg: &Message,
        client_name: &str,
        field_index: usize,
        backend: &BackendStatements,
    ) -> Result<Rewrite, PreparedError> {
        if client_name == UNNAMED {
            return Ok(Rewrite::Unchanged);
        }

        let statement =
            self.by_name.get(client_name).ok_or_else(|| PreparedError::UnknownStatement(client_name.to_string()))?;

        let body = replace_cstring(&msg.body, field_index, &statement.global_name)?;
        let rewritten = Message::new(msg.tag, body);

        if backend.has(&statement.global_name) {
            Ok(Rewrite::Replace(rewritten))
        } else {
            Ok(Rewrite::ReplayThen {
                parse: statement.parse_message.clone(),
                global_name: statement.global_name.clone(),
                message: rewritten,
            })
        }
    }

    /// Forget a client-side name after a successful `Close`.
    pub fn forget(&mut self, client_name: &str) {
        self.by_name.remove(client_name);
    }
}

/// Which global statements a particular backend has parsed.
#[derive(Debug, Default)]
pub struct BackendStatements {
    present: HashSet<String>,
    /// Insertion order, for eviction once the cache is full.
    order: VecDeque<String>,
}

impl BackendStatements {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn has(&self, global_name: &str) -> bool {
        self.present.contains(global_name)
    }

    pub fn len(&self) -> usize {
        self.present.len()
    }

    pub fn is_empty(&self) -> bool {
        self.present.is_empty()
    }

    /// Record a statement, returning the name that had to be evicted to make
    /// room. The caller is expected to send a `Close` for it.
    pub fn insert(&mut self, global_name: &str) -> Option<String> {
        if self.present.contains(global_name) {
            return None;
        }

        let evicted = if self.present.len() >= MAX_STATEMENTS_PER_BACKEND {
            self.order.pop_front().inspect(|old| {
                self.present.remove(old);
            })
        } else {
            None
        };

        self.present.insert(global_name.to_string());
        self.order.push_back(global_name.to_string());
        evicted
    }

    pub fn remove(&mut self, global_name: &str) {
        if self.present.remove(global_name) {
            self.order.retain(|n| n != global_name);
        }
    }

    /// Called after a reset, which deallocates everything server-side.
    pub fn clear(&mut self) {
        self.present.clear();
        self.order.clear();
    }
}

/// Deterministic name for a statement.
///
/// Derived from the SQL *and* the declared parameter types: the same text with
/// different types is a different statement, and reusing the name would produce
/// wrong results rather than an error.
fn global_name(sql: &str, param_types: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sql.as_bytes());
    hasher.update([0]);
    hasher.update(param_types);
    let digest = hasher.finalize();

    let mut out = String::with_capacity(6 + 32);
    out.push_str("havuz_");
    for byte in &digest[..16] {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn build_parse(name: &str, sql: &str, param_types: &[u8]) -> Bytes {
    let mut body = BytesMut::with_capacity(name.len() + sql.len() + param_types.len() + 2);
    body.put_slice(name.as_bytes());
    body.put_u8(0);
    body.put_slice(sql.as_bytes());
    body.put_u8(0);
    body.put_slice(param_types);
    body.freeze()
}

struct ParseParts<'a> {
    name: &'a str,
    sql: &'a str,
    /// Parameter type block, copied verbatim.
    param_types: &'a [u8],
}

impl<'a> ParseParts<'a> {
    fn decode(body: &'a [u8]) -> Result<Self, PreparedError> {
        let name_end = body
            .iter()
            .position(|b| *b == 0)
            .ok_or(PreparedError::Malformed { message: "Parse", detail: "no statement name" })?;
        let sql_start = name_end + 1;
        let sql_end = body[sql_start..]
            .iter()
            .position(|b| *b == 0)
            .map(|at| sql_start + at)
            .ok_or(PreparedError::Malformed { message: "Parse", detail: "no query text" })?;

        Ok(Self {
            name: std::str::from_utf8(&body[..name_end])
                .map_err(|_| PreparedError::Malformed { message: "Parse", detail: "name is not utf-8" })?,
            sql: std::str::from_utf8(&body[sql_start..sql_end])
                .map_err(|_| PreparedError::Malformed { message: "Parse", detail: "query is not utf-8" })?,
            param_types: &body[sql_end + 1..],
        })
    }
}

/// The statement name in a `Bind`: the second null-terminated string.
fn bind_statement_name(body: &[u8]) -> Result<&str, PreparedError> {
    let portal_end = body
        .iter()
        .position(|b| *b == 0)
        .ok_or(PreparedError::Malformed { message: "Bind", detail: "no portal name" })?;
    let start = portal_end + 1;
    let end = body[start..]
        .iter()
        .position(|b| *b == 0)
        .map(|at| start + at)
        .ok_or(PreparedError::Malformed { message: "Bind", detail: "no statement name" })?;

    std::str::from_utf8(&body[start..end])
        .map_err(|_| PreparedError::Malformed { message: "Bind", detail: "name is not utf-8" })
}

/// The `(kind, name)` pair in a `Describe` or `Close`.
fn describe_target(body: &[u8]) -> Result<(u8, &str), PreparedError> {
    let kind = *body.first().ok_or(PreparedError::Malformed { message: "Describe/Close", detail: "empty body" })?;
    let end = body[1..]
        .iter()
        .position(|b| *b == 0)
        .map(|at| 1 + at)
        .ok_or(PreparedError::Malformed { message: "Describe/Close", detail: "unterminated name" })?;

    let name = std::str::from_utf8(&body[1..end])
        .map_err(|_| PreparedError::Malformed { message: "Describe/Close", detail: "name is not utf-8" })?;
    Ok((kind, name))
}

/// Replace the `index`-th null-terminated string in `body`.
///
/// `Describe` and `Close` start with a kind byte, so their name is at index 0
/// counting from just after it; the caller passes the right index for the
/// message shape.
fn replace_cstring(body: &[u8], index: usize, replacement: &str) -> Result<Bytes, PreparedError> {
    // `Describe`/`Close` carry a leading kind byte before the first string.
    let (prefix_len, index) = if index == 0 && !body.is_empty() && matches!(body[0], b'S' | b'P') && body.len() > 1 {
        (1, 0)
    } else {
        (0, index)
    };

    let mut start = prefix_len;
    for _ in 0..index {
        let end = body[start..]
            .iter()
            .position(|b| *b == 0)
            .map(|at| start + at)
            .ok_or(PreparedError::Malformed { message: "message", detail: "unterminated string" })?;
        start = end + 1;
    }

    let end = body[start..]
        .iter()
        .position(|b| *b == 0)
        .map(|at| start + at)
        .ok_or(PreparedError::Malformed { message: "message", detail: "unterminated string" })?;

    let mut out = BytesMut::with_capacity(body.len() + replacement.len());
    out.put_slice(&body[..start]);
    out.put_slice(replacement.as_bytes());
    out.put_u8(0);
    out.put_slice(&body[end + 1..]);
    Ok(out.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_msg(name: &str, sql: &str) -> Message {
        let mut body = BytesMut::new();
        body.put_slice(name.as_bytes());
        body.put_u8(0);
        body.put_slice(sql.as_bytes());
        body.put_u8(0);
        body.put_i16(0); // no parameter types
        Message::new(b'P', body.freeze())
    }

    fn bind_msg(portal: &str, statement: &str) -> Message {
        let mut body = BytesMut::new();
        body.put_slice(portal.as_bytes());
        body.put_u8(0);
        body.put_slice(statement.as_bytes());
        body.put_u8(0);
        body.put_i16(0); // format codes
        body.put_i16(0); // parameters
        body.put_i16(0); // result formats
        Message::new(b'B', body.freeze())
    }

    fn describe_msg(kind: u8, name: &str) -> Message {
        let mut body = BytesMut::new();
        body.put_u8(kind);
        body.put_slice(name.as_bytes());
        body.put_u8(0);
        Message::new(b'D', body.freeze())
    }

    #[test]
    fn the_unnamed_statement_is_left_alone() {
        let mut client = ClientStatements::new();
        assert_eq!(client.on_parse(&parse_msg("", "SELECT 1")).unwrap(), Rewrite::Unchanged);
        assert!(client.is_empty(), "the unnamed statement needs no bookkeeping");

        let backend = BackendStatements::new();
        assert_eq!(client.on_bind(&bind_msg("", ""), &backend).unwrap(), Rewrite::Unchanged);
    }

    #[test]
    fn a_named_parse_is_renamed_to_a_global_name() {
        let mut client = ClientStatements::new();
        let Rewrite::Parse { message: rewritten, global_name } =
            client.on_parse(&parse_msg("s1", "SELECT $1")).unwrap()
        else {
            panic!("a named Parse must be rewritten");
        };
        assert!(global_name.starts_with("havuz_"));

        let parts = ParseParts::decode(&rewritten.body).unwrap();
        assert!(parts.name.starts_with("havuz_"), "got {}", parts.name);
        assert_eq!(parts.sql, "SELECT $1", "the statement text must survive untouched");
        assert_eq!(client.len(), 1);
    }

    #[test]
    fn identical_sql_from_two_clients_shares_one_server_statement() {
        // This is what makes the cache worth having: an ORM's query set is the
        // same across every connection in the fleet.
        let mut a = ClientStatements::new();
        let mut b = ClientStatements::new();
        a.on_parse(&parse_msg("s1", "SELECT $1")).unwrap();
        b.on_parse(&parse_msg("stmt_42", "SELECT $1")).unwrap();

        assert_eq!(a.get("s1").unwrap().global_name, b.get("stmt_42").unwrap().global_name);
    }

    #[test]
    fn different_sql_gets_different_names() {
        let mut client = ClientStatements::new();
        client.on_parse(&parse_msg("a", "SELECT 1")).unwrap();
        client.on_parse(&parse_msg("b", "SELECT 2")).unwrap();
        assert_ne!(client.get("a").unwrap().global_name, client.get("b").unwrap().global_name);
    }

    #[test]
    fn parameter_types_are_part_of_the_identity() {
        // Same text, different declared types, is a different statement. Reusing
        // the name would silently produce wrong results rather than an error.
        let mut client = ClientStatements::new();
        client.on_parse(&parse_msg("a", "SELECT $1")).unwrap();
        let first = client.get("a").unwrap().global_name.clone();

        let mut body = BytesMut::new();
        body.put_slice(b"b\0SELECT $1\0");
        body.put_i16(1);
        body.put_i32(23); // int4
        client.on_parse(&Message::new(b'P', body.freeze())).unwrap();

        assert_ne!(first, client.get("b").unwrap().global_name);
    }

    #[test]
    fn binding_on_a_fresh_backend_replays_the_parse_first() {
        let mut client = ClientStatements::new();
        client.on_parse(&parse_msg("s1", "SELECT $1")).unwrap();
        let backend = BackendStatements::new();

        let Rewrite::ReplayThen { parse, global_name, message } =
            client.on_bind(&bind_msg("", "s1"), &backend).unwrap()
        else {
            panic!("a backend that has never seen the statement must be taught it");
        };

        assert!(global_name.starts_with("havuz_"));
        assert_eq!(ParseParts::decode(&parse).unwrap().sql, "SELECT $1");
        assert_eq!(bind_statement_name(&message.body).unwrap(), global_name);
    }

    #[test]
    fn binding_on_a_backend_that_knows_the_statement_only_renames() {
        let mut client = ClientStatements::new();
        client.on_parse(&parse_msg("s1", "SELECT $1")).unwrap();
        let global = client.get("s1").unwrap().global_name.clone();

        let mut backend = BackendStatements::new();
        backend.insert(&global);

        let Rewrite::Replace(message) = client.on_bind(&bind_msg("p1", "s1"), &backend).unwrap() else {
            panic!("no replay needed once the backend has it");
        };
        assert_eq!(bind_statement_name(&message.body).unwrap(), global);
    }

    #[test]
    fn binding_to_an_unknown_statement_is_an_error_not_a_guess() {
        // Forwarding this blindly is how one client ends up executing another
        // client's statement.
        let client = ClientStatements::new();
        let backend = BackendStatements::new();
        assert_eq!(
            client.on_bind(&bind_msg("", "never_parsed"), &backend).unwrap_err(),
            PreparedError::UnknownStatement("never_parsed".into())
        );
    }

    #[test]
    fn bind_rewriting_preserves_everything_after_the_name() {
        let mut client = ClientStatements::new();
        client.on_parse(&parse_msg("s1", "SELECT $1")).unwrap();
        let backend = BackendStatements::new();

        // A bind with real parameter data, which must survive byte for byte.
        let mut body = BytesMut::new();
        body.put_slice(b"portal1\0s1\0");
        body.put_i16(1);
        body.put_i16(1); // binary format
        body.put_i16(1);
        body.put_i32(4);
        body.put_i32(0xdead_beefu32 as i32);
        body.put_i16(0);
        let tail_start = b"portal1\0s1\0".len();
        let original = body.clone().freeze();

        let Rewrite::ReplayThen { message, .. } =
            client.on_bind(&Message::new(b'B', original.clone()), &backend).unwrap()
        else {
            panic!("expected a replay");
        };

        let global = client.get("s1").unwrap().global_name.clone();
        let expected_tail = &original[tail_start..];
        let actual_tail = &message.body[b"portal1\0".len() + global.len() + 1..];
        assert_eq!(actual_tail, expected_tail, "parameter data must not be disturbed");
        assert_eq!(&message.body[..b"portal1\0".len()], b"portal1\0", "the portal name is untouched");
    }

    #[test]
    fn describe_of_a_statement_is_rewritten_and_of_a_portal_is_not() {
        let mut client = ClientStatements::new();
        client.on_parse(&parse_msg("s1", "SELECT $1")).unwrap();
        let global = client.get("s1").unwrap().global_name.clone();
        let mut backend = BackendStatements::new();
        backend.insert(&global);

        let Rewrite::Replace(message) = client.on_describe_or_close(&describe_msg(b'S', "s1"), &backend).unwrap()
        else {
            panic!("statement describes must be rewritten");
        };
        assert_eq!(describe_target(&message.body).unwrap(), (b'S', global.as_str()));

        // Portals are per-transaction; their names are the client's business.
        assert_eq!(client.on_describe_or_close(&describe_msg(b'P', "portal1"), &backend).unwrap(), Rewrite::Unchanged);
    }

    #[test]
    fn the_backend_cache_evicts_the_oldest_entry_when_full() {
        let mut backend = BackendStatements::new();
        for i in 0..MAX_STATEMENTS_PER_BACKEND {
            assert_eq!(backend.insert(&format!("havuz_{i}")), None);
        }
        assert_eq!(backend.len(), MAX_STATEMENTS_PER_BACKEND);

        // Each cached statement costs a plan on the server, so the cache is a
        // real resource and must be bounded.
        let evicted = backend.insert("havuz_new").expect("something must give way");
        assert_eq!(evicted, "havuz_0", "the oldest goes first");
        assert!(!backend.has("havuz_0"));
        assert!(backend.has("havuz_new"));
        assert_eq!(backend.len(), MAX_STATEMENTS_PER_BACKEND);
    }

    #[test]
    fn reinserting_a_known_statement_is_a_no_op() {
        let mut backend = BackendStatements::new();
        backend.insert("havuz_a");
        assert_eq!(backend.insert("havuz_a"), None);
        assert_eq!(backend.len(), 1);
    }

    #[test]
    fn clearing_the_backend_cache_forces_reparsing() {
        let mut client = ClientStatements::new();
        client.on_parse(&parse_msg("s1", "SELECT 1")).unwrap();
        let global = client.get("s1").unwrap().global_name.clone();

        let mut backend = BackendStatements::new();
        backend.insert(&global);
        backend.clear();

        // After a DISCARD ALL the server has forgotten everything, so the next
        // bind must teach it again rather than fail.
        assert!(matches!(client.on_bind(&bind_msg("", "s1"), &backend).unwrap(), Rewrite::ReplayThen { .. }));
    }

    #[test]
    fn malformed_messages_produce_errors_not_panics() {
        let mut client = ClientStatements::new();
        let backend = BackendStatements::new();

        assert!(client.on_parse(&Message::new(b'P', Bytes::from_static(b"no-nul"))).is_err());
        assert!(client.on_parse(&Message::new(b'P', Bytes::from_static(b"name\0no-terminator"))).is_err());
        assert!(client.on_bind(&Message::new(b'B', Bytes::new()), &backend).is_err());
        assert!(client.on_bind(&Message::new(b'B', Bytes::from_static(b"portal\0")), &backend).is_err());
        assert!(client.on_describe_or_close(&Message::new(b'D', Bytes::new()), &backend).is_err());
        assert!(client.on_describe_or_close(&Message::new(b'D', Bytes::from_static(b"S")), &backend).is_err());

        // Invalid UTF-8 in a name.
        assert!(client.on_parse(&Message::new(b'P', Bytes::from_static(&[0xff, 0, b'x', 0, 0, 0]))).is_err());
    }

    #[test]
    fn the_realistic_asyncpg_sequence_works_across_two_backends() {
        // asyncpg parses a named statement once and binds to it for the life of
        // the connection. In transaction mode those binds land wherever the
        // pool sends them.
        let mut client = ClientStatements::new();
        client.on_parse(&parse_msg("stmt_1", "SELECT * FROM t WHERE id = $1")).unwrap();
        let global = client.get("stmt_1").unwrap().global_name.clone();

        let mut backend_a = BackendStatements::new();
        let mut backend_b = BackendStatements::new();

        // First transaction lands on A and teaches it.
        let Rewrite::ReplayThen { global_name, .. } = client.on_bind(&bind_msg("", "stmt_1"), &backend_a).unwrap()
        else {
            panic!("A has never seen it");
        };
        backend_a.insert(&global_name);

        // Second transaction on A needs no replay.
        assert!(matches!(client.on_bind(&bind_msg("", "stmt_1"), &backend_a).unwrap(), Rewrite::Replace(_)));

        // Third lands on B, which must be taught in turn rather than erroring.
        let Rewrite::ReplayThen { global_name: on_b, .. } =
            client.on_bind(&bind_msg("", "stmt_1"), &backend_b).unwrap()
        else {
            panic!("B has never seen it and must be taught");
        };
        assert_eq!(on_b, global, "the same statement keeps the same global name everywhere");
        backend_b.insert(&on_b);
        assert!(matches!(client.on_bind(&bind_msg("", "stmt_1"), &backend_b).unwrap(), Rewrite::Replace(_)));
    }

    #[test]
    fn global_names_are_stable_across_runs() {
        // A name derived from a process-local counter or a random value would
        // work within one process and break the moment havuz restarts while
        // backends stay warm.
        let a = global_name("SELECT $1", &[0, 0]);
        let b = global_name("SELECT $1", &[0, 0]);
        assert_eq!(a, b);
        assert_eq!(a.len(), 6 + 32);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'), "must be a valid identifier: {a}");
    }
}
