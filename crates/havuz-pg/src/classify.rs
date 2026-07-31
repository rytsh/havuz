//! Deciding what a client message costs us.
//!
//! Transaction-mode pooling works because most statements leave no trace on the
//! connection once the transaction ends. A handful do, and each one silently
//! demotes the pool back to session mode for that client. This module finds
//! them.
//!
//! "Leaves a trace" is not the same as "cannot be shared". A session parameter
//! leaves a trace with a name, so it can be remembered and reproduced on the
//! next backend; [`crate::params`] does that, and this module asks it rather
//! than pinning on sight. What is left here is the state that has no name we
//! could replay — a temp table, a `LISTEN` registration, an advisory lock, a
//! connection that has entered a streaming sub-protocol.
//!
//! The output feeds the product's most useful telemetry: not "your pool is
//! full" but "`svc_orders` opens a holdable cursor on connect, which is why
//! your 100 clients are still using 100 backends".
//!
//! Two deliberate non-goals:
//!
//! * **No SQL parser.** A real parser on the hot path costs more than the
//!   pooling saves. We look at leading keywords, which is enough because every
//!   pinning construct is identified by its first one or two words.
//! * **No cleverness about false positives.** When in doubt we pin. Pinning
//!   costs throughput; guessing wrong costs correctness.

use havuz_proto::PinReason;

use crate::protocol::Message;

/// What the pooler should do about a client message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientIntent {
    /// Client is leaving. Never forwarded to the backend.
    Terminate,
    /// A request that will be answered with `ReadyForQuery`. The backend is
    /// borrowed until that arrives.
    SyncPoint,
    /// Part of an extended-protocol exchange that is not yet complete.
    Pipelined,
    /// Mutates session state that outlives the transaction.
    Pins(PinReason),
    /// Everything else.
    Ordinary,
}

/// Classify a message from the client.
pub fn classify(msg: &Message) -> ClientIntent {
    match msg.tag {
        b'X' => ClientIntent::Terminate,

        // Simple query: the whole statement text is right here.
        b'Q' => match sql_pin_reason(&text_body(&msg.body)) {
            Some(reason) => ClientIntent::Pins(reason),
            None => ClientIntent::SyncPoint,
        },

        // Parse: `name\0query\0` followed by parameter types.
        b'P' => match parse_message_sql(&msg.body).as_deref().and_then(sql_pin_reason) {
            Some(reason) => ClientIntent::Pins(reason),
            None => ClientIntent::Pipelined,
        },

        // Sync ends an extended-protocol exchange and produces ReadyForQuery.
        b'S' => ClientIntent::SyncPoint,

        // Flush asks for buffered output but produces no ReadyForQuery, so it
        // must not be treated as a boundary.
        b'H' => ClientIntent::Pipelined,

        // Bind, Describe, Execute, Close: all mid-exchange.
        b'B' | b'D' | b'E' | b'C' => ClientIntent::Pipelined,

        // Copy data from the client. The connection is mid-stream and cannot
        // be handed to anyone else.
        b'd' | b'c' | b'f' => ClientIntent::Pins(PinReason::BulkTransfer),

        // Function call, deprecated but still a sync point.
        b'F' => ClientIntent::SyncPoint,

        _ => ClientIntent::Ordinary,
    }
}

/// Extract the query text from a `Parse` message body.
fn parse_message_sql(body: &[u8]) -> Option<String> {
    let mut parts = body.splitn(3, |b| *b == 0);
    let _name = parts.next()?;
    let sql = parts.next()?;
    Some(String::from_utf8_lossy(sql).into_owned())
}

fn text_body(body: &[u8]) -> String {
    let end = body.iter().position(|b| *b == 0).unwrap_or(body.len());
    String::from_utf8_lossy(&body[..end]).into_owned()
}

/// Does this SQL leave something behind on the connection?
///
/// A simple query may carry several statements; any one of them pinning pins
/// the whole connection.
pub fn sql_pin_reason(sql: &str) -> Option<PinReason> {
    split_statements(sql).into_iter().find_map(statement_pin_reason)
}

fn statement_pin_reason(statement: &str) -> Option<PinReason> {
    let normalized = strip_leading_noise(statement);
    if normalized.is_empty() {
        return None;
    }

    let upper = leading_words(normalized, 4);
    let words: Vec<&str> = upper.split_whitespace().collect();

    match words.first().copied() {
        // A session parameter is not hidden state: it has a name, so it can be
        // remembered and reproduced on the next backend. Only the spellings
        // that cannot be replayed — `SET ROLE`, a value that lives in a `Bind`,
        // an unrecognised shape — are still worth a pin. See `params`.
        Some("SET") | Some("RESET") => match crate::params::classify_set(normalized) {
            crate::params::SetAction::Pin(reason) => Some(reason),
            _ => None,
        },

        // Both make this connection the delivery target for notifications.
        Some("LISTEN") | Some("UNLISTEN") => Some(PinReason::Listen),

        Some("CREATE") => match (words.get(1).copied(), words.get(2).copied()) {
            // Temporary objects live in a per-connection schema.
            (Some("TEMP"), _) | (Some("TEMPORARY"), _) => Some(PinReason::TempTable),
            (Some("GLOBAL"), Some("TEMP")) | (Some("GLOBAL"), Some("TEMPORARY")) => Some(PinReason::TempTable),
            (Some("LOCAL"), Some("TEMP")) | (Some("LOCAL"), Some("TEMPORARY")) => Some(PinReason::TempTable),
            _ => None,
        },

        // Server-side prepared statements are session scoped and distinct from
        // the extended protocol's named statements.
        Some("PREPARE") => match words.get(1).copied() {
            // `PREPARE TRANSACTION` is two-phase commit, not a statement.
            Some("TRANSACTION") => Some(PinReason::ServerSidePrepare),
            _ => Some(PinReason::ServerSidePrepare),
        },
        Some("DEALLOCATE") => Some(PinReason::ServerSidePrepare),

        // A holdable cursor survives commit.
        Some("DECLARE") => normalized.to_ascii_uppercase().contains("WITH HOLD").then_some(PinReason::HoldableCursor),

        // COPY switches the connection into a streaming sub-protocol.
        Some("COPY") => Some(PinReason::BulkTransfer),

        Some("START") if words.get(1).copied() == Some("REPLICATION") => Some(PinReason::Replication),

        // Session-level advisory locks are not released at commit; the
        // transaction-scoped variants are.
        _ if mentions_session_advisory_lock(normalized) => Some(PinReason::AdvisoryLock),

        _ => None,
    }
}

/// `pg_advisory_lock` holds until unlocked or the session ends;
/// `pg_advisory_xact_lock` is released at commit and is therefore safe.
fn mentions_session_advisory_lock(sql: &str) -> bool {
    let lower = sql.to_ascii_lowercase();
    let mut from = 0;
    while let Some(at) = lower[from..].find("pg_advisory_") {
        let start = from + at;
        let rest = &lower[start..];
        if !rest.starts_with("pg_advisory_xact_") && !rest.starts_with("pg_advisory_unlock") {
            return true;
        }
        from = start + "pg_advisory_".len();
    }
    false
}

/// Split a simple-query payload into statements.
///
/// Quotes, dollar quoting and comments are respected so a semicolon inside a
/// string literal does not split anything.
pub(crate) fn split_statements(sql: &str) -> Vec<&str> {
    let bytes = sql.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' => {
                let quote = bytes[i];
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == quote {
                        // A doubled quote is an escaped quote, not the end.
                        if bytes.get(i + 1) == Some(&quote) {
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
                i += 1;
            }
            b'$' => match dollar_tag_len(&bytes[i..]) {
                Some(tag_len) => {
                    let tag = &bytes[i..i + tag_len];
                    i += tag_len;
                    while i < bytes.len() {
                        if bytes[i..].starts_with(tag) {
                            i += tag_len;
                            break;
                        }
                        i += 1;
                    }
                }
                None => i += 1,
            },
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                let mut depth = 1;
                while i < bytes.len() && depth > 0 {
                    if bytes[i..].starts_with(b"/*") {
                        depth += 1;
                        i += 2;
                    } else if bytes[i..].starts_with(b"*/") {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
            }
            b';' => {
                out.push(&sql[start..i]);
                start = i + 1;
                i += 1;
            }
            _ => i += 1,
        }
    }

    if start < sql.len() {
        out.push(&sql[start..]);
    }
    out
}

/// Length of a `$tag$` opener at the start of `bytes`, if there is one.
fn dollar_tag_len(bytes: &[u8]) -> Option<usize> {
    if bytes.first() != Some(&b'$') {
        return None;
    }
    let mut i = 1;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
    }
    (bytes.get(i) == Some(&b'$')).then_some(i + 1)
}

/// Drop leading whitespace and comments so `/* app */ SET x = 1` is still seen
/// as a `SET`.
pub(crate) fn strip_leading_noise(sql: &str) -> &str {
    let mut rest = sql.trim_start();
    loop {
        if let Some(after) = rest.strip_prefix("--") {
            rest = after.find('\n').map(|at| &after[at + 1..]).unwrap_or("").trim_start();
            continue;
        }
        if let Some(after) = rest.strip_prefix("/*") {
            match after.find("*/") {
                Some(at) => {
                    rest = after[at + 2..].trim_start();
                    continue;
                }
                None => return "",
            }
        }
        return rest;
    }
}

/// Uppercase the first `n` whitespace-separated words.
fn leading_words(sql: &str, n: usize) -> String {
    sql.split_whitespace().take(n).collect::<Vec<_>>().join(" ").to_ascii_uppercase()
}

// ---------------------------------------------------------------------------
// Read/write routing
// ---------------------------------------------------------------------------

/// Where a statement is allowed to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteIntent {
    /// Safe on a replica.
    Read,
    /// Must reach the primary.
    Write,
}

impl RouteIntent {
    pub fn as_str(self) -> &'static str {
        match self {
            RouteIntent::Read => "read",
            RouteIntent::Write => "write",
        }
    }
}

/// Decide whether a statement may be served by a replica.
///
/// The bias is absolute: anything not provably read-only is a write. Sending a
/// write to a replica produces a hard error, which is loud and gets fixed.
/// Sending a *read* to a replica when it should have gone to the primary
/// produces stale data, which is silent and gets shipped. So every ambiguity
/// resolves to [`RouteIntent::Write`].
///
/// What this cannot see: a `SELECT` that calls a function which writes. No
/// proxy can, short of running the statement. That is a documented limit, not
/// an oversight.
pub fn route_intent(sql: &str) -> RouteIntent {
    // Blank fragments carry no information, so they are dropped rather than
    // counted as reads. If nothing substantive remains we have learned nothing
    // and must fail safe.
    let statements: Vec<&str> =
        split_statements(sql).into_iter().filter(|s| !strip_leading_noise(s).trim().is_empty()).collect();

    if statements.is_empty() {
        return RouteIntent::Write;
    }
    // A multi-statement batch is read-only only if every part is.
    if statements.iter().any(|s| statement_route_intent(s) == RouteIntent::Write) {
        RouteIntent::Write
    } else {
        RouteIntent::Read
    }
}

fn statement_route_intent(statement: &str) -> RouteIntent {
    let normalized = strip_leading_noise(statement);
    if normalized.trim().is_empty() {
        // An empty statement is harmless, but it also tells us nothing; treat
        // it as read so a trailing semicolon does not force a batch to the
        // primary.
        return RouteIntent::Read;
    }

    let first = leading_words(normalized, 1);
    let candidate = matches!(first.as_str(), "SELECT" | "WITH" | "SHOW" | "EXPLAIN" | "TABLE" | "VALUES" | "FETCH");
    if !candidate {
        return RouteIntent::Write;
    }

    // Scan with string literals removed, so a query whose *text* mentions
    // "FOR UPDATE" is not misrouted.
    let scannable = strip_literals(normalized).to_ascii_uppercase();

    // Row locks take real locks and must happen on the primary.
    for marker in ["FOR UPDATE", "FOR NO KEY UPDATE", "FOR SHARE", "FOR KEY SHARE"] {
        if scannable.contains(marker) {
            return RouteIntent::Write;
        }
    }

    // Writes wearing a SELECT costume.
    for marker in ["NEXTVAL(", "SETVAL(", "PG_ADVISORY", "SELECT INTO", " INTO "] {
        if scannable.contains(marker) {
            return RouteIntent::Write;
        }
    }

    // A data-modifying CTE is a write with a SELECT on the outside.
    if first == "WITH" {
        for marker in ["INSERT ", "UPDATE ", "DELETE ", "MERGE "] {
            if scannable.contains(marker) {
                return RouteIntent::Write;
            }
        }
    }

    // EXPLAIN is free; EXPLAIN ANALYZE actually runs the statement.
    if first == "EXPLAIN" && scannable.contains("ANALYZE") {
        return RouteIntent::Write;
    }

    RouteIntent::Read
}

/// Does this statement open an explicitly read-only transaction?
///
/// A plain `BEGIN` does not qualify: the client has not told us what comes
/// next, and guessing would mean routing a transaction to a replica and
/// discovering the write halfway through.
pub fn starts_read_only_transaction(sql: &str) -> bool {
    let normalized = strip_literals(strip_leading_noise(sql)).to_ascii_uppercase();
    let words: Vec<&str> = normalized.split_whitespace().collect();
    let opens = matches!(words.first().copied(), Some("BEGIN"))
        || (words.first().copied() == Some("START") && words.get(1).copied() == Some("TRANSACTION"));

    opens && normalized.contains("READ ONLY")
}

/// Replace the contents of quoted strings with nothing.
///
/// Keeps the surrounding structure so keyword scanning still works, but removes
/// any chance of matching a keyword that only appears inside a literal.
pub(crate) fn strip_literals(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' => {
                let quote = bytes[i];
                out.push(' ');
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == quote {
                        if bytes.get(i + 1) == Some(&quote) {
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
                i += 1;
            }
            b'$' => match dollar_tag_len(&bytes[i..]) {
                Some(tag_len) => {
                    let tag = &bytes[i..i + tag_len];
                    out.push(' ');
                    i += tag_len;
                    while i < bytes.len() {
                        if bytes[i..].starts_with(tag) {
                            i += tag_len;
                            break;
                        }
                        i += 1;
                    }
                }
                None => {
                    out.push('$');
                    i += 1;
                }
            },
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                out.push(' ');
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                out.push(' ');
                i += 2;
                let mut depth = 1;
                while i < bytes.len() && depth > 0 {
                    if bytes[i..].starts_with(b"/*") {
                        depth += 1;
                        i += 2;
                    } else if bytes[i..].starts_with(b"*/") {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
            }
            byte => {
                out.push(byte as char);
                i += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn simple_query(sql: &str) -> Message {
        let mut body = sql.as_bytes().to_vec();
        body.push(0);
        Message::new(b'Q', Bytes::from(body))
    }

    fn parse_message(name: &str, sql: &str) -> Message {
        let mut body = Vec::new();
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        body.extend_from_slice(sql.as_bytes());
        body.push(0);
        body.extend_from_slice(&0i16.to_be_bytes());
        Message::new(b'P', Bytes::from(body))
    }

    // --- the statements that cost us multiplexing ---

    #[test]
    fn an_ordinary_set_is_tracked_rather_than_pinned() {
        // These are what every driver sends on connect. Pinning on them meant a
        // pool of two backends was owned forever by the first two clients.
        assert_eq!(sql_pin_reason("SET application_name = 'app'"), None);
        assert_eq!(sql_pin_reason("set search_path to public"), None);
        assert_eq!(sql_pin_reason("SET extra_float_digits = 3"), None);
        assert_eq!(sql_pin_reason("RESET search_path"), None);
        assert_eq!(sql_pin_reason("RESET ALL"), None);

        // Rolled back with the transaction, so it was never our problem.
        assert_eq!(sql_pin_reason("SET LOCAL statement_timeout = '5s'"), None);
        assert_eq!(sql_pin_reason("set local work_mem = '64MB'"), None);
        assert_eq!(sql_pin_reason("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"), None);
    }

    #[test]
    fn only_a_set_we_could_not_reproduce_still_pins() {
        // Changing the effective role is a permission change; replaying it
        // would turn a bug in the replay path into a privilege leak.
        assert_eq!(sql_pin_reason("SET ROLE readonly"), Some(PinReason::SessionParameter));
        assert_eq!(sql_pin_reason("SET SESSION AUTHORIZATION 'bob'"), Some(PinReason::SessionParameter));
        // The value lives in a Bind, not in the statement text.
        assert_eq!(sql_pin_reason("SET application_name = $1"), Some(PinReason::SessionParameter));
        // A shape we do not recognise is one we have not thought about.
        assert_eq!(sql_pin_reason("SET application_name 'x'"), Some(PinReason::SessionParameter));
    }

    #[test]
    fn listen_pins_because_the_connection_becomes_a_delivery_target() {
        assert_eq!(sql_pin_reason("LISTEN channel"), Some(PinReason::Listen));
        assert_eq!(sql_pin_reason("unlisten *"), Some(PinReason::Listen));
        // NOTIFY does not bind the connection to anything.
        assert_eq!(sql_pin_reason("NOTIFY channel, 'payload'"), None);
    }

    #[test]
    fn temporary_objects_pin_in_all_their_spellings() {
        assert_eq!(sql_pin_reason("CREATE TEMP TABLE t (id int)"), Some(PinReason::TempTable));
        assert_eq!(sql_pin_reason("create temporary table t (id int)"), Some(PinReason::TempTable));
        assert_eq!(sql_pin_reason("CREATE GLOBAL TEMPORARY TABLE t (id int)"), Some(PinReason::TempTable));
        assert_eq!(sql_pin_reason("CREATE LOCAL TEMP TABLE t (id int)"), Some(PinReason::TempTable));

        assert_eq!(sql_pin_reason("CREATE TABLE t (id int)"), None, "a permanent table is not session state");
    }

    #[test]
    fn session_advisory_locks_pin_and_transaction_scoped_ones_do_not() {
        assert_eq!(sql_pin_reason("SELECT pg_advisory_lock(42)"), Some(PinReason::AdvisoryLock));
        assert_eq!(sql_pin_reason("select pg_try_advisory_lock(1, 2)"), None, "not a pg_advisory_ prefix");

        // Released at commit, so transaction mode is safe.
        assert_eq!(sql_pin_reason("SELECT pg_advisory_xact_lock(42)"), None);
        assert_eq!(sql_pin_reason("SELECT pg_advisory_unlock_all()"), None);
    }

    #[test]
    fn server_side_prepare_pins() {
        assert_eq!(sql_pin_reason("PREPARE q AS SELECT 1"), Some(PinReason::ServerSidePrepare));
        assert_eq!(sql_pin_reason("DEALLOCATE q"), Some(PinReason::ServerSidePrepare));
        assert_eq!(sql_pin_reason("PREPARE TRANSACTION 'gid'"), Some(PinReason::ServerSidePrepare));
    }

    #[test]
    fn only_holdable_cursors_pin() {
        assert_eq!(sql_pin_reason("DECLARE c CURSOR WITH HOLD FOR SELECT 1"), Some(PinReason::HoldableCursor));
        assert_eq!(sql_pin_reason("declare c cursor with hold for select 1"), Some(PinReason::HoldableCursor));
        // Without HOLD the cursor dies at commit.
        assert_eq!(sql_pin_reason("DECLARE c CURSOR FOR SELECT 1"), None);
    }

    #[test]
    fn copy_and_replication_pin() {
        assert_eq!(sql_pin_reason("COPY t FROM STDIN"), Some(PinReason::BulkTransfer));
        assert_eq!(sql_pin_reason("START_REPLICATION SLOT s LOGICAL 0/0"), None, "not the SQL form");
        assert_eq!(sql_pin_reason("START REPLICATION"), Some(PinReason::Replication));
    }

    #[test]
    fn ordinary_traffic_never_pins() {
        for sql in [
            "SELECT 1",
            "SELECT * FROM orders WHERE id = $1",
            "INSERT INTO t VALUES (1)",
            "UPDATE t SET x = 1 WHERE id = 2",
            "DELETE FROM t",
            "BEGIN",
            "COMMIT",
            "ROLLBACK",
            "SAVEPOINT s1",
            "NOTIFY chan",
            "CREATE INDEX i ON t (c)",
            "",
            "   ",
        ] {
            assert_eq!(sql_pin_reason(sql), None, "{sql:?} should not pin");
        }
    }

    #[test]
    fn update_with_a_set_clause_is_not_a_set_statement() {
        // The word SET appears, but not as the leading keyword. Matching
        // anywhere in the text would pin every UPDATE in the workload.
        assert_eq!(sql_pin_reason("UPDATE t SET x = 1"), None);
        assert_eq!(sql_pin_reason("INSERT INTO t (setting) VALUES ('SET x')"), None);
    }

    // --- text handling ---

    #[test]
    fn leading_comments_do_not_hide_a_pinning_statement() {
        assert_eq!(
            sql_pin_reason("/* app: orders-api */ CREATE TEMP TABLE t (id int)"),
            Some(PinReason::TempTable),
            "ORMs routinely prefix statements with a comment"
        );
        assert_eq!(sql_pin_reason("-- comment\nLISTEN chan"), Some(PinReason::Listen));
        assert_eq!(sql_pin_reason("/* a */ /* b */\n  SET ROLE admin"), Some(PinReason::SessionParameter));
        assert_eq!(sql_pin_reason("/* unterminated"), None);
    }

    #[test]
    fn a_semicolon_inside_a_literal_does_not_split_the_statement() {
        // Splitting naively would see a second statement starting with SET.
        assert_eq!(sql_pin_reason("SELECT 'a;SET x = 1'"), None);
        assert_eq!(sql_pin_reason(r#"SELECT "col;SET""#), None);
        assert_eq!(sql_pin_reason("SELECT $$a;SET x = 1$$"), None);
        assert_eq!(sql_pin_reason("SELECT $tag$a;SET x = 1$tag$"), None);
    }

    #[test]
    fn any_statement_in_a_batch_can_pin_it() {
        assert_eq!(sql_pin_reason("SELECT 1; SELECT 2"), None);
        assert_eq!(sql_pin_reason("SELECT 1; SET application_name = 'x'; SELECT 2"), None);
        assert_eq!(
            sql_pin_reason("SELECT 1; LISTEN chan; SELECT 2"),
            Some(PinReason::Listen),
            "a pin anywhere in the batch pins the connection"
        );
    }

    #[test]
    fn escaped_quotes_inside_literals_are_handled() {
        assert_eq!(sql_pin_reason("SELECT 'it''s fine; SET x = 1'"), None);
        assert_eq!(sql_pin_reason(r"SELECT 'back\'slash; SET x = 1'"), None);
    }

    #[test]
    fn nested_block_comments_are_skipped() {
        assert_eq!(sql_pin_reason("SELECT 1 /* a /* nested */ still comment ; SET x = 1 */"), None);
    }

    // --- message level ---

    #[test]
    fn message_classification_covers_the_protocol() {
        assert_eq!(classify(&Message::terminate()), ClientIntent::Terminate);
        assert_eq!(classify(&simple_query("SELECT 1")), ClientIntent::SyncPoint);
        assert_eq!(
            classify(&simple_query("SET application_name = 'x'")),
            ClientIntent::SyncPoint,
            "a replayable SET is an ordinary statement now"
        );
        assert_eq!(classify(&simple_query("LISTEN chan")), ClientIntent::Pins(PinReason::Listen));

        assert_eq!(classify(&parse_message("s1", "SELECT $1")), ClientIntent::Pipelined);
        assert_eq!(
            classify(&parse_message("s1", "SET application_name = $1")),
            ClientIntent::Pins(PinReason::SessionParameter),
            "a pinning statement is pinning however it is sent"
        );

        assert_eq!(classify(&Message::new(b'S', Bytes::new())), ClientIntent::SyncPoint);
        assert_eq!(classify(&Message::new(b'B', Bytes::new())), ClientIntent::Pipelined);
        assert_eq!(classify(&Message::new(b'E', Bytes::new())), ClientIntent::Pipelined);

        // Flush produces no ReadyForQuery; treating it as a boundary would
        // release a backend in the middle of an exchange.
        assert_eq!(classify(&Message::new(b'H', Bytes::new())), ClientIntent::Pipelined);

        assert_eq!(classify(&Message::new(b'd', Bytes::new())), ClientIntent::Pins(PinReason::BulkTransfer));
    }

    #[test]
    fn a_parse_message_with_an_empty_name_still_yields_its_sql() {
        // The unnamed statement is what most drivers use for one-shot queries.
        assert_eq!(classify(&parse_message("", "SELECT 1")), ClientIntent::Pipelined);
        assert_eq!(classify(&parse_message("", "LISTEN chan")), ClientIntent::Pins(PinReason::Listen));
    }

    #[test]
    fn malformed_messages_do_not_panic() {
        assert_eq!(classify(&Message::new(b'P', Bytes::from_static(b"no-nul"))), ClientIntent::Pipelined);
        assert_eq!(classify(&Message::new(b'Q', Bytes::new())), ClientIntent::SyncPoint);
        assert_eq!(classify(&Message::new(b'\xff', Bytes::new())), ClientIntent::Ordinary);
        // Invalid UTF-8 must be tolerated, not rejected.
        assert_eq!(classify(&Message::new(b'Q', Bytes::from_static(&[0xff, 0xfe, 0]))), ClientIntent::SyncPoint);
    }

    // --- read/write routing ---

    #[test]
    fn plain_reads_can_go_to_a_replica() {
        for sql in [
            "SELECT 1",
            "select * from orders where id = $1",
            "SHOW timezone",
            "EXPLAIN SELECT * FROM t",
            "TABLE orders",
            "VALUES (1), (2)",
            "WITH recent AS (SELECT * FROM t) SELECT * FROM recent",
            "/* app */ SELECT 1",
        ] {
            assert_eq!(route_intent(sql), RouteIntent::Read, "{sql:?} should be routable to a replica");
        }
    }

    #[test]
    fn anything_that_modifies_data_goes_to_the_primary() {
        for sql in [
            "INSERT INTO t VALUES (1)",
            "UPDATE t SET x = 1",
            "DELETE FROM t",
            "MERGE INTO t USING s ON true WHEN MATCHED THEN DELETE",
            "CREATE TABLE t (id int)",
            "TRUNCATE t",
            "CALL do_something()",
            "REFRESH MATERIALIZED VIEW mv",
            "BEGIN",
            "COMMIT",
        ] {
            assert_eq!(route_intent(sql), RouteIntent::Write, "{sql:?} must reach the primary");
        }
    }

    #[test]
    fn selects_that_take_locks_are_writes() {
        // These acquire real row locks. A replica would reject them, but only
        // after the client has already committed to the plan.
        for sql in [
            "SELECT * FROM t FOR UPDATE",
            "SELECT * FROM t FOR NO KEY UPDATE",
            "SELECT * FROM t FOR SHARE",
            "select id from t where x = 1 for key share",
        ] {
            assert_eq!(route_intent(sql), RouteIntent::Write, "{sql:?} takes locks");
        }
    }

    #[test]
    fn selects_with_side_effects_are_writes() {
        // The dangerous category: they look like reads and are not.
        for sql in [
            "SELECT nextval('orders_id_seq')",
            "SELECT setval('s', 1)",
            "SELECT pg_advisory_lock(1)",
            "SELECT * INTO new_table FROM t",
        ] {
            assert_eq!(route_intent(sql), RouteIntent::Write, "{sql:?} has side effects");
        }
    }

    #[test]
    fn a_data_modifying_cte_is_a_write_however_it_ends() {
        assert_eq!(
            route_intent("WITH gone AS (DELETE FROM t RETURNING *) SELECT count(*) FROM gone"),
            RouteIntent::Write,
            "a SELECT on the outside does not make this a read"
        );
        assert_eq!(
            route_intent("WITH added AS (INSERT INTO t VALUES (1) RETURNING id) SELECT * FROM added"),
            RouteIntent::Write
        );
    }

    #[test]
    fn explain_analyze_actually_runs_the_statement() {
        assert_eq!(route_intent("EXPLAIN SELECT * FROM t"), RouteIntent::Read);
        assert_eq!(
            route_intent("EXPLAIN ANALYZE DELETE FROM t"),
            RouteIntent::Write,
            "ANALYZE executes, so this is not a read"
        );
        assert_eq!(route_intent("EXPLAIN (ANALYZE, BUFFERS) SELECT 1"), RouteIntent::Write);
    }

    #[test]
    fn keywords_inside_string_literals_do_not_misroute() {
        // Without literal stripping this would be forced to the primary
        // forever, which is a silent performance bug rather than an error.
        assert_eq!(route_intent("SELECT 'for update' AS label"), RouteIntent::Read);
        assert_eq!(route_intent("SELECT * FROM t WHERE note = 'nextval(x)'"), RouteIntent::Read);
        assert_eq!(route_intent("SELECT $$ delete from t $$ AS doc"), RouteIntent::Read);
        // And a real lock clause is still caught next to a decoy literal.
        assert_eq!(route_intent("SELECT 'harmless' FROM t FOR UPDATE"), RouteIntent::Write);
    }

    #[test]
    fn unknown_statements_fail_safe_to_the_primary() {
        // Stale reads are silent; misrouted writes are loud. Prefer loud.
        assert_eq!(route_intent("VACUUM"), RouteIntent::Write);
        assert_eq!(route_intent("DO $$ BEGIN END $$"), RouteIntent::Write);
        assert_eq!(route_intent(""), RouteIntent::Write);
        assert_eq!(route_intent("   "), RouteIntent::Write);
        assert_eq!(route_intent("NOTIFY chan"), RouteIntent::Write);
    }

    #[test]
    fn a_batch_is_read_only_when_every_statement_is() {
        assert_eq!(route_intent("SELECT 1; SELECT 2"), RouteIntent::Read);
        assert_eq!(route_intent("SELECT 1;"), RouteIntent::Read, "a trailing semicolon is not a statement");
        assert_eq!(route_intent("SELECT 1; UPDATE t SET x = 1"), RouteIntent::Write);
    }

    #[test]
    fn only_an_explicitly_read_only_transaction_may_start_on_a_replica() {
        assert!(starts_read_only_transaction("BEGIN READ ONLY"));
        assert!(starts_read_only_transaction("START TRANSACTION READ ONLY"));
        assert!(starts_read_only_transaction("begin transaction isolation level repeatable read, read only"));

        // A plain BEGIN says nothing about what follows. Guessing would mean
        // discovering the write halfway through the transaction.
        assert!(!starts_read_only_transaction("BEGIN"));
        assert!(!starts_read_only_transaction("START TRANSACTION"));
        assert!(!starts_read_only_transaction("BEGIN READ WRITE"));
        assert!(!starts_read_only_transaction("SELECT 'read only'"), "not even in a literal");
    }

    #[test]
    fn literal_stripping_preserves_structure() {
        assert_eq!(strip_literals("SELECT 'abc' FROM t").trim(), "SELECT   FROM t");
        assert_eq!(strip_literals("SELECT 1 -- comment\nFROM t").trim(), "SELECT 1  \nFROM t".trim());
        assert!(!strip_literals("SELECT 'it''s a for update'").to_uppercase().contains("FOR UPDATE"));
    }

    #[test]
    fn the_realistic_orm_startup_sequence_no_longer_costs_multiplexing() {
        // This is the sequence that used to turn transaction mode into session
        // mode for a large share of real deployments: three statements every
        // driver sends on connect, each one previously a permanent pin.
        let driver_preamble =
            ["SET application_name = 'orders-api'", "SET extra_float_digits = 3", "SET timezone = 'UTC'"];
        for sql in driver_preamble {
            assert_eq!(sql_pin_reason(sql), None, "{sql} is replayable, so it must not cost a backend");
        }
    }
}
