//! Session parameters, tracked and replayed instead of pinned.
//!
//! Transaction mode only pays off if a client can be moved between backends
//! between transactions. The single biggest thing that used to stop that was
//! `SET`: almost every driver issues two or three on connect
//! (`SET extra_float_digits`, `SET application_name`, `SET search_path`), and
//! treating each one as a pin meant a pool of two backends was permanently
//! owned by the first two clients that connected. The pooler diagnosed the
//! problem beautifully and then did nothing about it.
//!
//! The fix is to stop treating a `SET` as damage. A session parameter is not
//! hidden state — it is a value we can name, remember, and reproduce on
//! whatever backend the client lands on next. So each client carries a small
//! map of the parameters it wants, each backend remembers the parameters it
//! currently has, and a checkout that finds a difference sends the delta before
//! the client's own message.
//!
//! Three rules keep this honest.
//!
//! **Replay is verbatim.** We store the client's own statement text keyed by
//! the parameter name, not a reconstruction of it. Rebuilding `SET search_path
//! TO "My Schema", public` from parsed pieces means reimplementing PostgreSQL's
//! quoting rules and being wrong occasionally; echoing what the client sent
//! cannot be.
//!
//! **Nothing is remembered until the server accepts it.** A `SET` that errors
//! changes nothing, and a multi-statement simple query is an implicit
//! transaction, so a failure anywhere in it rolls the whole batch back. Pending
//! changes are therefore committed only after an exchange completes without an
//! `ErrorResponse`.
//!
//! **Anything we cannot name still pins.** `SET ROLE` changes permissions,
//! `SET a = $1` hides its value in a `Bind`, and an unrecognised shape is a
//! shape we have not thought about. Each of those returns [`SetAction::Pin`],
//! which costs throughput — the thing pinning was always supposed to cost.

use std::collections::BTreeMap;

use havuz_proto::PinReason;

use crate::classify::{split_statements, strip_leading_noise, strip_literals};

/// Startup-packet keys that are not session parameters.
///
/// `user`, `database` and `replication` select the connection itself and are
/// consumed by the handshake. `options` carries GUCs but in its own syntax, so
/// it is unpacked separately rather than forwarded whole.
///
/// `client_encoding` is deliberately excluded: havuz opens every backend as
/// UTF8 (see `backend.rs`) so that it never has to interpret a text encoding it
/// did not choose, and replaying a client's preference would break that.
const NOT_A_PARAMETER: &[&str] = &["user", "database", "replication", "options", "client_encoding"];

/// What a `SET`- or `RESET`-family statement means for parameter tracking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetAction {
    /// Remember `statement` under `name`. Replaying it reproduces the effect.
    Track { name: String, statement: String },
    /// Forget `name`. If a backend still has it, it must be told to reset.
    Reset { name: String },
    /// Forget everything.
    ResetAll,
    /// Cannot be reproduced by replay, so the session has to pin.
    Pin(PinReason),
    /// Not a session parameter statement.
    None,
}

/// Classify a single statement.
///
/// `statement` may carry leading whitespace and comments; they are stripped
/// here so callers do not have to.
pub fn classify_set(statement: &str) -> SetAction {
    let normalized = strip_leading_noise(statement).trim_end();
    let normalized = normalized.strip_suffix(';').unwrap_or(normalized).trim_end();
    if normalized.is_empty() {
        return SetAction::None;
    }

    let (keyword, rest) = take_word(normalized);
    match keyword.to_ascii_uppercase().as_str() {
        "SET" => classify_set_body(normalized, rest),
        "RESET" => classify_reset_body(rest),
        _ => SetAction::None,
    }
}

fn classify_set_body(statement: &str, rest: &str) -> SetAction {
    let (first, after_first) = take_word(rest);
    let upper = first.to_ascii_uppercase();

    match upper.as_str() {
        // Both are undone by the surrounding transaction, so they were never
        // our problem.
        "LOCAL" | "TRANSACTION" => return SetAction::None,

        // Changes the effective permissions of the connection. Replaying it is
        // technically possible and deliberately not done: a bug in the replay
        // path would be a privilege leak rather than a slow query.
        "ROLE" => return SetAction::Pin(PinReason::SessionParameter),

        // Transaction-scoped in practice, and rare enough that the safe answer
        // costs nothing.
        "CONSTRAINTS" => return SetAction::Pin(PinReason::SessionParameter),

        "SESSION" => {
            let (second, _) = take_word(after_first);
            return match second.to_ascii_uppercase().as_str() {
                // Same reasoning as SET ROLE.
                "AUTHORIZATION" => SetAction::Pin(PinReason::SessionParameter),
                // Sets three defaults at once under a name that is not one of
                // them, so a single tracked key could not undo it.
                "CHARACTERISTICS" => SetAction::Pin(PinReason::SessionParameter),
                // `SET SESSION x = 1` is just `SET x = 1`.
                _ => classify_set_body(statement, after_first),
            };
        }

        // Spellings that set a parameter whose name does not appear in the
        // statement. Each maps to the GUC it actually writes, so a later
        // `SET timezone` overwrites `SET TIME ZONE` rather than accumulating.
        "TIME" => {
            let (second, _) = take_word(after_first);
            if second.eq_ignore_ascii_case("ZONE") {
                return track(statement, "timezone");
            }
        }
        "NAMES" => return track(statement, "client_encoding"),
        "SCHEMA" => return track(statement, "search_path"),
        "XML" => {
            let (second, _) = take_word(after_first);
            if second.eq_ignore_ascii_case("OPTION") {
                return track(statement, "xmloption");
            }
        }
        _ => {}
    }

    if !is_parameter_name(first) {
        return SetAction::Pin(PinReason::SessionParameter);
    }

    // The value has to be introduced by `=` or `TO`; anything else is a shape
    // we do not recognise, and an unrecognised SET is not one we can undo.
    let after_first = after_first.trim_start();
    let value = if let Some(value) = after_first.strip_prefix('=') {
        value
    } else {
        let (to, value) = take_word(after_first);
        if !to.eq_ignore_ascii_case("TO") {
            return SetAction::Pin(PinReason::SessionParameter);
        }
        value
    }
    .trim();

    if value.is_empty() {
        return SetAction::Pin(PinReason::SessionParameter);
    }

    // The extended protocol allows `SET x = $1`, and the value then lives in a
    // Bind we would have to remember and re-send. Not worth it.
    if has_placeholder(value) {
        return SetAction::Pin(PinReason::SessionParameter);
    }

    if value.eq_ignore_ascii_case("DEFAULT") {
        return SetAction::Reset { name: first.to_ascii_lowercase() };
    }

    track(statement, &first.to_ascii_lowercase())
}

fn classify_reset_body(rest: &str) -> SetAction {
    let (first, after_first) = take_word(rest);
    match first.to_ascii_uppercase().as_str() {
        "ALL" => SetAction::ResetAll,
        "ROLE" => SetAction::Reset { name: "role".into() },
        "SESSION" => SetAction::Reset { name: "session_authorization".into() },
        "TIME" => {
            let (second, _) = take_word(after_first);
            if second.eq_ignore_ascii_case("ZONE") {
                SetAction::Reset { name: "timezone".into() }
            } else {
                SetAction::Pin(PinReason::SessionParameter)
            }
        }
        _ if is_parameter_name(first) => SetAction::Reset { name: first.to_ascii_lowercase() },
        // A RESET we cannot name is a change we cannot reproduce.
        _ => SetAction::Pin(PinReason::SessionParameter),
    }
}

fn track(statement: &str, name: &str) -> SetAction {
    SetAction::Track { name: name.to_ascii_lowercase(), statement: statement.trim().to_string() }
}

/// Every action carried by one client message.
///
/// A simple query may batch several statements, and any of them may be a `SET`.
///
/// A batch that also rolls back is refused. `BEGIN; SET search_path TO x;
/// ROLLBACK` succeeds as far as the wire is concerned — no `ErrorResponse`,
/// `ReadyForQuery` reports idle — while the server has thrown the `SET` away.
/// Believing it would leave us replaying a value the client does not have.
pub fn actions_for_sql(sql: &str) -> Vec<SetAction> {
    let statements = split_statements(sql);
    let actions: Vec<SetAction> =
        statements.iter().map(|s| classify_set(s)).filter(|action| !matches!(action, SetAction::None)).collect();

    if actions.is_empty() {
        return actions;
    }
    if statements.iter().any(|s| undoes_the_batch(s)) {
        return vec![SetAction::Pin(PinReason::SessionParameter)];
    }
    actions
}

/// Does this statement discard work done earlier in the same batch?
///
/// Covers `ROLLBACK`, its `ABORT` spelling, and `ROLLBACK TO SAVEPOINT`, which
/// reverts only part of a transaction and is therefore just as opaque to us.
fn undoes_the_batch(statement: &str) -> bool {
    let normalized = strip_leading_noise(statement);
    let (first, _) = take_word(normalized);
    first.eq_ignore_ascii_case("ROLLBACK") || first.eq_ignore_ascii_case("ABORT")
}

/// The GUC that makes PostgreSQL refuse writes.
pub const READ_ONLY_GUC: &str = "default_transaction_read_only";

/// Would this statement let a read-only session write again?
///
/// havuz enforces `read_only` by setting [`READ_ONLY_GUC`] rather than by
/// deciding for itself which statements are writes. That is deliberate: a
/// keyword classifier cannot see the `INSERT` inside a `SELECT
/// refresh_totals()`, and PostgreSQL can. It also means the enforcement is
/// exactly as correct as the database's own, rather than as correct as our
/// parser.
///
/// The cost is that the setting is a default the client is otherwise free to
/// override, so the handful of statements that would override it have to be
/// refused. That set is small and closed:
///
/// * `SET`/`RESET` of the GUC itself, and `RESET ALL`, which clears it
/// * `SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE`
/// * `SET TRANSACTION READ WRITE`, which overrides the default for one
///   transaction
/// * `BEGIN`/`START TRANSACTION` with an explicit `READ WRITE`
pub fn defeats_read_only(sql: &str) -> bool {
    split_statements(sql).into_iter().any(statement_defeats_read_only)
}

fn statement_defeats_read_only(statement: &str) -> bool {
    let normalized = strip_leading_noise(statement);
    let (keyword, rest) = take_word(normalized);

    match keyword.to_ascii_uppercase().as_str() {
        "SET" | "RESET" => match classify_set(normalized) {
            SetAction::Track { ref name, .. } | SetAction::Reset { ref name } => name == READ_ONLY_GUC,
            SetAction::ResetAll => true,
            // `SET TRANSACTION READ WRITE` and `SET SESSION CHARACTERISTICS ...
            // READ WRITE` are not tracked as parameters, so the text is the
            // only thing left to look at.
            _ => mentions_read_write(normalized),
        },

        // A transaction may always ask for read-write explicitly, whatever the
        // session default says.
        "BEGIN" => mentions_read_write(normalized),
        "START" => {
            let (second, _) = take_word(rest);
            second.eq_ignore_ascii_case("TRANSACTION") && mentions_read_write(normalized)
        }

        _ => false,
    }
}

/// Does this statement contain a `READ WRITE` clause?
///
/// Scanned with literals removed so a statement whose *text* mentions read
/// write is not mistaken for one that requests it.
fn mentions_read_write(statement: &str) -> bool {
    let scannable = strip_literals(statement).to_ascii_uppercase();
    let mut words = scannable.split_whitespace().peekable();
    while let Some(word) = words.next() {
        if word == "READ" && words.peek() == Some(&"WRITE") {
            return true;
        }
    }
    false
}

/// Split off the leading word, returning it and the rest of the input.
///
/// `=` and `,` end a word so that `SET a=1` and `SET a TO b,c` both yield `a`.
fn take_word(input: &str) -> (&str, &str) {
    let trimmed = input.trim_start();
    let end = trimmed.find(|c: char| c.is_whitespace() || c == '=' || c == ',').unwrap_or(trimmed.len());
    trimmed.split_at(end)
}

/// Does this text contain a `$1`-style parameter placeholder?
///
/// Scanned with string literals removed, so `SET application_name = 'costs $5'`
/// is still a value we can replay.
fn has_placeholder(value: &str) -> bool {
    let scannable = strip_literals(value);
    let bytes = scannable.as_bytes();
    bytes.iter().enumerate().any(|(i, b)| *b == b'$' && bytes.get(i + 1).is_some_and(u8::is_ascii_digit))
}

/// Is this a GUC name we are willing to write into a generated statement?
///
/// Deliberately narrow. The name ends up in `SET <name> = ...` and in `RESET
/// <name>`, both of which we compose ourselves, so anything that would need
/// quoting is rejected rather than quoted.
fn is_parameter_name(name: &str) -> bool {
    let mut parts = name.split('.');
    let Some(first) = parts.next() else { return false };
    let second = parts.next();
    if parts.next().is_some() {
        return false;
    }
    is_identifier(first) && second.map(is_identifier).unwrap_or(true)
}

fn is_identifier(part: &str) -> bool {
    let mut chars = part.chars();
    let Some(first) = chars.next() else { return false };
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

/// The session parameters one client wants, wherever it runs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientParams {
    /// Parameter name to the statement that produces it.
    desired: BTreeMap<String, String>,
    /// Changes observed in the current exchange, not yet believed.
    pending: Vec<SetAction>,
}

impl ClientParams {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed from the client's startup packet.
    ///
    /// These never reached a backend before: the handshake read them, used
    /// `application_name` for logging and dropped the rest. A client that
    /// passed `?options=-c search_path%3Dapp` in its connection string was
    /// silently getting the service account's `search_path` instead.
    pub fn from_startup(params: &[(String, String)]) -> Self {
        let mut this = Self::new();
        for (key, value) in params {
            if key.eq_ignore_ascii_case("options") {
                for (key, value) in parse_options(value) {
                    this.seed(&key, &value);
                }
                continue;
            }
            if NOT_A_PARAMETER.iter().any(|skip| key.eq_ignore_ascii_case(skip)) {
                continue;
            }
            this.seed(key, value);
        }
        this
    }

    /// Make PostgreSQL refuse writes for this session.
    ///
    /// Rides on the same replay machinery as any other parameter, so it is
    /// re-asserted on every backend the client touches. See
    /// [`defeats_read_only`] for the statements that must be refused to keep
    /// it true.
    pub fn enforce_read_only(&mut self) {
        self.desired.insert(READ_ONLY_GUC.to_string(), format!("SET {READ_ONLY_GUC} = 'on'"));
    }

    fn seed(&mut self, key: &str, value: &str) {
        if !is_parameter_name(key) {
            return;
        }
        let name = key.to_ascii_lowercase();
        let statement = format!("SET {name} = '{}'", value.replace('\'', "''"));
        self.desired.insert(name, statement);
    }

    /// Record a change that the server has not confirmed yet.
    pub fn stage(&mut self, action: SetAction) {
        if !matches!(action, SetAction::None) {
            self.pending.push(action);
        }
    }

    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Believe the staged changes. Call only after an exchange that produced no
    /// `ErrorResponse`.
    pub fn commit_pending(&mut self) {
        for action in self.pending.drain(..) {
            match action {
                SetAction::Track { name, statement } => {
                    self.desired.insert(name, statement);
                }
                SetAction::Reset { name } => {
                    self.desired.remove(&name);
                }
                SetAction::ResetAll => self.desired.clear(),
                SetAction::Pin(_) | SetAction::None => {}
            }
        }
    }

    /// Forget the staged changes, because the exchange failed and the server
    /// applied none of them.
    pub fn discard_pending(&mut self) {
        self.pending.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.desired.is_empty()
    }

    pub fn desired(&self) -> &BTreeMap<String, String> {
        &self.desired
    }

    /// Statements that bring a backend holding `applied` in line with this
    /// client.
    ///
    /// Resets come first so that the generated batch reads as "undo what the
    /// last client left, then set up mine", which is also how it is easiest to
    /// read in a log.
    pub fn delta(&self, applied: &BTreeMap<String, String>) -> Vec<String> {
        let mut out = Vec::new();
        for name in applied.keys() {
            if !self.desired.contains_key(name) {
                out.push(format!("RESET {name}"));
            }
        }
        for (name, statement) in &self.desired {
            if applied.get(name) != Some(statement) {
                out.push(statement.clone());
            }
        }
        out
    }
}

/// Unpack the startup packet's `options` field into GUC assignments.
///
/// libpq accepts `-c name=value`, `-cname=value` and `--name=value`, with
/// backslash-escaped spaces inside a value. Anything else in there is a
/// postgres command line switch that has no meaning for a pooled connection.
fn parse_options(options: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut tokens = split_options(options).into_iter().peekable();

    while let Some(token) = tokens.next() {
        let assignment = if token == "-c" {
            match tokens.next() {
                Some(next) => next,
                None => break,
            }
        } else if let Some(rest) = token.strip_prefix("-c") {
            rest.to_string()
        } else if let Some(rest) = token.strip_prefix("--") {
            rest.to_string()
        } else {
            continue;
        };

        if let Some((key, value)) = assignment.split_once('=') {
            out.push((key.trim().to_string(), value.trim().to_string()));
        }
    }
    out
}

fn split_options(options: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut chars = options.chars();

    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(escaped) = chars.next() {
                    current.push(escaped);
                }
            }
            c if c.is_whitespace() => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracked(statement: &str) -> (String, String) {
        match classify_set(statement) {
            SetAction::Track { name, statement } => (name, statement),
            other => panic!("{statement:?} should be trackable, got {other:?}"),
        }
    }

    // --- the whole point: driver preambles no longer pin ---

    #[test]
    fn the_realistic_orm_startup_sequence_is_tracked_rather_than_pinned() {
        // This is the sequence that used to turn transaction mode into session
        // mode for a large share of real deployments. Every one of them is now
        // a value we can carry to the next backend.
        for (sql, expected) in [
            ("SET application_name = 'orders-api'", "application_name"),
            ("SET extra_float_digits = 3", "extra_float_digits"),
            ("SET timezone = 'UTC'", "timezone"),
            ("set search_path to public, app", "search_path"),
            ("SET statement_timeout = '5s'", "statement_timeout"),
        ] {
            assert_eq!(tracked(sql).0, expected, "{sql} must be tracked");
        }
    }

    #[test]
    fn the_statement_is_stored_verbatim_so_replay_cannot_mangle_quoting() {
        let (_, statement) = tracked(r#"SET search_path TO "My Schema", public"#);
        assert_eq!(statement, r#"SET search_path TO "My Schema", public"#);

        // A trailing semicolon would break the batch we build from these.
        assert_eq!(tracked("SET timezone = 'UTC';").1, "SET timezone = 'UTC'");
    }

    #[test]
    fn a_later_set_of_the_same_parameter_replaces_the_earlier_one() {
        let mut params = ClientParams::new();
        params.stage(classify_set("SET search_path TO a"));
        params.stage(classify_set("SET search_path TO b"));
        params.commit_pending();

        assert_eq!(params.desired().len(), 1, "a parameter is a value, not a log");
        assert_eq!(params.desired()["search_path"], "SET search_path TO b");
    }

    // --- spellings that name a parameter they do not mention ---

    #[test]
    fn alternative_spellings_map_onto_the_parameter_they_actually_write() {
        assert_eq!(tracked("SET TIME ZONE 'UTC'").0, "timezone");
        assert_eq!(tracked("set time zone local").0, "timezone");
        assert_eq!(tracked("SET NAMES 'utf8'").0, "client_encoding");
        assert_eq!(tracked("SET SCHEMA 'public'").0, "search_path");
        assert_eq!(tracked("SET XML OPTION DOCUMENT").0, "xmloption");
    }

    #[test]
    fn set_time_zone_and_set_timezone_are_the_same_parameter() {
        // If these tracked separately, the pooler would replay both and the
        // loser would silently win on the next backend.
        let mut params = ClientParams::new();
        params.stage(classify_set("SET TIME ZONE 'UTC'"));
        params.stage(classify_set("SET timezone = 'Europe/Istanbul'"));
        params.commit_pending();

        assert_eq!(params.desired().len(), 1);
        assert_eq!(params.desired()["timezone"], "SET timezone = 'Europe/Istanbul'");
    }

    #[test]
    fn session_is_a_noise_word_but_session_replication_role_is_a_parameter() {
        assert_eq!(tracked("SET SESSION statement_timeout = '5s'").0, "statement_timeout");
        // The parameter merely starts with the same letters; matching on a
        // prefix would misread it as `SET SESSION ...`.
        assert_eq!(tracked("SET session_replication_role = 'replica'").0, "session_replication_role");
    }

    #[test]
    fn a_qualified_extension_parameter_is_a_valid_name() {
        assert_eq!(tracked("SET pg_trgm.similarity_threshold = 0.5").0, "pg_trgm.similarity_threshold");
    }

    // --- what still pins ---

    #[test]
    fn changing_the_effective_role_still_pins() {
        // Replaying these would mean a bug in the replay path becomes a
        // privilege leak. Pinning makes it a throughput problem instead.
        assert_eq!(classify_set("SET ROLE readonly"), SetAction::Pin(PinReason::SessionParameter));
        assert_eq!(classify_set("set role none"), SetAction::Pin(PinReason::SessionParameter));
        assert_eq!(classify_set("SET SESSION AUTHORIZATION 'bob'"), SetAction::Pin(PinReason::SessionParameter));
    }

    #[test]
    fn a_value_that_lives_in_a_bind_cannot_be_replayed() {
        // The extended protocol allows this and the value is not in the text.
        assert_eq!(classify_set("SET application_name = $1"), SetAction::Pin(PinReason::SessionParameter));
        // A literal dollar sign is not a placeholder.
        assert_eq!(tracked("SET application_name = 'costs $5'").0, "application_name");
    }

    #[test]
    fn an_unrecognised_shape_pins_rather_than_guessing() {
        assert_eq!(classify_set("SET application_name 'x'"), SetAction::Pin(PinReason::SessionParameter));
        assert_eq!(classify_set("SET \"weird name\" = 1"), SetAction::Pin(PinReason::SessionParameter));
        assert_eq!(classify_set("SET application_name ="), SetAction::Pin(PinReason::SessionParameter));
        assert_eq!(
            classify_set("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY"),
            SetAction::Pin(PinReason::SessionParameter)
        );
        assert_eq!(classify_set("SET CONSTRAINTS ALL DEFERRED"), SetAction::Pin(PinReason::SessionParameter));
    }

    #[test]
    fn transaction_scoped_statements_are_not_our_business() {
        assert_eq!(classify_set("SET LOCAL work_mem = '64MB'"), SetAction::None);
        assert_eq!(classify_set("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"), SetAction::None);
        assert_eq!(classify_set("SELECT 1"), SetAction::None);
        assert_eq!(classify_set(""), SetAction::None);
        assert_eq!(classify_set("   "), SetAction::None);
    }

    // --- undoing ---

    #[test]
    fn default_and_reset_both_forget_a_parameter() {
        assert_eq!(classify_set("SET search_path TO DEFAULT"), SetAction::Reset { name: "search_path".into() });
        assert_eq!(classify_set("RESET search_path"), SetAction::Reset { name: "search_path".into() });
        assert_eq!(classify_set("reset TIME ZONE"), SetAction::Reset { name: "timezone".into() });
        assert_eq!(classify_set("RESET ALL"), SetAction::ResetAll);
    }

    #[test]
    fn reset_all_clears_everything_the_client_had_asked_for() {
        let mut params = ClientParams::new();
        params.stage(classify_set("SET a = 1"));
        params.stage(classify_set("SET b = 2"));
        params.commit_pending();
        assert_eq!(params.desired().len(), 2);

        params.stage(classify_set("RESET ALL"));
        params.commit_pending();
        assert!(params.is_empty());
    }

    // --- pending changes ---

    #[test]
    fn a_failed_exchange_leaves_the_client_exactly_as_it_was() {
        // The server applies nothing when the statement errors, and a batch is
        // an implicit transaction, so believing a SET before it succeeds would
        // make us replay a value the client never actually has.
        let mut params = ClientParams::new();
        params.stage(classify_set("SET search_path TO app"));
        assert!(params.has_pending());
        params.discard_pending();

        assert!(params.is_empty());
        assert!(!params.has_pending());
    }

    #[test]
    fn a_batch_stages_every_set_it_contains() {
        let actions = actions_for_sql("SET a = 1; SELECT 1; SET b = 2");
        assert_eq!(actions.len(), 2, "the SELECT contributes nothing");

        let mut params = ClientParams::new();
        for action in actions {
            params.stage(action);
        }
        params.commit_pending();
        assert_eq!(params.desired().keys().collect::<Vec<_>>(), vec!["a", "b"]);
    }

    #[test]
    fn a_semicolon_inside_a_literal_does_not_invent_a_set() {
        assert!(actions_for_sql("SELECT 'a; SET x = 1'").is_empty());
    }

    #[test]
    fn a_batch_that_rolls_itself_back_pins_instead_of_lying() {
        // Nothing on the wire distinguishes this from a batch that committed:
        // no ErrorResponse, and ReadyForQuery reports idle either way. The
        // server has discarded the SET, so believing it would leave us
        // replaying a value the client does not have.
        assert_eq!(
            actions_for_sql("BEGIN; SET search_path TO x; ROLLBACK"),
            vec![SetAction::Pin(PinReason::SessionParameter)]
        );
        assert_eq!(
            actions_for_sql("BEGIN; SET search_path TO x; ROLLBACK TO SAVEPOINT s"),
            vec![SetAction::Pin(PinReason::SessionParameter)]
        );

        // A batch that commits is honest about what it did.
        assert_eq!(actions_for_sql("BEGIN; SET search_path TO x; COMMIT").len(), 1);
        // And a rollback on its own has nothing to undo.
        assert!(actions_for_sql("ROLLBACK").is_empty());
    }

    #[test]
    fn a_leading_comment_does_not_hide_a_set() {
        // ORMs routinely prefix statements with a comment.
        assert_eq!(tracked("/* app: orders-api */ SET application_name = 'x'").0, "application_name");
    }

    // --- the delta ---

    #[test]
    fn a_backend_that_already_matches_costs_nothing() {
        let mut params = ClientParams::new();
        params.stage(classify_set("SET search_path TO app"));
        params.commit_pending();

        let applied = params.desired().clone();
        assert!(params.delta(&applied).is_empty(), "an identical backend must not cost a round trip");
    }

    #[test]
    fn the_delta_undoes_the_previous_client_before_setting_up_this_one() {
        let mut previous = ClientParams::new();
        previous.stage(classify_set("SET search_path TO other"));
        previous.stage(classify_set("SET work_mem = '64MB'"));
        previous.commit_pending();

        let mut mine = ClientParams::new();
        mine.stage(classify_set("SET search_path TO app"));
        mine.commit_pending();

        assert_eq!(
            mine.delta(previous.desired()),
            vec!["RESET work_mem".to_string(), "SET search_path TO app".to_string()],
            "a parameter this client never asked for must not leak in from the last one"
        );
    }

    #[test]
    fn a_client_with_no_parameters_still_cleans_up_after_the_last_one() {
        let mut previous = ClientParams::new();
        previous.stage(classify_set("SET search_path TO other"));
        previous.commit_pending();

        assert_eq!(ClientParams::new().delta(previous.desired()), vec!["RESET search_path".to_string()]);
    }

    #[test]
    fn a_fresh_backend_gets_the_whole_set() {
        let mut params = ClientParams::new();
        params.stage(classify_set("SET a = 1"));
        params.stage(classify_set("SET b = 2"));
        params.commit_pending();

        assert_eq!(params.delta(&BTreeMap::new()), vec!["SET a = 1".to_string(), "SET b = 2".to_string()]);
        assert!(ClientParams::new().delta(&BTreeMap::new()).is_empty());
    }

    // --- startup packet ---

    #[test]
    fn startup_parameters_reach_the_backend() {
        // Previously read and thrown away, which is why a connection string
        // that set search_path silently did nothing.
        let params = ClientParams::from_startup(&[
            ("user".into(), "svc_orders".into()),
            ("database".into(), "app_main".into()),
            ("application_name".into(), "orders-api".into()),
            ("extra_float_digits".into(), "3".into()),
        ]);

        assert_eq!(params.desired()["application_name"], "SET application_name = 'orders-api'");
        assert_eq!(params.desired()["extra_float_digits"], "SET extra_float_digits = '3'");
        assert!(!params.desired().contains_key("user"), "credentials are not session parameters");
        assert!(!params.desired().contains_key("database"));
    }

    #[test]
    fn the_options_field_is_unpacked_into_its_assignments() {
        let params = ClientParams::from_startup(&[(
            "options".into(),
            "-c search_path=app,public -c work_mem=64MB --statement_timeout=5s".into(),
        )]);

        assert_eq!(params.desired()["search_path"], "SET search_path = 'app,public'");
        assert_eq!(params.desired()["work_mem"], "SET work_mem = '64MB'");
        assert_eq!(params.desired()["statement_timeout"], "SET statement_timeout = '5s'");
    }

    #[test]
    fn an_escaped_space_stays_inside_its_value() {
        let params = ClientParams::from_startup(&[("options".into(), r"-c application_name=my\ app".into())]);
        assert_eq!(params.desired()["application_name"], "SET application_name = 'my app'");
    }

    #[test]
    fn a_quote_in_a_startup_value_is_escaped_not_injected() {
        let params = ClientParams::from_startup(&[("application_name".into(), "it's mine".into())]);
        assert_eq!(params.desired()["application_name"], "SET application_name = 'it''s mine'");
    }

    #[test]
    fn client_encoding_is_left_alone() {
        // havuz opens every backend as UTF8 so it never has to interpret an
        // encoding it did not choose; replaying the client's would break that.
        let params = ClientParams::from_startup(&[("client_encoding".into(), "LATIN1".into())]);
        assert!(params.is_empty());
    }

    #[test]
    fn a_startup_key_that_is_not_a_usable_name_is_ignored() {
        let params = ClientParams::from_startup(&[("weird name".into(), "x".into()), ("".into(), "y".into())]);
        assert!(params.is_empty(), "we compose SET statements from these, so unquotable names are dropped");
    }

    // --- read-only enforcement ---

    #[test]
    fn a_read_only_session_carries_the_guc_onto_every_backend() {
        let mut params = ClientParams::new();
        params.enforce_read_only();
        assert_eq!(params.delta(&BTreeMap::new()), vec!["SET default_transaction_read_only = 'on'".to_string()]);
    }

    #[test]
    fn every_way_out_of_a_read_only_session_is_closed() {
        // havuz lets PostgreSQL decide what a write is, which is only sound if
        // the client cannot turn the setting back off.
        for sql in [
            "SET default_transaction_read_only = off",
            "set DEFAULT_TRANSACTION_READ_ONLY to false",
            "RESET default_transaction_read_only",
            "RESET ALL",
            "SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE",
            "SET TRANSACTION READ WRITE",
            // Refused even though it asks for the value we already want.
            // PostgreSQL spells false six ways (`off`, `false`, `0`, `f`,
            // `no`, `n`), and a boolean parser that disagrees with the server
            // about any one of them is a silent hole. The setting is already
            // on, so there is nothing a client loses by being refused.
            "SET default_transaction_read_only = on",
            "BEGIN READ WRITE",
            "START TRANSACTION READ WRITE",
            "begin transaction isolation level serializable, read write",
            // Hidden in a batch, which is how it would actually be attempted.
            "SELECT 1; SET TRANSACTION READ WRITE",
        ] {
            assert!(defeats_read_only(sql), "{sql:?} must be refused for a read-only user");
        }
    }

    #[test]
    fn ordinary_traffic_is_not_mistaken_for_an_escape_attempt() {
        for sql in [
            "SELECT 1",
            "BEGIN",
            "BEGIN READ ONLY",
            "START TRANSACTION READ ONLY",
            "COMMIT",
            "SET search_path TO app",
            "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
            // The words appear, but only inside a literal.
            "SELECT 'read write' AS mode",
            "INSERT INTO audit (note) VALUES ('begin read write')",
            // A column called `read`, followed by an unrelated identifier.
            "SELECT read, write FROM counters",
        ] {
            assert!(!defeats_read_only(sql), "{sql:?} is not an escape attempt");
        }
    }

    // --- helpers ---

    #[test]
    fn word_splitting_handles_the_shapes_a_set_can_take() {
        assert_eq!(take_word("SET a = 1"), ("SET", " a = 1"));
        assert_eq!(take_word(" a=1"), ("a", "=1"));
        assert_eq!(take_word("a,b"), ("a", ",b"));
        assert_eq!(take_word(""), ("", ""));
    }

    #[test]
    fn parameter_names_are_accepted_only_when_we_can_write_them_back() {
        assert!(is_parameter_name("search_path"));
        assert!(is_parameter_name("pg_trgm.similarity_threshold"));
        assert!(is_parameter_name("_x9"));
        assert!(!is_parameter_name("a.b.c"));
        assert!(!is_parameter_name("9lives"));
        assert!(!is_parameter_name("has space"));
        assert!(!is_parameter_name(""));
        assert!(!is_parameter_name("\"quoted\""));
    }
}
