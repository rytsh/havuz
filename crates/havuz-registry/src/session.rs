//! What a product's statements do to session state.
//!
//! Transaction-mode pooling rests on one claim: after this transaction ends,
//! the backend carries nothing belonging to the client that just used it. A
//! family that parses the wire protocol can verify the claim itself —
//! `havuz-pg` reads the transaction status byte and classifies statements with
//! a proper classifier. A family that only sees statement text cannot, so the
//! product has to say what its own statements mean, and that is what lives
//! here.
//!
//! [`PinReason`] is defined in this crate rather than in `havuz-proto` because
//! the rules that produce one are static per-product data, and static
//! per-product data is what the registry is for.

use serde::{Deserialize, Serialize};

use std::fmt;

/// Why a backend is stuck with one client for the rest of its session.
///
/// This enum is the product's most valuable telemetry. Transaction-mode pooling
/// silently degrades to session-mode whenever one of these fires, and no other
/// pooler tells operators which one, for which user, on which query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinReason {
    /// `SET` outside a transaction. `SET LOCAL` is scoped and does not pin.
    SessionParameter,
    /// `LISTEN` makes the connection a delivery target for asynchronous
    /// notifications, so it can never be shared.
    Listen,
    /// Temporary tables live in a per-connection schema.
    TempTable,
    /// Session-level advisory locks outlive the transaction that took them.
    AdvisoryLock,
    /// `PREPARE` creates a session-scoped statement (distinct from the extended
    /// query protocol's per-connection prepared statements).
    ServerSidePrepare,
    /// A cursor declared `WITH HOLD` survives commit.
    HoldableCursor,
    /// Bulk transfer has taken over the connection.
    BulkTransfer,
    /// Replication or change-stream mode.
    Replication,
    /// Stored-procedure state that outlives the call: Oracle package globals,
    /// DB2 module variables. Invisible in the statement text beyond the fact
    /// that a procedural block ran at all.
    ProcedureState,
    /// The family saw something it could not classify. Fails safe by pinning.
    Unclassified,
}

impl PinReason {
    pub fn as_str(self) -> &'static str {
        match self {
            PinReason::SessionParameter => "session_parameter",
            PinReason::Listen => "listen",
            PinReason::TempTable => "temp_table",
            PinReason::AdvisoryLock => "advisory_lock",
            PinReason::ServerSidePrepare => "server_side_prepare",
            PinReason::HoldableCursor => "holdable_cursor",
            PinReason::BulkTransfer => "bulk_transfer",
            PinReason::Replication => "replication",
            PinReason::ProcedureState => "procedure_state",
            PinReason::Unclassified => "unclassified",
        }
    }

    /// Whether an operator can realistically fix this by changing their
    /// application. Drives the "actionable" filter in the dashboard.
    pub fn is_actionable(self) -> bool {
        !matches!(self, PinReason::Replication | PinReason::Unclassified)
    }

    /// Every variant, so the UI can render a complete breakdown with zeros
    /// instead of only the reasons seen so far.
    pub const ALL: [PinReason; 10] = [
        PinReason::SessionParameter,
        PinReason::Listen,
        PinReason::TempTable,
        PinReason::AdvisoryLock,
        PinReason::ServerSidePrepare,
        PinReason::HoldableCursor,
        PinReason::BulkTransfer,
        PinReason::Replication,
        PinReason::ProcedureState,
        PinReason::Unclassified,
    ];
}

impl fmt::Display for PinReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A statement shape whose effect outlives the transaction that ran it.
///
/// `words` is matched against the statement's leading words, so `SET ROLE`
/// matches `set  role app_ro` and not `settings`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PinRule {
    pub words: &'static str,
    pub reason: PinReason,
}

/// How a product's statements affect the state a pooled connection carries.
///
/// Only consulted by families that classify statements by their leading words
/// rather than by parsing them — in practice the JDBC bridge, which sees SQL in
/// a dialect it does not know. `havuz-pg` has a real classifier and ignores
/// this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SessionRules {
    /// Statement that returns a connection to a state the next client may be
    /// given.
    ///
    /// `None` means this product has no such statement, and a connection is
    /// closed rather than reused when its client goes away. That is a real
    /// cost — a pool that never recycles is a connection limiter, not a pool —
    /// but handing over a connection that might still hold a temporary table
    /// is a correctness bug, and the two are not comparable.
    pub reset_query: Option<&'static str>,

    /// Statements whose effect outlives their transaction, and what to report.
    pub pins: &'static [PinRule],

    /// Statements known to leave no session state behind.
    ///
    /// An allowlist rather than a denylist, because the two mistakes do not
    /// cost the same. A safe statement missing from this list costs
    /// multiplexing and says so in the pin breakdown, where an operator can
    /// see it. A dirtying statement missing from `pins` hands one client's
    /// state to the next, silently.
    ///
    /// Empty means this product does not classify at all, and every statement
    /// pins. See [`SessionRules::classifies`].
    pub shareable: &'static [&'static str],
}

impl SessionRules {
    /// A product havuz knows nothing about: no reset, no classification.
    ///
    /// Safe by construction — every statement pins and every connection is
    /// closed rather than recycled — and useless for multiplexing, which is
    /// why [`crate::Quirks::max_pool_mode`] must stay at
    /// [`crate::PoolMode::Session`] for a profile that carries it.
    pub const OPAQUE: SessionRules = SessionRules { reset_query: None, pins: &[], shareable: &[] };

    /// Whether this product said enough for a statement to be judged safe.
    pub fn classifies(&self) -> bool {
        !self.shareable.is_empty()
    }

    /// Why this statement makes its connection unshareable, if it does.
    ///
    /// `None` means the statement leaves nothing behind. Anything matching
    /// neither list is [`PinReason::Unclassified`], which pins: not knowing is
    /// treated as the bad case, on purpose.
    ///
    /// The most specific rule wins, across both lists. That is what lets a
    /// profile say `SET` pins and `SET LOCAL` does not without either list
    /// having to be written in a particular order — an ordering constraint
    /// nobody would remember when adding the tenth rule. A tie goes to the
    /// pin, which cannot happen with well-formed rules but must not be
    /// resolved in favour of sharing if it ever does.
    pub fn classify(&self, sql: &str) -> Option<PinReason> {
        if !self.classifies() {
            return Some(PinReason::Unclassified);
        }
        let head = leading_words(sql);
        let mut best: Option<(usize, Option<PinReason>)> = None;

        for rule in self.pins {
            if starts_with_words(&head, rule.words) && best.is_none_or(|(len, _)| rule.words.len() > len) {
                best = Some((rule.words.len(), Some(rule.reason)));
            }
        }
        for safe in self.shareable {
            if starts_with_words(&head, safe) && best.is_none_or(|(len, _)| safe.len() > len) {
                best = Some((safe.len(), None));
            }
        }

        match best {
            Some((_, verdict)) => verdict,
            None => Some(PinReason::Unclassified),
        }
    }
}

/// The first few words of a statement, upper-cased and single-spaced.
///
/// Bounded at six words because no rule in any profile is longer, and an
/// unbounded normalisation would allocate proportionally to a statement that
/// can be megabytes of `INSERT`.
fn leading_words(sql: &str) -> String {
    let mut out = String::with_capacity(48);
    let trimmed = sql.trim_start().trim_start_matches('(');
    for word in trimmed.split_whitespace().take(6) {
        // A trailing semicolon or parenthesis belongs to the syntax, not the
        // word: `BEGIN;` is the same keyword as `BEGIN`.
        let word = word.trim_matches(|c: char| c == ';' || c == '(' || c == ')');
        if word.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&word.to_ascii_uppercase());
    }
    out
}

/// Whether `head` begins with `words`, on a word boundary.
///
/// `words` is expected upper-cased and single-spaced, as written in a profile.
fn starts_with_words(head: &str, words: &str) -> bool {
    match head.strip_prefix(words) {
        Some("") => true,
        Some(rest) => rest.starts_with(' '),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: SessionRules = SessionRules {
        reset_query: Some("RESET"),
        pins: &[
            PinRule { words: "SET", reason: PinReason::SessionParameter },
            PinRule { words: "CREATE GLOBAL TEMPORARY TABLE", reason: PinReason::TempTable },
        ],
        shareable: &["SELECT", "INSERT", "SET LOCAL"],
    };

    #[test]
    fn a_shareable_statement_does_not_pin() {
        assert_eq!(RULES.classify("select 1 from dual"), None);
        assert_eq!(RULES.classify("  INSERT INTO t VALUES (1)"), None);
    }

    #[test]
    fn a_pinning_statement_reports_its_reason() {
        assert_eq!(RULES.classify("set role app_ro"), Some(PinReason::SessionParameter));
        assert_eq!(RULES.classify("create global temporary table t (a int)"), Some(PinReason::TempTable));
    }

    #[test]
    fn the_most_specific_rule_wins_whichever_list_it_is_in() {
        // The shape every real profile needs: `SET` pins, `SET LOCAL` is
        // transaction-scoped and does not. Neither list may depend on the
        // other's order for this to come out right.
        const SCOPED: SessionRules = SessionRules {
            reset_query: None,
            pins: &[PinRule { words: "SET", reason: PinReason::SessionParameter }],
            shareable: &["SELECT", "SET LOCAL"],
        };
        assert_eq!(SCOPED.classify("SET LOCAL work_mem = '64MB'"), None);
        assert_eq!(SCOPED.classify("SET work_mem = '64MB'"), Some(PinReason::SessionParameter));

        // And the same again with the specific rule on the pinning side.
        const INVERTED: SessionRules = SessionRules {
            reset_query: None,
            pins: &[PinRule { words: "SET CONSTRAINTS", reason: PinReason::SessionParameter }],
            shareable: &["SET"],
        };
        assert_eq!(INVERTED.classify("SET CONSTRAINTS ALL DEFERRED"), Some(PinReason::SessionParameter));
        assert_eq!(INVERTED.classify("SET work_mem = '64MB'"), None);
    }

    #[test]
    fn an_unknown_statement_pins_rather_than_being_assumed_safe() {
        // The whole point of the allowlist: not knowing costs multiplexing,
        // never correctness.
        assert_eq!(RULES.classify("alter session set current_schema = app"), Some(PinReason::Unclassified));
        assert_eq!(RULES.classify("call some_package.some_proc()"), Some(PinReason::Unclassified));
        assert_eq!(RULES.classify(""), Some(PinReason::Unclassified));
    }

    #[test]
    fn a_product_that_declares_nothing_pins_everything() {
        assert!(!SessionRules::OPAQUE.classifies());
        assert_eq!(SessionRules::OPAQUE.classify("select 1"), Some(PinReason::Unclassified));
    }

    #[test]
    fn matching_is_on_word_boundaries_not_prefixes() {
        // `settings` is not `SET`, and a pooler that thought so would pin every
        // client that reads a settings table.
        assert_eq!(RULES.classify("select * from settings"), None);
        assert_eq!(RULES.classify("selective_thing()"), Some(PinReason::Unclassified));
    }

    #[test]
    fn punctuation_and_whitespace_do_not_change_a_keyword() {
        assert_eq!(RULES.classify("SELECT;"), None);
        assert_eq!(RULES.classify("\n\t select\n  1"), None);
        assert_eq!(RULES.classify("(select 1)"), None);
    }

    #[test]
    fn pin_reasons_are_all_enumerable_for_the_dashboard() {
        let mut seen: Vec<&str> = PinReason::ALL.iter().map(|r| r.as_str()).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), PinReason::ALL.len(), "every reason needs a distinct metric label");
    }
}
