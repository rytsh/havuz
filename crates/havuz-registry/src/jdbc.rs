//! JDBC bridge family descriptor.
//!
//! One driver, many products, and unlike the PostgreSQL family the products do
//! not share a wire protocol — they share an API. That changes what a profile
//! is for. Here it carries the two things a bridge cannot work out for itself:
//! how to clear a connection ([`SessionRules::reset_query`]) and which
//! statements leave something behind ([`SessionRules::pins`]).
//!
//! ## Why most profiles stay in session mode
//!
//! Transaction-mode pooling needs one guarantee: when a transaction ends, the
//! backend carries nothing belonging to the client that used it. Whether a
//! product can give that guarantee turns out to hinge on a detail of how it
//! spells "temporary table".
//!
//! PostgreSQL temporary tables are *created* per session, so the `CREATE` pins
//! the connection and it is never shared again. Oracle global temporary tables
//! and DB2 declared global temporary tables are schema objects a DBA created
//! once; only their **rows** are session-scoped, and they are filled by an
//! ordinary `INSERT` that no classifier can tell from any other. A connection
//! released after that `INSERT` carries the rows to the next client, and
//! nothing in the statement text says so.
//!
//! So `postgresql` may multiplex and `oracle` and `db2` may not. They still
//! declare a reset query, which is what turns their pools from connection
//! limiters into pools that actually recycle.

use crate::field::{ConfigField, FieldKind, FieldRole};
use crate::session::{PinRule, SessionRules};
use crate::{Capabilities, DriverProfile, FamilyDescriptor, Maturity, PinReason, PoolMode, Quirks};

pub(crate) const JDBC: FamilyDescriptor = FamilyDescriptor {
    id: "jdbc",
    label: "JDBC bridge",
    description: "Oracle, DB2, Informix, Snowflake and the rest of the long tail, through a JVM sidecar.",
    // Experimental, and the word is meant. Every other family relays frames; this
    // one parses statements and composes result sets, so its correctness depends
    // on a type mapping that only widens as more databases are tried.
    maturity: Maturity::Experimental,
    // There is no default: a JDBC URL names its own port, and a bridge that
    // guessed 1521 would be guessing Oracle.
    default_port: 0,
    capabilities: Capabilities {
        tls: true,
        scram_sha256: true,
        md5_auth: false,
        // The sidecar holds one JDBC URL with one set of credentials in it, so
        // there is nowhere to put a client's own.
        per_user_auth: false,
        // The client's prepared statements become the driver's. What is absent
        // is havuz's own rewriting, which exists to move a statement between
        // backends and has nothing to move it between here.
        prepared_statements: true,
        // The bridge relays no statements of its own to inspect and has no
        // portable GUC to set through a JDBC URL, so it could offer a default
        // and not a guarantee. It offers neither.
        read_only_sessions: false,
        cancel_request: false,
        bulk_copy: false,
        // The agent reports it from the driver rather than inferring it, which
        // is the same standard the PostgreSQL side holds itself to.
        reports_transaction_status: true,
        listen_notify: false,
        advisory_locks: false,
        // The bridge sees SQL in a dialect it was not told the name of. It
        // cannot decide what a statement means, so the profile has to.
        classifies_statements: false,
    },
    pool_modes: &[PoolMode::Session, PoolMode::Transaction],
    // Session, not transaction: the default profile is `generic`, which knows
    // nothing about its database and would pin every statement. Defaulting to a
    // mode that silently degrades is worse than defaulting to the mode it would
    // degrade into.
    default_pool_mode: PoolMode::Session,
    profiles: PROFILES,
    config_fields: FIELDS,
};

const PROFILES: &[DriverProfile] = &[
    DriverProfile {
        id: "generic",
        label: "Generic JDBC",
        maturity: Maturity::Experimental,
        default_port: None,
        quirks: Quirks {
            supports_discard_all: false,
            supports_advisory_locks: false,
            supports_listen_notify: false,
            supports_prepared_statements: true,
            max_pool_mode: PoolMode::Session,
            // Nothing is claimed about a database nobody named. Every
            // connection is closed rather than recycled and every statement
            // pins — which is exactly what session mode does anyway, so the
            // cost is zero and the guarantee is real.
            session: SessionRules::OPAQUE,
        },
    },
    DriverProfile {
        id: "postgresql",
        label: "PostgreSQL (via JDBC)",
        maturity: Maturity::Experimental,
        default_port: None,
        quirks: Quirks {
            supports_discard_all: true,
            supports_advisory_locks: true,
            supports_listen_notify: true,
            supports_prepared_statements: true,
            // The one profile here that can multiplex, and the one the
            // end-to-end suite actually drives: every query in tests/e2e/jdbc.sh
            // runs twice, once natively and once through the bridge, and the
            // outputs must match. Claiming this for a database we cannot test
            // against would be claiming it on faith.
            max_pool_mode: PoolMode::Transaction,
            session: POSTGRESQL_RULES,
        },
    },
    DriverProfile {
        id: "oracle",
        label: "Oracle Database",
        maturity: Maturity::Experimental,
        default_port: Some(1521),
        quirks: Quirks {
            supports_discard_all: false,
            supports_advisory_locks: true,
            supports_listen_notify: false,
            supports_prepared_statements: true,
            // See the module header: an ordinary INSERT into a global temporary
            // table leaves session-scoped rows behind and no classifier can see
            // it happen.
            max_pool_mode: PoolMode::Session,
            session: ORACLE_RULES,
        },
    },
    DriverProfile {
        id: "db2",
        label: "IBM Db2",
        maturity: Maturity::Experimental,
        default_port: Some(50000),
        quirks: Quirks {
            supports_discard_all: false,
            supports_advisory_locks: false,
            supports_listen_notify: false,
            supports_prepared_statements: true,
            // Declared global temporary tables, for the same reason as Oracle.
            max_pool_mode: PoolMode::Session,
            session: DB2_RULES,
        },
    },
];

/// PostgreSQL reached through pgjdbc.
///
/// Mirrors what `havuz_pg::classify` decides on the native path, minus the
/// shapes that cannot arrive here: the bridge performs transaction control
/// itself and never forwards `COPY`.
const POSTGRESQL_RULES: SessionRules = SessionRules {
    reset_query: Some("DISCARD ALL"),
    pins: &[
        PinRule { words: "SET", reason: PinReason::SessionParameter },
        PinRule { words: "RESET", reason: PinReason::SessionParameter },
        PinRule { words: "LISTEN", reason: PinReason::Listen },
        PinRule { words: "UNLISTEN", reason: PinReason::Listen },
        PinRule { words: "CREATE TEMP", reason: PinReason::TempTable },
        PinRule { words: "CREATE TEMPORARY", reason: PinReason::TempTable },
        PinRule { words: "CREATE LOCAL TEMP", reason: PinReason::TempTable },
        PinRule { words: "CREATE LOCAL TEMPORARY", reason: PinReason::TempTable },
        PinRule { words: "CREATE GLOBAL TEMP", reason: PinReason::TempTable },
        PinRule { words: "CREATE GLOBAL TEMPORARY", reason: PinReason::TempTable },
        // Session-scoped, and distinct from the extended protocol's named
        // statements which the bridge keeps on its own side.
        PinRule { words: "PREPARE", reason: PinReason::ServerSidePrepare },
        PinRule { words: "DEALLOCATE", reason: PinReason::ServerSidePrepare },
        // Not every DECLARE is holdable, but the bridge matches leading words
        // and `WITH HOLD` is at the end. Pinning the shareable ones costs
        // multiplexing; missing the holdable ones costs correctness.
        PinRule { words: "DECLARE", reason: PinReason::HoldableCursor },
        PinRule { words: "COPY", reason: PinReason::BulkTransfer },
    ],
    shareable: &[
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "MERGE",
        "WITH",
        "VALUES",
        "TABLE",
        "SHOW",
        "EXPLAIN",
        "ANALYZE",
        "CALL",
        "SAVEPOINT",
        "RELEASE",
        "ROLLBACK",
        "COMMIT",
        "BEGIN",
        "START",
        "END",
        "ABORT",
        // Transaction-scoped by definition, and the reason `classify` resolves
        // by specificity rather than by list order.
        "SET LOCAL",
        "SET TRANSACTION",
        "SET CONSTRAINTS",
    ],
};

/// Oracle reached through ojdbc.
///
/// `MODIFY_PACKAGE_STATE(REINITIALIZE)` is the closest thing Oracle has to
/// `DISCARD ALL`: it resets PL/SQL package globals, which is the state most
/// likely to survive a connection unnoticed. It does **not** clear global
/// temporary table rows or application contexts, which is why this profile is
/// session-only — the reset is good enough to recycle a connection between
/// clients, not to hand one over mid-session.
const ORACLE_RULES: SessionRules = SessionRules {
    reset_query: Some("BEGIN DBMS_SESSION.MODIFY_PACKAGE_STATE(DBMS_SESSION.REINITIALIZE); END;"),
    pins: &[
        PinRule { words: "ALTER SESSION", reason: PinReason::SessionParameter },
        PinRule { words: "SET ROLE", reason: PinReason::SessionParameter },
        PinRule { words: "CREATE GLOBAL TEMPORARY", reason: PinReason::TempTable },
        PinRule { words: "CREATE PRIVATE TEMPORARY", reason: PinReason::TempTable },
        // An anonymous block can do anything, including set package state that
        // outlives it. The statement text says only that PL/SQL ran.
        PinRule { words: "DECLARE", reason: PinReason::ProcedureState },
    ],
    shareable: &["SELECT", "INSERT", "UPDATE", "DELETE", "MERGE", "WITH", "SAVEPOINT", "COMMIT", "ROLLBACK"],
};

/// Db2 reached through the IBM Data Server Driver.
///
/// No reset statement: `SET CURRENT SCHEMA` and friends would each have to be
/// restored to a value havuz never recorded, and declared global temporary
/// tables have to be dropped by name. Saying so costs connection reuse and is
/// the truth; inventing a statement that half-works would cost correctness.
const DB2_RULES: SessionRules = SessionRules {
    reset_query: None,
    pins: &[
        PinRule { words: "SET CURRENT", reason: PinReason::SessionParameter },
        PinRule { words: "SET SCHEMA", reason: PinReason::SessionParameter },
        PinRule { words: "SET PATH", reason: PinReason::SessionParameter },
        PinRule { words: "SET SESSION", reason: PinReason::SessionParameter },
        PinRule { words: "DECLARE GLOBAL TEMPORARY", reason: PinReason::TempTable },
        PinRule { words: "BEGIN", reason: PinReason::ProcedureState },
    ],
    shareable: &["SELECT", "INSERT", "UPDATE", "DELETE", "MERGE", "WITH", "VALUES", "SAVEPOINT", "COMMIT", "ROLLBACK"],
};

const FIELDS: &[ConfigField] = &[
    ConfigField {
        name: "url",
        label: "JDBC URL",
        kind: FieldKind::Text,
        required: true,
        default: None,
        help: Some("The driver's own connection string, including host, port and database."),
        placeholder: Some("jdbc:oracle:thin:@//db.internal:1521/ORCLPDB1"),
        secret: false,
        // The URL carries host and port itself, so neither has a field of its
        // own: two places to write the same host is two places to get it wrong.
        role: Some(FieldRole::Host),
    },
    ConfigField {
        name: "driver_class",
        label: "Driver class",
        kind: FieldKind::Text,
        required: false,
        default: None,
        help: Some("Leave empty for a JAR that declares itself through META-INF/services."),
        placeholder: Some("oracle.jdbc.OracleDriver"),
        secret: false,
        role: None,
    },
    ConfigField {
        name: "driver_paths",
        label: "Driver JARs",
        kind: FieldKind::Text,
        required: true,
        default: None,
        help: Some("Absolute paths, comma separated. Vendor drivers are usually not redistributable."),
        placeholder: Some("/opt/havuz/drivers/ojdbc11.jar"),
        secret: false,
        role: None,
    },
    ConfigField {
        name: "username",
        label: "Database user",
        kind: FieldKind::Text,
        required: true,
        default: None,
        help: None,
        placeholder: Some("app"),
        secret: false,
        role: Some(FieldRole::User),
    },
    ConfigField {
        name: "password",
        label: "Database password",
        kind: FieldKind::Password,
        required: false,
        default: None,
        help: Some("Stored encrypted. Never returned by the API."),
        placeholder: None,
        secret: true,
        role: Some(FieldRole::Password),
    },
    ConfigField {
        name: "reset_query",
        label: "Reset query",
        kind: FieldKind::Text,
        required: false,
        default: None,
        help: Some(
            "Run when a connection returns to the pool. Leave empty to use the profile's own, and set it only to \
             override that. Without either, a connection is closed rather than reused: temporary tables and session \
             settings would otherwise reach the next client.",
        ),
        placeholder: Some("DISCARD ALL"),
        secret: false,
        role: None,
    },
    ConfigField {
        name: "agent_jar",
        label: "Agent JAR",
        kind: FieldKind::Text,
        required: false,
        default: None,
        help: Some("Defaults to the JAR built by agent/build.sh."),
        placeholder: Some("/usr/share/havuz/havuz-agent.jar"),
        secret: false,
        role: None,
    },
    ConfigField {
        name: "java",
        label: "Java runtime",
        kind: FieldKind::Text,
        required: false,
        default: Some("java"),
        help: Some("Pin a runtime when the one on PATH is the wrong version. Needs 17 or newer."),
        placeholder: None,
        secret: false,
        role: None,
    },
    ConfigField {
        name: "connect_timeout",
        label: "Connect timeout",
        kind: FieldKind::Duration,
        required: false,
        default: Some("10s"),
        help: None,
        placeholder: None,
        secret: false,
        role: None,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(id: &str) -> &'static DriverProfile {
        PROFILES.iter().find(|p| p.id == id).expect("profile exists")
    }

    #[test]
    fn the_default_profile_is_the_one_that_claims_nothing() {
        // `default_profile` takes the first entry, and an operator who did not
        // pick a product must not be given another product's reset query.
        assert_eq!(JDBC.default_profile().id, "generic");
        assert_eq!(profile("generic").quirks.session, SessionRules::OPAQUE);
    }

    #[test]
    fn only_a_profile_that_classifies_may_leave_session_mode() {
        // The invariant the whole design rests on: a bridge that cannot tell
        // what a statement did must not hand the connection to anyone else.
        for p in PROFILES {
            if p.quirks.max_pool_mode.multiplexes() {
                assert!(p.quirks.session.classifies(), "{} multiplexes without saying which statements are safe", p.id);
            }
        }
    }

    #[test]
    fn no_profile_claims_a_mode_the_family_does_not_offer() {
        for p in PROFILES {
            assert!(JDBC.pool_modes.contains(&p.quirks.max_pool_mode), "{} allows a mode the family does not", p.id);
        }
    }

    #[test]
    fn ordinary_traffic_stays_shareable_on_postgresql() {
        let rules = profile("postgresql").quirks.session;
        for sql in ["select 1", "INSERT INTO t VALUES (1)", "with x as (select 1) select * from x", "commit"] {
            assert_eq!(rules.classify(sql), None, "{sql} should not pin");
        }
    }

    #[test]
    fn the_statements_that_dirty_a_postgresql_session_pin_it() {
        let rules = profile("postgresql").quirks.session;
        assert_eq!(rules.classify("SET application_name = 'x'"), Some(PinReason::SessionParameter));
        assert_eq!(rules.classify("listen chan"), Some(PinReason::Listen));
        assert_eq!(rules.classify("create temp table t (a int)"), Some(PinReason::TempTable));
        assert_eq!(rules.classify("PREPARE q AS SELECT 1"), Some(PinReason::ServerSidePrepare));
        assert_eq!(rules.classify("DECLARE c CURSOR WITH HOLD FOR SELECT 1"), Some(PinReason::HoldableCursor));
    }

    #[test]
    fn transaction_scoped_settings_do_not_pin() {
        // Every driver sends a couple of these on connect; pinning on them
        // would mean a pool of two backends owned by the first two clients.
        let rules = profile("postgresql").quirks.session;
        assert_eq!(rules.classify("SET LOCAL statement_timeout = '5s'"), None);
        assert_eq!(rules.classify("set transaction isolation level serializable"), None);
    }

    #[test]
    fn oracle_pins_the_things_that_survive_a_transaction() {
        let rules = profile("oracle").quirks.session;
        assert_eq!(rules.classify("ALTER SESSION SET CURRENT_SCHEMA = app"), Some(PinReason::SessionParameter));
        assert_eq!(rules.classify("declare v number; begin null; end;"), Some(PinReason::ProcedureState));
        assert_eq!(rules.classify("select 1 from dual"), None);
    }

    #[test]
    fn every_profile_that_can_recycle_says_how() {
        // A reset query is what separates a pool from a connection limiter, so
        // the absence of one has to be a deliberate entry rather than an
        // oversight. `generic` and `db2` are the deliberate ones.
        let without: Vec<&str> =
            PROFILES.iter().filter(|p| p.quirks.session.reset_query.is_none()).map(|p| p.id).collect();
        assert_eq!(without, ["generic", "db2"]);
    }

    #[test]
    fn required_fields_are_the_ones_we_cannot_guess() {
        let required: Vec<&str> = FIELDS.iter().filter(|f| f.required && f.default.is_none()).map(|f| f.name).collect();
        assert_eq!(required, ["url", "driver_paths", "username"]);
    }

    #[test]
    fn the_password_is_the_only_secret() {
        let secret: Vec<&str> = FIELDS.iter().filter(|f| f.secret).map(|f| f.name).collect();
        assert_eq!(secret, ["password"]);
    }
}
