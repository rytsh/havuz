//! JDBC types to PostgreSQL types.
//!
//! The agent hands back a canonical string per value and says what JDBC thought
//! the column was. This module decides what to tell the client it is, and does
//! the small amount of reformatting that PostgreSQL's text format needs.
//!
//! Two sources, because neither alone is enough.
//!
//! The **JDBC type code** is portable but coarse. `java.sql.Types` has no entry
//! for `jsonb`, so pgjdbc reports `OTHER` for it — and none for a time zone
//! either, so `timestamp` and `timestamptz` both come back as `TIMESTAMP`.
//!
//! The **driver's type name** is precise but local. `int4`, `jsonb` and
//! `timestamptz` map exactly; `NUMBER` and `VARCHAR2` mean nothing outside
//! Oracle.
//!
//! So the name refines the code, except where it would throw information away.
//! Oracle reports a column as `DATE` with a JDBC type of `TIMESTAMP`, because an
//! Oracle `DATE` carries a time; trusting the name there would silently drop
//! it. When the two disagree, the one that discards nothing wins.
//!
//! Anything unrecognised becomes `text`. That is not a cop-out: the value is
//! already a string, every client can display a string, and the alternative —
//! guessing a binary layout — produces garbage rather than an honest fallback.

/// A PostgreSQL type as `RowDescription` needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PgType {
    pub oid: i32,
    /// Bytes for a fixed-width type, `-1` for variable length.
    pub size: i16,
    /// How the agent's canonical string has to be adjusted for the wire.
    pub encoding: Encoding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// Already in PostgreSQL's text format.
    Verbatim,
    /// `true`/`false` from the agent, `t`/`f` on the wire.
    Boolean,
    /// Hex from the agent, `\x`-prefixed on the wire.
    Bytea,
}

impl PgType {
    const fn new(oid: i32, size: i16) -> Self {
        Self { oid, size, encoding: Encoding::Verbatim }
    }

    const fn with(oid: i32, size: i16, encoding: Encoding) -> Self {
        Self { oid, size, encoding }
    }

    /// Render the agent's canonical string as PostgreSQL text format.
    pub fn encode(&self, value: &str) -> Vec<u8> {
        match self.encoding {
            Encoding::Verbatim => value.as_bytes().to_vec(),
            Encoding::Boolean => match value {
                "true" => b"t".to_vec(),
                "false" => b"f".to_vec(),
                // A driver that reported BOOLEAN and then produced something
                // else is passed through rather than silently turned into
                // false, which would be a wrong answer instead of a visible one.
                other => other.as_bytes().to_vec(),
            },
            Encoding::Bytea => {
                let mut out = Vec::with_capacity(value.len() + 2);
                out.extend_from_slice(b"\\x");
                out.extend_from_slice(value.as_bytes());
                out
            }
        }
    }
}

// The handful of OIDs a client actually decodes differently.
const BOOL: PgType = PgType::with(16, 1, Encoding::Boolean);
const BYTEA: PgType = PgType::with(17, -1, Encoding::Bytea);
const INT8: PgType = PgType::new(20, 8);
const INT2: PgType = PgType::new(21, 2);
const INT4: PgType = PgType::new(23, 4);
const TEXT: PgType = PgType::new(25, -1);
const JSON: PgType = PgType::new(114, -1);
const XML: PgType = PgType::new(142, -1);
const FLOAT4: PgType = PgType::new(700, 4);
const FLOAT8: PgType = PgType::new(701, 8);
const BPCHAR: PgType = PgType::new(1042, -1);
const VARCHAR: PgType = PgType::new(1043, -1);
const DATE: PgType = PgType::new(1082, 4);
const TIME: PgType = PgType::new(1083, 8);
const TIMESTAMP: PgType = PgType::new(1114, 8);
const TIMESTAMPTZ: PgType = PgType::new(1184, 8);
const INTERVAL: PgType = PgType::new(1186, 16);
const TIMETZ: PgType = PgType::new(1266, 12);
const NUMERIC: PgType = PgType::new(1700, -1);
const UUID: PgType = PgType::new(2950, 16);
const JSONB: PgType = PgType::new(3802, -1);

/// `java.sql.Types`, spelled out so the mapping below reads as a table rather
/// than as a column of magic numbers.
mod jdbc {
    pub const BIT: i32 = -7;
    pub const TINYINT: i32 = -6;
    pub const SMALLINT: i32 = 5;
    pub const INTEGER: i32 = 4;
    pub const BIGINT: i32 = -5;
    pub const FLOAT: i32 = 6;
    pub const REAL: i32 = 7;
    pub const DOUBLE: i32 = 8;
    pub const NUMERIC: i32 = 2;
    pub const DECIMAL: i32 = 3;
    pub const CHAR: i32 = 1;
    pub const VARCHAR: i32 = 12;
    pub const LONGVARCHAR: i32 = -1;
    pub const DATE: i32 = 91;
    pub const TIME: i32 = 92;
    pub const TIMESTAMP: i32 = 93;
    pub const BINARY: i32 = -2;
    pub const VARBINARY: i32 = -3;
    pub const LONGVARBINARY: i32 = -4;
    pub const BOOLEAN: i32 = 16;
    pub const NCHAR: i32 = -15;
    pub const NVARCHAR: i32 = -9;
    pub const LONGNVARCHAR: i32 = -16;
    pub const BLOB: i32 = 2004;
    pub const CLOB: i32 = 2005;
    pub const NCLOB: i32 = 2011;
    pub const SQLXML: i32 = 2009;
    pub const TIME_WITH_TIMEZONE: i32 = 2013;
    pub const TIMESTAMP_WITH_TIMEZONE: i32 = 2014;
}

/// What to tell the client a column is.
pub fn pg_type(jdbc_type: i32, type_name: &str) -> PgType {
    let coded = by_code(jdbc_type);
    let Some(named) = by_name(type_name) else { return coded };

    // The name normally wins: it is what makes `jsonb` come out as `jsonb`
    // rather than as `OTHER`, and `timestamptz` as itself rather than as a
    // plain timestamp.
    //
    // The exception is a name that means less than the code does. Oracle calls
    // a column `DATE` and reports it as `TIMESTAMP`, because an Oracle `DATE`
    // has a time in it. Telling the client `date` would drop that time from
    // every row, quietly, which is the worst kind of wrong answer.
    if discards_information(named, coded) {
        return coded;
    }
    named
}

/// Would trusting `named` lose something `coded` says is there?
fn discards_information(named: PgType, coded: PgType) -> bool {
    let temporal_widening =
        named.oid == DATE.oid && matches!(coded.oid, o if o == TIMESTAMP.oid || o == TIMESTAMPTZ.oid);
    let time_widening = named.oid == TIME.oid && coded.oid == TIMESTAMP.oid;
    temporal_widening || time_widening
}

/// PostgreSQL's own type names, for when the database behind the bridge is
/// PostgreSQL and the answer can be exactly right instead of merely usable.
fn by_name(type_name: &str) -> Option<PgType> {
    let name = type_name.trim().to_ascii_lowercase();
    Some(match name.as_str() {
        "bool" | "boolean" => BOOL,
        "bytea" => BYTEA,
        "int2" | "smallint" => INT2,
        "int4" | "integer" | "serial" => INT4,
        "int8" | "bigint" | "bigserial" => INT8,
        "float4" | "real" => FLOAT4,
        "float8" | "double precision" => FLOAT8,
        "numeric" | "decimal" => NUMERIC,
        "json" => JSON,
        "jsonb" => JSONB,
        "uuid" => UUID,
        "xml" => XML,
        "date" => DATE,
        "time" => TIME,
        "timetz" | "time with time zone" => TIMETZ,
        "timestamp" | "timestamp without time zone" => TIMESTAMP,
        "timestamptz" | "timestamp with time zone" => TIMESTAMPTZ,
        "interval" => INTERVAL,
        "varchar" | "character varying" => VARCHAR,
        "bpchar" | "char" | "character" => BPCHAR,
        "text" | "name" => TEXT,
        _ => return None,
    })
}

fn by_code(jdbc_type: i32) -> PgType {
    match jdbc_type {
        jdbc::BOOLEAN | jdbc::BIT => BOOL,
        jdbc::TINYINT | jdbc::SMALLINT => INT2,
        jdbc::INTEGER => INT4,
        jdbc::BIGINT => INT8,
        jdbc::REAL => FLOAT4,
        jdbc::FLOAT | jdbc::DOUBLE => FLOAT8,
        jdbc::NUMERIC | jdbc::DECIMAL => NUMERIC,
        jdbc::DATE => DATE,
        jdbc::TIME => TIME,
        jdbc::TIME_WITH_TIMEZONE => TIMETZ,
        jdbc::TIMESTAMP => TIMESTAMP,
        jdbc::TIMESTAMP_WITH_TIMEZONE => TIMESTAMPTZ,
        jdbc::BINARY | jdbc::VARBINARY | jdbc::LONGVARBINARY | jdbc::BLOB => BYTEA,
        jdbc::SQLXML => XML,
        jdbc::CHAR | jdbc::VARCHAR | jdbc::LONGVARCHAR => TEXT,
        jdbc::NCHAR | jdbc::NVARCHAR | jdbc::LONGNVARCHAR => TEXT,
        jdbc::CLOB | jdbc::NCLOB => TEXT,
        // Arrays, structs, vendor types, and anything a future JDBC adds. The
        // value is already a string and every client can render one.
        _ => TEXT,
    }
}

/// The `CommandComplete` tag for a statement that ran.
///
/// PostgreSQL's format is not uniform — `INSERT` carries an OID slot that has
/// been zero since 12, `SELECT` and `UPDATE` carry a count, `BEGIN` carries
/// nothing — and clients parse it, so the shape matters.
pub fn command_tag(sql: &str, rows: u64, update_count: i64) -> String {
    let verb = leading_word(sql).to_ascii_uppercase();
    let affected = if update_count >= 0 { update_count as u64 } else { rows };

    match verb.as_str() {
        "SELECT" | "FETCH" => format!("SELECT {rows}"),
        "INSERT" => format!("INSERT 0 {affected}"),
        "UPDATE" | "DELETE" | "MERGE" | "MOVE" | "COPY" => format!("{verb} {affected}"),
        // `WITH` may be a data-modifying CTE; the row count is the honest part
        // and the verb is what the client asked for.
        "WITH" => format!("SELECT {rows}"),
        "" => "SELECT 0".to_string(),
        // DDL and everything else: the verb alone, which is what PostgreSQL
        // sends for CREATE, DROP, SET, BEGIN and friends.
        _ => two_word_tag(sql, &verb),
    }
}

/// `CREATE TABLE`, `DROP INDEX`, `ALTER TABLE` — PostgreSQL includes the object
/// kind, and at least one migration tool checks for it.
///
/// The modifiers in between are skipped, because `CREATE TEMP TABLE` reports
/// `CREATE TABLE` and a client comparing against that string would not match
/// `CREATE TEMP`.
fn two_word_tag(sql: &str, verb: &str) -> String {
    const MODIFIERS: &[&str] = &[
        "TEMP",
        "TEMPORARY",
        "UNLOGGED",
        "GLOBAL",
        "LOCAL",
        "OR",
        "REPLACE",
        "IF",
        "NOT",
        "EXISTS",
        "MATERIALIZED",
        "RECURSIVE",
        "UNIQUE",
        "CONCURRENTLY",
    ];

    if !matches!(verb, "CREATE" | "DROP" | "ALTER") {
        return verb.to_string();
    }
    let mut rest = sql.trim_start().split_once(char::is_whitespace).map(|(_, rest)| rest).unwrap_or("");
    loop {
        let word = leading_word(rest).to_ascii_uppercase();
        if word.is_empty() {
            return verb.to_string();
        }
        if !MODIFIERS.contains(&word.as_str()) {
            return format!("{verb} {word}");
        }
        rest = rest.trim_start().split_once(char::is_whitespace).map(|(_, rest)| rest).unwrap_or("");
    }
}

fn leading_word(sql: &str) -> &str {
    let trimmed = sql.trim_start();
    let end = trimmed.find(|c: char| c.is_whitespace() || c == '(' || c == ';').unwrap_or(trimmed.len());
    &trimmed[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgres_type_names_reproduce_the_native_oid() {
        // The point of honouring the driver's name: a client sees exactly what
        // it would have seen talking to PostgreSQL directly.
        assert_eq!(pg_type(4, "int4").oid, 23);
        assert_eq!(pg_type(2, "numeric").oid, 1700);
        assert_eq!(pg_type(1111, "jsonb").oid, 3802);
        assert_eq!(pg_type(1111, "uuid").oid, 2950);
        assert_eq!(pg_type(93, "timestamptz").oid, 1184);
    }

    #[test]
    fn an_unknown_vendor_type_falls_back_to_the_jdbc_code() {
        // Oracle's NUMBER is not a PostgreSQL type name, but JDBC calls it
        // NUMERIC and that is enough to decode it correctly.
        assert_eq!(pg_type(2, "NUMBER").oid, NUMERIC.oid);
        assert_eq!(pg_type(12, "VARCHAR2").oid, TEXT.oid);
        // Oracle calls it DATE and reports TIMESTAMP, because an Oracle DATE
        // has a time in it. The name must not be allowed to drop that.
        assert_eq!(pg_type(93, "DATE").oid, TIMESTAMP.oid);
    }

    #[test]
    fn the_name_supplies_what_the_jdbc_code_cannot_express() {
        // java.sql.Types has no jsonb and no time zone, so pgjdbc reports
        // OTHER and TIMESTAMP for four genuinely different types.
        assert_eq!(pg_type(1111, "jsonb").oid, JSONB.oid);
        assert_eq!(pg_type(1111, "uuid").oid, UUID.oid);
        assert_eq!(pg_type(93, "timestamptz").oid, TIMESTAMPTZ.oid);
        assert_eq!(pg_type(93, "timestamp").oid, TIMESTAMP.oid);
        assert_eq!(pg_type(92, "timetz").oid, TIMETZ.oid);
        assert_eq!(pg_type(1, "bpchar").oid, BPCHAR.oid);
    }

    #[test]
    fn everything_unrecognised_is_text_rather_than_a_guess() {
        // A string renders; a wrong binary layout produces garbage.
        assert_eq!(pg_type(2003, "_int4").oid, TEXT.oid, "arrays render as their text form");
        assert_eq!(pg_type(1111, "geometry").oid, TEXT.oid);
        assert_eq!(pg_type(-99999, "").oid, TEXT.oid);
    }

    #[test]
    fn booleans_are_rewritten_to_the_wire_spelling() {
        assert_eq!(pg_type(16, "bool").encode("true"), b"t");
        assert_eq!(pg_type(16, "bool").encode("false"), b"f");
    }

    #[test]
    fn a_boolean_that_is_not_one_is_passed_through_not_defaulted() {
        // Turning an unexpected value into `f` would be a wrong answer; showing
        // it is a visible one.
        assert_eq!(pg_type(16, "bool").encode("Y"), b"Y");
    }

    #[test]
    fn binary_gets_the_prefix_postgres_clients_expect() {
        assert_eq!(pg_type(-2, "bytea").encode("00ff"), b"\\x00ff");
        assert_eq!(pg_type(-2, "bytea").encode(""), b"\\x", "an empty blob is not a null");
    }

    #[test]
    fn text_passes_through_untouched_including_utf8() {
        assert_eq!(pg_type(12, "text").encode("çğü 日本語"), "çğü 日本語".as_bytes());
    }

    #[test]
    fn command_tags_match_what_clients_parse() {
        assert_eq!(command_tag("select * from t", 3, -1), "SELECT 3");
        // The zero is the OID slot, unused since PostgreSQL 12 but still sent.
        assert_eq!(command_tag("insert into t values (1)", 0, 1), "INSERT 0 1");
        assert_eq!(command_tag("update t set x = 1", 0, 5), "UPDATE 5");
        assert_eq!(command_tag("delete from t", 0, 2), "DELETE 2");
        assert_eq!(command_tag("  CREATE   TABLE t (x int)", 0, 0), "CREATE TABLE");
        assert_eq!(command_tag("drop index i", 0, 0), "DROP INDEX");
        // The modifiers are skipped: PostgreSQL reports CREATE TABLE for all
        // of these, and a client comparing strings would not match CREATE TEMP.
        assert_eq!(command_tag("create temp table t(x int)", 0, 0), "CREATE TABLE");
        assert_eq!(command_tag("CREATE UNLOGGED TABLE t(x int)", 0, 0), "CREATE TABLE");
        assert_eq!(command_tag("drop table if exists t", 0, 0), "DROP TABLE");
        assert_eq!(command_tag("create or replace view v as select 1", 0, 0), "CREATE VIEW");
        assert_eq!(command_tag("create index concurrently i on t(x)", 0, 0), "CREATE INDEX");
        assert_eq!(command_tag("begin", 0, 0), "BEGIN");
        assert_eq!(command_tag("set search_path = app", 0, 0), "SET");
    }

    #[test]
    fn a_data_modifying_cte_reports_the_rows_it_returned() {
        assert_eq!(command_tag("with x as (delete from t returning *) select * from x", 4, -1), "SELECT 4");
    }

    #[test]
    fn an_empty_statement_does_not_panic() {
        assert_eq!(command_tag("", 0, -1), "SELECT 0");
        assert_eq!(command_tag("   ", 0, -1), "SELECT 0");
    }

    #[test]
    fn a_statement_with_no_space_before_its_paren_is_still_recognised() {
        assert_eq!(command_tag("select(1)", 1, -1), "SELECT 1");
    }
}
