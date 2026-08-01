//! `$1` to `?`.
//!
//! PostgreSQL numbers its placeholders; JDBC uses positional question marks.
//! Every client that speaks the extended query protocol — which is every
//! client that matters — sends `$1`, so a bridge that does not translate can
//! only ever run statements with no parameters.
//!
//! The translation looks like a one-line regular expression and is not, because
//! a `$` inside a string literal is data:
//!
//! ```sql
//! select 'costs $1 today', $1        -- one placeholder, not two
//! select $tag$ raw $1 text $tag$     -- zero placeholders
//! ```
//!
//! So this walks the statement, skips over everything that is not code, and
//! rewrites only what is left. Getting it wrong turns a literal into a bind
//! parameter, which is a data corruption that no test of the happy path would
//! ever notice.

/// A statement rewritten for JDBC, and how many parameters it wants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rewritten {
    pub sql: String,
    /// Highest `$n` seen. Placeholders may repeat and may be out of order, so
    /// this is the count JDBC needs, not the number of `?` emitted.
    pub highest: u16,
    /// Which original `$n` each emitted `?` refers to, in order. `$1` used
    /// twice produces two entries, both `0`.
    pub order: Vec<u16>,
}

/// Rewrite PostgreSQL placeholders into JDBC ones.
///
/// Anything that is not a placeholder is copied through byte for byte,
/// including whitespace and comments: the statement reaching the database
/// should be recognisable in its logs.
pub fn to_jdbc(sql: &str) -> Rewritten {
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut order = Vec::new();
    let mut highest = 0u16;
    let mut i = 0usize;

    while i < bytes.len() {
        match bytes[i] {
            b'\'' => i = copy_quoted(sql, bytes, i, b'\'', &mut out),
            b'"' => i = copy_quoted(sql, bytes, i, b'"', &mut out),
            b'-' if bytes.get(i + 1) == Some(&b'-') => i = copy_line_comment(sql, bytes, i, &mut out),
            b'/' if bytes.get(i + 1) == Some(&b'*') => i = copy_block_comment(sql, bytes, i, &mut out),
            b'$' => match dollar_quote(bytes, i) {
                Some(end) => {
                    out.push_str(&sql[i..end]);
                    i = end;
                }
                None => match placeholder(bytes, i) {
                    Some((number, end)) => {
                        out.push('?');
                        // `$0` is not a legal placeholder; treating it as one
                        // would produce a parameter index JDBC cannot bind.
                        if number >= 1 {
                            highest = highest.max(number);
                            order.push(number - 1);
                        }
                        i = end;
                    }
                    None => {
                        out.push('$');
                        i += 1;
                    }
                },
            },
            _ => {
                let start = i;
                // Copy the run of ordinary bytes in one go rather than a char
                // at a time; most of a statement is ordinary.
                while i < bytes.len() && !matches!(bytes[i], b'\'' | b'"' | b'$' | b'-' | b'/') {
                    i += 1;
                }
                if i == start {
                    out.push(bytes[i] as char);
                    i += 1;
                } else {
                    out.push_str(&sql[start..i]);
                }
            }
        }
    }

    Rewritten { sql: out, highest, order }
}

/// A `'...'` or `"..."` run, where the delimiter is escaped by doubling.
fn copy_quoted(sql: &str, bytes: &[u8], start: usize, delimiter: u8, out: &mut String) -> usize {
    let mut i = start + 1;
    while i < bytes.len() {
        if bytes[i] == delimiter {
            // A doubled delimiter is an escaped one and the literal continues.
            if bytes.get(i + 1) == Some(&delimiter) {
                i += 2;
                continue;
            }
            i += 1;
            break;
        }
        i += 1;
    }
    // An unterminated literal is copied as-is: the database will reject it with
    // a better message than anything invented here.
    out.push_str(&sql[start..i.min(bytes.len())]);
    i.min(bytes.len())
}

fn copy_line_comment(sql: &str, bytes: &[u8], start: usize, out: &mut String) -> usize {
    let mut i = start + 2;
    while i < bytes.len() && bytes[i] != b'\n' {
        i += 1;
    }
    out.push_str(&sql[start..i]);
    i
}

fn copy_block_comment(sql: &str, bytes: &[u8], start: usize, out: &mut String) -> usize {
    let mut i = start + 2;
    let mut depth = 1;
    while i < bytes.len() && depth > 0 {
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            // PostgreSQL block comments nest, unlike C's.
            depth += 1;
            i += 2;
        } else if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
            depth -= 1;
            i += 2;
        } else {
            i += 1;
        }
    }
    out.push_str(&sql[start..i.min(bytes.len())]);
    i.min(bytes.len())
}

/// `$tag$ ... $tag$`, returning the offset just past the closing tag.
///
/// The tag is empty (`$$`) or an identifier. Anything else is not a dollar
/// quote — `$1` is a placeholder and `$` alone is just a character.
fn dollar_quote(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start + 1;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        // A digit cannot start a tag; that would be a placeholder.
        if bytes[i].is_ascii_digit() && i == start + 1 {
            return None;
        }
        i += 1;
    }
    if bytes.get(i) != Some(&b'$') {
        return None;
    }
    let tag = &bytes[start..=i];
    let body = i + 1;
    let mut j = body;
    while j + tag.len() <= bytes.len() {
        if &bytes[j..j + tag.len()] == tag {
            return Some(j + tag.len());
        }
        j += 1;
    }
    // Unterminated: swallow the rest so a stray `$1` inside it is not rewritten.
    Some(bytes.len())
}

/// `$n`, returning the number and the offset just past it.
fn placeholder(bytes: &[u8], start: usize) -> Option<(u16, usize)> {
    let mut i = start + 1;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == start + 1 {
        return None;
    }
    let text = std::str::from_utf8(&bytes[start + 1..i]).ok()?;
    // A number too large to be a parameter index is not one.
    let number: u16 = text.parse().ok()?;
    Some((number, i))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sql(input: &str) -> String {
        to_jdbc(input).sql
    }

    #[test]
    fn placeholders_become_question_marks() {
        let out = to_jdbc("select * from t where a = $1 and b = $2");
        assert_eq!(out.sql, "select * from t where a = ? and b = ?");
        assert_eq!(out.highest, 2);
        assert_eq!(out.order, [0, 1]);
    }

    #[test]
    fn a_repeated_placeholder_is_bound_twice() {
        // JDBC has no way to say "the same parameter again", so the value has
        // to be sent once per occurrence.
        let out = to_jdbc("select $1, $1, $2");
        assert_eq!(out.sql, "select ?, ?, ?");
        assert_eq!(out.highest, 2);
        assert_eq!(out.order, [0, 0, 1]);
    }

    #[test]
    fn out_of_order_placeholders_keep_their_meaning() {
        let out = to_jdbc("select $2, $1");
        assert_eq!(out.order, [1, 0], "the second ? binds the first parameter");
        assert_eq!(out.highest, 2);
    }

    #[test]
    fn a_dollar_inside_a_string_is_data() {
        // The bug this whole module exists to avoid: rewriting a literal into
        // a bind parameter changes what the query means, silently.
        assert_eq!(sql("select 'costs $1 today', $1"), "select 'costs $1 today', ?");
        assert_eq!(to_jdbc("select 'costs $1 today', $1").order, [0]);
    }

    #[test]
    fn a_doubled_quote_does_not_end_the_literal() {
        assert_eq!(sql("select 'it''s $1', $1"), "select 'it''s $1', ?");
    }

    #[test]
    fn a_dollar_inside_a_quoted_identifier_is_data() {
        assert_eq!(sql(r#"select "col$1", $1"#), r#"select "col$1", ?"#);
    }

    #[test]
    fn dollar_quoted_bodies_are_left_alone() {
        assert_eq!(sql("select $$ raw $1 text $$, $1"), "select $$ raw $1 text $$, ?");
        assert_eq!(sql("select $tag$ $1 $tag$, $2"), "select $tag$ $1 $tag$, ?");
    }

    #[test]
    fn a_function_body_survives_intact() {
        // The realistic case: a CREATE FUNCTION whose body is full of $1.
        let body = "create function f() returns int as $body$ begin return $1; end $body$ language plpgsql";
        assert_eq!(sql(body), body);
        assert_eq!(to_jdbc(body).highest, 0);
    }

    #[test]
    fn comments_are_preserved_and_not_scanned() {
        assert_eq!(sql("select 1 -- $1 here\nwhere a = $1"), "select 1 -- $1 here\nwhere a = ?");
        assert_eq!(sql("select /* $1 */ $1"), "select /* $1 */ ?");
        assert_eq!(sql("select /* a /* $1 */ b */ $1"), "select /* a /* $1 */ b */ ?", "block comments nest");
    }

    #[test]
    fn a_bare_dollar_is_not_a_placeholder() {
        assert_eq!(sql("select 1 $ 2"), "select 1 $ 2");
        assert_eq!(sql("select a$b from t"), "select a$b from t");
    }

    #[test]
    fn dollar_zero_is_not_a_parameter() {
        // Postgres numbers from one; treating $0 as a parameter would produce
        // an index JDBC cannot bind.
        let out = to_jdbc("select $0");
        assert_eq!(out.highest, 0);
        assert!(out.order.is_empty());
    }

    #[test]
    fn an_unterminated_literal_is_passed_through_for_the_database_to_reject() {
        assert_eq!(sql("select 'unterminated $1"), "select 'unterminated $1");
        assert_eq!(sql("select $tag$ unterminated $1"), "select $tag$ unterminated $1");
    }

    #[test]
    fn statements_without_parameters_are_untouched() {
        for statement in ["select 1", "", "  ", "insert into t values (1)", "select '100%'"] {
            assert_eq!(sql(statement), statement);
        }
    }

    #[test]
    fn multibyte_text_is_not_split() {
        // Copying by byte offset would panic on a char boundary if the run
        // scanner ever stopped mid-character.
        assert_eq!(sql("select 'çğüöşi̇', $1"), "select 'çğüöşi̇', ?");
        assert_eq!(sql("select '日本語' || $1"), "select '日本語' || ?");
    }
}
