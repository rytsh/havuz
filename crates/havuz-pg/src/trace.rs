//! Turning Postgres wire messages into trace observations.
//!
//! The trace store itself is family-neutral and lives in `havuz-control`. This
//! module is the only part of tracing that could not be shared: decoding
//! `RowDescription`, `DataRow`, `CommandComplete` and `ErrorResponse` is by
//! definition protocol work, and a second family would write its own version of
//! exactly this file and nothing else.
//!
//! Decoding is deliberately forgiving. A trace is diagnostics; a malformed or
//! unexpected frame must degrade to "we captured less" and never to an error
//! that the relay has to handle. Every parser here returns empty or `None`
//! rather than failing.

use havuz_control::TraceSpan;

use crate::protocol::{ErrorField, Message};

/// Feeds a [`TraceSpan`] from the backend's message stream.
pub trait PgTraceSpan {
    /// Offer one backend message. Messages the trace does not care about are
    /// ignored, which is most of them.
    fn observe(&mut self, message: &Message);
}

impl PgTraceSpan for TraceSpan {
    fn observe(&mut self, message: &Message) {
        match message.tag {
            b'T' => self.begin_result_set(parse_columns(&message.body)),
            b'D' => {
                if let Some(row) = parse_data_row(&message.body) {
                    self.push_row(row);
                }
            }
            b'C' => {
                let command = cstring(&message.body).unwrap_or_default();
                let rows = command_row_count(&command);
                self.command_complete(command, rows);
            }
            b'E' => {
                let fields = message.error_fields();
                let code = fields
                    .iter()
                    .find(|(field, _)| *field == ErrorField::Code as u8)
                    .map(|(_, value)| value.clone())
                    .unwrap_or_else(|| "XX000".into());
                let text = fields
                    .iter()
                    .find(|(field, _)| *field == ErrorField::Message as u8)
                    .map(|(_, value)| value.clone())
                    .unwrap_or_else(|| "backend error".into());
                self.record_error(code, text);
            }
            _ => {}
        }
    }
}

/// Column names out of a `RowDescription`.
///
/// Each field is a NUL-terminated name followed by 18 bytes of table OID,
/// column number, type OID, type length, type modifier and format code. We want
/// only the name, so the rest is skipped wholesale.
fn parse_columns(body: &[u8]) -> Vec<String> {
    if body.len() < 2 {
        return Vec::new();
    }
    let count = i16::from_be_bytes([body[0], body[1]]).max(0) as usize;
    let mut offset = 2usize;
    let mut columns = Vec::with_capacity(count);
    for _ in 0..count {
        let Some(end) = body[offset..].iter().position(|byte| *byte == 0).map(|position| offset + position) else {
            return Vec::new();
        };
        columns.push(String::from_utf8_lossy(&body[offset..end]).into_owned());
        offset = end + 1;
        if offset.saturating_add(18) > body.len() {
            return Vec::new();
        }
        offset += 18;
    }
    columns
}

/// Values out of a `DataRow`.
///
/// A length of `-1` is SQL NULL. Binary-format values are not valid UTF-8, so
/// they are rendered as `\x…` rather than dropped: seeing the bytes is more
/// useful in a trace than seeing a blank.
fn parse_data_row(body: &[u8]) -> Option<Vec<Option<String>>> {
    if body.len() < 2 {
        return None;
    }
    let count = i16::from_be_bytes([body[0], body[1]]);
    if count < 0 {
        return None;
    }
    let mut offset = 2usize;
    let mut row = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let length = read_i32(body, offset)?;
        offset += 4;
        if length == -1 {
            row.push(None);
            continue;
        }
        if length < 0 {
            return None;
        }
        let end = offset.checked_add(length as usize)?;
        let value = body.get(offset..end)?;
        row.push(Some(match std::str::from_utf8(value) {
            Ok(text) => text.to_string(),
            Err(_) => format!("\\x{}", hex(value)),
        }));
        offset = end;
    }
    Some(row)
}

fn read_i32(body: &[u8], offset: usize) -> Option<i32> {
    Some(i32::from_be_bytes(body.get(offset..offset + 4)?.try_into().ok()?))
}

fn cstring(body: &[u8]) -> Option<String> {
    let end = body.iter().position(|byte| *byte == 0).unwrap_or(body.len());
    Some(String::from_utf8_lossy(body.get(..end)?).into_owned())
}

/// `SELECT 42` -> 42. Tags without a count (`BEGIN`, `SET`) report zero.
fn command_row_count(command: &str) -> u64 {
    command.split_whitespace().next_back().and_then(|part| part.parse().ok()).unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use bytes::{BufMut, Bytes, BytesMut};
    use havuz_control::{TraceContext, TraceFilter, TraceStore};

    use super::*;

    fn context() -> TraceContext {
        TraceContext {
            pool: "app_main".into(),
            user: "svc_orders".into(),
            application: Some("orders-api".into()),
            client_addr: "127.0.0.1:1234".into(),
        }
    }

    fn row_description(names: &[&str]) -> Message {
        let mut body = BytesMut::new();
        body.put_i16(names.len() as i16);
        for name in names {
            body.put_slice(name.as_bytes());
            body.put_u8(0);
            body.put_i32(0);
            body.put_i16(0);
            body.put_i32(25);
            body.put_i16(-1);
            body.put_i32(-1);
            body.put_i16(0);
        }
        Message::new(b'T', body.freeze())
    }

    fn data_row(values: &[Option<&str>]) -> Message {
        let mut body = BytesMut::new();
        body.put_i16(values.len() as i16);
        for value in values {
            match value {
                Some(value) => {
                    body.put_i32(value.len() as i32);
                    body.put_slice(value.as_bytes());
                }
                None => body.put_i32(-1),
            }
        }
        Message::new(b'D', body.freeze())
    }

    fn wait_for_history(store: &TraceStore) {
        for _ in 0..50 {
            if !store.list(&TraceFilter::default()).unwrap().is_empty() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("trace writer did not flush");
    }

    #[test]
    fn a_result_set_survives_the_round_trip_through_the_wire_format() {
        let store = TraceStore::memory();
        let mut span = store.begin(&context(), "select 42 as answer");
        span.assign("primary/127.0.0.1:5432", Some(42));
        span.observe(&row_description(&["answer"]));
        span.observe(&data_row(&[Some("42"), None]));
        span.observe(&Message::new(b'C', Bytes::from_static(b"SELECT 1\0")));
        span.succeed();

        wait_for_history(&store);
        let summary = &store.list(&TraceFilter::default()).unwrap()[0];
        assert_eq!(summary.row_count, 1, "the count comes from the command tag, not from rows seen");
        let detail = store.get(summary.id).unwrap().unwrap();
        assert_eq!(detail.result.sets[0].columns, ["answer"]);
        assert_eq!(detail.result.sets[0].rows[0], [Some("42".into()), None]);
    }

    #[test]
    fn an_error_response_is_decoded_into_sqlstate_and_message() {
        let store = TraceStore::memory();
        let mut span = store.begin(&context(), "select missing");
        span.observe(&Message::error_response("ERROR", "42703", "column missing does not exist"));
        span.succeed();
        wait_for_history(&store);

        let trace = &store.list(&TraceFilter::default()).unwrap()[0];
        assert_eq!(trace.status, "failed");
        assert_eq!(trace.error_code.as_deref(), Some("42703"));
    }

    #[test]
    fn binary_values_are_shown_as_hex_rather_than_dropped() {
        let mut body = BytesMut::new();
        body.put_i16(1);
        body.put_i32(2);
        body.put_slice(&[0xff, 0xfe]);
        let row = parse_data_row(&body.freeze()).expect("a well-formed DataRow");
        assert_eq!(row, [Some("\\xfffe".to_string())]);
    }

    #[test]
    fn a_truncated_frame_captures_nothing_instead_of_panicking() {
        // Diagnostics must never be able to take down the relay.
        assert!(parse_columns(&[0x00]).is_empty());
        assert!(parse_columns(&[0x00, 0x01, b'a']).is_empty(), "a name with no trailing metadata");
        assert!(parse_data_row(&[0x00, 0x01, 0x00, 0x00]).is_none());
    }

    #[test]
    fn command_tags_without_a_count_report_zero_rows() {
        assert_eq!(command_row_count("SELECT 42"), 42);
        assert_eq!(command_row_count("INSERT 0 3"), 3);
        assert_eq!(command_row_count("BEGIN"), 0);
        assert_eq!(command_row_count(""), 0);
    }
}
