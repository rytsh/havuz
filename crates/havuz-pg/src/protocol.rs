//! Message framing.
//!
//! Postgres has two framings. The first packet a client sends carries no type
//! byte — its length prefix is followed by a 32-bit code that says whether this
//! is a normal startup, an SSL upgrade request, or a cancellation. Every packet
//! after that is `type(1) + length(4) + body`.
//!
//! Getting the first packet wrong is how proxies break `psql` in ways that only
//! show up with TLS enabled, so it is modelled explicitly rather than being
//! special-cased inside a read loop.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// `3.0`, the only protocol version in use since 2003.
pub const PROTOCOL_VERSION_3: i32 = 196_608;

const SSL_REQUEST_CODE: i32 = 80_877_103;
const CANCEL_REQUEST_CODE: i32 = 80_877_102;
const GSSENC_REQUEST_CODE: i32 = 80_877_104;

/// Startup packets are attacker-controlled and unauthenticated at this point,
/// so the length prefix gets a hard ceiling before we allocate anything.
const MAX_STARTUP_LEN: usize = 10_000;
/// Regular messages can legitimately be large (bind parameters, COPY data).
const MAX_MESSAGE_LEN: usize = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("packet length {0} is invalid")]
    BadLength(i32),
    #[error("packet of {len} bytes exceeds the {max} byte limit")]
    TooLarge { len: usize, max: usize },
    #[error("unsupported protocol version {major}.{minor}; havuz speaks 3.0")]
    UnsupportedVersion { major: i32, minor: i32 },
    #[error("malformed startup packet: {0}")]
    MalformedStartup(&'static str),
    #[error("startup packet is missing the required '{0}' parameter")]
    MissingParameter(&'static str),
    #[error("message body is truncated")]
    Truncated,
    #[error("string is not valid utf-8")]
    NotUtf8,
}

/// The first packet on a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupPacket {
    /// A normal connection attempt.
    Startup {
        /// Startup parameters. `user` is mandatory; `database` defaults to the
        /// user name, which is where havuz reads the pool name from.
        params: Vec<(String, String)>,
    },
    /// Client asks to upgrade to TLS before sending its real startup packet.
    SslRequest,
    /// Client wants to cancel a running query on another connection.
    CancelRequest { process_id: i32, secret_key: i32 },
    /// GSSAPI encryption request. Refused, and the client falls back.
    GssEncRequest,
}

impl StartupPacket {
    pub fn param(&self, key: &str) -> Option<&str> {
        match self {
            StartupPacket::Startup { params } => params.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str()),
            _ => None,
        }
    }

    /// The havuz user, taken from the `user` startup parameter.
    pub fn user(&self) -> Result<&str, ProtocolError> {
        self.param("user").ok_or(ProtocolError::MissingParameter("user"))
    }

    /// The pool name. Postgres defaults `database` to `user` when omitted, and
    /// so do we, so `psql -U svc_orders` reaches the `svc_orders` pool.
    pub fn database(&self) -> Result<&str, ProtocolError> {
        match self.param("database") {
            Some(db) => Ok(db),
            None => self.user(),
        }
    }

    pub fn application_name(&self) -> Option<&str> {
        self.param("application_name")
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        match self {
            StartupPacket::Startup { params } => {
                buf.put_i32(0); // placeholder
                buf.put_i32(PROTOCOL_VERSION_3);
                for (k, v) in params {
                    buf.put_slice(k.as_bytes());
                    buf.put_u8(0);
                    buf.put_slice(v.as_bytes());
                    buf.put_u8(0);
                }
                buf.put_u8(0);
            }
            StartupPacket::SslRequest => {
                buf.put_i32(8);
                buf.put_i32(SSL_REQUEST_CODE);
                return buf.freeze();
            }
            StartupPacket::GssEncRequest => {
                buf.put_i32(8);
                buf.put_i32(GSSENC_REQUEST_CODE);
                return buf.freeze();
            }
            StartupPacket::CancelRequest { process_id, secret_key } => {
                buf.put_i32(16);
                buf.put_i32(CANCEL_REQUEST_CODE);
                buf.put_i32(*process_id);
                buf.put_i32(*secret_key);
                return buf.freeze();
            }
        }
        let len = buf.len() as i32;
        buf[0..4].copy_from_slice(&len.to_be_bytes());
        buf.freeze()
    }

    pub fn decode(mut body: Bytes) -> Result<Self, ProtocolError> {
        if body.len() < 4 {
            return Err(ProtocolError::Truncated);
        }
        let code = body.get_i32();
        match code {
            SSL_REQUEST_CODE => Ok(StartupPacket::SslRequest),
            GSSENC_REQUEST_CODE => Ok(StartupPacket::GssEncRequest),
            CANCEL_REQUEST_CODE => {
                if body.len() < 8 {
                    return Err(ProtocolError::Truncated);
                }
                Ok(StartupPacket::CancelRequest { process_id: body.get_i32(), secret_key: body.get_i32() })
            }
            PROTOCOL_VERSION_3 => {
                let params = decode_params(&body)?;
                if !params.iter().any(|(k, _)| k == "user") {
                    return Err(ProtocolError::MissingParameter("user"));
                }
                Ok(StartupPacket::Startup { params })
            }
            other => Err(ProtocolError::UnsupportedVersion { major: other >> 16, minor: other & 0xffff }),
        }
    }

    /// Read the first packet from a client socket.
    pub async fn read<R: AsyncRead + Unpin>(io: &mut R) -> Result<Self, ProtocolError> {
        let len = io.read_i32().await?;
        // The length includes its own four bytes.
        if len < 8 {
            return Err(ProtocolError::BadLength(len));
        }
        let body_len = len as usize - 4;
        if body_len > MAX_STARTUP_LEN {
            return Err(ProtocolError::TooLarge { len: body_len, max: MAX_STARTUP_LEN });
        }
        let mut body = vec![0u8; body_len];
        io.read_exact(&mut body).await?;
        Self::decode(Bytes::from(body))
    }

    pub async fn write<W: AsyncWrite + Unpin>(&self, io: &mut W) -> Result<(), ProtocolError> {
        io.write_all(&self.encode()).await?;
        io.flush().await?;
        Ok(())
    }
}

fn decode_params(body: &[u8]) -> Result<Vec<(String, String)>, ProtocolError> {
    let mut params = Vec::new();
    let mut parts = body.split(|b| *b == 0);
    loop {
        let Some(key) = parts.next() else {
            // A well-formed packet ends with the terminating empty string, so
            // running out of parts means it was truncated.
            return Err(ProtocolError::MalformedStartup("missing terminator"));
        };
        if key.is_empty() {
            break;
        }
        let value = parts.next().ok_or(ProtocolError::MalformedStartup("parameter without a value"))?;
        params.push((
            std::str::from_utf8(key).map_err(|_| ProtocolError::NotUtf8)?.to_string(),
            std::str::from_utf8(value).map_err(|_| ProtocolError::NotUtf8)?.to_string(),
        ));
    }
    Ok(params)
}

/// Any message after the startup exchange.
///
/// One column of a result set, as `RowDescription` carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDescription {
    pub name: String,
    pub type_oid: i32,
    /// Bytes for a fixed-width type, `-1` for a variable-length one.
    pub type_size: i16,
    /// Type-specific detail such as `numeric(10,2)`. `-1` means unspecified,
    /// which every client accepts.
    pub type_modifier: i32,
}

/// The body is kept as raw [`Bytes`] on purpose: in session mode we forward it
/// untouched, and in transaction mode only a handful of tags need inspecting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub tag: u8,
    pub body: Bytes,
}

impl Message {
    pub fn new(tag: u8, body: impl Into<Bytes>) -> Self {
        Self { tag, body: body.into() }
    }

    /// Total wire size including tag and length prefix.
    pub fn wire_len(&self) -> usize {
        1 + 4 + self.body.len()
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.wire_len());
        buf.put_u8(self.tag);
        buf.put_i32((self.body.len() + 4) as i32);
        buf.put_slice(&self.body);
        buf.freeze()
    }

    pub async fn read<R: AsyncRead + Unpin>(io: &mut R) -> Result<Self, ProtocolError> {
        let tag = io.read_u8().await?;
        let len = io.read_i32().await?;
        if len < 4 {
            return Err(ProtocolError::BadLength(len));
        }
        let body_len = len as usize - 4;
        if body_len > MAX_MESSAGE_LEN {
            return Err(ProtocolError::TooLarge { len: body_len, max: MAX_MESSAGE_LEN });
        }
        let mut body = vec![0u8; body_len];
        io.read_exact(&mut body).await?;
        Ok(Message { tag, body: Bytes::from(body) })
    }

    pub async fn write<W: AsyncWrite + Unpin>(&self, io: &mut W) -> Result<(), ProtocolError> {
        io.write_all(&self.encode()).await?;
        io.flush().await?;
        Ok(())
    }

    // --- Backend messages havuz produces itself ---

    pub fn authentication_ok() -> Self {
        let mut body = BytesMut::with_capacity(4);
        body.put_i32(0);
        Message::new(b'R', body.freeze())
    }

    /// `AuthenticationCleartextPassword`.
    ///
    /// Only ever sent on a pool that authenticates per user, where havuz needs
    /// the plaintext to open a backend connection as that client. The handshake
    /// refuses to send it over an unencrypted socket unless that pool has
    /// `allow_password_without_tls` set, because a password on the wire is
    /// worse than no pooler at all.
    pub fn authentication_cleartext() -> Self {
        let mut body = BytesMut::with_capacity(4);
        body.put_i32(3);
        Message::new(b'R', body.freeze())
    }

    /// `AuthenticationSASL` advertising SCRAM-SHA-256.
    pub fn authentication_sasl() -> Self {
        let mut body = BytesMut::new();
        body.put_i32(10);
        body.put_slice(b"SCRAM-SHA-256");
        body.put_u8(0);
        body.put_u8(0); // end of mechanism list
        Message::new(b'R', body.freeze())
    }

    pub fn authentication_sasl_continue(data: &[u8]) -> Self {
        let mut body = BytesMut::new();
        body.put_i32(11);
        body.put_slice(data);
        Message::new(b'R', body.freeze())
    }

    pub fn authentication_sasl_final(data: &[u8]) -> Self {
        let mut body = BytesMut::new();
        body.put_i32(12);
        body.put_slice(data);
        Message::new(b'R', body.freeze())
    }

    pub fn parameter_status(name: &str, value: &str) -> Self {
        let mut body = BytesMut::new();
        body.put_slice(name.as_bytes());
        body.put_u8(0);
        body.put_slice(value.as_bytes());
        body.put_u8(0);
        Message::new(b'S', body.freeze())
    }

    /// Cancellation key handed to the client.
    ///
    /// havuz issues its own key and maps it to the backend's, because the
    /// client may be cancelling a query on a backend it will never see again.
    pub fn backend_key_data(process_id: i32, secret_key: i32) -> Self {
        let mut body = BytesMut::with_capacity(8);
        body.put_i32(process_id);
        body.put_i32(secret_key);
        Message::new(b'K', body.freeze())
    }

    /// `ReadyForQuery`. The status byte is the single most important signal in
    /// the whole protocol for a pooler: `I` means no transaction is open and
    /// the backend can be released.
    pub fn ready_for_query(status: TransactionStatus) -> Self {
        Message::new(b'Z', Bytes::from(vec![status.as_byte()]))
    }

    // --- Result sets ---
    //
    // Nothing on the pooling path builds these: a pooler relays a backend's
    // result rather than composing one. They exist for the JDBC bridge, which
    // has no PostgreSQL on the other side to copy frames from and so has to be
    // a PostgreSQL server rather than a relay.

    /// `RowDescription`.
    ///
    /// Everything except the name and the type OID is optional in practice —
    /// clients use the OID to decode and ignore the rest — but `psql` prints
    /// nothing at all if the field count and the `DataRow` width disagree, so
    /// the two are built from the same slice.
    pub fn row_description(fields: &[FieldDescription]) -> Self {
        let mut body = BytesMut::new();
        body.put_i16(fields.len() as i16);
        for field in fields {
            body.put_slice(field.name.as_bytes());
            body.put_u8(0);
            // Table OID and column number: zero means "not a plain column of a
            // real table", which is the truth for anything coming through a
            // bridge and is what PostgreSQL itself sends for a computed column.
            body.put_i32(0);
            body.put_i16(0);
            body.put_i32(field.type_oid);
            body.put_i16(field.type_size);
            body.put_i32(field.type_modifier);
            body.put_i16(0); // text format
        }
        Message::new(b'T', body.freeze())
    }

    /// `DataRow`. `None` is SQL NULL, which is a length of -1 and no bytes —
    /// distinct from a zero-length value, and conflating the two is the classic
    /// way to turn an empty string into a null halfway down a pipeline.
    pub fn data_row(values: &[Option<Vec<u8>>]) -> Self {
        let mut body = BytesMut::new();
        body.put_i16(values.len() as i16);
        for value in values {
            match value {
                Some(bytes) => {
                    body.put_i32(bytes.len() as i32);
                    body.put_slice(bytes);
                }
                None => body.put_i32(-1),
            }
        }
        Message::new(b'D', body.freeze())
    }

    /// `CommandComplete`, e.g. `SELECT 3` or `INSERT 0 1`.
    pub fn command_complete(tag: &str) -> Self {
        let mut body = BytesMut::with_capacity(tag.len() + 1);
        body.put_slice(tag.as_bytes());
        body.put_u8(0);
        Message::new(b'C', body.freeze())
    }

    /// `EmptyQueryResponse`, for a query that was only whitespace or comments.
    /// Sending `CommandComplete` instead makes some clients report a row count
    /// for a statement that never existed.
    pub fn empty_query_response() -> Self {
        Message::new(b'I', Bytes::new())
    }

    /// `ParameterDescription`. An OID of 0 means "decide for yourself", which
    /// is the honest answer when the driver would not describe the statement.
    pub fn parameter_description(oids: &[i32]) -> Self {
        let mut body = BytesMut::new();
        body.put_i16(oids.len() as i16);
        for oid in oids {
            body.put_i32(*oid);
        }
        Message::new(b't', body.freeze())
    }

    pub fn parse_complete() -> Self {
        Message::new(b'1', Bytes::new())
    }

    pub fn bind_complete() -> Self {
        Message::new(b'2', Bytes::new())
    }

    pub fn close_complete() -> Self {
        Message::new(b'3', Bytes::new())
    }

    /// `NoData`, the answer to describing a statement that returns no rows.
    pub fn no_data() -> Self {
        Message::new(b'n', Bytes::new())
    }

    pub fn error_response(severity: &str, code: &str, message: &str) -> Self {
        let mut body = BytesMut::new();
        for (field, value) in [
            (ErrorField::Severity, severity),
            (ErrorField::SeverityNonLocalized, severity),
            (ErrorField::Code, code),
            (ErrorField::Message, message),
        ] {
            body.put_u8(field as u8);
            body.put_slice(value.as_bytes());
            body.put_u8(0);
        }
        body.put_u8(0);
        Message::new(b'E', body.freeze())
    }

    /// A fatal error that also terminates the connection.
    pub fn fatal(code: &str, message: &str) -> Self {
        Self::error_response("FATAL", code, message)
    }

    pub fn terminate() -> Self {
        Message::new(b'X', Bytes::new())
    }

    /// Parse an `ErrorResponse`/`NoticeResponse` body into its fields.
    pub fn error_fields(&self) -> Vec<(u8, String)> {
        let mut out = Vec::new();
        let mut rest = &self.body[..];
        while let Some(pos) = rest.iter().position(|b| *b == 0) {
            if pos == 0 {
                break;
            }
            let field = rest[0];
            let value = String::from_utf8_lossy(&rest[1..pos]).into_owned();
            out.push((field, value));
            rest = &rest[pos + 1..];
        }
        out
    }

    /// Transaction status carried by a `ReadyForQuery` message.
    pub fn transaction_status(&self) -> Option<TransactionStatus> {
        if self.tag != b'Z' || self.body.len() != 1 {
            return None;
        }
        TransactionStatus::from_byte(self.body[0])
    }
}

/// `ErrorResponse` field identifiers we care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorField {
    Severity = b'S',
    SeverityNonLocalized = b'V',
    Code = b'C',
    Message = b'M',
}

/// The byte in `ReadyForQuery`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatus {
    /// No transaction open — the backend is releasable.
    Idle,
    /// Inside a transaction block.
    InTransaction,
    /// Inside a failed transaction block; the client still owes a rollback.
    Failed,
}

impl TransactionStatus {
    pub fn as_byte(self) -> u8 {
        match self {
            TransactionStatus::Idle => b'I',
            TransactionStatus::InTransaction => b'T',
            TransactionStatus::Failed => b'E',
        }
    }

    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            b'I' => Some(TransactionStatus::Idle),
            b'T' => Some(TransactionStatus::InTransaction),
            b'E' => Some(TransactionStatus::Failed),
            _ => None,
        }
    }

    /// Whether the backend may be handed to another client.
    pub fn is_releasable(self) -> bool {
        matches!(self, TransactionStatus::Idle)
    }
}

/// SQLSTATE codes havuz raises on its own behalf.
pub mod sqlstate {
    pub const INVALID_AUTHORIZATION: &str = "28000";
    pub const INVALID_PASSWORD: &str = "28P01";
    pub const UNDEFINED_DATABASE: &str = "3D000";
    pub const TOO_MANY_CONNECTIONS: &str = "53300";
    pub const CANNOT_CONNECT_NOW: &str = "57P03";
    pub const PROTOCOL_VIOLATION: &str = "08P01";
    pub const ADMIN_SHUTDOWN: &str = "57P01";
    /// Raised when a session parameter the client asked for cannot be applied
    /// to the backend it landed on.
    pub const INVALID_PARAMETER_VALUE: &str = "22023";
    /// What PostgreSQL itself raises for a write in a read-only transaction.
    /// havuz reuses it when refusing a statement that would escape `read_only`.
    pub const READ_ONLY_SQL_TRANSACTION: &str = "25006";
    /// PostgreSQL's own code for ending a session that sat inside an open
    /// transaction. Reused verbatim: it is the same event, and a client that
    /// already handles it from the database should not have to learn a second
    /// spelling because a pooler is in the way.
    pub const IDLE_IN_TRANSACTION_SESSION_TIMEOUT: &str = "25P03";
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn startup(params: &[(&str, &str)]) -> StartupPacket {
        StartupPacket::Startup { params: params.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect() }
    }

    #[tokio::test]
    async fn startup_packet_roundtrip() {
        let packet = startup(&[("user", "svc_orders"), ("database", "app_main"), ("application_name", "psql")]);
        let encoded = packet.encode();

        let mut cursor = Cursor::new(encoded.to_vec());
        let decoded = StartupPacket::read(&mut cursor).await.unwrap();

        assert_eq!(decoded, packet);
        assert_eq!(decoded.user().unwrap(), "svc_orders");
        assert_eq!(decoded.database().unwrap(), "app_main");
        assert_eq!(decoded.application_name(), Some("psql"));
    }

    #[tokio::test]
    async fn database_defaults_to_user_like_postgres_does() {
        // `psql -U svc_orders` sends no database parameter.
        let packet = startup(&[("user", "svc_orders")]);
        assert_eq!(packet.database().unwrap(), "svc_orders");
    }

    #[tokio::test]
    async fn ssl_request_is_recognised() {
        let encoded = StartupPacket::SslRequest.encode();
        assert_eq!(encoded.len(), 8, "SSLRequest is exactly 8 bytes");

        let mut cursor = Cursor::new(encoded.to_vec());
        assert_eq!(StartupPacket::read(&mut cursor).await.unwrap(), StartupPacket::SslRequest);
    }

    #[tokio::test]
    async fn cancel_request_carries_the_key_pair() {
        let packet = StartupPacket::CancelRequest { process_id: 4242, secret_key: -12345 };
        let mut cursor = Cursor::new(packet.encode().to_vec());
        assert_eq!(StartupPacket::read(&mut cursor).await.unwrap(), packet);
    }

    #[tokio::test]
    async fn gssenc_request_is_recognised_so_we_can_refuse_it_politely() {
        let mut cursor = Cursor::new(StartupPacket::GssEncRequest.encode().to_vec());
        assert_eq!(StartupPacket::read(&mut cursor).await.unwrap(), StartupPacket::GssEncRequest);
    }

    #[tokio::test]
    async fn protocol_version_2_is_rejected_with_a_useful_message() {
        let mut body = BytesMut::new();
        body.put_i32(131_072); // 2.0
        let err = StartupPacket::decode(body.freeze()).unwrap_err();
        match err {
            ProtocolError::UnsupportedVersion { major, minor } => {
                assert_eq!((major, minor), (2, 0));
            }
            other => panic!("expected an unsupported version error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn startup_without_a_user_is_rejected() {
        let mut body = BytesMut::new();
        body.put_i32(PROTOCOL_VERSION_3);
        body.put_slice(b"database\0app_main\0\0");
        let err = StartupPacket::decode(body.freeze()).unwrap_err();
        assert!(matches!(err, ProtocolError::MissingParameter("user")));
    }

    #[tokio::test]
    async fn an_absurd_startup_length_is_refused_before_allocating() {
        // 100 MB claimed length. Unauthenticated at this point, so this is the
        // cheapest denial-of-service there is.
        let mut raw = Vec::new();
        raw.extend_from_slice(&100_000_000i32.to_be_bytes());
        let mut cursor = Cursor::new(raw);
        let err = StartupPacket::read(&mut cursor).await.unwrap_err();
        assert!(matches!(err, ProtocolError::TooLarge { max: MAX_STARTUP_LEN, .. }), "got {err:?}");
    }

    #[tokio::test]
    async fn a_length_smaller_than_the_header_is_refused() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&4i32.to_be_bytes());
        let mut cursor = Cursor::new(raw);
        assert!(matches!(StartupPacket::read(&mut cursor).await.unwrap_err(), ProtocolError::BadLength(4)));
    }

    #[tokio::test]
    async fn truncated_parameters_are_rejected_rather_than_silently_accepted() {
        let mut body = BytesMut::new();
        body.put_i32(PROTOCOL_VERSION_3);
        body.put_slice(b"user\0svc\0database"); // no terminator
        assert!(matches!(StartupPacket::decode(body.freeze()).unwrap_err(), ProtocolError::MalformedStartup(_)));
    }

    #[tokio::test]
    async fn message_roundtrip() {
        let msg = Message::new(b'Q', Bytes::from_static(b"SELECT 1\0"));
        let mut cursor = Cursor::new(msg.encode().to_vec());
        let decoded = Message::read(&mut cursor).await.unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(decoded.wire_len(), 1 + 4 + 9);
    }

    #[test]
    fn message_encoding_matches_the_wire_format() {
        let msg = Message::new(b'Q', Bytes::from_static(b"SELECT 1\0"));
        let encoded = msg.encode();
        assert_eq!(encoded[0], b'Q');
        // Length covers itself plus the body, but not the tag.
        assert_eq!(i32::from_be_bytes(encoded[1..5].try_into().unwrap()), 13);
        assert_eq!(&encoded[5..], b"SELECT 1\0");
    }

    #[test]
    fn ready_for_query_carries_the_transaction_status() {
        for status in [TransactionStatus::Idle, TransactionStatus::InTransaction, TransactionStatus::Failed] {
            let msg = Message::ready_for_query(status);
            assert_eq!(msg.tag, b'Z');
            assert_eq!(msg.transaction_status(), Some(status));
        }
    }

    #[test]
    fn only_idle_allows_releasing_the_backend() {
        assert!(TransactionStatus::Idle.is_releasable());
        assert!(!TransactionStatus::InTransaction.is_releasable());
        // A failed transaction still holds locks and awaits a rollback.
        assert!(!TransactionStatus::Failed.is_releasable());
    }

    #[test]
    fn transaction_status_is_only_read_from_ready_for_query() {
        assert_eq!(Message::new(b'Q', Bytes::from_static(b"I")).transaction_status(), None);
        assert_eq!(Message::new(b'Z', Bytes::from_static(b"XY")).transaction_status(), None);
        assert_eq!(Message::new(b'Z', Bytes::from_static(b"?")).transaction_status(), None);
    }

    #[test]
    fn error_response_is_parseable_by_a_real_client() {
        let msg = Message::fatal(sqlstate::INVALID_PASSWORD, "password authentication failed");
        assert_eq!(msg.tag, b'E');

        let fields = msg.error_fields();
        assert_eq!(fields.iter().find(|(f, _)| *f == b'S').unwrap().1, "FATAL");
        assert_eq!(fields.iter().find(|(f, _)| *f == b'C').unwrap().1, "28P01");
        assert_eq!(fields.iter().find(|(f, _)| *f == b'M').unwrap().1, "password authentication failed");
        // The body must be terminated by a zero byte or clients hang.
        assert_eq!(*msg.body.last().unwrap(), 0);
    }

    #[test]
    fn sasl_advertisement_lists_scram_and_terminates_the_list() {
        let msg = Message::authentication_sasl();
        assert_eq!(msg.tag, b'R');
        assert_eq!(i32::from_be_bytes(msg.body[0..4].try_into().unwrap()), 10);
        assert_eq!(&msg.body[4..17], b"SCRAM-SHA-256");
        assert_eq!(&msg.body[17..], &[0, 0], "mechanism string and list both need terminators");
    }

    #[test]
    fn a_result_set_round_trips_through_the_wire_format() {
        let fields = vec![
            FieldDescription { name: "id".into(), type_oid: 23, type_size: 4, type_modifier: -1 },
            FieldDescription { name: "note".into(), type_oid: 25, type_size: -1, type_modifier: -1 },
        ];
        let described = Message::row_description(&fields);
        assert_eq!(described.tag, b'T');
        assert_eq!(i16::from_be_bytes([described.body[0], described.body[1]]), 2);
        assert!(described.body.windows(3).any(|w| w == b"id\0"));

        let row = Message::data_row(&[Some(b"7".to_vec()), None]);
        assert_eq!(row.tag, b'D');
        assert_eq!(i16::from_be_bytes([row.body[0], row.body[1]]), 2);
        // -1 is SQL NULL. A zero length would be an empty string, and turning
        // one into the other is the classic way to lose a null in a pipeline.
        let tail = &row.body[row.body.len() - 4..];
        assert_eq!(i32::from_be_bytes(tail.try_into().unwrap()), -1);
    }

    #[test]
    fn an_empty_value_is_not_the_same_as_a_null() {
        let row = Message::data_row(&[Some(Vec::new())]);
        assert_eq!(i32::from_be_bytes(row.body[2..6].try_into().unwrap()), 0);
    }

    #[test]
    fn command_complete_and_parameter_description_are_nul_and_count_framed() {
        assert_eq!(&Message::command_complete("SELECT 3").body[..], b"SELECT 3\0");

        let params = Message::parameter_description(&[23, 0]);
        assert_eq!(params.tag, b't');
        assert_eq!(i16::from_be_bytes([params.body[0], params.body[1]]), 2);
        assert_eq!(i32::from_be_bytes(params.body[2..6].try_into().unwrap()), 23);
    }

    #[test]
    fn authentication_ok_is_the_zero_subtype() {
        let msg = Message::authentication_ok();
        assert_eq!(msg.tag, b'R');
        assert_eq!(i32::from_be_bytes(msg.body[..].try_into().unwrap()), 0);
    }

    #[test]
    fn backend_key_data_roundtrips_negative_secrets() {
        // Secret keys are signed 32-bit and routinely negative.
        let msg = Message::backend_key_data(4242, -987_654_321);
        assert_eq!(msg.tag, b'K');
        assert_eq!(i32::from_be_bytes(msg.body[0..4].try_into().unwrap()), 4242);
        assert_eq!(i32::from_be_bytes(msg.body[4..8].try_into().unwrap()), -987_654_321);
    }

    #[test]
    fn parameter_status_is_null_terminated_on_both_halves() {
        let msg = Message::parameter_status("server_version", "16.2");
        assert_eq!(msg.tag, b'S');
        // Spelled out byte by byte: `\016` in a literal reads as an octal
        // escape to human eyes even though Rust treats it as NUL + "16".
        assert_eq!(&msg.body[..], [b"server_version".as_slice(), &[0], b"16.2", &[0]].concat().as_slice());
    }

    #[tokio::test]
    async fn oversized_messages_are_refused() {
        let mut raw = vec![b'd'];
        raw.extend_from_slice(&(MAX_MESSAGE_LEN as i32 + 100).to_be_bytes());
        let mut cursor = Cursor::new(raw);
        assert!(matches!(Message::read(&mut cursor).await.unwrap_err(), ProtocolError::TooLarge { .. }));
    }

    #[tokio::test]
    async fn a_stream_of_messages_decodes_in_order() {
        let mut raw = BytesMut::new();
        raw.put_slice(&Message::authentication_ok().encode());
        raw.put_slice(&Message::parameter_status("client_encoding", "UTF8").encode());
        raw.put_slice(&Message::backend_key_data(1, 2).encode());
        raw.put_slice(&Message::ready_for_query(TransactionStatus::Idle).encode());

        let mut cursor = Cursor::new(raw.to_vec());
        let tags: Vec<u8> = {
            let mut tags = Vec::new();
            for _ in 0..4 {
                tags.push(Message::read(&mut cursor).await.unwrap().tag);
            }
            tags
        };
        assert_eq!(tags, vec![b'R', b'S', b'K', b'Z']);
    }
}
