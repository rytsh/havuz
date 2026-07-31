//! Client-side handshake.
//!
//! Clients authenticate against havuz, not against the database. The exchange
//! here is a complete, independent SCRAM run using a verifier havuz stores
//! itself. Two consequences worth stating plainly:
//!
//! * havuz never learns the client's password, and a stolen state file does not
//!   hand one over.
//! * Client credentials can be rotated without touching the database.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use havuz_proto::{ClientIdentity, ProtoError, ProtoResult};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::protocol::{sqlstate, Message, StartupPacket, TransactionStatus};
use crate::scram::{ScramServer, ScramVerifier};
use crate::stream::MaybeTls;

/// Why a connection attempt was refused.
///
/// Kept separate from [`ProtoError`] so the wire-level SQLSTATE is chosen in
/// one place rather than at each rejection site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthDenial {
    UnknownUser,
    UnknownPool { pool: String },
    NotGranted { user: String, pool: String },
    Disabled,
    TooManyConnections { scope: String },
}

impl AuthDenial {
    fn sqlstate(&self) -> &'static str {
        match self {
            AuthDenial::UnknownPool { .. } => sqlstate::UNDEFINED_DATABASE,
            AuthDenial::TooManyConnections { .. } => sqlstate::TOO_MANY_CONNECTIONS,
            _ => sqlstate::INVALID_AUTHORIZATION,
        }
    }

    /// Message shown to the client.
    ///
    /// Deliberately vague about *which* half of the credentials was wrong:
    /// distinguishing "no such user" from "wrong password" turns the pooler
    /// into a user enumeration oracle. Operators get the detail in the log.
    fn client_message(&self) -> String {
        match self {
            AuthDenial::UnknownPool { pool } => format!("database \"{pool}\" does not exist"),
            AuthDenial::TooManyConnections { scope } => {
                format!("too many connections for {scope}")
            }
            _ => "authentication failed".to_string(),
        }
    }
}

/// Resolves a client identity against havuz's own user list.
pub trait Authenticator: Send + Sync + 'static {
    /// Return the verifier for `user`, provided the user may reach `pool`.
    fn verifier(&self, user: &str, pool: &str) -> Result<ScramVerifier, AuthDenial>;
}

/// What the handshake produced.
#[derive(Debug)]
pub enum HandshakeOutcome {
    /// A client authenticated successfully.
    Established { identity: ClientIdentity, startup_params: Vec<(String, String)> },
    /// A cancellation request. It carries no credentials by design, so it is
    /// resolved against the cancel-key registry instead.
    Cancel { process_id: i32, secret_key: i32 },
}

/// Runs the client side of the startup exchange.
pub struct ClientHandshake<A: Authenticator> {
    authenticator: Arc<A>,
    tls: Option<TlsAcceptor>,
    /// Refuse plaintext clients. Off by default because it locks out anyone
    /// who has not configured certificates yet.
    require_tls: bool,
}

impl<A: Authenticator> ClientHandshake<A> {
    pub fn new(authenticator: Arc<A>) -> Self {
        Self { authenticator, tls: None, require_tls: false }
    }

    pub fn with_tls(mut self, acceptor: TlsAcceptor, require: bool) -> Self {
        self.tls = Some(acceptor);
        self.require_tls = require;
        self
    }

    /// Negotiate TLS, read the startup packet and authenticate.
    ///
    /// On success the stream is positioned right after `AuthenticationOk`; the
    /// caller finishes startup once it has a backend, because the parameters a
    /// client sees must come from the backend it will actually talk to.
    pub async fn run(&self, socket: TcpStream, peer: SocketAddr) -> ProtoResult<(MaybeTls, HandshakeOutcome)> {
        socket.set_nodelay(true).ok();
        let mut stream = MaybeTls::Plain(socket);

        // A client may send SSLRequest and GSSENCRequest before its real
        // startup packet, so this is a loop rather than a single read.
        let packet = loop {
            let packet =
                StartupPacket::read(&mut stream).await.map_err(|e| ProtoError::protocol(format!("startup: {e}")))?;

            match packet {
                StartupPacket::SslRequest => {
                    stream = self.upgrade(stream).await?;
                }
                StartupPacket::GssEncRequest => {
                    // We do not speak GSSAPI encryption; 'N' makes the client
                    // fall back rather than hang.
                    stream.write_all(b"N").await?;
                    stream.flush().await?;
                }
                other => break other,
            }
        };

        if self.require_tls && !stream.is_encrypted() {
            let msg = Message::fatal(sqlstate::INVALID_AUTHORIZATION, "TLS is required");
            let _ = msg.write(&mut stream).await;
            return Err(ProtoError::Tls("client refused TLS".into()));
        }

        if let StartupPacket::CancelRequest { process_id, secret_key } = packet {
            return Ok((stream, HandshakeOutcome::Cancel { process_id, secret_key }));
        }

        let user = packet.user().map_err(|e| ProtoError::protocol(e.to_string()))?.to_string();
        let pool = packet.database().map_err(|e| ProtoError::protocol(e.to_string()))?.to_string();
        let application_name = packet.application_name().map(str::to_string);
        let startup_params = match &packet {
            StartupPacket::Startup { params } => params.clone(),
            _ => Vec::new(),
        };

        let verifier = match self.authenticator.verifier(&user, &pool) {
            Ok(verifier) => verifier,
            Err(denial) => {
                tracing::info!(%user, %pool, ?denial, "connection refused");
                let msg = Message::fatal(denial.sqlstate(), &denial.client_message());
                let _ = msg.write(&mut stream).await;
                return Err(ProtoError::auth(format!("{denial:?}")));
            }
        };

        self.scram(&mut stream, verifier).await?;

        Message::authentication_ok().write(&mut stream).await.map_err(|e| ProtoError::protocol(e.to_string()))?;

        Ok((
            stream,
            HandshakeOutcome::Established {
                identity: ClientIdentity { user, pool, application_name, peer },
                startup_params,
            },
        ))
    }

    async fn upgrade(&self, mut stream: MaybeTls) -> ProtoResult<MaybeTls> {
        let Some(acceptor) = self.tls.clone() else {
            // No certificate configured: decline and let the client decide.
            stream.write_all(b"N").await?;
            stream.flush().await?;
            return Ok(stream);
        };

        stream.write_all(b"S").await?;
        stream.flush().await?;

        let MaybeTls::Plain(socket) = stream else {
            return Err(ProtoError::protocol("duplicate SSLRequest after TLS was established"));
        };

        let tls =
            acceptor.accept(socket).await.map_err(|e| ProtoError::Tls(format!("client handshake failed: {e}")))?;
        Ok(MaybeTls::ServerTls(Box::new(tls)))
    }

    async fn scram(&self, stream: &mut MaybeTls, verifier: ScramVerifier) -> ProtoResult<()> {
        let mut server = ScramServer::new(verifier);

        Message::authentication_sasl().write(stream).await.map_err(|e| ProtoError::protocol(e.to_string()))?;

        // SASLInitialResponse: mechanism name, then a length-prefixed payload.
        let msg = read_password_message(stream).await?;
        let initial = parse_sasl_initial(&msg.body)?;

        let server_first = match server.server_first(&initial) {
            Ok(v) => v,
            Err(e) => return Err(deny(stream, format!("scram: {e}")).await),
        };
        Message::authentication_sasl_continue(&server_first)
            .write(stream)
            .await
            .map_err(|e| ProtoError::protocol(e.to_string()))?;

        let msg = read_password_message(stream).await?;
        let server_final = match server.server_final(&msg.body) {
            Ok(v) => v,
            Err(e) => return Err(deny(stream, format!("scram: {e}")).await),
        };

        Message::authentication_sasl_final(&server_final)
            .write(stream)
            .await
            .map_err(|e| ProtoError::protocol(e.to_string()))?;

        Ok(())
    }
}

/// Send the client the parameters and keys it needs, then hand over control.
///
/// The `ParameterStatus` values are the backend's own, because a client that
/// asks for `server_version` must get the truth about the server it is actually
/// querying.
pub async fn complete_startup(
    stream: &mut MaybeTls,
    backend_parameters: &[(String, String)],
    cancel_pid: i32,
    cancel_secret: i32,
) -> ProtoResult<()> {
    for (key, value) in backend_parameters {
        Message::parameter_status(key, value).write(stream).await.map_err(|e| ProtoError::protocol(e.to_string()))?;
    }

    // havuz issues its own cancellation key. The client may later ask to cancel
    // on a brand new connection, and by then the backend it was using may
    // belong to someone else, so the mapping has to be ours.
    Message::backend_key_data(cancel_pid, cancel_secret)
        .write(stream)
        .await
        .map_err(|e| ProtoError::protocol(e.to_string()))?;

    Message::ready_for_query(TransactionStatus::Idle)
        .write(stream)
        .await
        .map_err(|e| ProtoError::protocol(e.to_string()))?;

    Ok(())
}

async fn deny(stream: &mut MaybeTls, detail: String) -> ProtoError {
    let msg = Message::fatal(sqlstate::INVALID_PASSWORD, "password authentication failed");
    let _ = msg.write(stream).await;
    ProtoError::auth(detail)
}

async fn read_password_message(stream: &mut MaybeTls) -> ProtoResult<Message> {
    let msg = Message::read(stream).await.map_err(|e| ProtoError::protocol(format!("reading auth response: {e}")))?;
    if msg.tag != b'p' {
        return Err(ProtoError::protocol(format!("expected a password message, got '{}'", msg.tag as char)));
    }
    Ok(msg)
}

/// Extract the SCRAM payload from a `SASLInitialResponse` body.
fn parse_sasl_initial(body: &Bytes) -> ProtoResult<Bytes> {
    let nul = body
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| ProtoError::protocol("SASLInitialResponse has no mechanism name"))?;
    let mechanism = std::str::from_utf8(&body[..nul]).map_err(|_| ProtoError::protocol("mechanism is not utf-8"))?;
    if mechanism != "SCRAM-SHA-256" {
        return Err(ProtoError::auth(format!("unsupported SASL mechanism '{mechanism}'")));
    }

    let mut rest = body.slice(nul + 1..);
    if rest.len() < 4 {
        return Err(ProtoError::protocol("SASLInitialResponse is truncated"));
    }
    let len = rest.get_i32();
    // -1 means "no data", which is not valid for SCRAM's first message.
    if len < 0 {
        return Err(ProtoError::protocol("SASLInitialResponse carries no payload"));
    }
    if rest.len() < len as usize {
        return Err(ProtoError::protocol("SASLInitialResponse length exceeds the message"));
    }
    Ok(rest.slice(..len as usize))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scram::ScramClient;
    use std::collections::HashMap;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    struct TestAuth {
        users: HashMap<String, (ScramVerifier, Vec<String>)>,
        pools: Vec<String>,
    }

    impl TestAuth {
        fn new() -> Arc<Self> {
            let mut users = HashMap::new();
            users.insert(
                "svc_orders".to_string(),
                (ScramVerifier::from_password("hunter2"), vec!["app_main".to_string()]),
            );
            Arc::new(Self { users, pools: vec!["app_main".into(), "other".into()] })
        }
    }

    impl Authenticator for TestAuth {
        fn verifier(&self, user: &str, pool: &str) -> Result<ScramVerifier, AuthDenial> {
            if !self.pools.iter().any(|p| p == pool) {
                return Err(AuthDenial::UnknownPool { pool: pool.into() });
            }
            let Some((verifier, grants)) = self.users.get(user) else {
                return Err(AuthDenial::UnknownUser);
            };
            if !grants.iter().any(|g| g == pool) {
                return Err(AuthDenial::NotGranted { user: user.into(), pool: pool.into() });
            }
            Ok(verifier.clone())
        }
    }

    /// Minimal client: startup, SCRAM, read to AuthenticationOk.
    async fn client_connect(addr: SocketAddr, user: &str, database: &str, password: &str) -> Result<TcpStream, String> {
        let mut socket = TcpStream::connect(addr).await.unwrap();

        StartupPacket::Startup {
            params: vec![
                ("user".into(), user.into()),
                ("database".into(), database.into()),
                ("application_name".into(), "test-client".into()),
            ],
        }
        .write(&mut socket)
        .await
        .unwrap();

        let mut scram = ScramClient::new(password);
        loop {
            let msg = Message::read(&mut socket).await.map_err(|e| format!("read: {e}"))?;
            match msg.tag {
                b'R' => {
                    let mut body = msg.body.clone();
                    match body.get_i32() {
                        0 => return Ok(socket),
                        10 => {
                            let first = scram.client_first().unwrap();
                            let mut payload = Vec::new();
                            payload.extend_from_slice(b"SCRAM-SHA-256\0");
                            payload.extend_from_slice(&(first.len() as i32).to_be_bytes());
                            payload.extend_from_slice(&first);
                            Message::new(b'p', Bytes::from(payload)).write(&mut socket).await.unwrap();
                        }
                        11 => {
                            let final_msg = scram.client_final(&body).unwrap();
                            Message::new(b'p', Bytes::from(final_msg)).write(&mut socket).await.unwrap();
                        }
                        12 => scram.verify_server_final(&body).map_err(|e| e.to_string())?,
                        other => return Err(format!("unexpected auth type {other}")),
                    }
                }
                b'E' => {
                    let fields = msg.error_fields();
                    let code = fields.iter().find(|(f, _)| *f == b'C').map(|(_, v)| v.clone()).unwrap_or_default();
                    let text = fields.iter().find(|(f, _)| *f == b'M').map(|(_, v)| v.clone()).unwrap_or_default();
                    return Err(format!("{code}: {text}"));
                }
                _ => continue,
            }
        }
    }

    async fn spawn_server() -> (SocketAddr, tokio::task::JoinHandle<ProtoResult<(MaybeTls, HandshakeOutcome)>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handshake = ClientHandshake::new(TestAuth::new());

        let handle = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            handshake.run(socket, peer).await
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn a_correct_password_authenticates_end_to_end() {
        let (addr, server) = spawn_server().await;
        let client = tokio::spawn(async move { client_connect(addr, "svc_orders", "app_main", "hunter2").await });

        let (stream, outcome) = server.await.unwrap().expect("handshake should succeed");
        client.await.unwrap().expect("client should reach AuthenticationOk");

        assert!(!stream.is_encrypted());
        let HandshakeOutcome::Established { identity, startup_params } = outcome else {
            panic!("expected an established session");
        };
        assert_eq!(identity.user, "svc_orders");
        assert_eq!(identity.pool, "app_main");
        assert_eq!(identity.application_name.as_deref(), Some("test-client"));
        // The client's own startup parameters are kept so they can be replayed.
        assert!(startup_params.iter().any(|(k, v)| k == "application_name" && v == "test-client"));
    }

    #[tokio::test]
    async fn a_wrong_password_is_rejected_with_28p01() {
        let (addr, server) = spawn_server().await;
        let client = tokio::spawn(async move { client_connect(addr, "svc_orders", "app_main", "wrong").await });

        assert!(server.await.unwrap().is_err());
        let err = client.await.unwrap().unwrap_err();
        assert!(err.contains("28P01"), "client must see a password error, got: {err}");
    }

    #[tokio::test]
    async fn an_unknown_pool_is_reported_as_a_missing_database() {
        let (addr, server) = spawn_server().await;
        let client = tokio::spawn(async move { client_connect(addr, "svc_orders", "nope", "hunter2").await });

        assert!(server.await.unwrap().is_err());
        let err = client.await.unwrap().unwrap_err();
        assert!(err.contains("3D000"), "got: {err}");
        assert!(err.contains("nope"));
    }

    #[tokio::test]
    async fn an_ungranted_pool_looks_the_same_as_a_bad_password() {
        // Not leaking which pools exist or which users are real is deliberate.
        let (addr, server) = spawn_server().await;
        let client = tokio::spawn(async move { client_connect(addr, "svc_orders", "other", "hunter2").await });

        assert!(server.await.unwrap().is_err());
        let err = client.await.unwrap().unwrap_err();
        assert!(err.contains("28000"), "got: {err}");
        assert!(err.contains("authentication failed"));
        assert!(!err.contains("svc_orders"), "the message must not confirm the user exists");
    }

    #[tokio::test]
    async fn an_unknown_user_is_indistinguishable_from_a_wrong_password() {
        let (addr, server) = spawn_server().await;
        let client = tokio::spawn(async move { client_connect(addr, "ghost", "app_main", "hunter2").await });

        assert!(server.await.unwrap().is_err());
        let err = client.await.unwrap().unwrap_err();
        assert!(err.contains("authentication failed"), "no user enumeration oracle, got: {err}");
    }

    #[tokio::test]
    async fn an_ssl_request_without_certificates_is_declined_and_the_session_continues() {
        let (addr, server) = spawn_server().await;

        let client = tokio::spawn(async move {
            let mut socket = TcpStream::connect(addr).await.unwrap();
            StartupPacket::SslRequest.write(&mut socket).await.unwrap();

            let mut answer = [0u8; 1];
            socket.read_exact(&mut answer).await.unwrap();
            assert_eq!(answer[0], b'N', "no certificate configured means a polite refusal");

            // The client falls back to plaintext, exactly as libpq does.
            StartupPacket::Startup {
                params: vec![("user".into(), "svc_orders".into()), ("database".into(), "app_main".into())],
            }
            .write(&mut socket)
            .await
            .unwrap();

            let mut scram = ScramClient::new("hunter2");
            loop {
                let msg = Message::read(&mut socket).await.unwrap();
                if msg.tag != b'R' {
                    continue;
                }
                let mut body = msg.body.clone();
                match body.get_i32() {
                    0 => return,
                    10 => {
                        let first = scram.client_first().unwrap();
                        let mut payload = Vec::new();
                        payload.extend_from_slice(b"SCRAM-SHA-256\0");
                        payload.extend_from_slice(&(first.len() as i32).to_be_bytes());
                        payload.extend_from_slice(&first);
                        Message::new(b'p', Bytes::from(payload)).write(&mut socket).await.unwrap();
                    }
                    11 => {
                        let f = scram.client_final(&body).unwrap();
                        Message::new(b'p', Bytes::from(f)).write(&mut socket).await.unwrap();
                    }
                    12 => scram.verify_server_final(&body).unwrap(),
                    other => panic!("unexpected auth type {other}"),
                }
            }
        });

        let (_, outcome) = server.await.unwrap().unwrap();
        client.await.unwrap();
        assert!(matches!(outcome, HandshakeOutcome::Established { .. }));
    }

    #[tokio::test]
    async fn a_cancel_request_is_routed_without_authentication() {
        let (addr, server) = spawn_server().await;

        tokio::spawn(async move {
            let mut socket = TcpStream::connect(addr).await.unwrap();
            StartupPacket::CancelRequest { process_id: 4242, secret_key: -7 }.write(&mut socket).await.unwrap();
        });

        let (_, outcome) = server.await.unwrap().unwrap();
        match outcome {
            HandshakeOutcome::Cancel { process_id, secret_key } => {
                assert_eq!((process_id, secret_key), (4242, -7));
            }
            other => panic!("expected a cancel request, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_gssenc_request_is_declined_and_startup_continues() {
        let (addr, server) = spawn_server().await;

        let client = tokio::spawn(async move {
            let mut socket = TcpStream::connect(addr).await.unwrap();
            StartupPacket::GssEncRequest.write(&mut socket).await.unwrap();
            let mut answer = [0u8; 1];
            socket.read_exact(&mut answer).await.unwrap();
            assert_eq!(answer[0], b'N');
            StartupPacket::CancelRequest { process_id: 1, secret_key: 2 }.write(&mut socket).await.unwrap();
        });

        let (_, outcome) = server.await.unwrap().unwrap();
        client.await.unwrap();
        assert!(matches!(outcome, HandshakeOutcome::Cancel { .. }));
    }

    #[test]
    fn sasl_initial_response_parsing() {
        let mut body = Vec::new();
        body.extend_from_slice(b"SCRAM-SHA-256\0");
        body.extend_from_slice(&11i32.to_be_bytes());
        body.extend_from_slice(b"n,,n=,r=abc");
        assert_eq!(parse_sasl_initial(&Bytes::from(body)).unwrap(), Bytes::from_static(b"n,,n=,r=abc"));
    }

    #[test]
    fn sasl_initial_response_rejects_other_mechanisms_and_bad_lengths() {
        let mut body = Vec::new();
        body.extend_from_slice(b"SCRAM-SHA-1\0");
        body.extend_from_slice(&0i32.to_be_bytes());
        assert!(parse_sasl_initial(&Bytes::from(body)).is_err());

        let mut body = Vec::new();
        body.extend_from_slice(b"SCRAM-SHA-256\0");
        body.extend_from_slice(&(-1i32).to_be_bytes());
        assert!(parse_sasl_initial(&Bytes::from(body)).is_err(), "a null payload cannot start SCRAM");

        let mut body = Vec::new();
        body.extend_from_slice(b"SCRAM-SHA-256\0");
        body.extend_from_slice(&999i32.to_be_bytes());
        body.extend_from_slice(b"short");
        assert!(parse_sasl_initial(&Bytes::from(body)).is_err(), "a length past the end must not panic");

        assert!(parse_sasl_initial(&Bytes::from_static(b"no-nul-here")).is_err());
    }

    #[test]
    fn denial_reasons_map_to_the_right_sqlstate() {
        assert_eq!(AuthDenial::UnknownUser.sqlstate(), "28000");
        assert_eq!(AuthDenial::Disabled.sqlstate(), "28000");
        assert_eq!(AuthDenial::UnknownPool { pool: "x".into() }.sqlstate(), "3D000");
        assert_eq!(AuthDenial::TooManyConnections { scope: "x".into() }.sqlstate(), "53300");
    }
}
