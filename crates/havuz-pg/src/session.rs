//! Client-side handshake.
//!
//! Clients authenticate against havuz, not against the database. The default
//! exchange is a complete, independent SCRAM run using a verifier havuz stores
//! itself. Two consequences worth stating plainly:
//!
//! * havuz never learns the client's password, and a stolen state file does not
//!   hand one over.
//! * Client credentials can be rotated without touching the database.
//!
//! ## The exception, and why it is shaped like this
//!
//! A pool configured for per-user backend authentication needs the client's
//! plaintext password, because that is what it will authenticate to PostgreSQL
//! with — SCRAM cannot be proxied, so there is no way to reuse the client's
//! proof. Such a pool asks for `AuthenticationCleartextPassword` instead.
//!
//! Two properties are preserved even then:
//!
//! * **The password does not travel in the clear.** A cleartext request on an
//!   unencrypted socket is refused outright, whatever `require_tls` says. This
//!   is the default and the only part of the handshake an operator can turn
//!   off — `allow_password_without_tls` on the pool — because the link havuz
//!   runs over is not always havuz's to judge. What is at stake is worth being
//!   plain about: this password opens the database, so leaking it does not give
//!   an eavesdropper a session through havuz, it gives them the database.
//! * **The stored verifier is still checked.** Not configurable at all.
//!   Skipping it would turn havuz into a credential-stuffing proxy pointed at
//!   the database, and would leave `disabled`, `read_only` and the pool grants
//!   with nothing to hang off.
//!
//! What havuz still does not do is *store* the password. It is held for the
//! life of the session, handed to the connector, and gone when the last client
//! of that user disconnects.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use havuz_proto::{ClientIdentity, PoolRoute, ProtoError, ProtoResult};
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

/// How a client should prove who it is, and what havuz needs out of it.
#[derive(Debug, Clone)]
pub struct ClientAuth {
    pub verifier: ScramVerifier,
    /// The pool opens backend connections as this client, so the handshake
    /// must come away holding the plaintext password.
    pub needs_plaintext: bool,
    /// The pool has been told it may ask for that password on an unencrypted
    /// socket. Only consulted when `needs_plaintext` is set; the SCRAM path
    /// never learns a password and so has nothing to expose.
    pub allow_without_tls: bool,
}

/// Resolves a client identity against havuz's own user list.
pub trait Authenticator: Send + Sync + 'static {
    /// Return the auth policy for `user`, provided the user may reach `pool`.
    fn resolve(&self, user: &str, pool: &str) -> Result<ClientAuth, AuthDenial>;
}

/// A client's database password, held only for the life of its session.
///
/// Never serialised, never logged, and never placed in [`ClientIdentity`] —
/// that type is shared with every family and its whole point is that clients
/// and backends do not learn each other's credentials.
#[derive(Clone)]
pub struct BackendCredential(String);

impl BackendCredential {
    /// Only for tests: a real one can only come from a client handshake.
    #[doc(hidden)]
    pub fn for_test(password: &str) -> Self {
        Self(password.to_string())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    /// A stable, non-reversible tag for "is this the same password as before".
    ///
    /// Used to notice that a user rotated their password and that the
    /// connections opened with the old one have to go, without keeping a
    /// second copy of the password around to compare against.
    pub fn fingerprint(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"havuz-backend-credential-v1");
        hasher.update(self.0.as_bytes());
        hasher.finalize().into()
    }
}

impl std::fmt::Debug for BackendCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BackendCredential(<redacted>)")
    }
}

impl Drop for BackendCredential {
    fn drop(&mut self) {
        // Best effort: `String` may have reallocated, so this is a courtesy
        // rather than a guarantee. The guarantee is that it is never persisted.
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

/// What the handshake produced.
#[derive(Debug)]
pub enum HandshakeOutcome {
    /// A client authenticated successfully.
    Established {
        identity: ClientIdentity,
        startup_params: Vec<(String, String)>,
        /// Present only for pools that authenticate per user.
        credential: Option<BackendCredential>,
    },
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
    pub async fn run(
        &self,
        socket: TcpStream,
        peer: SocketAddr,
        pool: &str,
    ) -> ProtoResult<(MaybeTls, HandshakeOutcome)> {
        self.run_for_pool(socket, peer, &PoolRoute::new(vec![pool.to_string()])).await
    }

    /// Negotiate, authenticate, and resolve which of the listener's pools the
    /// client asked for.
    pub async fn run_for_pool(
        &self,
        socket: TcpStream,
        peer: SocketAddr,
        route: &PoolRoute,
    ) -> ProtoResult<(MaybeTls, HandshakeOutcome)> {
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
        let pool = match route.sole() {
            // One pool on this port: the database field carries no routing
            // information, so a connection string may omit it entirely.
            Some(only) => only.to_string(),
            None => {
                let asked = packet.database().map_err(|e| ProtoError::protocol(e.to_string()))?;
                match route.resolve(asked) {
                    // The name the client sent and the pool it reached are not
                    // necessarily the same string: an alias exists so that a
                    // connection string can keep naming the database while the
                    // pool is called something an operator chose.
                    Some(pool) => pool.to_string(),
                    None => {
                        // Not "database does not exist": the pool may well
                        // exist, just on another port, and saying so sends an
                        // operator looking in the right place. Aliases are
                        // listed too, or a refusal reads as if the alias had
                        // never been applied.
                        let text = format!(
                            "no pool named \"{asked}\" on this port; available here: {}",
                            route.reachable().join(", ")
                        );
                        let _ = Message::fatal(sqlstate::UNDEFINED_DATABASE, &text).write(&mut stream).await;
                        return Err(ProtoError::NoRoute(asked.to_string()));
                    }
                }
            }
        };
        let application_name = packet.application_name().map(str::to_string);
        let startup_params = match &packet {
            StartupPacket::Startup { params } => params.clone(),
            _ => Vec::new(),
        };

        let auth = match self.authenticator.resolve(&user, &pool) {
            Ok(auth) => auth,
            Err(denial) => {
                tracing::info!(%user, %pool, ?denial, "connection refused");
                let msg = Message::fatal(denial.sqlstate(), &denial.client_message());
                let _ = msg.write(&mut stream).await;
                return Err(ProtoError::auth(format!("{denial:?}")));
            }
        };

        let credential = if auth.needs_plaintext {
            // Asking for a password on a plaintext socket hands it to anyone on
            // the path, and the whole point of this pool is that the password
            // also opens the database. Refused by default; an operator who
            // knows something about the link that havuz cannot see may say so
            // per pool, and then gets told about it every single time.
            if !stream.is_encrypted() {
                if !auth.allow_without_tls {
                    let text = format!(
                        "pool \"{pool}\" authenticates against the database as you, so it needs your password \
                         and will only ask for it over TLS; connect with sslmode=require or higher"
                    );
                    let _ = Message::fatal(sqlstate::INVALID_AUTHORIZATION, &text).write(&mut stream).await;
                    return Err(ProtoError::Tls(format!("pool '{pool}' requires TLS for per-user authentication")));
                }
                tracing::warn!(
                    %user,
                    %pool,
                    %peer,
                    "asking for a database password on an unencrypted socket because \
                     allow_password_without_tls is set on this pool; anyone on the path can read it \
                     and use it against the database directly"
                );
            }
            Some(self.cleartext(&mut stream, &auth.verifier, &user, &pool).await?)
        } else {
            self.scram(&mut stream, auth.verifier).await?;
            None
        };

        Message::authentication_ok().write(&mut stream).await.map_err(|e| ProtoError::protocol(e.to_string()))?;

        Ok((
            stream,
            HandshakeOutcome::Established {
                identity: ClientIdentity { user, pool, application_name, peer },
                startup_params,
                credential,
            },
        ))
    }

    /// Ask for the password itself, and check it against the stored verifier.
    ///
    /// Verifying locally first means a wrong password is refused by havuz and
    /// never reaches the database, so a pool in this mode cannot be used to
    /// brute-force database roles.
    async fn cleartext(
        &self,
        stream: &mut MaybeTls,
        verifier: &ScramVerifier,
        user: &str,
        pool: &str,
    ) -> ProtoResult<BackendCredential> {
        Message::authentication_cleartext().write(stream).await.map_err(|e| ProtoError::protocol(e.to_string()))?;

        let msg = read_password_message(stream).await?;
        // The payload is a NUL-terminated string; some clients omit the NUL.
        let end = msg.body.iter().position(|byte| *byte == 0).unwrap_or(msg.body.len());
        let password = std::str::from_utf8(&msg.body[..end])
            .map_err(|_| ProtoError::auth("password is not valid utf-8"))?
            .to_string();

        // Recomputing with the stored salt and iteration count is the only way
        // to check a plaintext against a verifier, and it is the same work the
        // SCRAM path does.
        let candidate = ScramVerifier::from_password_with(&password, verifier.salt(), verifier.iterations());
        if candidate.stored_key() != verifier.stored_key() {
            tracing::info!(%user, %pool, "connection refused: password does not match the stored verifier");
            let denial = AuthDenial::UnknownUser;
            let _ = Message::fatal(denial.sqlstate(), &denial.client_message()).write(stream).await;
            return Err(ProtoError::auth("password did not verify"));
        }

        Ok(BackendCredential(password))
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

    #[derive(Clone)]
    struct TestAuth {
        users: HashMap<String, (ScramVerifier, Vec<String>)>,
        pools: Vec<String>,
        per_user: bool,
        allow_without_tls: bool,
    }

    impl TestAuth {
        fn new() -> Arc<Self> {
            let mut users = HashMap::new();
            users.insert(
                "svc_orders".to_string(),
                (ScramVerifier::from_password("hunter2"), vec!["app_main".to_string()]),
            );
            Arc::new(Self {
                users,
                pools: vec!["app_main".into(), "other".into()],
                per_user: false,
                allow_without_tls: false,
            })
        }

        /// A pool that authenticates clients against the database as
        /// themselves, and so must ask for the password itself.
        fn per_user() -> Arc<Self> {
            let mut auth = (*Self::new()).clone();
            auth.per_user = true;
            Arc::new(auth)
        }

        /// The same, with the operator having accepted that the password may
        /// cross an unencrypted socket.
        fn per_user_without_tls() -> Arc<Self> {
            let mut auth = (*Self::per_user()).clone();
            auth.allow_without_tls = true;
            Arc::new(auth)
        }
    }

    impl Authenticator for TestAuth {
        fn resolve(&self, user: &str, pool: &str) -> Result<ClientAuth, AuthDenial> {
            if !self.pools.iter().any(|p| p == pool) {
                return Err(AuthDenial::UnknownPool { pool: pool.into() });
            }
            let Some((verifier, grants)) = self.users.get(user) else {
                return Err(AuthDenial::UnknownUser);
            };
            if !grants.iter().any(|g| g == pool) {
                return Err(AuthDenial::NotGranted { user: user.into(), pool: pool.into() });
            }
            Ok(ClientAuth {
                verifier: verifier.clone(),
                needs_plaintext: self.per_user,
                allow_without_tls: self.allow_without_tls,
            })
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
                        // AuthenticationCleartextPassword.
                        3 => {
                            let mut payload = password.as_bytes().to_vec();
                            payload.push(0);
                            Message::new(b'p', Bytes::from(payload)).write(&mut socket).await.unwrap();
                        }
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

    /// A port shared by two pools, so the startup packet's database field is
    /// what selects between them.
    async fn spawn_server() -> (SocketAddr, tokio::task::JoinHandle<ProtoResult<(MaybeTls, HandshakeOutcome)>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handshake = ClientHandshake::new(TestAuth::new());
        let route = PoolRoute::new(vec!["app_main".to_string(), "other".to_string()]);

        let handle = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            handshake.run_for_pool(socket, peer, &route).await
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
        let HandshakeOutcome::Established { identity, startup_params, .. } = outcome else {
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

    /// The same shared port, but `app_main` also answers to `orders`.
    async fn spawn_aliased_server() -> (SocketAddr, tokio::task::JoinHandle<ProtoResult<(MaybeTls, HandshakeOutcome)>>)
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handshake = ClientHandshake::new(TestAuth::new());
        let route = PoolRoute::with_aliases(
            vec!["app_main".to_string(), "other".to_string()],
            vec![("orders".to_string(), "app_main".to_string())],
        );

        let handle = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            handshake.run_for_pool(socket, peer, &route).await
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn a_client_naming_an_alias_lands_on_the_pool_behind_it() {
        // What the client writes and what the pool is called are allowed to
        // differ; everything downstream sees the pool.
        let (addr, server) = spawn_aliased_server().await;
        let client = tokio::spawn(async move { client_connect(addr, "svc_orders", "orders", "hunter2").await });

        let (_, outcome) = server.await.unwrap().expect("the alias must resolve");
        client.await.unwrap().expect("client should reach AuthenticationOk");

        let HandshakeOutcome::Established { identity, .. } = outcome else {
            panic!("expected an established session");
        };
        assert_eq!(identity.pool, "app_main", "authorisation and pooling both key on the pool, not the alias");
    }

    #[tokio::test]
    async fn a_refusal_lists_the_aliases_too() {
        // Otherwise the message reads as if the alias had never been applied,
        // and an operator goes looking for a bug that is not there.
        let (addr, server) = spawn_aliased_server().await;
        let client = tokio::spawn(async move { client_connect(addr, "svc_orders", "payroll", "hunter2").await });

        assert!(server.await.unwrap().is_err());
        let err = client.await.unwrap().unwrap_err();
        assert!(err.contains("3D000"), "got: {err}");
        assert!(err.contains("orders"), "the alias belongs in the list of what is reachable: {err}");
        assert!(err.contains("app_main"), "and so does the pool it points at: {err}");
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
    async fn a_port_with_one_pool_ignores_the_startup_database() {
        // The whole convenience of a per-pool port: the connection string does
        // not have to repeat what the port already says.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handshake = ClientHandshake::new(TestAuth::new());
        let server = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            handshake.run(socket, peer, "app_main").await
        });

        let client = tokio::spawn(async move { client_connect(addr, "svc_orders", "anything", "hunter2").await });
        let (_, outcome) = server.await.unwrap().expect("the port decides, so this must authenticate");
        client.await.unwrap().expect("client must reach AuthenticationOk");
        let HandshakeOutcome::Established { identity, .. } = outcome else {
            panic!("expected an established session");
        };
        assert_eq!(identity.pool, "app_main");
    }

    const TEST_CERT: &str = include_str!("../tests/fixtures/test-cert.pem");
    const TEST_KEY: &str = include_str!("../tests/fixtures/test-key.pem");

    /// A listener that can actually negotiate TLS, so the per-user tests
    /// exercise the real encrypted path rather than a flag that says they did.
    fn tls_acceptor() -> (TlsAcceptor, tempfile::TempDir) {
        havuz_core::tls::install_default_provider();
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        std::fs::write(&cert, TEST_CERT).unwrap();
        std::fs::write(&key, TEST_KEY).unwrap();
        let config = havuz_core::tls::server_config(&cert, &key).expect("test certificate must load");
        (TlsAcceptor::from(config), dir)
    }

    async fn spawn_per_user_server(
        with_tls: bool,
    ) -> (SocketAddr, tokio::task::JoinHandle<ProtoResult<(MaybeTls, HandshakeOutcome)>>) {
        spawn_per_user_server_as(TestAuth::per_user(), with_tls).await
    }

    async fn spawn_per_user_server_as(
        auth: Arc<TestAuth>,
        with_tls: bool,
    ) -> (SocketAddr, tokio::task::JoinHandle<ProtoResult<(MaybeTls, HandshakeOutcome)>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handshake = ClientHandshake::new(auth);
        // The directory has to outlive the acceptor's construction only; rustls
        // has parsed the material by then.
        let (handshake, _material) = match with_tls {
            true => {
                let (acceptor, dir) = tls_acceptor();
                (handshake.with_tls(acceptor, false), Some(dir))
            }
            false => (handshake, None),
        };

        let handle = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            handshake.run(socket, peer, "app_main").await
        });
        (addr, handle)
    }

    /// Startup over TLS: SSLRequest, then the same exchange inside the tunnel.
    async fn client_connect_tls(addr: SocketAddr, user: &str, password: &str) -> Result<(), String> {
        let mut socket = TcpStream::connect(addr).await.unwrap();
        StartupPacket::SslRequest.write(&mut socket).await.unwrap();

        let mut answer = [0u8; 1];
        tokio::io::AsyncReadExt::read_exact(&mut socket, &mut answer).await.unwrap();
        if answer[0] != b'S' {
            return Err("server declined TLS".into());
        }

        // `require` semantics: encrypt, do not authenticate. Enough for a test
        // certificate that nothing has ever heard of.
        let config = havuz_core::tls::client_config(havuz_core::SslMode::Require, None).unwrap().unwrap();
        let connector = tokio_rustls::TlsConnector::from(config);
        let name = rustls_pki_types::ServerName::try_from("havuz-test").unwrap();
        let mut stream = MaybeTls::ClientTls(Box::new(connector.connect(name, socket).await.unwrap()));

        StartupPacket::Startup { params: vec![("user".into(), user.into()), ("database".into(), "app_main".into())] }
            .write(&mut stream)
            .await
            .unwrap();

        loop {
            let msg = Message::read(&mut stream).await.map_err(|e| format!("read: {e}"))?;
            match msg.tag {
                b'R' => {
                    let mut body = msg.body.clone();
                    match body.get_i32() {
                        0 => return Ok(()),
                        3 => {
                            let mut payload = password.as_bytes().to_vec();
                            payload.push(0);
                            Message::new(b'p', Bytes::from(payload)).write(&mut stream).await.unwrap();
                        }
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

    #[tokio::test]
    async fn a_per_user_pool_asks_for_the_password_and_hands_it_back() {
        let (addr, server) = spawn_per_user_server(true).await;
        let client = tokio::spawn(async move { client_connect_tls(addr, "svc_orders", "hunter2").await });

        let (_, outcome) = server.await.unwrap().expect("the password must verify");
        client.await.unwrap().expect("client must reach AuthenticationOk");

        let HandshakeOutcome::Established { credential, .. } = outcome else {
            panic!("expected an established session");
        };
        let credential = credential.expect("a per-user pool must come away holding the password");
        assert_eq!(credential.expose(), "hunter2", "this is what opens the backend connection");
    }

    #[tokio::test]
    async fn a_per_user_pool_refuses_to_ask_for_a_password_in_the_clear() {
        // The default, and checked before the request is sent: a password on an
        // unencrypted socket is worse than no pooler at all.
        let (addr, server) = spawn_per_user_server(false).await;
        let client = tokio::spawn(async move { client_connect(addr, "svc_orders", "app_main", "hunter2").await });

        let err = server.await.unwrap().unwrap_err();
        assert!(matches!(err, ProtoError::Tls(_)), "got {err:?}");
        let client_error = client.await.unwrap().unwrap_err();
        assert!(client_error.contains("TLS"), "the client must be told why: {client_error}");
    }

    #[tokio::test]
    async fn a_pool_may_be_told_to_ask_in_the_clear_anyway() {
        // The escape hatch for links havuz cannot see the safety of. It changes
        // nothing else: the verifier is still checked, and the handshake still
        // comes away holding the password, because that is what opens the
        // backend connection.
        let (addr, server) = spawn_per_user_server_as(TestAuth::per_user_without_tls(), false).await;
        let client = tokio::spawn(async move { client_connect(addr, "svc_orders", "app_main", "hunter2").await });

        let (stream, outcome) = server.await.unwrap().expect("the pool opted into this");
        client.await.unwrap().expect("client must reach AuthenticationOk");

        assert!(!stream.is_encrypted(), "the whole point is that this socket is plaintext");
        let HandshakeOutcome::Established { credential, .. } = outcome else {
            panic!("expected an established session");
        };
        assert_eq!(credential.expect("still needed to open the backend").expose(), "hunter2");
    }

    #[tokio::test]
    async fn opting_out_of_tls_does_not_opt_out_of_the_verifier() {
        // The two are separate promises. Skipping the verifier would make the
        // pool a credential-stuffing proxy pointed at the database, which no
        // amount of operator consent makes reasonable.
        let (addr, server) = spawn_per_user_server_as(TestAuth::per_user_without_tls(), false).await;
        let client = tokio::spawn(async move { client_connect(addr, "svc_orders", "app_main", "wrong").await });

        assert!(server.await.unwrap().is_err());
        let err = client.await.unwrap().unwrap_err();
        assert!(err.contains("28000"), "got: {err}");
    }

    #[tokio::test]
    async fn a_wrong_password_never_reaches_the_database() {
        // havuz checks the plaintext against its own verifier first, so a pool
        // in this mode cannot be used to brute-force database roles.
        let (addr, server) = spawn_per_user_server(true).await;
        let client = tokio::spawn(async move { client_connect_tls(addr, "svc_orders", "wrong").await });

        assert!(server.await.unwrap().is_err());
        let err = client.await.unwrap().unwrap_err();
        assert!(err.contains("28000"), "got: {err}");
    }

    #[tokio::test]
    async fn a_shared_pool_still_runs_scram_and_learns_no_password() {
        let (addr, server) = spawn_server().await;
        let client = tokio::spawn(async move { client_connect(addr, "svc_orders", "app_main", "hunter2").await });

        let (_, outcome) = server.await.unwrap().expect("handshake should succeed");
        client.await.unwrap().unwrap();
        let HandshakeOutcome::Established { credential, .. } = outcome else {
            panic!("expected an established session");
        };
        assert!(credential.is_none(), "the default path must not come away holding a password");
    }

    #[test]
    fn a_credential_never_renders_itself() {
        let credential = BackendCredential("hunter2".into());
        assert!(!format!("{credential:?}").contains("hunter2"));
    }

    #[test]
    fn the_fingerprint_tracks_the_password_and_not_the_user() {
        let a = BackendCredential("hunter2".into());
        let b = BackendCredential("hunter2".into());
        let rotated = BackendCredential("hunter3".into());
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_ne!(a.fingerprint(), rotated.fingerprint(), "a rotation must invalidate the old connections");
    }

    #[tokio::test]
    async fn a_shared_port_names_the_pools_it_actually_serves() {
        // "database does not exist" would send an operator to the wrong place:
        // the pool may exist, just on another port.
        let (addr, server) = spawn_server().await;
        let client = tokio::spawn(async move { client_connect(addr, "svc_orders", "payroll", "hunter2").await });

        assert!(server.await.unwrap().is_err());
        let err = client.await.unwrap().unwrap_err();
        assert!(err.contains("app_main"), "the error must list what is reachable here, got: {err}");
        assert!(err.contains("other"), "got: {err}");
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
