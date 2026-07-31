//! SCRAM-SHA-256 (RFC 5802 / RFC 7677) for both directions.
//!
//! havuz needs both halves of this exchange, and for different reasons:
//!
//! * **Server side** — clients authenticate against havuz's own user list. We
//!   store a verifier, never a password, so a stolen state file does not hand
//!   over anyone's credentials.
//! * **Client side** — havuz authenticates to the backend with the pool's
//!   service account.
//!
//! These are deliberately two separate exchanges. SCRAM cannot be proxied: the
//! proof is computed over nonces chosen by both endpoints, and with channel
//! binding it is tied to the TLS session as well. Any pooler that claims
//! pass-through SCRAM is either storing your plaintext password or not doing
//! SCRAM.

use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const KEY_LEN: usize = 32;
const DEFAULT_ITERATIONS: u32 = 4096;
const NONCE_LEN: usize = 18;
const SALT_LEN: usize = 16;

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScramError {
    #[error("malformed SCRAM message: {0}")]
    Malformed(&'static str),
    #[error("unsupported SCRAM feature: {0}")]
    Unsupported(&'static str),
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("server signature did not verify; the backend may be impersonated")]
    BadServerSignature,
    #[error("SCRAM exchange used out of order")]
    OutOfOrder,
    #[error("malformed stored verifier: {0}")]
    BadVerifier(&'static str),
}

/// What havuz stores for a client user.
///
/// Same shape Postgres uses in `pg_authid.rolpassword`, so verifiers can be
/// copied in either direction:
/// `SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>`
#[derive(Clone, PartialEq, Eq)]
pub struct ScramVerifier {
    iterations: u32,
    salt: Vec<u8>,
    stored_key: [u8; KEY_LEN],
    server_key: [u8; KEY_LEN],
}

impl std::fmt::Debug for ScramVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The verifier is not a password, but it is still credential-adjacent
        // and must not end up in a log line.
        f.debug_struct("ScramVerifier").field("iterations", &self.iterations).finish_non_exhaustive()
    }
}

impl ScramVerifier {
    /// Derive a verifier from a plaintext password. Used once, when a user is
    /// created in the UI; the password is not kept afterwards.
    pub fn from_password(password: &str) -> Self {
        let mut salt = vec![0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        Self::from_password_with(password, &salt, DEFAULT_ITERATIONS)
    }

    pub fn from_password_with(password: &str, salt: &[u8], iterations: u32) -> Self {
        let normalized = normalize(password);
        let salted = hi(normalized.as_bytes(), salt, iterations);
        let client_key = hmac(&salted, b"Client Key");
        let stored_key: [u8; KEY_LEN] = Sha256::digest(client_key).into();
        let server_key = hmac(&salted, b"Server Key");

        Self { iterations, salt: salt.to_vec(), stored_key, server_key }
    }

    pub fn iterations(&self) -> u32 {
        self.iterations
    }

    /// Serialise in Postgres' `rolpassword` format.
    pub fn encode(&self) -> String {
        format!(
            "SCRAM-SHA-256${}:{}${}:{}",
            self.iterations,
            B64.encode(&self.salt),
            B64.encode(self.stored_key),
            B64.encode(self.server_key)
        )
    }

    pub fn parse(input: &str) -> Result<Self, ScramError> {
        let rest = input.strip_prefix("SCRAM-SHA-256$").ok_or(ScramError::BadVerifier("wrong mechanism prefix"))?;
        let (params, keys) = rest.split_once('$').ok_or(ScramError::BadVerifier("missing key section"))?;
        let (iterations, salt) = params.split_once(':').ok_or(ScramError::BadVerifier("missing salt"))?;
        let (stored, server) = keys.split_once(':').ok_or(ScramError::BadVerifier("missing server key"))?;

        let iterations: u32 = iterations.parse().map_err(|_| ScramError::BadVerifier("iteration count"))?;
        if iterations == 0 {
            return Err(ScramError::BadVerifier("iteration count"));
        }
        let salt = B64.decode(salt).map_err(|_| ScramError::BadVerifier("salt encoding"))?;
        let stored_key: [u8; KEY_LEN] = B64
            .decode(stored)
            .map_err(|_| ScramError::BadVerifier("stored key encoding"))?
            .try_into()
            .map_err(|_| ScramError::BadVerifier("stored key length"))?;
        let server_key: [u8; KEY_LEN] = B64
            .decode(server)
            .map_err(|_| ScramError::BadVerifier("server key encoding"))?
            .try_into()
            .map_err(|_| ScramError::BadVerifier("server key length"))?;

        Ok(Self { iterations, salt, stored_key, server_key })
    }
}

/// havuz authenticating an incoming client.
#[derive(Debug)]
pub struct ScramServer {
    verifier: ScramVerifier,
    state: ServerState,
}

#[derive(Debug)]
enum ServerState {
    Initial,
    AwaitingFinal { client_first_bare: String, server_first: String, nonce: String },
    Done,
}

impl ScramServer {
    pub fn new(verifier: ScramVerifier) -> Self {
        Self { verifier, state: ServerState::Initial }
    }

    /// Consume `client-first-message`, produce `server-first-message`.
    pub fn server_first(&mut self, client_first: &[u8]) -> Result<Vec<u8>, ScramError> {
        if !matches!(self.state, ServerState::Initial) {
            return Err(ScramError::OutOfOrder);
        }
        let client_first = std::str::from_utf8(client_first).map_err(|_| ScramError::Malformed("not utf-8"))?;

        // gs2-header is one of "n,,", "y,," or "p=<type>,,". We do not implement
        // channel binding, so "p=" must be refused rather than ignored: silently
        // downgrading a client that asked for binding would defeat its purpose.
        let (gs2, bare) = split_gs2(client_first)?;
        if gs2.starts_with("p=") {
            return Err(ScramError::Unsupported("channel binding"));
        }

        let client_nonce = field(bare, 'r').ok_or(ScramError::Malformed("missing client nonce"))?;
        if client_nonce.is_empty() {
            return Err(ScramError::Malformed("empty client nonce"));
        }

        let nonce = format!("{client_nonce}{}", make_nonce());
        let server_first = format!("r={nonce},s={},i={}", B64.encode(&self.verifier.salt), self.verifier.iterations);

        self.state = ServerState::AwaitingFinal {
            client_first_bare: bare.to_string(),
            server_first: server_first.clone(),
            nonce,
        };
        Ok(server_first.into_bytes())
    }

    /// Consume `client-final-message`, produce `server-final-message`.
    pub fn server_final(&mut self, client_final: &[u8]) -> Result<Vec<u8>, ScramError> {
        let ServerState::AwaitingFinal { client_first_bare, server_first, nonce } = &self.state else {
            return Err(ScramError::OutOfOrder);
        };
        let client_final = std::str::from_utf8(client_final).map_err(|_| ScramError::Malformed("not utf-8"))?;

        let received_nonce = field(client_final, 'r').ok_or(ScramError::Malformed("missing nonce"))?;
        // A mismatched nonce means someone spliced two exchanges together.
        if received_nonce != nonce {
            return Err(ScramError::AuthenticationFailed);
        }

        let proof_b64 = field(client_final, 'p').ok_or(ScramError::Malformed("missing proof"))?;
        let proof = B64.decode(proof_b64).map_err(|_| ScramError::Malformed("proof encoding"))?;
        if proof.len() != KEY_LEN {
            return Err(ScramError::Malformed("proof length"));
        }

        let without_proof = client_final
            .rsplit_once(",p=")
            .map(|(head, _)| head)
            .ok_or(ScramError::Malformed("missing proof separator"))?;
        let auth_message = format!("{client_first_bare},{server_first},{without_proof}");

        let client_signature = hmac(&self.verifier.stored_key, auth_message.as_bytes());
        let mut client_key = [0u8; KEY_LEN];
        for i in 0..KEY_LEN {
            client_key[i] = proof[i] ^ client_signature[i];
        }
        let candidate: [u8; KEY_LEN] = Sha256::digest(client_key).into();

        if !constant_time_eq(&candidate, &self.verifier.stored_key) {
            return Err(ScramError::AuthenticationFailed);
        }

        let server_signature = hmac(&self.verifier.server_key, auth_message.as_bytes());
        self.state = ServerState::Done;
        Ok(format!("v={}", B64.encode(server_signature)).into_bytes())
    }

    pub fn is_done(&self) -> bool {
        matches!(self.state, ServerState::Done)
    }
}

/// havuz authenticating to a backend.
#[derive(Debug)]
pub struct ScramClient {
    password: String,
    state: ClientState,
}

#[derive(Debug)]
enum ClientState {
    Initial,
    AwaitingServerFirst { client_first_bare: String, client_nonce: String },
    AwaitingServerFinal { server_signature: [u8; KEY_LEN] },
    Done,
}

impl ScramClient {
    pub fn new(password: impl Into<String>) -> Self {
        Self { password: password.into(), state: ClientState::Initial }
    }

    /// Produce `client-first-message`.
    ///
    /// The username field is left empty, matching what Postgres itself sends:
    /// the real user name travelled in the startup packet and SCRAM's `n=` is
    /// redundant here.
    pub fn client_first(&mut self) -> Result<Vec<u8>, ScramError> {
        if !matches!(self.state, ClientState::Initial) {
            return Err(ScramError::OutOfOrder);
        }
        let client_nonce = make_nonce();
        let bare = format!("n=,r={client_nonce}");
        self.state = ClientState::AwaitingServerFirst { client_first_bare: bare.clone(), client_nonce };
        Ok(format!("n,,{bare}").into_bytes())
    }

    /// Consume `server-first-message`, produce `client-final-message`.
    pub fn client_final(&mut self, server_first: &[u8]) -> Result<Vec<u8>, ScramError> {
        let ClientState::AwaitingServerFirst { client_first_bare, client_nonce } = &self.state else {
            return Err(ScramError::OutOfOrder);
        };
        let server_first = std::str::from_utf8(server_first).map_err(|_| ScramError::Malformed("not utf-8"))?;

        let nonce = field(server_first, 'r').ok_or(ScramError::Malformed("missing nonce"))?;
        // The server must extend our nonce, not replace it. This is what stops
        // an attacker from replaying a captured server-first.
        if !nonce.starts_with(client_nonce.as_str()) || nonce.len() == client_nonce.len() {
            return Err(ScramError::Malformed("server nonce does not extend the client nonce"));
        }

        let salt = B64
            .decode(field(server_first, 's').ok_or(ScramError::Malformed("missing salt"))?)
            .map_err(|_| ScramError::Malformed("salt encoding"))?;
        let iterations: u32 = field(server_first, 'i')
            .ok_or(ScramError::Malformed("missing iteration count"))?
            .parse()
            .map_err(|_| ScramError::Malformed("iteration count"))?;
        if iterations == 0 {
            return Err(ScramError::Malformed("iteration count"));
        }

        let salted = hi(normalize(&self.password).as_bytes(), &salt, iterations);
        let client_key = hmac(&salted, b"Client Key");
        let stored_key: [u8; KEY_LEN] = Sha256::digest(client_key).into();

        // "biws" is base64("n,,"), the gs2-header we sent.
        let without_proof = format!("c=biws,r={nonce}");
        let auth_message = format!("{client_first_bare},{server_first},{without_proof}");

        let client_signature = hmac(&stored_key, auth_message.as_bytes());
        let mut proof = [0u8; KEY_LEN];
        for i in 0..KEY_LEN {
            proof[i] = client_key[i] ^ client_signature[i];
        }

        let server_key = hmac(&salted, b"Server Key");
        let server_signature = hmac(&server_key, auth_message.as_bytes());

        self.state = ClientState::AwaitingServerFinal { server_signature };
        Ok(format!("{without_proof},p={}", B64.encode(proof)).into_bytes())
    }

    /// Verify `server-final-message`.
    ///
    /// Skipping this step is a real vulnerability: it is the only thing proving
    /// the backend also knows the password, rather than being an impostor that
    /// accepted whatever we sent.
    pub fn verify_server_final(&mut self, server_final: &[u8]) -> Result<(), ScramError> {
        let ClientState::AwaitingServerFinal { server_signature } = &self.state else {
            return Err(ScramError::OutOfOrder);
        };
        let server_final = std::str::from_utf8(server_final).map_err(|_| ScramError::Malformed("not utf-8"))?;

        if let Some(err) = field(server_final, 'e') {
            tracing::debug!(error = %err, "backend rejected SCRAM authentication");
            return Err(ScramError::AuthenticationFailed);
        }

        let received = B64
            .decode(field(server_final, 'v').ok_or(ScramError::Malformed("missing server signature"))?)
            .map_err(|_| ScramError::Malformed("server signature encoding"))?;

        if received.len() != KEY_LEN || !constant_time_eq(&received, server_signature) {
            return Err(ScramError::BadServerSignature);
        }
        self.state = ClientState::Done;
        Ok(())
    }

    pub fn is_done(&self) -> bool {
        matches!(self.state, ClientState::Done)
    }
}

/// `Hi()` from RFC 5802: PBKDF2-HMAC-SHA256 with a one-block output.
fn hi(password: &[u8], salt: &[u8], iterations: u32) -> [u8; KEY_LEN] {
    let mut salted = [0u8; KEY_LEN];

    let mut block = Vec::with_capacity(salt.len() + 4);
    block.extend_from_slice(salt);
    block.extend_from_slice(&1u32.to_be_bytes());

    let mut u = hmac(password, &block);
    salted.copy_from_slice(&u);

    for _ in 1..iterations {
        u = hmac(password, &u);
        for i in 0..KEY_LEN {
            salted[i] ^= u[i];
        }
    }
    salted
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; KEY_LEN] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// SASLprep, falling back to the raw value.
///
/// Postgres does the same: a password that cannot be prepared is used verbatim
/// rather than rejected, so existing accounts keep working.
fn normalize(password: &str) -> String {
    stringprep::saslprep(password).map(|c| c.into_owned()).unwrap_or_else(|_| password.to_string())
}

fn make_nonce() -> String {
    // Printable ASCII excluding ',' which is the field separator.
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char).collect()
}

/// Split `gs2-header` from `client-first-message-bare`.
fn split_gs2(message: &str) -> Result<(&str, &str), ScramError> {
    // The header is "<cbind>,<authzid>," — two commas before the bare part.
    let first = message.find(',').ok_or(ScramError::Malformed("missing gs2 header"))?;
    let second = message[first + 1..].find(',').ok_or(ScramError::Malformed("missing gs2 header"))? + first + 1;
    Ok((&message[..first], &message[second + 1..]))
}

/// Extract a `key=value` attribute.
fn field(message: &str, key: char) -> Option<&str> {
    message.split(',').find_map(|part| {
        let mut chars = part.chars();
        (chars.next() == Some(key) && chars.next() == Some('=')).then(|| &part[2..])
    })
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive a complete exchange between our client and our server.
    fn handshake(server_password: &str, client_password: &str) -> Result<(), ScramError> {
        let verifier = ScramVerifier::from_password(server_password);
        let mut server = ScramServer::new(verifier);
        let mut client = ScramClient::new(client_password);

        let client_first = client.client_first().unwrap();
        let server_first = server.server_first(&client_first)?;
        let client_final = client.client_final(&server_first)?;
        let server_final = server.server_final(&client_final)?;
        client.verify_server_final(&server_final)?;

        assert!(server.is_done());
        assert!(client.is_done());
        Ok(())
    }

    #[test]
    fn a_matching_password_authenticates() {
        handshake("hunter2", "hunter2").expect("correct password must authenticate");
    }

    #[test]
    fn a_wrong_password_is_rejected() {
        assert_eq!(handshake("hunter2", "hunter3").unwrap_err(), ScramError::AuthenticationFailed);
    }

    #[test]
    fn an_empty_password_still_produces_a_working_exchange() {
        handshake("", "").unwrap();
        assert_eq!(handshake("", "x").unwrap_err(), ScramError::AuthenticationFailed);
    }

    #[test]
    fn unicode_passwords_are_normalized_consistently() {
        handshake("parolam-ğüşiöç", "parolam-ğüşiöç").unwrap();
    }

    #[test]
    fn known_answer_test_against_rfc_7677() {
        // RFC 7677 section 3 worked example, which pins our Hi/HMAC/key
        // derivation against an external source rather than against ourselves.
        let salt = B64.decode("W22ZaJ0SNY7soEsUEjb6gQ==").unwrap();
        let verifier = ScramVerifier::from_password_with("pencil", &salt, 4096);

        assert_eq!(B64.encode(verifier.stored_key), "WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=");
        assert_eq!(B64.encode(verifier.server_key), "wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=");
    }

    #[test]
    fn verifier_uses_the_postgres_storage_format() {
        let verifier = ScramVerifier::from_password("hunter2");
        let encoded = verifier.encode();

        assert!(encoded.starts_with("SCRAM-SHA-256$4096:"), "got {encoded}");
        assert!(!encoded.contains("hunter2"), "a verifier must never contain the password");

        let parsed = ScramVerifier::parse(&encoded).unwrap();
        assert_eq!(parsed, verifier, "roundtrip must be lossless");
    }

    #[test]
    fn a_verifier_copied_from_postgres_can_be_used_directly() {
        let salt = B64.decode("W22ZaJ0SNY7soEsUEjb6gQ==").unwrap();
        let ours = ScramVerifier::from_password_with("pencil", &salt, 4096);

        // The exact string Postgres would store in pg_authid.rolpassword.
        let from_pg = "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$\
                       WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:\
                       wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=";
        assert_eq!(ScramVerifier::parse(from_pg).unwrap(), ours);
    }

    #[test]
    fn malformed_verifiers_are_rejected_with_a_reason() {
        for bad in [
            "MD5$4096:aaaa$bbbb:cccc",
            "SCRAM-SHA-256$4096",
            "SCRAM-SHA-256$4096:aaaa",
            "SCRAM-SHA-256$notanumber:aaaa$bbbb:cccc",
            "SCRAM-SHA-256$0:aaaa$bbbb:cccc",
            "SCRAM-SHA-256$4096:!!!$bbbb:cccc",
        ] {
            assert!(ScramVerifier::parse(bad).is_err(), "should have rejected {bad}");
        }
    }

    #[test]
    fn debug_output_does_not_leak_key_material() {
        let verifier = ScramVerifier::from_password("hunter2");
        let rendered = format!("{verifier:?}");
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains(&B64.encode(verifier.stored_key)));
    }

    #[test]
    fn channel_binding_is_refused_rather_than_silently_downgraded() {
        let mut server = ScramServer::new(ScramVerifier::from_password("hunter2"));
        let err = server.server_first(b"p=tls-server-end-point,,n=,r=abcdefgh").unwrap_err();
        assert_eq!(err, ScramError::Unsupported("channel binding"));
    }

    #[test]
    fn a_client_that_could_have_used_binding_is_still_accepted() {
        // "y,," means the client supports binding but thinks the server does
        // not. That is exactly our situation and must work.
        let mut server = ScramServer::new(ScramVerifier::from_password("hunter2"));
        assert!(server.server_first(b"y,,n=,r=abcdefgh").is_ok());
    }

    #[test]
    fn a_spliced_nonce_is_rejected() {
        let verifier = ScramVerifier::from_password("hunter2");
        let mut server = ScramServer::new(verifier);
        let mut client = ScramClient::new("hunter2");

        let client_first = client.client_first().unwrap();
        let server_first = server.server_first(&client_first).unwrap();
        let client_final = client.client_final(&server_first).unwrap();

        // Tamper with the nonce the client echoes back.
        let tampered = String::from_utf8(client_final).unwrap().replace("r=", "r=X");
        assert_eq!(server.server_final(tampered.as_bytes()).unwrap_err(), ScramError::AuthenticationFailed);
    }

    #[test]
    fn client_rejects_a_server_that_does_not_extend_its_nonce() {
        let mut client = ScramClient::new("hunter2");
        client.client_first().unwrap();
        // Server invents a completely fresh nonce, as a replayed message would.
        let err = client.client_final(b"r=totallydifferent,s=c2FsdA==,i=4096").unwrap_err();
        assert!(matches!(err, ScramError::Malformed(_)), "got {err:?}");
    }

    #[test]
    fn client_rejects_a_forged_server_signature() {
        let verifier = ScramVerifier::from_password("hunter2");
        let mut server = ScramServer::new(verifier);
        let mut client = ScramClient::new("hunter2");

        let client_first = client.client_first().unwrap();
        let server_first = server.server_first(&client_first).unwrap();
        let client_final = client.client_final(&server_first).unwrap();
        let _ = server.server_final(&client_final).unwrap();

        // An impostor backend that accepted our proof without knowing the
        // password cannot produce a valid server signature.
        let forged = format!("v={}", B64.encode([0u8; KEY_LEN]));
        assert_eq!(client.verify_server_final(forged.as_bytes()).unwrap_err(), ScramError::BadServerSignature);
    }

    #[test]
    fn client_surfaces_a_server_side_error_message() {
        // A backend that rejects us replies with `e=<reason>` instead of `v=`.
        let mut client = ScramClient::new("hunter2");
        client.state = ClientState::AwaitingServerFinal { server_signature: [0u8; KEY_LEN] };
        assert_eq!(client.verify_server_final(b"e=invalid-proof").unwrap_err(), ScramError::AuthenticationFailed);
    }

    #[test]
    fn steps_cannot_be_run_out_of_order() {
        let mut server = ScramServer::new(ScramVerifier::from_password("hunter2"));
        assert_eq!(server.server_final(b"anything").unwrap_err(), ScramError::OutOfOrder);

        let mut client = ScramClient::new("hunter2");
        assert_eq!(client.client_final(b"anything").unwrap_err(), ScramError::OutOfOrder);
        assert_eq!(client.verify_server_final(b"anything").unwrap_err(), ScramError::OutOfOrder);
    }

    #[test]
    fn malformed_client_messages_are_rejected() {
        let mut server = ScramServer::new(ScramVerifier::from_password("hunter2"));
        assert!(server.server_first(b"no-commas-here").is_err());

        let mut server = ScramServer::new(ScramVerifier::from_password("hunter2"));
        assert!(server.server_first(b"n,,n=,").is_err(), "empty nonce must be refused");
    }

    #[test]
    fn nonces_are_unique_and_comma_free() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let nonce = make_nonce();
            assert_eq!(nonce.len(), NONCE_LEN);
            assert!(!nonce.contains(','), "a comma would break field parsing");
            assert!(seen.insert(nonce), "nonces must not repeat");
        }
    }

    #[test]
    fn field_parsing_handles_values_containing_equals() {
        // Base64 payloads end in '=' padding, so the parser must only split on
        // the first character pair.
        assert_eq!(field("r=abc,s=c2FsdA==,i=4096", 's'), Some("c2FsdA=="));
        assert_eq!(field("r=abc,s=c2FsdA==,i=4096", 'i'), Some("4096"));
        assert_eq!(field("r=abc", 'z'), None);
    }

    #[test]
    fn gs2_header_is_split_correctly() {
        assert_eq!(split_gs2("n,,n=,r=abc").unwrap(), ("n", "n=,r=abc"));
        assert_eq!(split_gs2("y,,n=,r=abc").unwrap(), ("y", "n=,r=abc"));
        assert_eq!(split_gs2("n,a=admin,n=,r=abc").unwrap(), ("n", "n=,r=abc"));
        assert!(split_gs2("nocommas").is_err());
    }

    #[test]
    fn constant_time_comparison_is_length_safe() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn iteration_count_actually_affects_the_derived_keys() {
        let salt = b"same-salt-here!!";
        let a = ScramVerifier::from_password_with("pencil", salt, 4096);
        let b = ScramVerifier::from_password_with("pencil", salt, 8192);
        assert_ne!(a.stored_key, b.stored_key);
    }

    #[test]
    fn different_salts_produce_different_verifiers_for_the_same_password() {
        let a = ScramVerifier::from_password("hunter2");
        let b = ScramVerifier::from_password("hunter2");
        assert_ne!(a, b, "a random salt per user is what stops rainbow tables");
    }
}
