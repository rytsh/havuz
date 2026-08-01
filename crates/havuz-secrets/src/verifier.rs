//! What havuz stores for a client user.
//!
//! This is a credential format, not a protocol, which is why it lives here
//! rather than in a protocol family. havuz authenticates clients against its
//! own user list; the family that later proves the credential over the wire is
//! a separate question, and `havuz-admin` should not have to depend on a wire
//! protocol crate just to hash a password.
//!
//! The encoding is the one PostgreSQL uses in `pg_authid.rolpassword`:
//!
//! ```text
//! SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>
//! ```
//!
//! Keeping that shape means a verifier can be copied in either direction —
//! lifted out of a database into havuz, or pushed the other way — without
//! anyone ever handling the plaintext password.

use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub(crate) const KEY_LEN: usize = 32;
const DEFAULT_ITERATIONS: u32 = 4096;
const SALT_LEN: usize = 16;

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("malformed stored verifier: {0}")]
pub struct VerifierError(pub &'static str);

/// A salted, iterated credential. Never a password.
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

    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// `H(ClientKey)`. The server compares against this; it never learns
    /// `ClientKey` itself, which is what makes the stored form non-replayable.
    pub fn stored_key(&self) -> &[u8; KEY_LEN] {
        &self.stored_key
    }

    /// Signs the server's half of the exchange, so the client can tell a real
    /// server from one that merely stole the verifier.
    pub fn server_key(&self) -> &[u8; KEY_LEN] {
        &self.server_key
    }

    /// Serialise in PostgreSQL's `rolpassword` format.
    pub fn encode(&self) -> String {
        format!(
            "SCRAM-SHA-256${}:{}${}:{}",
            self.iterations,
            B64.encode(&self.salt),
            B64.encode(self.stored_key),
            B64.encode(self.server_key)
        )
    }

    pub fn parse(input: &str) -> Result<Self, VerifierError> {
        let rest = input.strip_prefix("SCRAM-SHA-256$").ok_or(VerifierError("wrong mechanism prefix"))?;
        let (params, keys) = rest.split_once('$').ok_or(VerifierError("missing key section"))?;
        let (iterations, salt) = params.split_once(':').ok_or(VerifierError("missing salt"))?;
        let (stored, server) = keys.split_once(':').ok_or(VerifierError("missing server key"))?;

        let iterations: u32 = iterations.parse().map_err(|_| VerifierError("iteration count"))?;
        if iterations == 0 {
            return Err(VerifierError("iteration count"));
        }
        let salt = B64.decode(salt).map_err(|_| VerifierError("salt encoding"))?;
        let stored_key: [u8; KEY_LEN] = B64
            .decode(stored)
            .map_err(|_| VerifierError("stored key encoding"))?
            .try_into()
            .map_err(|_| VerifierError("stored key length"))?;
        let server_key: [u8; KEY_LEN] = B64
            .decode(server)
            .map_err(|_| VerifierError("server key encoding"))?
            .try_into()
            .map_err(|_| VerifierError("server key length"))?;

        Ok(Self { iterations, salt, stored_key, server_key })
    }
}

/// `SaltedPassword` from RFC 5802.
///
/// Exposed because a protocol family authenticating *outward* — havuz opening a
/// backend connection with the pool's service account — has to derive the same
/// value from a plaintext password it holds, and must derive it identically or
/// the exchange silently fails against a real server.
pub fn salted_password(password: &str, salt: &[u8], iterations: u32) -> [u8; KEY_LEN] {
    hi(normalize(password).as_bytes(), salt, iterations)
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

/// HMAC-SHA-256, exposed so a protocol family can compute the proofs and
/// signatures the exchange needs without reimplementing the primitive.
pub fn hmac(key: &[u8], data: &[u8]) -> [u8; KEY_LEN] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// SASLprep, falling back to the raw value.
///
/// PostgreSQL does the same: a password that cannot be prepared is used
/// verbatim rather than rejected, so existing accounts keep working.
fn normalize(password: &str) -> String {
    stringprep::saslprep(password).map(|c| c.into_owned()).unwrap_or_else(|_| password.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7677 §3 test vector: password "pencil", salt "W22ZaJ0SNY7soEsUEjb6gQ==",
    /// 4096 iterations. Getting this wrong means every stored credential is
    /// subtly incompatible with PostgreSQL's own.
    #[test]
    fn matches_the_rfc_7677_vector() {
        let salt = B64.decode("W22ZaJ0SNY7soEsUEjb6gQ==").unwrap();
        let verifier = ScramVerifier::from_password_with("pencil", &salt, 4096);
        assert_eq!(B64.encode(verifier.stored_key()), "WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=");
        assert_eq!(B64.encode(verifier.server_key()), "wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=");
    }

    #[test]
    fn a_verifier_survives_the_postgres_encoding_round_trip() {
        let verifier = ScramVerifier::from_password("hunter2");
        let encoded = verifier.encode();

        assert!(encoded.starts_with("SCRAM-SHA-256$4096:"), "got {encoded}");
        assert!(!encoded.contains("hunter2"), "a verifier must never contain the password");
        assert_eq!(ScramVerifier::parse(&encoded).expect("our own encoding must parse"), verifier);
    }

    /// The point of keeping PostgreSQL's exact storage format: an operator can
    /// lift a verifier straight out of `pg_authid` and havuz will accept it.
    #[test]
    fn a_verifier_copied_from_postgres_can_be_used_directly() {
        let salt = B64.decode("W22ZaJ0SNY7soEsUEjb6gQ==").unwrap();
        let ours = ScramVerifier::from_password_with("pencil", &salt, 4096);

        let from_pg = "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$\
                       WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:\
                       wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=";
        assert_eq!(ScramVerifier::parse(from_pg).unwrap(), ours);
    }

    #[test]
    fn iteration_count_actually_affects_the_derived_keys() {
        let salt = b"same-salt-here!!";
        let a = ScramVerifier::from_password_with("pencil", salt, 4096);
        let b = ScramVerifier::from_password_with("pencil", salt, 8192);
        assert_ne!(a.stored_key(), b.stored_key());
    }

    #[test]
    fn two_verifiers_for_one_password_differ_because_the_salt_does() {
        // A random salt per user is what stops one rainbow table covering
        // every account in the state file.
        assert_ne!(ScramVerifier::from_password("hunter2"), ScramVerifier::from_password("hunter2"));
    }

    #[test]
    fn malformed_verifiers_are_rejected_rather_than_defaulted() {
        for input in [
            "",
            "MD5$4096:aaaa$bbbb:cccc",
            "SCRAM-SHA-256$4096",
            "SCRAM-SHA-256$4096:aaaa",
            "SCRAM-SHA-256$notanumber:aaaa$bbbb:cccc",
            "SCRAM-SHA-256$0:c2FsdA==$c2hvcnQ=:c2hvcnQ=",
            "SCRAM-SHA-256$4096:!!!$bbbb:cccc",
            "SCRAM-SHA-256$4096:c2FsdA==$too-short:too-short",
        ] {
            assert!(ScramVerifier::parse(input).is_err(), "{input:?} must not parse");
        }
    }

    #[test]
    fn the_debug_rendering_never_leaks_key_material() {
        let verifier = ScramVerifier::from_password("hunter2");
        let rendered = format!("{verifier:?}");
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains(&B64.encode(verifier.stored_key())));
        assert!(!rendered.contains(&B64.encode(verifier.server_key())));
    }
}
