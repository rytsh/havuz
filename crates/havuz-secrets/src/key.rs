//! Master key handling.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::Engine as _;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum MasterKeyError {
    #[error("HAVUZ_MASTER_KEY is not set")]
    Missing,
    #[error("HAVUZ_MASTER_KEY must be 32 bytes of base64 (got {0} bytes after decoding)")]
    BadLength(usize),
    #[error("HAVUZ_MASTER_KEY is not valid base64: {0}")]
    BadEncoding(String),
    #[error("failed to seal secret")]
    Seal,
    #[error("failed to open secret: wrong master key, or the state file was tampered with")]
    Open,
}

/// AES-256-GCM master key.
///
/// Wiped on drop, and deliberately has no `Display`/`Serialize` so it cannot be
/// logged or accidentally serialised into the state file.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    bytes: [u8; KEY_LEN],
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterKey").field("id", &self.id()).finish_non_exhaustive()
    }
}

impl MasterKey {
    pub const ENV_VAR: &'static str = "HAVUZ_MASTER_KEY";

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self { bytes }
    }

    /// Parse a base64-encoded 32-byte key.
    pub fn from_base64(encoded: &str) -> Result<Self, MasterKeyError> {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .map_err(|e| MasterKeyError::BadEncoding(e.to_string()))?;
        let len = decoded.len();
        let bytes: [u8; KEY_LEN] = decoded.try_into().map_err(|_| MasterKeyError::BadLength(len))?;
        Ok(Self { bytes })
    }

    pub fn from_env() -> Result<Self, MasterKeyError> {
        let raw = std::env::var(Self::ENV_VAR).map_err(|_| MasterKeyError::Missing)?;
        Self::from_base64(&raw)
    }

    /// Generate a fresh key. Used by `havuz keygen` and by tests.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self { bytes }
    }

    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.bytes)
    }

    /// Short, non-reversible fingerprint used to tag ciphertexts.
    ///
    /// Lets rotation find entries sealed under an older key without ever
    /// exposing key material.
    pub fn id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"havuz-master-key-id\0");
        hasher.update(self.bytes);
        let digest = hasher.finalize();
        hex(&digest[..6])
    }

    /// Seal `plaintext`, binding it to `aad` so a ciphertext cannot be moved
    /// from one secret slot to another.
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_LEN]), MasterKeyError> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.bytes));
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), Payload { msg: plaintext, aad })
            .map_err(|_| MasterKeyError::Seal)?;
        Ok((ciphertext, nonce_bytes))
    }

    pub fn open(&self, ciphertext: &[u8], nonce: &[u8; NONCE_LEN], aad: &[u8]) -> Result<Vec<u8>, MasterKeyError> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.bytes));
        cipher.decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad }).map_err(|_| MasterKeyError::Open)
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = MasterKey::generate();
        let (ct, nonce) = key.seal(b"hunter2", b"pool/app_main").unwrap();
        assert_ne!(ct, b"hunter2", "ciphertext must not equal plaintext");
        let pt = key.open(&ct, &nonce, b"pool/app_main").unwrap();
        assert_eq!(pt, b"hunter2");
    }

    #[test]
    fn aad_binds_ciphertext_to_its_slot() {
        let key = MasterKey::generate();
        let (ct, nonce) = key.seal(b"hunter2", b"pool/app_main").unwrap();
        // Moving the blob to another secret slot must fail, not silently decrypt.
        assert!(key.open(&ct, &nonce, b"pool/other").is_err());
    }

    #[test]
    fn wrong_key_fails_closed() {
        let key = MasterKey::generate();
        let other = MasterKey::generate();
        let (ct, nonce) = key.seal(b"hunter2", b"aad").unwrap();
        assert!(other.open(&ct, &nonce, b"aad").is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let key = MasterKey::generate();
        let (mut ct, nonce) = key.seal(b"hunter2", b"aad").unwrap();
        ct[0] ^= 0xff;
        assert!(key.open(&ct, &nonce, b"aad").is_err());
    }

    #[test]
    fn nonce_is_fresh_per_seal() {
        let key = MasterKey::generate();
        let (ct1, n1) = key.seal(b"same", b"aad").unwrap();
        let (ct2, n2) = key.seal(b"same", b"aad").unwrap();
        assert_ne!(n1, n2, "nonce reuse under GCM leaks plaintext");
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn base64_roundtrip_and_validation() {
        let key = MasterKey::generate();
        let encoded = key.to_base64();
        let parsed = MasterKey::from_base64(&encoded).unwrap();
        assert_eq!(parsed.id(), key.id());

        assert!(matches!(MasterKey::from_base64("c2hvcnQ="), Err(MasterKeyError::BadLength(5))));
        assert!(matches!(MasterKey::from_base64("!!!not base64"), Err(MasterKeyError::BadEncoding(_))));
    }

    #[test]
    fn key_id_is_stable_and_not_the_key() {
        let key = MasterKey::generate();
        assert_eq!(key.id(), key.id());
        assert_eq!(key.id().len(), 12);
        assert!(!key.to_base64().contains(&key.id()));
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let key = MasterKey::generate();
        let rendered = format!("{key:?}");
        assert!(!rendered.contains(&key.to_base64()));
        assert!(rendered.contains(&key.id()));
    }
}
