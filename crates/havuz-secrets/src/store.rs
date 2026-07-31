//! The secret store itself.
//!
//! Sealed entries are plain serialisable data so they can be embedded directly
//! in the state file that `havuz-core` writes atomically. This crate does no
//! file IO of its own — it owns the crypto, not the persistence.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::key::{MasterKey, MasterKeyError, NONCE_LEN};

/// Namespaced pointer to a secret: `kind/owner/field`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SecretRef {
    kind: String,
    owner: String,
    field: String,
}

impl SecretRef {
    pub fn new(kind: impl Into<String>, owner: impl Into<String>, field: impl Into<String>) -> Self {
        Self { kind: kind.into(), owner: owner.into(), field: field.into() }
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn field(&self) -> &str {
        &self.field
    }

    /// Canonical string form. Doubles as the AEAD associated data, which is why
    /// it must be stable and unambiguous.
    pub fn as_key(&self) -> String {
        format!("{}/{}/{}", self.kind, self.owner, self.field)
    }
}

impl std::fmt::Display for SecretRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_key())
    }
}

impl From<SecretRef> for String {
    fn from(value: SecretRef) -> Self {
        value.as_key()
    }
}

impl TryFrom<String> for SecretRef {
    type Error = StoreError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut parts = value.splitn(3, '/');
        match (parts.next(), parts.next(), parts.next()) {
            (Some(kind), Some(owner), Some(field)) if !kind.is_empty() && !owner.is_empty() && !field.is_empty() => {
                Ok(Self::new(kind, owner, field))
            }
            _ => Err(StoreError::MalformedRef(value)),
        }
    }
}

/// An encrypted secret as it appears on disk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedSecret {
    /// Fingerprint of the master key used, so rotation can find stale entries.
    pub key_id: String,
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("secret '{0}' not found")]
    NotFound(String),
    #[error("malformed secret reference '{0}', expected kind/owner/field")]
    MalformedRef(String),
    #[error("secret '{r}' has a {len}-byte nonce, expected {NONCE_LEN}")]
    BadNonce { r: String, len: usize },
    #[error("secret '{r}' is not valid UTF-8")]
    NotUtf8 { r: String },
    #[error(transparent)]
    Key(#[from] MasterKeyError),
}

/// In-memory map of sealed secrets.
///
/// Cloning is cheap enough at our scale (tens of pools) and keeps the calling
/// code free of lifetimes.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretStore {
    entries: BTreeMap<SecretRef, SealedSecret>,
}

impl SecretStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, r: &SecretRef) -> bool {
        self.entries.contains_key(r)
    }

    pub fn refs(&self) -> impl Iterator<Item = &SecretRef> {
        self.entries.keys()
    }

    /// Seal and store a secret, replacing any previous value.
    pub fn put(&mut self, key: &MasterKey, r: SecretRef, plaintext: &str) -> Result<(), StoreError> {
        let aad = r.as_key();
        let (ciphertext, nonce) = key.seal(plaintext.as_bytes(), aad.as_bytes())?;
        self.entries.insert(r, SealedSecret { key_id: key.id(), nonce: nonce.to_vec(), ciphertext });
        Ok(())
    }

    /// Open a secret.
    ///
    /// Intentionally not reachable from the admin API: the HTTP layer only ever
    /// sees [`SecretStore::contains`].
    pub fn get(&self, key: &MasterKey, r: &SecretRef) -> Result<String, StoreError> {
        let sealed = self.entries.get(r).ok_or_else(|| StoreError::NotFound(r.as_key()))?;
        let nonce: [u8; NONCE_LEN] = sealed
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::BadNonce { r: r.as_key(), len: sealed.nonce.len() })?;
        let plaintext = key.open(&sealed.ciphertext, &nonce, r.as_key().as_bytes())?;
        String::from_utf8(plaintext).map_err(|_| StoreError::NotUtf8 { r: r.as_key() })
    }

    pub fn remove(&mut self, r: &SecretRef) -> bool {
        self.entries.remove(r).is_some()
    }

    /// Drop secrets whose owner is no longer referenced by the configuration.
    ///
    /// Called after a pool or user is deleted so the state file does not
    /// accumulate unreachable ciphertext.
    pub fn retain_owners(&mut self, kind: &str, live_owners: &[String]) -> usize {
        let before = self.entries.len();
        self.entries.retain(|r, _| r.kind != kind || live_owners.iter().any(|o| o == &r.owner));
        before - self.entries.len()
    }

    /// Re-seal every entry under a new master key.
    ///
    /// Returns the number of entries rotated. Fails atomically: if any entry
    /// cannot be opened with `old`, the store is left untouched.
    pub fn rotate(&mut self, old: &MasterKey, new: &MasterKey) -> Result<usize, StoreError> {
        let mut rotated = BTreeMap::new();
        for (r, _) in self.entries.iter() {
            let plaintext = self.get(old, r)?;
            let aad = r.as_key();
            let (ciphertext, nonce) = new.seal(plaintext.as_bytes(), aad.as_bytes())?;
            rotated.insert(r.clone(), SealedSecret { key_id: new.id(), nonce: nonce.to_vec(), ciphertext });
        }
        let count = rotated.len();
        self.entries = rotated;
        Ok(count)
    }

    /// Entries not sealed under `key`. A non-empty result means rotation was
    /// interrupted or the operator swapped keys without rotating.
    pub fn stale_refs(&self, key: &MasterKey) -> Vec<&SecretRef> {
        let id = key.id();
        self.entries.iter().filter(|(_, s)| s.key_id != id).map(|(r, _)| r).collect()
    }
}

mod b64 {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(owner: &str) -> SecretRef {
        SecretRef::new("pool", owner, "backend_password")
    }

    #[test]
    fn put_then_get() {
        let key = MasterKey::generate();
        let mut store = SecretStore::new();
        store.put(&key, r("app_main"), "hunter2").unwrap();
        assert_eq!(store.get(&key, &r("app_main")).unwrap(), "hunter2");
    }

    #[test]
    fn missing_secret_is_an_error_not_a_default() {
        let key = MasterKey::generate();
        let store = SecretStore::new();
        assert!(matches!(store.get(&key, &r("nope")), Err(StoreError::NotFound(_))));
    }

    #[test]
    fn ciphertext_is_bound_to_its_ref() {
        let key = MasterKey::generate();
        let mut store = SecretStore::new();
        store.put(&key, r("app_main"), "hunter2").unwrap();

        // Swap the sealed blob into a different slot; AAD must reject it.
        let stolen = store.entries.get(&r("app_main")).unwrap().clone();
        store.entries.insert(r("other"), stolen);
        assert!(store.get(&key, &r("other")).is_err(), "a blob must not decrypt under a different ref");
    }

    #[test]
    fn serde_roundtrip_survives_the_state_file() {
        let key = MasterKey::generate();
        let mut store = SecretStore::new();
        store.put(&key, r("app_main"), "hunter2").unwrap();
        store.put(&key, SecretRef::new("user", "svc_orders", "scram_verifier"), "verifier-blob").unwrap();

        let json = serde_json::to_string(&store).unwrap();
        assert!(!json.contains("hunter2"), "plaintext must never reach the state file");
        assert!(json.contains("pool/app_main/backend_password"), "refs are human readable keys");

        let restored: SecretStore = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.get(&key, &r("app_main")).unwrap(), "hunter2");
        assert_eq!(restored.len(), 2);
    }

    #[test]
    fn rotation_reseals_everything_and_marks_nothing_stale() {
        let old = MasterKey::generate();
        let new = MasterKey::generate();
        let mut store = SecretStore::new();
        store.put(&old, r("a"), "one").unwrap();
        store.put(&old, r("b"), "two").unwrap();

        assert_eq!(store.stale_refs(&new).len(), 2);
        assert_eq!(store.rotate(&old, &new).unwrap(), 2);
        assert!(store.stale_refs(&new).is_empty());

        assert_eq!(store.get(&new, &r("a")).unwrap(), "one");
        assert_eq!(store.get(&new, &r("b")).unwrap(), "two");
        assert!(store.get(&old, &r("a")).is_err(), "old key must stop working after rotation");
    }

    #[test]
    fn rotation_with_wrong_old_key_leaves_store_untouched() {
        let old = MasterKey::generate();
        let wrong = MasterKey::generate();
        let new = MasterKey::generate();
        let mut store = SecretStore::new();
        store.put(&old, r("a"), "one").unwrap();

        assert!(store.rotate(&wrong, &new).is_err());
        assert_eq!(store.get(&old, &r("a")).unwrap(), "one", "failed rotation must not corrupt the store");
    }

    #[test]
    fn retain_owners_drops_orphans() {
        let key = MasterKey::generate();
        let mut store = SecretStore::new();
        store.put(&key, r("live"), "x").unwrap();
        store.put(&key, r("deleted"), "y").unwrap();
        store.put(&key, SecretRef::new("user", "svc", "scram_verifier"), "z").unwrap();

        let removed = store.retain_owners("pool", &["live".to_string()]);
        assert_eq!(removed, 1);
        assert!(store.contains(&r("live")));
        assert!(!store.contains(&r("deleted")));
        assert!(store.contains(&SecretRef::new("user", "svc", "scram_verifier")), "other kinds are untouched");
    }

    #[test]
    fn secret_ref_parsing() {
        assert_eq!(
            SecretRef::try_from("pool/app_main/backend_password".to_string()).unwrap(),
            SecretRef::new("pool", "app_main", "backend_password")
        );
        // Owners may contain slashes only in the trailing field position.
        assert_eq!(SecretRef::try_from("user/svc/a/b".to_string()).unwrap().field(), "a/b");
        assert!(SecretRef::try_from("too/short".to_string()).is_err());
        assert!(SecretRef::try_from("//".to_string()).is_err());
    }
}
