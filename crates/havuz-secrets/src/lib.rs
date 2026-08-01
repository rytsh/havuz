//! Encrypted secret store.
//!
//! Backend service-account passwords are entered in the UI, so they cannot live
//! in an environment variable. They are sealed with AES-256-GCM under a master
//! key supplied through `HAVUZ_MASTER_KEY` and stored alongside the state file.
//!
//! Design rules, in order of importance:
//!
//! 1. The admin API never returns a plaintext secret. [`SecretStore::get`] is
//!    only reachable from the pooler and the control plane.
//! 2. Every secret gets a fresh 96-bit nonce. Nonce reuse under GCM is
//!    catastrophic, so the nonce is generated per `seal` call and never derived
//!    from the secret's name.
//! 3. The key id is stored next to the ciphertext so rotation can tell which
//!    entries still need re-sealing.

mod key;
mod store;
mod verifier;

pub use key::{MasterKey, MasterKeyError};
pub use store::{SealedSecret, SecretRef, SecretStore, StoreError};
pub use verifier::{hmac, salted_password, ScramVerifier, VerifierError};

/// Namespaced handle to a secret, e.g. `pool/app_main/backend_password`.
///
/// Using a structured reference instead of a bare string keeps the state file
/// self-describing and makes orphan detection possible.
pub fn pool_backend_password(pool: &str) -> SecretRef {
    SecretRef::new("pool", pool, "backend_password")
}

/// SCRAM verifier for a havuz client user.
pub fn user_verifier(user: &str) -> SecretRef {
    SecretRef::new("user", user, "scram_verifier")
}
