//! Query cancellation.
//!
//! Cancellation in Postgres does not travel on the connection being cancelled.
//! The client opens a *second* connection and sends a `CancelRequest` carrying
//! the `(process_id, secret_key)` pair it was handed at startup.
//!
//! For a pooler this is genuinely awkward, and getting it wrong is one of the
//! quieter ways to break a deployment: `Ctrl-C` in `psql` stops working,
//! statement timeouts on the client side stop taking effect, and runaway
//! queries keep burning database CPU. Nobody notices until production.
//!
//! havuz issues its own key pair to each client and keeps a mapping to the real
//! backend. The client's key must be ours, because by the time a cancellation
//! arrives the backend it refers to may already belong to somebody else — in
//! which case the right answer is to do nothing rather than cancel an innocent
//! third party's query.

use std::collections::HashMap;
use std::sync::{Mutex, RwLock};
use std::time::Duration;

use rand::Rng;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::protocol::StartupPacket;

/// Where a cancellation should actually be delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelTarget {
    pub host: String,
    pub port: u16,
    pub backend_pid: i32,
    pub backend_secret: i32,
}

/// The key pair havuz hands to a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CancelKey {
    pub process_id: i32,
    pub secret_key: i32,
}

/// Maps havuz-issued keys to backend keys.
#[derive(Debug, Default)]
pub struct CancelRegistry {
    entries: RwLock<HashMap<CancelKey, CancelTarget>>,
    next_id: Mutex<i32>,
}

impl CancelRegistry {
    pub fn new() -> Self {
        Self { entries: RwLock::new(HashMap::new()), next_id: Mutex::new(1) }
    }

    /// Issue a fresh key for a client session.
    ///
    /// The process id is a counter so it stays readable in logs; the secret is
    /// random, because it is the only thing standing between an attacker and
    /// the ability to cancel other people's queries.
    pub fn register(&self, target: CancelTarget) -> CancelKey {
        let process_id = {
            let mut next = self.next_id.lock().expect("cancel id counter poisoned");
            let id = *next;
            *next = next.wrapping_add(1).max(1);
            id
        };
        let key = CancelKey { process_id, secret_key: rand::thread_rng().gen() };
        self.entries.write().expect("cancel registry poisoned").insert(key, target);
        key
    }

    pub fn unregister(&self, key: CancelKey) {
        self.entries.write().expect("cancel registry poisoned").remove(&key);
    }

    pub fn lookup(&self, key: CancelKey) -> Option<CancelTarget> {
        self.entries.read().expect("cancel registry poisoned").get(&key).cloned()
    }

    pub fn len(&self) -> usize {
        self.entries.read().expect("cancel registry poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Deliver a cancellation to the backend.
///
/// Postgres never answers a `CancelRequest`; it closes the socket whether or
/// not anything was cancelled. So this is best-effort by construction, and a
/// timeout is applied so a hung backend cannot tie up the caller.
pub async fn deliver(target: &CancelTarget, timeout: Duration) -> std::io::Result<()> {
    let connect = TcpStream::connect((target.host.as_str(), target.port));
    let mut socket = tokio::time::timeout(timeout, connect)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "cancel connect timed out"))??;

    let packet = StartupPacket::CancelRequest { process_id: target.backend_pid, secret_key: target.backend_secret };
    socket.write_all(&packet.encode()).await?;
    socket.flush().await?;
    let _ = socket.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    fn target() -> CancelTarget {
        CancelTarget { host: "pg".into(), port: 5432, backend_pid: 9001, backend_secret: -42 }
    }

    #[test]
    fn a_registered_key_resolves_to_its_backend() {
        let registry = CancelRegistry::new();
        let key = registry.register(target());
        assert_eq!(registry.lookup(key), Some(target()));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn the_key_handed_to_the_client_is_never_the_backend_key() {
        // If we passed the backend's key through, any client could cancel any
        // query on that backend, including one belonging to another tenant.
        let registry = CancelRegistry::new();
        let key = registry.register(target());
        assert_ne!(key.secret_key, -42, "the secret must be ours, not the backend's");
        assert_ne!(key.process_id, 9001);
    }

    #[test]
    fn secrets_are_unpredictable_and_keys_are_unique() {
        let registry = CancelRegistry::new();
        let mut secrets = std::collections::HashSet::new();
        let mut pids = std::collections::HashSet::new();
        for _ in 0..500 {
            let key = registry.register(target());
            secrets.insert(key.secret_key);
            pids.insert(key.process_id);
        }
        assert_eq!(pids.len(), 500, "process ids must not collide");
        assert!(secrets.len() > 495, "secrets must be random, got {} distinct", secrets.len());
    }

    #[test]
    fn an_unknown_key_resolves_to_nothing_rather_than_a_guess() {
        let registry = CancelRegistry::new();
        registry.register(target());
        // A stale or forged key must cancel nothing at all.
        assert_eq!(registry.lookup(CancelKey { process_id: 12345, secret_key: 678 }), None);
    }

    #[test]
    fn unregistering_prevents_cancelling_a_reassigned_backend() {
        let registry = CancelRegistry::new();
        let key = registry.register(target());
        registry.unregister(key);
        assert_eq!(registry.lookup(key), None, "a finished session must not remain cancellable");
        assert!(registry.is_empty());
    }

    #[tokio::test]
    async fn delivery_sends_the_backend_key_pair_verbatim() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 16];
            socket.read_exact(&mut buf).await.unwrap();
            buf
        });

        let target =
            CancelTarget { host: addr.ip().to_string(), port: addr.port(), backend_pid: 9001, backend_secret: -42 };
        deliver(&target, Duration::from_secs(2)).await.unwrap();

        let buf = server.await.unwrap();
        assert_eq!(i32::from_be_bytes(buf[0..4].try_into().unwrap()), 16);
        assert_eq!(i32::from_be_bytes(buf[4..8].try_into().unwrap()), 80_877_102);
        assert_eq!(i32::from_be_bytes(buf[8..12].try_into().unwrap()), 9001);
        assert_eq!(i32::from_be_bytes(buf[12..16].try_into().unwrap()), -42, "negative secrets must survive");
    }

    #[tokio::test]
    async fn delivery_to_a_dead_backend_fails_quickly_instead_of_hanging() {
        let target = CancelTarget { host: "127.0.0.1".into(), port: 1, backend_pid: 1, backend_secret: 2 };
        assert!(deliver(&target, Duration::from_millis(500)).await.is_err());
    }
}
