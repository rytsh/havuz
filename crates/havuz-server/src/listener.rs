//! Accept loops.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use havuz_pg::PgFamily;
use havuz_proto::ProtocolFamily;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::shutdown::Shutdown;

/// Serve the admin API until shutdown.
pub fn spawn_admin(addr: SocketAddr, router: axum_router::Router, shutdown: Shutdown) -> JoinHandle<()> {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(e) => {
                tracing::error!(%addr, error = %e, "cannot bind the admin listener");
                shutdown.trigger();
                return;
            }
        };
        tracing::info!(%addr, "admin api listening");

        let result =
            axum_router::serve(listener, router).with_graceful_shutdown(async move { shutdown.notified().await }).await;

        if let Err(e) = result {
            tracing::error!(error = %e, "admin api stopped");
        }
    })
}

/// Serve the pooler until shutdown.
///
/// Note what is *not* here: no per-connection thread, no unbounded task growth.
/// The global client cap is enforced at accept time so a connection storm
/// cannot exhaust file descriptors before per-pool limits get a say.
pub fn spawn_pooler(addr: SocketAddr, family: Arc<PgFamily>, max_clients: u32, shutdown: Shutdown) -> JoinHandle<()> {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(e) => {
                tracing::error!(%addr, error = %e, "cannot bind the pooler listener");
                shutdown.trigger();
                return;
            }
        };
        tracing::info!(%addr, max_clients, "pooler listening");

        let live = Arc::new(AtomicU64::new(0));

        loop {
            let accepted = tokio::select! {
                result = listener.accept() => result,
                _ = shutdown.notified() => {
                    tracing::info!("no longer accepting connections");
                    break;
                }
            };

            let (socket, peer) = match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    // Running out of file descriptors is transient under load;
                    // a tight retry loop here would make it much worse.
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };

            if live.load(Ordering::Relaxed) >= max_clients as u64 {
                tracing::warn!(%peer, max_clients, "refusing connection, global client limit reached");
                drop(socket);
                continue;
            }

            live.fetch_add(1, Ordering::Relaxed);
            let family = family.clone();
            let live = live.clone();

            tokio::spawn(async move {
                match family.serve(socket, peer).await {
                    Ok(outcome) if outcome.authenticated => {
                        tracing::debug!(
                            %peer,
                            to_client = outcome.bytes_to_client,
                            to_backend = outcome.bytes_to_backend,
                            "session ended"
                        );
                    }
                    Ok(_) => {}
                    Err(e) => tracing::debug!(%peer, error = %e, kind = e.kind(), "session failed"),
                }
                live.fetch_sub(1, Ordering::Relaxed);
            });
        }

        // Give in-flight sessions a moment to finish before the process exits.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while live.load(Ordering::Relaxed) > 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let remaining = live.load(Ordering::Relaxed);
        if remaining > 0 {
            tracing::warn!(remaining, "closing with sessions still active");
        }
    })
}

/// Thin alias so the accept loop reads the same whichever HTTP stack is used.
mod axum_router {
    pub use axum::serve;
    pub use axum::Router;
}

#[cfg(test)]
mod tests {
    use super::*;
    use havuz_core::{State, StateStore};
    use havuz_secrets::MasterKey;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    fn family() -> Arc<PgFamily> {
        let key = Arc::new(MasterKey::generate());
        let store = Arc::new(StateStore::ephemeral(State::default()));
        PgFamily::new(store, key)
    }

    async fn free_addr() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    }

    #[tokio::test]
    async fn the_pooler_accepts_and_then_stops_on_shutdown() {
        let addr = free_addr().await;
        let shutdown = Shutdown::new();
        let handle = spawn_pooler(addr, family(), 100, shutdown.clone());

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(TcpStream::connect(addr).await.is_ok(), "the listener should be up");

        shutdown.trigger();
        tokio::time::timeout(Duration::from_secs(15), handle).await.expect("accept loop must exit").unwrap();
    }

    #[tokio::test]
    async fn a_failed_bind_triggers_shutdown_instead_of_running_half_configured() {
        // Occupy the port first.
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = occupied.local_addr().unwrap();

        let shutdown = Shutdown::new();
        let handle = spawn_pooler(addr, family(), 100, shutdown.clone());
        handle.await.unwrap();

        assert!(shutdown.is_shutting_down(), "a pooler that cannot bind must not leave the process running");
    }

    #[tokio::test]
    async fn the_global_client_cap_is_enforced_at_accept_time() {
        let addr = free_addr().await;
        let shutdown = Shutdown::new();
        let _handle = spawn_pooler(addr, family(), 1, shutdown.clone());
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The first connection is accepted and parked waiting for a startup
        // packet that never comes, so it holds the single slot.
        let mut first = TcpStream::connect(addr).await.unwrap();
        first.write_all(&[]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The second is accepted by the OS then immediately dropped by us.
        let mut second = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), tokio::io::AsyncReadExt::read(&mut second, &mut buf))
            .await
            .expect("must not hang");
        assert_eq!(read.unwrap(), 0, "over the cap the connection is closed immediately");

        shutdown.trigger();
    }
}
