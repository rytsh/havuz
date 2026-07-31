//! Graceful shutdown.
//!
//! A pooler sits between applications and their database, so killing it
//! abruptly turns into application errors. On the first signal we stop
//! accepting new connections and let in-flight sessions finish; a second signal
//! means the operator is out of patience and we exit immediately.

use std::sync::Arc;

use tokio::sync::watch;

#[derive(Clone)]
pub struct Shutdown {
    tx: Arc<watch::Sender<bool>>,
    rx: watch::Receiver<bool>,
}

impl Shutdown {
    pub fn new() -> Self {
        let (tx, rx) = watch::channel(false);
        Self { tx: Arc::new(tx), rx }
    }

    #[allow(dead_code)] // used by tests and by future drain reporting
    pub fn is_shutting_down(&self) -> bool {
        *self.rx.borrow()
    }

    /// Resolve once shutdown has been requested.
    pub async fn notified(&self) {
        let mut rx = self.rx.clone();
        if *rx.borrow() {
            return;
        }
        let _ = rx.changed().await;
    }

    pub fn trigger(&self) {
        let _ = self.tx.send(true);
    }

    /// Wait for SIGINT or SIGTERM, then trigger.
    pub async fn wait_for_signal(&self) {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut term = signal(SignalKind::terminate()).expect("installing SIGTERM handler");
            let mut int = signal(SignalKind::interrupt()).expect("installing SIGINT handler");
            tokio::select! {
                _ = term.recv() => tracing::info!("received SIGTERM"),
                _ = int.recv() => tracing::info!("received SIGINT"),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("received ctrl-c");
        }

        self.trigger();

        // A second signal skips the grace period.
        let forceful = self.clone();
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let mut int = signal(SignalKind::interrupt()).expect("installing SIGINT handler");
                let _ = int.recv().await;
            }
            #[cfg(not(unix))]
            let _ = tokio::signal::ctrl_c().await;

            tracing::warn!("second signal, exiting without draining");
            std::process::exit(130);
        });
        let _ = forceful;
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn starts_running_and_flips_once() {
        let shutdown = Shutdown::new();
        assert!(!shutdown.is_shutting_down());

        shutdown.trigger();
        assert!(shutdown.is_shutting_down());
    }

    #[tokio::test]
    async fn every_clone_is_notified() {
        let shutdown = Shutdown::new();
        let waiters: Vec<_> = (0..5)
            .map(|_| {
                let s = shutdown.clone();
                tokio::spawn(async move { s.notified().await })
            })
            .collect();

        tokio::time::sleep(Duration::from_millis(10)).await;
        shutdown.trigger();

        for waiter in waiters {
            tokio::time::timeout(Duration::from_secs(1), waiter).await.expect("every listener must wake up").unwrap();
        }
    }

    #[tokio::test]
    async fn notifying_after_the_fact_returns_immediately() {
        let shutdown = Shutdown::new();
        shutdown.trigger();
        // A task spawned during shutdown must not block forever waiting for an
        // edge that already passed.
        tokio::time::timeout(Duration::from_millis(100), shutdown.notified())
            .await
            .expect("a late waiter must observe the level, not the edge");
    }
}
