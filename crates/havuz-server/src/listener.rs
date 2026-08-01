//! The admin accept loop. Client listeners live in [`crate::pooler`].

use std::net::SocketAddr;

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

/// Thin alias so the accept loop reads the same whichever HTTP stack is used.
mod axum_router {
    pub use axum::serve;
    pub use axum::Router;
}
