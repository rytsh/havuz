//! Configuration, runtime state and TLS.
//!
//! havuz has two distinct configuration planes and conflating them is the
//! easiest way to end up with a UI that fights a config file:
//!
//! * [`config::Bootstrap`] — process-level settings read from a TOML file at
//!   startup: listen addresses, TLS material, where the state file lives. These
//!   cannot be changed from the UI because changing them means rebinding
//!   sockets.
//! * [`state::State`] — pools, users and sealed secrets. This is the plane the
//!   admin UI writes. The state file is the source of truth; the bootstrap file
//!   only seeds it on first run.

pub mod config;
pub mod state;
pub mod store;
pub mod tls;

pub use config::{AdminAuth, AdminConfig, Bootstrap, BootstrapError, LogConfig, ServerConfig, ServerTls, StatePaths};
pub use state::{PoolConfig, PoolLimits, RoutingConfig, State, StateError, Target, TargetRole, UserConfig, Warning};
pub use store::{StateStore, StoreError};
pub use tls::{SslMode, TlsError};

/// Re-exported so downstream crates do not need a direct registry dependency
/// just to name a pooling mode.
pub use havuz_registry::PoolMode;
