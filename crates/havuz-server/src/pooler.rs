//! Client listeners.
//!
//! There is no process-wide client port. A pool declares the port clients reach
//! it on, pools that declare the same port share one socket, and this module
//! keeps the set of bound sockets equal to the set the configuration asks for.
//!
//! Sockets live here rather than inside a family for two reasons.
//!
//! **A family that owns listeners owns the process.** The shared port used to
//! route by the database name in the startup packet, which is a field only one
//! protocol defines, so a second family could never have a socket of its own.
//!
//! **Port conflicts are a process-level fact.** Two families each checking
//! their own pools would both believe a port was free.
//!
//! Rebinding is driven by [`StateStore::subscribe`], so moving a pool to
//! another port takes effect without a restart — which matters, because the
//! port is now the one piece of routing an operator actually edits.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use havuz_control::{ClientGate, FamilySet};
use havuz_core::StateStore;
use havuz_proto::PoolRoute;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::shutdown::Shutdown;

/// How long in-flight sessions get to finish once we stop accepting.
const DRAIN_GRACE: Duration = Duration::from_secs(10);

/// A bound socket and the accept loop reading from it.
struct Bound {
    /// The family this socket speaks. A port cannot change family without a
    /// rebind, because the accept loop holds that family's handle.
    family: String,
    /// Which pools are reachable here, read once per accepted connection.
    ///
    /// Swapped in place rather than baked into the accept loop: adding a pool
    /// to a live port must not close and reopen the socket. The first attempt
    /// did rebind, and it failed intermittently, because the old listener is
    /// only dropped when the aborted task actually stops — a race with no upper
    /// bound that would have surfaced in production as "the port disappeared
    /// for a moment when I added a pool".
    route: Arc<RwLock<Arc<PoolRoute>>>,
    /// What this socket is currently bound for, for logging and diffing.
    pools: Vec<String>,
    /// Diffed alongside `pools`: an alias is routing, so adding one has to
    /// reach the live socket exactly as adding a pool does. Comparing only the
    /// pool list would make a new alias need a restart.
    aliases: Vec<(String, String)>,
    accept: JoinHandle<()>,
}

impl Drop for Bound {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

pub struct Pooler {
    bind: IpAddr,
    /// Never handed to a pool, because the process already owns it.
    reserved: Option<u16>,
    families: FamilySet,
    store: Arc<StateStore>,
    gate: Arc<ClientGate>,
    shutdown: Shutdown,
    bound: HashMap<u16, Bound>,
}

impl Pooler {
    pub fn new(
        bind: IpAddr,
        reserved: Option<u16>,
        families: FamilySet,
        store: Arc<StateStore>,
        gate: Arc<ClientGate>,
        shutdown: Shutdown,
    ) -> Self {
        Self { bind, reserved, families, store, gate, shutdown, bound: HashMap::new() }
    }

    /// Bind what the current configuration asks for.
    ///
    /// Errors are reported per port and do not abort the rest: one pool with a
    /// port already taken by another process must not stop every other pool
    /// from serving traffic.
    pub fn reconcile(&mut self) {
        let desired = self.store.load().listeners();

        // Close first. A pool moving from 6001 to 6002 would otherwise find
        // 6001 still held by us if the two steps were reversed.
        self.bound.retain(|port, bound| {
            let keep = desired.get(port).is_some_and(|plan| plan.family == bound.family);
            if !keep {
                tracing::info!(port, pools = ?bound.pools, "closing client listener");
            }
            keep
        });

        for (port, plan) in desired {
            // A live socket only needs its pool list refreshed.
            if let Some(bound) = self.bound.get_mut(&port) {
                if bound.pools != plan.pools || bound.aliases != plan.aliases {
                    *bound.route.write().expect("route poisoned") =
                        Arc::new(PoolRoute::with_aliases(plan.pools.clone(), plan.aliases.clone()));
                    tracing::info!(
                        port,
                        pools = ?plan.pools,
                        aliases = ?plan.aliases,
                        "client listener now serves a different pool set"
                    );
                    bound.pools = plan.pools;
                    bound.aliases = plan.aliases;
                }
                continue;
            }
            if self.reserved == Some(port) {
                tracing::error!(
                    port,
                    pools = ?plan.pools,
                    "refusing to bind: this port belongs to the admin listener"
                );
                continue;
            }
            let Some(family) = self.families.get(&plan.family) else {
                tracing::error!(port, family = %plan.family, "no driver for this family, not binding");
                continue;
            };

            let addr = SocketAddr::new(self.bind, port);
            match bind(addr) {
                Ok(listener) => {
                    let route = Arc::new(RwLock::new(Arc::new(PoolRoute::with_aliases(
                        plan.pools.clone(),
                        plan.aliases.clone(),
                    ))));
                    tracing::info!(
                        %addr,
                        pools = ?plan.pools,
                        aliases = ?plan.aliases,
                        family = %plan.family,
                        "client listener ready"
                    );
                    let accept = tokio::spawn(accept_loop(
                        listener,
                        addr,
                        family.clone(),
                        route.clone(),
                        self.gate.clone(),
                        self.shutdown.clone(),
                    ));
                    self.bound.insert(
                        port,
                        Bound { family: plan.family, route, pools: plan.pools, aliases: plan.aliases, accept },
                    );
                }
                // Not fatal: the operator can fix the port in the dashboard and
                // the next reconcile picks it up. Killing the process would
                // take every healthy pool down with the broken one.
                Err(error) => tracing::error!(%addr, pools = ?plan.pools, %error, "cannot bind client listener"),
            }
        }
    }

    /// Reconcile now, then again on every configuration change, until shutdown.
    pub async fn run(mut self) {
        let mut changes = self.store.subscribe();
        self.reconcile();

        loop {
            tokio::select! {
                changed = changes.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    self.reconcile();
                }
                _ = self.shutdown.notified() => break,
            }
        }

        // Dropping the map aborts every accept loop, so no new connection is
        // taken while in-flight sessions finish.
        self.bound.clear();
        tracing::info!("no longer accepting connections");

        let deadline = tokio::time::Instant::now() + DRAIN_GRACE;
        while self.gate.live() > 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let remaining = self.gate.live();
        if remaining > 0 {
            tracing::warn!(remaining, "closing with sessions still active");
        }
    }
}

fn bind(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let listener = std::net::TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    TcpListener::from_std(listener)
}

async fn accept_loop(
    listener: TcpListener,
    addr: SocketAddr,
    family: Arc<dyn havuz_control::ControlPlane>,
    route: Arc<RwLock<Arc<PoolRoute>>>,
    gate: Arc<ClientGate>,
    shutdown: Shutdown,
) {
    loop {
        let accepted = tokio::select! {
            result = listener.accept() => result,
            _ = shutdown.notified() => return,
        };

        let (socket, peer) = match accepted {
            Ok(pair) => pair,
            Err(error) => {
                // Running out of file descriptors is transient under load; a
                // tight retry loop here would make it considerably worse.
                tracing::warn!(%addr, %error, "accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };

        // Before the handshake, not after: a connection storm must not be able
        // to exhaust file descriptors while every one of those sockets waits
        // for a startup packet.
        let Some(permit) = gate.try_acquire() else {
            tracing::warn!(%peer, %addr, "refusing connection, process client limit reached");
            drop(socket);
            continue;
        };

        let family = family.clone();
        // Read per connection, so a pool added to this port a moment ago is
        // already reachable.
        let route = route.read().expect("route poisoned").clone();
        tokio::spawn(async move {
            match family.serve(socket, peer, &route).await {
                Ok(outcome) if outcome.authenticated => tracing::debug!(
                    %peer,
                    to_client = outcome.bytes_to_client,
                    to_backend = outcome.bytes_to_backend,
                    "session ended"
                ),
                Ok(_) => {}
                Err(e) => tracing::debug!(%peer, error = %e, kind = e.kind(), "session failed"),
            }
            drop(permit);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use havuz_control::Registries;
    use havuz_core::state::{PoolConfig, PoolLimits, State, Target, UserConfig};
    use havuz_core::PoolMode;
    use havuz_secrets::MasterKey;
    use tokio::net::TcpStream;

    fn pool(port: u16) -> PoolConfig {
        PoolConfig {
            family: "postgres".into(),
            profile: None,
            mode: PoolMode::Session,
            targets: vec![Target::new("127.0.0.1", 1)],
            backend_user: "app".into(),
            database: "appdb".into(),
            listen_port: port,
            aliases: Vec::new(),
            limits: PoolLimits::default(),
            settings: Default::default(),
            routing: Default::default(),
            backend_auth: Default::default(),
            allow_password_without_tls: false,
            trace: Default::default(),
            disabled: false,
            description: None,
        }
    }

    async fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port()
    }

    fn pooler(store: Arc<StateStore>, reserved: Option<u16>, shutdown: Shutdown) -> Pooler {
        let families = FamilySet::new(vec![havuz_pg::PgFamily::new(
            store.clone(),
            Arc::new(MasterKey::generate()),
            Registries::ephemeral(),
        )]);
        Pooler::new("127.0.0.1".parse().unwrap(), reserved, families, store, Arc::new(ClientGate::new(100)), shutdown)
    }

    fn state_with(pools: &[(&str, u16)]) -> State {
        let mut state = State::default();
        for (name, port) in pools {
            state.pools.insert((*name).into(), pool(*port));
            state.users.insert(format!("svc_{name}"), UserConfig::new(vec![(*name).into()]));
        }
        state
    }

    #[tokio::test]
    async fn a_pool_port_is_bound_and_released_as_configuration_changes() {
        let port = free_port().await;
        let store = Arc::new(StateStore::ephemeral(state_with(&[("orders", port)])));
        let mut pooler = pooler(store.clone(), None, Shutdown::new());

        pooler.reconcile();
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_ok(), "the pool's port must be open");

        store
            .update(|state| {
                state.pools.clear();
                state.users.clear();
            })
            .await
            .unwrap();
        pooler.reconcile();
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err(), "a removed pool must not leave a socket open");
    }

    #[tokio::test]
    async fn moving_a_pool_to_another_port_closes_the_old_one() {
        let (old, new) = (free_port().await, free_port().await);
        let store = Arc::new(StateStore::ephemeral(state_with(&[("orders", old)])));
        let mut pooler = pooler(store.clone(), None, Shutdown::new());
        pooler.reconcile();

        store.update(|state| state.pools.get_mut("orders").unwrap().listen_port = new).await.unwrap();
        pooler.reconcile();

        assert!(TcpStream::connect(("127.0.0.1", new)).await.is_ok(), "the new port must be open");
        assert!(TcpStream::connect(("127.0.0.1", old)).await.is_err(), "the old port must be released");
    }

    #[tokio::test]
    async fn two_pools_on_one_port_share_a_single_socket() {
        let port = free_port().await;
        let store = Arc::new(StateStore::ephemeral(state_with(&[("orders", port), ("reports", port)])));
        let mut pooler = pooler(store, None, Shutdown::new());
        pooler.reconcile();

        assert_eq!(pooler.bound.len(), 1);
        assert_eq!(pooler.bound[&port].pools, ["orders", "reports"]);
    }

    #[tokio::test]
    async fn adding_a_pool_to_a_live_port_does_not_disturb_the_socket() {
        // Rebinding here used to race the aborted accept task for the port.
        let port = free_port().await;
        let store = Arc::new(StateStore::ephemeral(state_with(&[("orders", port)])));
        let mut pooler = pooler(store.clone(), None, Shutdown::new());
        pooler.reconcile();

        store
            .update(|state| {
                state.pools.insert("reports".into(), pool(port));
                state.users.insert("svc_reports".into(), UserConfig::new(vec!["reports".into()]));
            })
            .await
            .unwrap();
        pooler.reconcile();
        assert_eq!(pooler.bound[&port].pools, ["orders", "reports"]);
    }

    #[tokio::test]
    async fn adding_an_alias_reaches_the_live_socket_without_a_restart() {
        // An alias is routing, so it has to travel the same path a new pool
        // does. Diffing only the pool list would leave the socket answering to
        // the old set until the process was restarted — and the operator would
        // have no way to tell from the dashboard, which shows the stored state.
        let port = free_port().await;
        let store = Arc::new(StateStore::ephemeral(state_with(&[("orders_rw", port)])));
        let mut pooler = pooler(store.clone(), None, Shutdown::new());
        pooler.reconcile();
        assert!(pooler.bound[&port].aliases.is_empty());

        store.update(|state| state.pools.get_mut("orders_rw").unwrap().aliases = vec!["orders".into()]).await.unwrap();
        pooler.reconcile();

        assert_eq!(pooler.bound[&port].aliases, [("orders".to_string(), "orders_rw".to_string())]);
        let route = pooler.bound[&port].route.read().unwrap().clone();
        assert_eq!(route.resolve("orders"), Some("orders_rw"), "the socket routes on the new alias immediately");
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_ok(), "and the port never closed");
    }

    #[tokio::test]
    async fn a_disabled_pool_gives_its_port_back() {
        let port = free_port().await;
        let store = Arc::new(StateStore::ephemeral(state_with(&[("orders", port)])));
        let mut pooler = pooler(store.clone(), None, Shutdown::new());
        pooler.reconcile();

        store.update(|state| state.pools.get_mut("orders").unwrap().disabled = true).await.unwrap();
        pooler.reconcile();
        assert!(
            TcpStream::connect(("127.0.0.1", port)).await.is_err(),
            "a disabled pool must close its socket, not accept and then refuse"
        );
    }

    #[tokio::test]
    async fn the_admin_port_is_never_handed_to_a_pool() {
        let port = free_port().await;
        let store = Arc::new(StateStore::ephemeral(state_with(&[("orders", port)])));
        let mut pooler = pooler(store, Some(port), Shutdown::new());
        pooler.reconcile();
        assert!(pooler.bound.is_empty(), "binding here would race the admin API for the socket");
    }

    #[tokio::test]
    async fn one_unbindable_port_does_not_stop_the_others() {
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let taken = occupied.local_addr().unwrap().port();
        let healthy = free_port().await;

        let store = Arc::new(StateStore::ephemeral(state_with(&[("orders", taken), ("reports", healthy)])));
        let mut pooler = pooler(store, None, Shutdown::new());
        pooler.reconcile();

        assert!(!pooler.bound.contains_key(&taken));
        assert!(pooler.bound.contains_key(&healthy), "a broken pool must not take the healthy ones down");
    }

    #[tokio::test]
    async fn the_process_client_cap_is_enforced_at_accept_time() {
        let port = free_port().await;
        let store = Arc::new(StateStore::ephemeral(state_with(&[("orders", port)])));
        let families = FamilySet::new(vec![havuz_pg::PgFamily::new(
            store.clone(),
            Arc::new(MasterKey::generate()),
            Registries::ephemeral(),
        )]);
        let mut pooler = Pooler::new(
            "127.0.0.1".parse().unwrap(),
            None,
            families,
            store,
            Arc::new(ClientGate::new(1)),
            Shutdown::new(),
        );
        pooler.reconcile();

        // The first connection is accepted and parked waiting for a startup
        // packet that never comes, so it holds the only slot.
        let _first = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut second = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), tokio::io::AsyncReadExt::read(&mut second, &mut buf))
            .await
            .expect("must not hang");
        assert_eq!(read.unwrap(), 0, "over the cap the connection is closed immediately");
    }

    #[tokio::test]
    async fn shutdown_stops_accepting_and_returns() {
        let port = free_port().await;
        let store = Arc::new(StateStore::ephemeral(state_with(&[("orders", port)])));
        let shutdown = Shutdown::new();
        let pooler = pooler(store, None, shutdown.clone());
        let handle = tokio::spawn(pooler.run());

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_ok());

        shutdown.trigger();
        tokio::time::timeout(Duration::from_secs(15), handle).await.expect("the supervisor must exit").unwrap();
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
    }
}
