//! Live visibility into clients that hold or wait for backend slots while no
//! query is executing.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use havuz_proto::PinReason;
use havuz_registry::PoolMode;
use serde::Serialize;

use crate::trace::TraceContext;

#[derive(Debug, Clone, Serialize)]
pub struct BackendHolder {
    pub id: u64,
    pub since_ms: i64,
    pub elapsed_us: u64,
    pub pool: String,
    pub user: String,
    pub application: Option<String>,
    pub client_addr: String,
    pub mode: String,
    pub reason: String,
    pub pin_reason: Option<String>,
    pub target: Option<String>,
    pub backend_pid: Option<u32>,
}

struct HolderEntry {
    public: BackendHolder,
    since: Instant,
}

#[derive(Default)]
pub struct HolderRegistry {
    next_id: AtomicU64,
    entries: RwLock<BTreeMap<u64, HolderEntry>>,
}

impl HolderRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { next_id: AtomicU64::new(1), entries: RwLock::new(BTreeMap::new()) })
    }

    pub fn session(self: &Arc<Self>, context: TraceContext, mode: PoolMode) -> HolderHandle {
        HolderHandle { registry: self.clone(), id: self.next_id.fetch_add(1, Ordering::Relaxed), context, mode }
    }

    pub fn snapshot(&self) -> Vec<BackendHolder> {
        let mut holders: Vec<_> = self
            .entries
            .read()
            .expect("backend holder registry poisoned")
            .values()
            .map(|entry| {
                let mut holder = entry.public.clone();
                holder.elapsed_us = entry.since.elapsed().as_micros() as u64;
                holder
            })
            .collect();
        holders.sort_by_key(|holder| std::cmp::Reverse(holder.elapsed_us));
        holders
    }

    pub fn timeout_hint(&self, pool: &str) -> String {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for entry in self.entries.read().expect("backend holder registry poisoned").values() {
            if entry.public.pool == pool && entry.public.reason != "startup_wait" {
                *counts.entry(entry.public.reason.clone()).or_default() += 1;
            }
        }
        if counts.is_empty() {
            return "no idle holder was observed; active queries may be using every backend slot".into();
        }
        let reasons =
            counts.into_iter().map(|(reason, count)| format!("{reason}={count}")).collect::<Vec<_>>().join(", ");
        format!("backend slots are held without a running query ({reasons}); see Query Trace > Backend holders")
    }

    fn set(
        &self,
        handle: &HolderHandle,
        reason: &str,
        pin_reason: Option<PinReason>,
        target: Option<String>,
        backend_pid: Option<u32>,
    ) {
        let since = Instant::now();
        let public = BackendHolder {
            id: handle.id,
            since_ms: now_ms(),
            elapsed_us: 0,
            pool: handle.context.pool.clone(),
            user: handle.context.user.clone(),
            application: handle.context.application.clone(),
            client_addr: handle.context.client_addr.clone(),
            mode: handle.mode.as_str().into(),
            reason: reason.into(),
            pin_reason: pin_reason.map(|reason| reason.as_str().into()),
            target,
            backend_pid,
        };
        self.entries
            .write()
            .expect("backend holder registry poisoned")
            .insert(handle.id, HolderEntry { public, since });
    }

    fn clear(&self, id: u64) {
        self.entries.write().expect("backend holder registry poisoned").remove(&id);
    }
}

pub struct HolderHandle {
    registry: Arc<HolderRegistry>,
    id: u64,
    context: TraceContext,
    mode: PoolMode,
}

impl HolderHandle {
    pub fn waiting_for_startup(&self) {
        self.registry.set(self, "startup_wait", None, None, None);
    }

    pub fn session_reserved(&self, target: String, backend_pid: Option<u32>) {
        self.registry.set(self, "session_mode", None, Some(target), backend_pid);
    }

    pub fn idle_in_transaction(&self, target: String, backend_pid: Option<u32>) {
        self.registry.set(self, "idle_in_transaction", None, Some(target), backend_pid);
    }

    pub fn pinned(&self, reason: PinReason, target: String, backend_pid: Option<u32>) {
        self.registry.set(self, "pinned", Some(reason), Some(target), backend_pid);
    }

    pub fn clear(&self) {
        self.registry.clear(self.id);
    }

    pub fn timeout_hint(&self) -> String {
        self.registry.timeout_hint(&self.context.pool)
    }
}

impl Drop for HolderHandle {
    fn drop(&mut self) {
        self.clear();
    }
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> TraceContext {
        TraceContext {
            pool: "app_main".into(),
            user: "svc_orders".into(),
            application: Some("orders-api".into()),
            client_addr: "127.0.0.1:5000".into(),
        }
    }

    #[test]
    fn holder_lifecycle_explains_invisible_pool_usage() {
        let registry = HolderRegistry::new();
        let handle = registry.session(context(), PoolMode::Transaction);
        handle.waiting_for_startup();
        assert_eq!(registry.snapshot()[0].reason, "startup_wait");

        handle.pinned(PinReason::Listen, "primary/db:5432".into(), Some(42));
        let holder = &registry.snapshot()[0];
        assert_eq!(holder.reason, "pinned");
        assert_eq!(holder.pin_reason.as_deref(), Some("listen"));
        assert_eq!(holder.backend_pid, Some(42));
        assert!(registry.timeout_hint("app_main").contains("pinned=1"));

        handle.clear();
        assert!(registry.snapshot().is_empty());
    }

    #[test]
    fn dropping_a_session_never_leaves_a_phantom_holder() {
        let registry = HolderRegistry::new();
        {
            let handle = registry.session(context(), PoolMode::Session);
            handle.session_reserved("primary/db:5432".into(), Some(7));
        }
        assert!(registry.snapshot().is_empty());
    }
}
