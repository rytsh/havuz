//! Atomic persistence for [`State`].
//!
//! The whole document is rewritten on every change. At our scale (tens of
//! pools) that costs nothing and buys a property that matters a lot: readers
//! never observe a partially written state. Writes go to a temporary file in
//! the same directory, get fsynced, then renamed over the target.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::state::{State, StateError};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("cannot create state directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot read state file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot write state file {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("state file {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("refusing to persist invalid state: {0}")]
    Invalid(#[from] StateError),
}

/// Owns the state document and its file.
///
/// Reads are lock-free via [`ArcSwap`], so the hot path can snapshot the
/// configuration without blocking the admin API. Writes are serialised by a
/// mutex because they touch the filesystem.
#[derive(Debug)]
pub struct StateStore {
    path: PathBuf,
    current: ArcSwap<State>,
    write_lock: tokio::sync::Mutex<()>,
    /// Bumped on every published change.
    ///
    /// The listener supervisor needs to know that a pool's port moved, and
    /// polling the state for that would either be slow to react or a busy loop.
    /// A counter rather than the state itself keeps `StateStore: Debug` cheap
    /// and makes a missed wakeup impossible: a receiver that was busy sees the
    /// latest value, not a queue of intermediate ones.
    revision: tokio::sync::watch::Sender<u64>,
}

impl StateStore {
    /// Open the state file, creating an empty one if it does not exist.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        if let Some(dir) = path.parent() {
            tokio::fs::create_dir_all(dir)
                .await
                .map_err(|source| StoreError::CreateDir { path: dir.to_path_buf(), source })?;
        }

        let state = match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let state: State = serde_json::from_slice(&bytes)
                    .map_err(|source| StoreError::Parse { path: path.clone(), source })?;
                state.validate()?;
                state
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!(path = %path.display(), "no state file yet, starting empty");
                State::default()
            }
            Err(source) => return Err(StoreError::Read { path, source }),
        };

        Ok(Self::wrap(path, state))
    }

    /// In-memory store for tests and for `--dry-run`.
    pub fn ephemeral(state: State) -> Self {
        Self::wrap(PathBuf::new(), state)
    }

    fn wrap(path: PathBuf, state: State) -> Self {
        Self {
            path,
            current: ArcSwap::from_pointee(state),
            write_lock: tokio::sync::Mutex::new(()),
            revision: tokio::sync::watch::channel(0).0,
        }
    }

    /// Resolves whenever the state has been republished.
    ///
    /// Marked as seen on subscription, so a fresh receiver waits for the next
    /// change rather than firing immediately.
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.revision.subscribe()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Cheap, lock-free snapshot.
    pub fn load(&self) -> Arc<State> {
        self.current.load_full()
    }

    /// Apply `mutate` to a copy of the state, validate it, persist it, then
    /// publish it.
    ///
    /// Nothing is published if validation or the write fails, so a rejected
    /// admin request leaves the running configuration untouched.
    pub async fn update<F, T>(&self, mutate: F) -> Result<T, StoreError>
    where
        F: FnOnce(&mut State) -> T,
    {
        let _guard = self.write_lock.lock().await;

        let mut next = (*self.current.load_full()).clone();
        let outcome = mutate(&mut next);
        next.validate()?;

        if !self.path.as_os_str().is_empty() {
            write_atomic(&self.path, &next).await?;
        }
        self.current.store(Arc::new(next));
        self.publish();
        Ok(outcome)
    }

    /// Re-read the file from disk, discarding the in-memory copy.
    ///
    /// Used by `SIGHUP` when an operator edits the file directly.
    pub async fn reload(&self) -> Result<Arc<State>, StoreError> {
        let _guard = self.write_lock.lock().await;
        let bytes =
            tokio::fs::read(&self.path).await.map_err(|source| StoreError::Read { path: self.path.clone(), source })?;
        let state: State =
            serde_json::from_slice(&bytes).map_err(|source| StoreError::Parse { path: self.path.clone(), source })?;
        state.validate()?;
        let state = Arc::new(state);
        self.current.store(state.clone());
        self.publish();
        Ok(state)
    }

    fn publish(&self) {
        // `send_modify` rather than `send`: it does not care whether anyone is
        // listening, which a store used by a test with no supervisor is not.
        self.revision.send_modify(|revision| *revision += 1);
    }
}

async fn write_atomic(path: &Path, state: &State) -> Result<(), StoreError> {
    let json = serde_json::to_vec_pretty(state).expect("State is always serialisable");

    // Temporary file must live in the same directory, otherwise the rename can
    // cross filesystems and stop being atomic.
    let tmp = path.with_extension("json.tmp");

    tokio::fs::write(&tmp, &json).await.map_err(|source| StoreError::Write { path: tmp.clone(), source })?;

    restrict_permissions(&tmp).await?;

    // fsync the file before the rename, otherwise a crash can leave a renamed
    // but empty file.
    let file = tokio::fs::File::open(&tmp).await.map_err(|source| StoreError::Write { path: tmp.clone(), source })?;
    file.sync_all().await.map_err(|source| StoreError::Write { path: tmp.clone(), source })?;
    drop(file);

    tokio::fs::rename(&tmp, path).await.map_err(|source| StoreError::Write { path: path.to_path_buf(), source })?;

    Ok(())
}

#[cfg(unix)]
async fn restrict_permissions(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt;
    // The file carries sealed secrets. Even encrypted, it should not be world
    // readable.
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .await
        .map_err(|source| StoreError::Write { path: path.to_path_buf(), source })
}

#[cfg(not(unix))]
async fn restrict_permissions(_path: &Path) -> Result<(), StoreError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{PoolConfig, PoolLimits, Target, UserConfig};
    use havuz_registry::PoolMode;

    fn pool() -> PoolConfig {
        PoolConfig {
            family: "postgres".into(),
            profile: None,
            mode: PoolMode::Session,
            targets: vec![Target::new("pg", 5432)],
            backend_user: "app".into(),
            database: "appdb".into(),
            listen_port: 6432,
            limits: PoolLimits::default(),
            settings: Default::default(),
            routing: Default::default(),
            backend_auth: Default::default(),
            disabled: false,
            description: None,
        }
    }

    #[tokio::test]
    async fn opening_a_missing_file_starts_empty_and_creates_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("state.json");

        let store = StateStore::open(&path).await.unwrap();
        assert!(store.load().pools.is_empty());
        assert!(path.parent().unwrap().exists(), "state directory is created eagerly");
        assert!(!path.exists(), "nothing is written until the first update");
    }

    #[tokio::test]
    async fn update_persists_and_publishes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let store = StateStore::open(&path).await.unwrap();

        store
            .update(|s| {
                s.pools.insert("app_main".into(), pool());
                s.users.insert("svc".into(), UserConfig::new(vec!["app_main".into()]));
            })
            .await
            .unwrap();

        assert!(store.load().pools.contains_key("app_main"), "new state is visible immediately");

        let reopened = StateStore::open(&path).await.unwrap();
        assert!(reopened.load().pools.contains_key("app_main"), "state survives a restart");
    }

    #[tokio::test]
    async fn a_rejected_update_leaves_the_running_config_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let store = StateStore::open(&path).await.unwrap();

        store
            .update(|s| {
                s.pools.insert("app_main".into(), pool());
                s.users.insert("svc".into(), UserConfig::new(vec!["app_main".into()]));
            })
            .await
            .unwrap();

        // Grant a user a pool that does not exist.
        let err = store
            .update(|s| {
                s.users.insert("ghost".into(), UserConfig::new(vec!["missing".into()]));
            })
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Invalid(_)));

        let current = store.load();
        assert!(!current.users.contains_key("ghost"), "invalid mutation must not be published");
        assert!(current.users.contains_key("svc"), "previous state is intact");

        let reopened = StateStore::open(&path).await.unwrap();
        assert!(!reopened.load().users.contains_key("ghost"), "invalid mutation must not be persisted");
    }

    #[tokio::test]
    async fn no_temporary_file_is_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let store = StateStore::open(&path).await.unwrap();
        store.update(|s| s.pools.insert("app_main".into(), pool())).await.unwrap();

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "atomic write must clean up: {leftovers:?}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn state_file_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let store = StateStore::open(&path).await.unwrap();
        store.update(|s| s.pools.insert("app_main".into(), pool())).await.unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "state file holds sealed secrets");
    }

    #[tokio::test]
    async fn corrupt_state_file_fails_loudly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(&path, b"{ not json").unwrap();

        let err = StateStore::open(&path).await.unwrap_err();
        assert!(matches!(err, StoreError::Parse { .. }), "a corrupt file must not silently reset the config");
    }

    #[tokio::test]
    async fn invalid_state_file_is_rejected_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        // A user granted a pool that does not exist.
        std::fs::write(&path, br#"{"version":1,"pools":{},"users":{"svc":{"pools":["missing"]}},"secrets":{}}"#)
            .unwrap();

        assert!(matches!(StateStore::open(&path).await.unwrap_err(), StoreError::Invalid(_)));
    }

    #[tokio::test]
    async fn reload_picks_up_external_edits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let store = StateStore::open(&path).await.unwrap();
        store.update(|s| s.pools.insert("app_main".into(), pool())).await.unwrap();

        // Simulate an operator editing the file directly.
        let mut edited = (*store.load()).clone();
        edited.pools.get_mut("app_main").unwrap().disabled = true;
        std::fs::write(&path, serde_json::to_vec_pretty(&edited).unwrap()).unwrap();

        let reloaded = store.reload().await.unwrap();
        assert!(reloaded.pools["app_main"].disabled);
    }

    #[tokio::test]
    async fn ephemeral_store_never_touches_the_filesystem() {
        let store = StateStore::ephemeral(State::default());
        store.update(|s| s.pools.insert("app_main".into(), pool())).await.unwrap();
        assert!(store.load().pools.contains_key("app_main"));
        assert_eq!(store.path(), Path::new(""));
    }

    #[tokio::test]
    async fn update_returns_the_closure_result() {
        let store = StateStore::ephemeral(State::default());
        let created = store.update(|s| s.pools.insert("app_main".into(), pool()).is_none()).await.unwrap();
        assert!(created, "update hands back whatever the mutation computed");
    }
}
