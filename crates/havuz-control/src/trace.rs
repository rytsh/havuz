//! Query tracing with a bounded result sample and SQLite persistence.
//!
//! Active queries stay in memory so the admin API can show them immediately.
//! Completed queries are handed to a dedicated writer thread; disk latency must
//! never stall a relay hot path.
//!
//! Nothing here parses a wire protocol. A family feeds a [`TraceSpan`] through
//! [`TraceSpan::begin_result_set`], [`TraceSpan::push_row`],
//! [`TraceSpan::command_complete`] and [`TraceSpan::record_error`]; decoding
//! its own messages into those calls is the family's job, and is the only part
//! of tracing that could not be shared.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use havuz_core::TraceLevel;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

pub const MAX_RESULT_ROWS: usize = 100;
pub const MAX_RESULT_BYTES: usize = 256 * 1024;
pub const RETENTION_DAYS: u64 = 7;
const RETENTION: Duration = Duration::from_secs(RETENTION_DAYS * 24 * 60 * 60);

#[derive(Debug, thiserror::Error)]
pub enum TraceError {
    #[error("opening query trace database: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("query trace storage I/O: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct TraceContext {
    pub pool: String,
    pub user: String,
    pub application: Option<String>,
    pub client_addr: String,
    /// How much of this pool's traffic is recorded. Carried on the context
    /// rather than checked by every caller: a family decodes its wire format
    /// into span calls and should not also have to remember which of them the
    /// operator asked for.
    pub level: TraceLevel,
}

/// How one protocol interrupts a query it is running.
///
/// Lives here rather than in a family because the thing an operator points at
/// is a running query, and running queries are what this module tracks. What
/// arrives on the wire — a PostgreSQL `CancelRequest` on a second connection,
/// something else entirely for another family — is the family's business.
///
/// Best effort by nature. PostgreSQL never confirms a cancellation, so `Ok`
/// means "asked", not "stopped".
#[async_trait]
pub trait CancelHook: Send + Sync + std::fmt::Debug {
    async fn cancel(&self) -> Result<(), String>;
}

#[derive(Debug, Clone, Serialize)]
pub struct ActiveTrace {
    pub id: u64,
    pub started_at_ms: i64,
    pub elapsed_us: u64,
    pub pool: String,
    pub user: String,
    pub application: Option<String>,
    pub client_addr: String,
    pub sql: String,
    pub phase: String,
    pub target: Option<String>,
    pub backend_pid: Option<u32>,
    /// Whether an operator can interrupt this query. False while it is still
    /// queueing for a backend — there is nothing to interrupt yet — and false
    /// for a family that cannot cancel at all, so the dashboard can offer the
    /// button only where pressing it would do something.
    pub cancellable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceSummary {
    pub id: u64,
    pub started_at_ms: i64,
    pub duration_us: u64,
    pub wait_us: u64,
    pub execution_us: u64,
    pub pool: String,
    pub user: String,
    pub application: Option<String>,
    pub client_addr: String,
    pub sql: String,
    pub status: String,
    pub target: Option<String>,
    pub backend_pid: Option<u32>,
    pub command_tag: Option<String>,
    pub row_count: u64,
    pub result_truncated: bool,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceDetail {
    #[serde(flatten)]
    pub summary: TraceSummary,
    pub result: QueryResult,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TraceFilter {
    pub pool: Option<String>,
    pub user: Option<String>,
    pub status: Option<String>,
    pub q: Option<String>,
    pub min_duration_ms: Option<u64>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueryResult {
    pub sets: Vec<ResultSet>,
    /// The pool records statements only, so an empty `sets` means "not kept"
    /// rather than "returned nothing". Defaulted rather than required so traces
    /// written before the setting existed still load, and read as captured —
    /// which they were.
    #[serde(default)]
    pub omitted: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResultSet {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Option<String>>>,
    pub command_tag: Option<String>,
}

struct ActiveEntry {
    public: ActiveTrace,
    started: Instant,
    /// Dropped with the entry when the query completes, so a cancellation can
    /// never outlive the query it was aimed at.
    cancel: Option<Arc<dyn CancelHook>>,
}

struct CompletedTrace {
    summary: TraceSummary,
    result: QueryResult,
}

pub struct TraceStore {
    connection: Arc<Mutex<Connection>>,
    active: RwLock<BTreeMap<u64, ActiveEntry>>,
    next_id: AtomicU64,
    completed_tx: mpsc::Sender<CompletedTrace>,
}

impl TraceStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Arc<Self>, TraceError> {
        let path = path.as_ref();
        let connection = Connection::open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Self::from_connection(connection)
    }

    pub fn memory() -> Arc<Self> {
        Self::from_connection(Connection::open_in_memory().expect("in-memory trace database must open"))
            .expect("in-memory trace database must initialise")
    }

    fn from_connection(connection: Connection) -> Result<Arc<Self>, TraceError> {
        connection.busy_timeout(Duration::from_secs(2))?;
        connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS query_traces (
                 id                INTEGER PRIMARY KEY,
                 started_at_ms     INTEGER NOT NULL,
                 duration_us       INTEGER NOT NULL,
                 wait_us           INTEGER NOT NULL,
                 execution_us      INTEGER NOT NULL,
                 pool              TEXT NOT NULL,
                 user_name         TEXT NOT NULL,
                 application       TEXT,
                 client_addr       TEXT NOT NULL,
                 sql_text          TEXT NOT NULL,
                 status            TEXT NOT NULL,
                 target            TEXT,
                 backend_pid       INTEGER,
                 command_tag       TEXT,
                 row_count         INTEGER NOT NULL,
                 result_truncated  INTEGER NOT NULL,
                 error_code        TEXT,
                 error_message     TEXT,
                 result_json       TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS query_traces_started ON query_traces(started_at_ms DESC);
             CREATE INDEX IF NOT EXISTS query_traces_pool_started ON query_traces(pool, started_at_ms DESC);
             CREATE INDEX IF NOT EXISTS query_traces_user_started ON query_traces(user_name, started_at_ms DESC);",
        )?;

        let cutoff = now_ms() - RETENTION.as_millis() as i64;
        connection.execute("DELETE FROM query_traces WHERE started_at_ms < ?1", [cutoff])?;
        let next_id = connection
            .query_row("SELECT COALESCE(MAX(id), 0) + 1 FROM query_traces", [], |row| row.get::<_, u64>(0))?;

        let connection = Arc::new(Mutex::new(connection));
        let (completed_tx, completed_rx) = mpsc::channel();
        let writer_connection = connection.clone();
        std::thread::Builder::new().name("havuz-trace-writer".into()).spawn(move || {
            let mut writes = 0u64;
            let mut next_cleanup = 256u64;
            while let Ok(first) = completed_rx.recv() {
                let mut batch = Vec::with_capacity(128);
                batch.push(first);
                batch.extend(completed_rx.try_iter().take(127));
                if let Err(error) = insert_traces(&writer_connection, &batch) {
                    tracing::error!(%error, count = batch.len(), "failed to persist query traces");
                }
                writes += batch.len() as u64;
                if writes >= next_cleanup {
                    let cutoff = now_ms() - RETENTION.as_millis() as i64;
                    if let Ok(connection) = writer_connection.lock() {
                        let _ = connection.execute("DELETE FROM query_traces WHERE started_at_ms < ?1", [cutoff]);
                    }
                    next_cleanup = writes.saturating_add(256);
                }
            }
        })?;

        Ok(Arc::new(Self {
            connection,
            active: RwLock::new(BTreeMap::new()),
            next_id: AtomicU64::new(next_id),
            completed_tx,
        }))
    }

    pub fn begin(self: &Arc<Self>, context: &TraceContext, sql: impl Into<String>) -> TraceSpan {
        if context.level.is_off() {
            return self.inert();
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let started = Instant::now();
        let public = ActiveTrace {
            id,
            started_at_ms: now_ms(),
            elapsed_us: 0,
            pool: context.pool.clone(),
            user: context.user.clone(),
            application: context.application.clone(),
            client_addr: context.client_addr.clone(),
            sql: sql.into(),
            phase: "waiting".into(),
            target: None,
            backend_pid: None,
            cancellable: false,
        };
        self.active.write().expect("trace registry poisoned").insert(id, ActiveEntry { public, started, cancel: None });
        TraceSpan {
            store: self.clone(),
            id,
            started,
            wait_us: 0,
            capture: ResultCapture::new(context.level.captures_results()),
            finished: false,
        }
    }

    /// A span that records nothing, for a pool with tracing off.
    ///
    /// Returned rather than `None` so the relays stay free of a second layer of
    /// `Option`: they already decode messages into span calls, and every one of
    /// those calls is a no-op here. Marking it finished is what makes it inert
    /// — completion and `Drop` both return immediately, and there is no entry
    /// in `active` to remove.
    fn inert(self: &Arc<Self>) -> TraceSpan {
        TraceSpan {
            store: self.clone(),
            id: 0,
            started: Instant::now(),
            wait_us: 0,
            capture: ResultCapture::new(false),
            finished: true,
        }
    }

    pub fn active(&self) -> Vec<ActiveTrace> {
        let mut traces: Vec<_> = self
            .active
            .read()
            .expect("trace registry poisoned")
            .values()
            .map(|entry| {
                let mut trace = entry.public.clone();
                trace.elapsed_us = entry.started.elapsed().as_micros() as u64;
                trace
            })
            .collect();
        traces.sort_by_key(|trace| std::cmp::Reverse(trace.started_at_ms));
        traces
    }

    pub fn list(&self, filter: &TraceFilter) -> Result<Vec<TraceSummary>, rusqlite::Error> {
        let connection = self.connection.lock().expect("trace database poisoned");
        let mut statement = connection.prepare(
            "SELECT id, started_at_ms, duration_us, wait_us, execution_us, pool, user_name,
                    application, client_addr, sql_text, status, target, backend_pid, command_tag,
                    row_count, result_truncated, error_code, error_message
             FROM query_traces
             WHERE (?1 IS NULL OR pool = ?1)
               AND (?2 IS NULL OR user_name = ?2)
               AND (?3 IS NULL OR status = ?3)
               AND (?4 IS NULL OR sql_text LIKE '%' || ?4 || '%' OR application LIKE '%' || ?4 || '%')
               AND duration_us >= ?5
             ORDER BY started_at_ms DESC
             LIMIT ?6 OFFSET ?7",
        )?;
        let limit = filter.limit.unwrap_or(100).clamp(1, 500) as i64;
        let offset = filter.offset.unwrap_or(0) as i64;
        let min_duration_us = filter.min_duration_ms.unwrap_or(0).saturating_mul(1_000) as i64;
        let rows = statement.query_map(
            params![
                filter.pool.as_deref(),
                filter.user.as_deref(),
                filter.status.as_deref(),
                filter.q.as_deref(),
                min_duration_us,
                limit,
                offset
            ],
            summary_from_row,
        )?;
        rows.collect()
    }

    pub fn count(&self, filter: &TraceFilter) -> Result<u64, rusqlite::Error> {
        let connection = self.connection.lock().expect("trace database poisoned");
        connection.query_row(
            "SELECT COUNT(*)
             FROM query_traces
             WHERE (?1 IS NULL OR pool = ?1)
               AND (?2 IS NULL OR user_name = ?2)
               AND (?3 IS NULL OR status = ?3)
               AND (?4 IS NULL OR sql_text LIKE '%' || ?4 || '%' OR application LIKE '%' || ?4 || '%')
               AND duration_us >= ?5",
            params![
                filter.pool.as_deref(),
                filter.user.as_deref(),
                filter.status.as_deref(),
                filter.q.as_deref(),
                filter.min_duration_ms.unwrap_or(0).saturating_mul(1_000) as i64,
            ],
            |row| row.get(0),
        )
    }

    pub fn record_failure(
        &self,
        context: &TraceContext,
        operation: impl Into<String>,
        waited: Duration,
        code: impl Into<String>,
        message: impl Into<String>,
    ) {
        if context.level.is_off() {
            return;
        }
        let duration_us = waited.as_micros() as u64;
        let completed = CompletedTrace {
            summary: TraceSummary {
                id: self.next_id.fetch_add(1, Ordering::Relaxed),
                started_at_ms: now_ms().saturating_sub(waited.as_millis() as i64),
                duration_us,
                wait_us: duration_us,
                execution_us: 0,
                pool: context.pool.clone(),
                user: context.user.clone(),
                application: context.application.clone(),
                client_addr: context.client_addr.clone(),
                sql: operation.into(),
                status: "failed".into(),
                target: None,
                backend_pid: None,
                command_tag: None,
                row_count: 0,
                result_truncated: false,
                error_code: Some(code.into()),
                error_message: Some(message.into()),
            },
            result: QueryResult { omitted: !context.level.captures_results(), ..QueryResult::default() },
        };
        if self.completed_tx.send(completed).is_err() {
            tracing::error!("query trace writer stopped");
        }
    }

    pub fn get(&self, id: u64) -> Result<Option<TraceDetail>, rusqlite::Error> {
        let connection = self.connection.lock().expect("trace database poisoned");
        connection
            .query_row(
                "SELECT id, started_at_ms, duration_us, wait_us, execution_us, pool, user_name,
                        application, client_addr, sql_text, status, target, backend_pid, command_tag,
                        row_count, result_truncated, error_code, error_message, result_json
                 FROM query_traces WHERE id = ?1",
                [id],
                |row| {
                    let result_json: String = row.get(18)?;
                    let result = serde_json::from_str(&result_json).unwrap_or_default();
                    Ok(TraceDetail { summary: summary_from_row(row)?, result })
                },
            )
            .optional()
    }

    pub fn clear(&self) -> Result<usize, rusqlite::Error> {
        self.connection.lock().expect("trace database poisoned").execute("DELETE FROM query_traces", [])
    }

    fn assign(&self, id: u64, target: String, backend_pid: Option<u32>) {
        if let Some(entry) = self.active.write().expect("trace registry poisoned").get_mut(&id) {
            entry.public.phase = "running".into();
            entry.public.target = Some(target);
            entry.public.backend_pid = backend_pid;
            entry.public.cancellable = entry.cancel.is_some();
        }
    }

    fn arm_cancel(&self, id: u64, hook: Arc<dyn CancelHook>) {
        if let Some(entry) = self.active.write().expect("trace registry poisoned").get_mut(&id) {
            entry.public.cancellable = entry.public.phase == "running";
            entry.cancel = Some(hook);
        }
    }

    /// How to interrupt a query that is running right now.
    ///
    /// Returns the hook rather than doing the cancelling, because delivering it
    /// means opening a socket and this lock must not be held across an await.
    /// `None` covers every way the answer is "nothing to do": an id that never
    /// existed, a query that finished while the operator was reading the screen,
    /// or a family with no way to cancel.
    pub fn cancel_hook(&self, id: u64) -> Option<Arc<dyn CancelHook>> {
        self.active.read().expect("trace registry poisoned").get(&id)?.cancel.clone()
    }

    fn complete(&self, span: &mut TraceSpan, status: &str, error: Option<(String, String)>) {
        if span.finished {
            return;
        }
        span.finished = true;
        let Some(entry) = self.active.write().expect("trace registry poisoned").remove(&span.id) else {
            return;
        };
        let duration_us = span.started.elapsed().as_micros() as u64;
        let captured_error = span.capture.error.clone();
        let error = error.or(captured_error);
        let final_status = if error.is_some() { "failed" } else { status };
        let summary = TraceSummary {
            id: span.id,
            started_at_ms: entry.public.started_at_ms,
            duration_us,
            wait_us: span.wait_us,
            execution_us: duration_us.saturating_sub(span.wait_us),
            pool: entry.public.pool,
            user: entry.public.user,
            application: entry.public.application,
            client_addr: entry.public.client_addr,
            sql: entry.public.sql,
            status: final_status.into(),
            target: entry.public.target,
            backend_pid: entry.public.backend_pid,
            command_tag: span.capture.command_tag.clone(),
            row_count: span.capture.row_count,
            result_truncated: span.capture.truncated,
            error_code: error.as_ref().map(|value| value.0.clone()),
            error_message: error.map(|value| value.1),
        };
        let mut result = std::mem::take(&mut span.capture.result);
        result.omitted = !span.capture.keep_rows;
        let completed = CompletedTrace { summary, result };
        if self.completed_tx.send(completed).is_err() {
            tracing::error!(trace_id = span.id, "query trace writer stopped");
        }
    }
}

pub struct TraceSpan {
    store: Arc<TraceStore>,
    id: u64,
    started: Instant,
    wait_us: u64,
    capture: ResultCapture,
    finished: bool,
}

impl TraceSpan {
    pub fn assign(&mut self, target: impl Into<String>, backend_pid: Option<u32>) {
        self.wait_us = self.started.elapsed().as_micros() as u64;
        self.store.assign(self.id, target.into(), backend_pid);
    }

    /// Declare this query interruptible, and how.
    ///
    /// The hook is dropped with the active entry when the query completes, so
    /// an operator can never cancel a query that has already finished — and, in
    /// transaction mode, can never reach a backend the client has given back.
    pub fn arm_cancel(&mut self, hook: Arc<dyn CancelHook>) {
        if self.finished {
            return;
        }
        self.store.arm_cancel(self.id, hook);
    }

    /// Start a new result set. The family supplies already-decoded column
    /// names; how it got them from the wire is its own business.
    pub fn begin_result_set(&mut self, columns: Vec<String>) {
        self.capture.begin_result_set(columns);
    }

    /// Offer one row. Silently dropped once the sample is full — a trace must
    /// never be the reason a large result set costs memory.
    pub fn push_row(&mut self, row: Vec<Option<String>>) {
        self.capture.push_row(row);
    }

    /// Close the current result set with the protocol's completion tag and the
    /// number of rows the server said it affected.
    pub fn command_complete(&mut self, tag: impl Into<String>, rows: u64) {
        self.capture.command_complete(tag.into(), rows);
    }

    /// Record a backend error. The last one wins, matching what the client saw.
    pub fn record_error(&mut self, code: impl Into<String>, message: impl Into<String>) {
        self.capture.record_error(code.into(), message.into());
    }

    pub fn succeed(mut self) {
        let store = self.store.clone();
        store.complete(&mut self, "succeeded", None);
    }

    pub fn fail(mut self, code: impl Into<String>, message: impl Into<String>) {
        let store = self.store.clone();
        store.complete(&mut self, "failed", Some((code.into(), message.into())));
    }
}

impl Drop for TraceSpan {
    fn drop(&mut self) {
        if !self.finished {
            let store = self.store.clone();
            store.complete(self, "cancelled", None);
        }
    }
}

#[derive(Default)]
struct ResultCapture {
    /// False under [`TraceLevel::Statements`]: columns and rows are dropped as
    /// they arrive rather than being collected and discarded later, so a pool
    /// that does not want its data kept never holds it in the first place.
    keep_rows: bool,
    result: QueryResult,
    current_set: Option<usize>,
    row_count: u64,
    captured_rows: usize,
    bytes: usize,
    truncated: bool,
    command_tag: Option<String>,
    error: Option<(String, String)>,
}

impl ResultCapture {
    fn new(keep_rows: bool) -> Self {
        Self { keep_rows, ..Self::default() }
    }

    fn begin_result_set(&mut self, columns: Vec<String>) {
        if !self.keep_rows {
            return;
        }
        self.result.sets.push(ResultSet { columns, ..ResultSet::default() });
        self.current_set = Some(self.result.sets.len() - 1);
    }

    fn command_complete(&mut self, tag: String, rows: u64) {
        // The tag and the row count are facts about the statement, not the data
        // it returned, so they survive at every level: "UPDATE 4000" is exactly
        // the sort of thing you want to see without wanting the 4000 rows.
        self.row_count = self.row_count.saturating_add(rows);
        self.command_tag = Some(tag.clone());
        if !self.keep_rows {
            return;
        }
        let index = match self.current_set {
            Some(index) => index,
            None => {
                self.result.sets.push(ResultSet::default());
                self.result.sets.len() - 1
            }
        };
        self.result.sets[index].command_tag = Some(tag);
        self.current_set = None;
    }

    fn record_error(&mut self, code: String, message: String) {
        self.error = Some((code, message));
    }

    fn push_row(&mut self, row: Vec<Option<String>>) {
        if !self.keep_rows {
            // Not truncation: nothing was ever going to be kept, and saying
            // "truncated" would read as "there was more" instead of "there was
            // none of it".
            return;
        }
        if self.captured_rows >= MAX_RESULT_ROWS || self.bytes >= MAX_RESULT_BYTES {
            self.truncated = true;
            return;
        }
        let row_bytes: usize = row.iter().flatten().map(String::len).sum();
        if self.bytes.saturating_add(row_bytes) > MAX_RESULT_BYTES {
            self.truncated = true;
            return;
        }
        let index = match self.current_set {
            Some(index) => index,
            None => {
                self.result.sets.push(ResultSet::default());
                let index = self.result.sets.len() - 1;
                self.current_set = Some(index);
                index
            }
        };
        self.bytes += row_bytes;
        self.captured_rows += 1;
        self.result.sets[index].rows.push(row);
        if self.captured_rows >= MAX_RESULT_ROWS {
            self.truncated = true;
        }
    }
}

fn insert_traces(connection: &Mutex<Connection>, traces: &[CompletedTrace]) -> Result<(), rusqlite::Error> {
    let mut connection = connection.lock().expect("trace database poisoned");
    let transaction = connection.transaction()?;
    {
        let mut statement = transaction.prepare(
            "INSERT INTO query_traces (
             id, started_at_ms, duration_us, wait_us, execution_us, pool, user_name, application,
             client_addr, sql_text, status, target, backend_pid, command_tag, row_count,
             result_truncated, error_code, error_message, result_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
        )?;
        for trace in traces {
            let result_json = serde_json::to_string(&trace.result).unwrap_or_else(|_| "{\"sets\":[]}".into());
            let summary = &trace.summary;
            statement.execute(params![
                summary.id,
                summary.started_at_ms,
                summary.duration_us,
                summary.wait_us,
                summary.execution_us,
                summary.pool,
                summary.user,
                summary.application,
                summary.client_addr,
                summary.sql,
                summary.status,
                summary.target,
                summary.backend_pid,
                summary.command_tag,
                summary.row_count,
                summary.result_truncated,
                summary.error_code,
                summary.error_message,
                result_json,
            ])?;
        }
    }
    transaction.commit()
}

fn summary_from_row(row: &rusqlite::Row<'_>) -> Result<TraceSummary, rusqlite::Error> {
    Ok(TraceSummary {
        id: row.get(0)?,
        started_at_ms: row.get(1)?,
        duration_us: row.get(2)?,
        wait_us: row.get(3)?,
        execution_us: row.get(4)?,
        pool: row.get(5)?,
        user: row.get(6)?,
        application: row.get(7)?,
        client_addr: row.get(8)?,
        sql: row.get(9)?,
        status: row.get(10)?,
        target: row.get(11)?,
        backend_pid: row.get(12)?,
        command_tag: row.get(13)?,
        row_count: row.get(14)?,
        result_truncated: row.get(15)?,
        error_code: row.get(16)?,
        error_message: row.get(17)?,
    })
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> TraceContext {
        context_at(TraceLevel::Full)
    }

    fn context_at(level: TraceLevel) -> TraceContext {
        TraceContext {
            pool: "app_main".into(),
            user: "svc_orders".into(),
            application: Some("orders-api".into()),
            client_addr: "127.0.0.1:1234".into(),
            level,
        }
    }

    fn wait_for_history(store: &TraceStore) {
        for _ in 0..50 {
            if !store.list(&TraceFilter::default()).unwrap().is_empty() {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("trace writer did not flush");
    }

    #[test]
    fn active_query_becomes_completed_history() {
        let store = TraceStore::memory();
        let mut span = store.begin(&context(), "select 42 as answer");
        assert_eq!(store.active()[0].phase, "waiting");
        span.assign("primary/127.0.0.1:5432", Some(42));
        span.begin_result_set(vec!["answer".into()]);
        span.push_row(vec![Some("42".into())]);
        span.command_complete("SELECT 1", 1);
        span.succeed();

        assert!(store.active().is_empty());
        wait_for_history(&store);
        let summary = &store.list(&TraceFilter::default()).unwrap()[0];
        assert_eq!(summary.status, "succeeded");
        assert_eq!(summary.row_count, 1);
        assert_eq!(summary.backend_pid, Some(42));
        let detail = store.get(summary.id).unwrap().unwrap();
        assert_eq!(detail.result.sets[0].columns, ["answer"]);
        assert_eq!(detail.result.sets[0].rows[0], [Some("42".into())]);
    }

    #[derive(Debug, Default)]
    struct RecordingHook {
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl CancelHook for RecordingHook {
        async fn cancel(&self) -> Result<(), String> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn an_armed_query_can_be_cancelled_while_it_runs() {
        let store = TraceStore::memory();
        let hook = Arc::new(RecordingHook::default());

        let mut span = store.begin(&context(), "select pg_sleep(600)");
        span.arm_cancel(hook.clone());
        assert!(!store.active()[0].cancellable, "nothing to cancel while it queues for a backend");

        span.assign("primary/127.0.0.1:5432", Some(42));
        assert!(store.active()[0].cancellable, "a query on a backend is interruptible");

        store.cancel_hook(store.active()[0].id).expect("armed").cancel().await.expect("delivered");
        assert_eq!(hook.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_finished_query_stops_being_cancellable() {
        // Otherwise an operator reading a one-second-old screen could press
        // cancel on a query that already returned — and in transaction mode the
        // backend it ran on may belong to somebody else by then.
        let store = TraceStore::memory();
        let mut span = store.begin(&context(), "select 1");
        span.arm_cancel(Arc::new(RecordingHook::default()));
        span.assign("primary/127.0.0.1:5432", Some(42));
        let id = store.active()[0].id;

        span.succeed();
        assert!(store.cancel_hook(id).is_none(), "a completed query must not remain cancellable");
    }

    #[test]
    fn a_query_nobody_can_cancel_says_so() {
        // A family with no cancellation of its own, or a pool whose backend
        // never sent a key pair. The dashboard needs to know not to offer the
        // button rather than offering one that always fails.
        let store = TraceStore::memory();
        let mut span = store.begin(&context(), "select 1");
        span.assign("primary/127.0.0.1:5432", Some(42));
        assert!(!store.active()[0].cancellable);
        assert!(store.cancel_hook(store.active()[0].id).is_none());
    }

    #[test]
    fn a_recorded_error_turns_a_succeeded_span_into_a_failure() {
        // The relay does not know a statement failed until the backend says so,
        // so the span is always closed with `succeed`; the captured error is
        // what decides the stored status.
        let store = TraceStore::memory();
        let mut span = store.begin(&context(), "select missing");
        span.record_error("42703", "column missing does not exist");
        span.succeed();
        wait_for_history(&store);

        let trace = &store.list(&TraceFilter::default()).unwrap()[0];
        assert_eq!(trace.status, "failed");
        assert_eq!(trace.error_code.as_deref(), Some("42703"));
    }

    #[test]
    fn statements_only_keeps_what_ran_and_none_of_what_came_back() {
        // The distinction the level exists for: timings, tag, row count and
        // outcome are diagnostics; the rows themselves are the customer's data.
        let store = TraceStore::memory();
        let mut span = store.begin(&context_at(TraceLevel::Statements), "select * from patients");
        span.assign("primary/127.0.0.1:5432", Some(42));
        span.begin_result_set(vec!["name".into()]);
        span.push_row(vec![Some("Ada Lovelace".into())]);
        span.command_complete("SELECT 1", 1);
        span.succeed();
        wait_for_history(&store);

        let summary = &store.list(&TraceFilter::default()).unwrap()[0];
        assert_eq!(summary.sql, "select * from patients", "the statement is still the point");
        assert_eq!(summary.row_count, 1, "how many rows came back is not the rows");
        assert_eq!(summary.command_tag.as_deref(), Some("SELECT 1"));
        assert_eq!(summary.backend_pid, Some(42));
        assert!(!summary.result_truncated, "nothing was truncated; nothing was collected");

        let detail = store.get(summary.id).unwrap().unwrap();
        assert!(detail.result.sets.is_empty());
        assert!(detail.result.omitted, "an empty result must be distinguishable from a withheld one");
    }

    #[test]
    fn tracing_off_records_nothing_at_all() {
        let store = TraceStore::memory();
        let context = context_at(TraceLevel::Off);
        let mut span = store.begin(&context, "select 42");
        assert!(store.active().is_empty(), "a pool with tracing off does not appear under 'running now'");
        span.assign("primary/127.0.0.1:5432", Some(42));
        span.push_row(vec![Some("42".into())]);
        span.command_complete("SELECT 1", 1);
        span.succeed();
        store.record_failure(&context, "connection checkout", Duration::from_secs(5), "53300", "pool exhausted");

        // Nothing is queued, so there is nothing to wait for; give the writer a
        // chance to prove it would have flushed.
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(store.list(&TraceFilter::default()).unwrap().is_empty());
        assert_eq!(store.count(&TraceFilter::default()).unwrap(), 0);
    }

    #[test]
    fn a_cancelled_span_from_a_silent_pool_is_not_resurrected_by_drop() {
        // `Drop` is what records an abandoned statement. An inert span must not
        // use that path to write the trace its pool asked not to have.
        let store = TraceStore::memory();
        drop(store.begin(&context_at(TraceLevel::Off), "select 42"));
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(store.list(&TraceFilter::default()).unwrap().is_empty());
    }

    #[test]
    fn a_result_stored_before_the_setting_existed_reads_as_captured() {
        let old: QueryResult = serde_json::from_str(r#"{"sets":[]}"#).unwrap();
        assert!(!old.omitted, "backfilling 'withheld' onto traces that were captured would be a lie");
    }

    #[test]
    fn filters_and_clear_are_applied_by_sqlite() {
        let store = TraceStore::memory();
        store.begin(&context(), "select 1").succeed();
        wait_for_history(&store);

        let matches = store
            .list(&TraceFilter { pool: Some("app_main".into()), q: Some("select".into()), ..Default::default() })
            .unwrap();
        assert_eq!(matches.len(), 1);
        assert!(store
            .list(&TraceFilter { user: Some("someone_else".into()), ..Default::default() })
            .unwrap()
            .is_empty());
        assert_eq!(store.clear().unwrap(), 1);
    }

    #[test]
    fn history_count_and_offset_support_pagination() {
        let store = TraceStore::memory();
        for sql in ["select 1", "select 2", "select 3"] {
            store.begin(&context(), sql).succeed();
        }
        wait_for_history(&store);

        let filter = TraceFilter { limit: Some(1), offset: Some(1), ..Default::default() };
        assert_eq!(store.count(&filter).unwrap(), 3);
        assert_eq!(store.list(&filter).unwrap().len(), 1);
    }

    #[test]
    fn failures_before_a_query_are_persisted() {
        let store = TraceStore::memory();
        store.record_failure(&context(), "connection checkout", Duration::from_secs(5), "53300", "pool exhausted");
        wait_for_history(&store);

        let trace = &store.list(&TraceFilter::default()).unwrap()[0];
        assert_eq!(trace.sql, "connection checkout");
        assert_eq!(trace.status, "failed");
        assert_eq!(trace.wait_us, 5_000_000);
        assert_eq!(trace.execution_us, 0);
        assert_eq!(trace.error_code.as_deref(), Some("53300"));
    }

    #[test]
    fn result_capture_is_bounded() {
        // A trace must never be the reason a large result set costs memory.
        let mut capture = ResultCapture::new(true);
        capture.begin_result_set(vec!["value".into()]);
        for _ in 0..MAX_RESULT_ROWS + 10 {
            capture.push_row(vec![Some("x".into())]);
        }
        assert_eq!(capture.result.sets[0].rows.len(), MAX_RESULT_ROWS);
        assert!(capture.truncated);
    }

    #[test]
    fn the_byte_budget_truncates_before_the_row_budget_does() {
        let mut capture = ResultCapture::new(true);
        capture.begin_result_set(vec!["blob".into()]);
        let big = "x".repeat(MAX_RESULT_BYTES / 2 + 1);
        capture.push_row(vec![Some(big.clone())]);
        capture.push_row(vec![Some(big)]);
        assert_eq!(capture.result.sets[0].rows.len(), 1, "the second row would blow the byte budget");
        assert!(capture.truncated);
    }

    #[test]
    fn rows_arriving_without_a_description_still_land_in_a_set() {
        let mut capture = ResultCapture::new(true);
        capture.push_row(vec![Some("orphan".into())]);
        capture.command_complete("SELECT 1".into(), 1);
        assert_eq!(capture.result.sets.len(), 1);
        assert_eq!(capture.result.sets[0].command_tag.as_deref(), Some("SELECT 1"));
    }

    #[cfg(unix)]
    #[test]
    fn persistent_trace_database_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("traces.sqlite3");
        let _store = TraceStore::open(&path).unwrap();
        assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
