// Mirrors the JSON the admin API serves. Kept hand-written and small rather
// than generated, so the shape stays visible at review time.

export type PoolMode = "session" | "transaction" | "statement";

export interface WaitStats {
  samples: number;
  mean_micros: number;
  max_micros: number;
}

export interface PoolSnapshot {
  name: string;
  status: string;
  active: number;
  idle: number;
  open: number;
  waiting: number;
  max_size: number;
  max_client_connections: number;
  created_total: number;
  closed_total: number;
  checkout_total: number;
  timeout_total: number;
  connect_error_total: number;
  discarded_total: number;
  wait: WaitStats;
}

export interface Target {
  host: string;
  port: number;
  role: "primary" | "replica";
  weight: number;
}

export interface PoolLimits {
  max_size: number;
  min_idle: number;
  max_client_connections: number;
  queue_timeout: string;
  connect_timeout: string;
  idle_timeout: string;
  max_lifetime: string;
  /**
   * How long a client may sit inside an open transaction before its session is
   * ended. "0s" means no limit, which is the default.
   *
   * Only enforced in transaction and statement mode. In session mode the client
   * owns its backend for the whole session anyway.
   */
  idle_in_transaction_timeout: string;
}

/**
 * Whose credentials backend connections are opened with.
 *
 * `passthrough` is `per_user` plus one more case: a client havuz has no user
 * record for is admitted if the database accepts its credentials. That is what
 * lets a pool exist with no stored backend credential at all, and it is why
 * such a pool carries a standing warning.
 */
export type BackendAuth = "shared" | "per_user" | "passthrough";

/**
 * How much of a pool's traffic reaches the query trace store.
 *
 * Not a boolean, because keeping *what ran* and keeping *what came back* are
 * different decisions: the first is diagnostics, the second is a sample of
 * production data with a life of its own.
 */
export type TraceLevel = "off" | "statements" | "full";

export interface Pool {
  name: string;
  family: string;
  profile: string | null;
  mode: PoolMode;
  database: string;
  backend_user: string;
  backend_auth: BackendAuth;
  /**
   * Whether this pool will ask for a password on an unencrypted socket.
   *
   * Only meaningful under per-user auth, which is the only mode that asks for
   * one at all. What crosses that socket is a working database credential, not
   * a pooler password.
   */
  allow_password_without_tls: boolean;
  /**
   * Whether every session through this pool is opened read-only, whoever
   * connects.
   *
   * A property of the route rather than of a person, unlike User.read_only.
   * The two combine by OR, so this can only ever take permissions away.
   */
  read_only: boolean;
  trace: TraceLevel;
  /** The port clients reach this pool on. Pools may share one. */
  listen_port: number;
  /**
   * Extra names clients may put in their database field to reach this pool.
   *
   * Only meaningful once a second pool shares the port: with one pool the
   * database field is ignored entirely.
   */
  aliases: string[];
  /** Whether a password is stored. The password itself is never served. */
  has_backend_password: boolean;
  targets: Target[];
  limits: PoolLimits;
  settings: Record<string, unknown>;
  disabled: boolean;
  description: string | null;
  routing: RoutingConfig;
  replica_count: number;
  /** Null in session mode, where multiplexing cannot happen. */
  configured_fan_in: number | null;
  /**
   * Total backend connections this pool may open, or null under per-user
   * authentication where max_size is a per-user budget and the ceiling depends
   * on how many users are connected at once.
   */
  backend_ceiling: number | null;
  runtime: PoolSnapshot | null;
}

/** One user running as its own database role. */
export interface BackendIdentity {
  pool: string;
  user: string;
  pool_snapshot: PoolSnapshot;
}

export interface PoolIdentities {
  pool: string;
  backend_auth: BackendAuth;
  max_size_is_per_user: boolean;
  identities: BackendIdentity[];
}

export type Warning =
  | { kind: "session_mode_queues"; pool: string; max_client_connections: number; max_size: number }
  | { kind: "backends_exceed_clients"; pool: string; max_client_connections: number; max_size: number }
  | { kind: "pool_without_users"; pool: string }
  | { kind: "split_without_replicas"; pool: string }
  | { kind: "no_sticky_window"; pool: string }
  | { kind: "read_only_not_enforced"; pool: string; pool_wide: boolean; users: string[] }
  | { kind: "idle_timeout_in_session_mode"; pool: string }
  | { kind: "users_without_backend_role"; pool: string; users: string[] }
  | { kind: "password_without_tls"; pool: string }
  | { kind: "passthrough_pool"; pool: string };

export interface Summary {
  uptime_seconds: number;
  pools: number;
  users: number;
  client_connections: number;
  backend_connections: number;
  fan_in: number | null;
  /**
   * Whether the client-facing listeners can offer TLS at all. Process-level, so
   * it cannot be changed from here — it decides whether a per-user pool needs
   * allow_password_without_tls to accept anyone.
   */
  client_tls: boolean;
  warnings: Warning[];
  pool_snapshots: PoolSnapshot[];
}

export interface User {
  name: string;
  pools: string[];
  max_client_connections: number;
  /**
   * Connects to the database as itself rather than as the pool's service
   * account. Only takes effect on pools with backend_auth = per_user.
   */
  own_backend_role: boolean;
  read_only: boolean;
  disabled: boolean;
  description: string | null;
  has_password: boolean;
  /** Sessions this user has attached right now. */
  live_sessions: number;
}

/** A client session currently attached to havuz. */
export interface LiveSession {
  id: number;
  user: string;
  pool: string;
  application: string | null;
  client_addr: string;
  since_ms: number;
  elapsed_us: number;
}

export interface DriverProfile {
  id: string;
  label: string;
  maturity: "stable" | "beta" | "experimental" | "planned";
  default_port: number | null;
}

/** What a field means to the pooler, as opposed to what the family calls it. */
export type FieldRole = "host" | "port" | "database" | "user" | "password";

export interface SchemaProperty {
  title?: string;
  type?: string;
  description?: string;
  default?: unknown;
  enum?: string[];
  minimum?: number;
  maximum?: number;
  format?: string;
  "x-havuz-placeholder"?: string;
  "x-havuz-secret"?: boolean;
  "x-havuz-labels"?: { value: string; label: string }[];
  /**
   * Present on the handful of fields the pooler itself needs. The form uses it
   * for grouping and to tell which fields the backend identity choice makes
   * optional; the server reads the values back through the same roles, so
   * nothing here has to know that Postgres spells the backend account
   * `username`.
   */
  "x-havuz-role"?: FieldRole;
}

export interface FamilySchema {
  properties: Record<string, SchemaProperty>;
  required: string[];
  "x-havuz-order": string[];
}

/** What the family's wire protocol and driver actually support. */
export interface Capabilities {
  tls: boolean;
  scram_sha256: boolean;
  md5_auth: boolean;
  /** Backend connections can be opened as the connecting client. */
  per_user_auth: boolean;
  prepared_statements: boolean;
  /**
   * A session can be opened read-only and held that way. False means the pool's
   * read_only flag is refused rather than accepted and ignored.
   */
  read_only_sessions: boolean;
  cancel_request: boolean;
  bulk_copy: boolean;
  reports_transaction_status: boolean;
  listen_notify: boolean;
  advisory_locks: boolean;
}

export interface Family {
  id: string;
  label: string;
  description: string;
  maturity: string;
  usable: boolean;
  default_port: number;
  capabilities: Capabilities;
  pool_modes: PoolMode[];
  default_pool_mode: PoolMode;
  profiles: DriverProfile[];
  /** The form is rendered from this, so a new family needs no UI change. */
  schema: FamilySchema;
}

export type PinReason =
  | "session_parameter"
  | "listen"
  | "temp_table"
  | "advisory_lock"
  | "server_side_prepare"
  | "holdable_cursor"
  | "bulk_transfer"
  | "replication"
  | "unclassified";

export interface ReasonCount {
  reason: PinReason;
  count: number;
}

export interface PinOffender {
  user: string;
  application: string;
  reason: PinReason;
  /** Whether changing the application can plausibly fix this. */
  actionable: boolean;
  count: number;
  first_seen_secs_ago: number;
  last_seen_secs_ago: number;
}

export interface PinReport {
  pinned_sessions: number;
  clean_sessions: number;
  pin_rate: number | null;
  by_reason: ReasonCount[];
  offenders: PinOffender[];
  /** Detail was capped; by_reason is still exact. */
  truncated: boolean;
}

export type PrimaryReason =
  | "split_disabled"
  | "write"
  | "read_after_write"
  | "transaction_pinned"
  | "no_replica_available";

export interface BreakerSnapshot {
  state: "closed" | "open" | "half_open";
  failures_total: number;
  trips_total: number;
  rejected_total: number;
}

export interface ReplicaSnapshot {
  label: string;
  weight: number;
  /** Null means never measured, which is not the same as caught up. */
  lag_millis: number | null;
  breaker: BreakerSnapshot;
  pool: PoolSnapshot;
}

export interface RoutingSnapshot {
  to_primary: number;
  to_replica: number;
  replica_share: number | null;
  primary_reasons: { reason: PrimaryReason; count: number }[];
}

export interface GroupSnapshot {
  name: string;
  mode: PoolMode;
  read_write_split: boolean;
  primary: { label: string; pool: PoolSnapshot };
  replicas: ReplicaSnapshot[];
  routing: RoutingSnapshot;
}

export interface RoutingConfig {
  read_write_split: boolean;
  sticky_after_write: string;
  max_replica_lag: string | null;
  health_interval: string;
  failure_threshold: number;
  recovery_cooldown: string;
}

export interface ActiveTrace {
  id: number;
  started_at_ms: number;
  elapsed_us: number;
  pool: string;
  user: string;
  application: string | null;
  client_addr: string;
  sql: string;
  phase: "waiting" | "running";
  target: string | null;
  backend_pid: number | null;
  /** Whether this query can be interrupted right now. False while it is still queueing for a backend. */
  cancellable: boolean;
}

export interface TraceSummary {
  id: number;
  started_at_ms: number;
  duration_us: number;
  wait_us: number;
  execution_us: number;
  pool: string;
  user: string;
  application: string | null;
  client_addr: string;
  sql: string;
  status: "succeeded" | "failed" | "cancelled";
  target: string | null;
  backend_pid: number | null;
  command_tag: string | null;
  row_count: number;
  result_truncated: boolean;
  error_code: string | null;
  error_message: string | null;
}

export interface TraceResultSet {
  columns: string[];
  rows: (string | null)[][];
  command_tag: string | null;
}

export interface TraceDetail extends TraceSummary {
  result: {
    sets: TraceResultSet[];
    /** The pool records statements only, so no sets is "not kept", not "none". */
    omitted: boolean;
  };
}

export interface TraceResponse {
  active: ActiveTrace[];
  holders: BackendHolder[];
  pool_snapshots: PoolSnapshot[];
  traces: TraceSummary[];
  pagination: { total: number; limit: number; offset: number };
  retention_days: number;
  result_limits: { rows: number; bytes: number };
}

export interface BackendHolder {
  id: number;
  since_ms: number;
  elapsed_us: number;
  pool: string;
  user: string;
  application: string | null;
  client_addr: string;
  mode: PoolMode;
  reason: "startup_wait" | "session_mode" | "idle_in_transaction" | "pinned";
  pin_reason: PinReason | null;
  target: string | null;
  backend_pid: number | null;
}
