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
}

export interface Pool {
  name: string;
  family: string;
  profile: string | null;
  mode: PoolMode;
  database: string;
  backend_user: string;
  listen_port: number | null;
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
  runtime: PoolSnapshot | null;
}

export type Warning =
  | { kind: "session_mode_queues"; pool: string; max_client_connections: number; max_size: number }
  | { kind: "backends_exceed_clients"; pool: string; max_client_connections: number; max_size: number }
  | { kind: "pool_without_users"; pool: string }
  | { kind: "split_without_replicas"; pool: string }
  | { kind: "no_sticky_window"; pool: string };

export interface Summary {
  uptime_seconds: number;
  pools: number;
  users: number;
  client_connections: number;
  backend_connections: number;
  fan_in: number | null;
  warnings: Warning[];
  pool_snapshots: PoolSnapshot[];
}

export interface User {
  name: string;
  pools: string[];
  max_client_connections: number;
  read_only: boolean;
  disabled: boolean;
  description: string | null;
  has_password: boolean;
}

export interface DriverProfile {
  id: string;
  label: string;
  maturity: "stable" | "beta" | "experimental" | "planned";
  default_port: number | null;
}

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
}

export interface FamilySchema {
  properties: Record<string, SchemaProperty>;
  required: string[];
  "x-havuz-order": string[];
}

export interface Family {
  id: string;
  label: string;
  description: string;
  maturity: string;
  usable: boolean;
  default_port: number;
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
  result: { sets: TraceResultSet[] };
}

export interface TraceResponse {
  active: ActiveTrace[];
  holders: BackendHolder[];
  pool_snapshots: PoolSnapshot[];
  traces: TraceSummary[];
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
