# havuz

A PostgreSQL connection pooler with a dashboard.

The point of a pooler is one number: how many application connections you can
serve from how few database connections. havuz puts that number on the front
page and tells you when your configuration cannot deliver it.

```
12 concurrent clients  ->  havuz  ->  3 PostgreSQL connections
```

## Status

Phases 1 and 2 are done. Session and transaction mode both work against a real
PostgreSQL, with pin analysis on top.

| Area | State |
|---|---|
| PostgreSQL wire protocol v3 | working |
| SCRAM-SHA-256, client and backend side | working, verified against RFC 7677 vectors |
| TLS, all five `sslmode` levels | working |
| Query cancellation with remapped keys | working |
| Session-mode pooling | working |
| Transaction-mode pooling | working |
| Pin analysis | working |
| Admin API, Prometheus, dashboard | working |
| Prepared statement rewriting | working |
| Read/write split with read-after-write safety | working |
| Replica health, lag gating, circuit breaker | working |
| MySQL, Redis, JDBC bridge | not yet, visible in the UI as planned |

### Measured

Against PostgreSQL 16, release build, `pgbench -S`:

| Test | Result |
|---|---|
| 30 concurrent clients, `max_size = 3` | 81,064 transactions served by **3** backend connections, 0 timeouts |
| Same, with `-M prepared` (named statements) | 80,716 transactions, **0 failed**, still 3 connections |
| Added latency at equal concurrency | **+0.061 ms** (0.339 ms direct vs 0.400 ms through havuz) |
| 20 sequential sessions, session mode | 1 backend connection |
| Read-after-write, 20 cycles through a real standby | **0 rows lost** |
| Replica killed mid-flight, 10 reads | **0 client-visible errors**, breaker tripped |

The honest caveat: at 30 clients over 3 backends, throughput is 7.5k tps rather
than the 143k a direct 30-connection benchmark reports. That is queueing, not
overhead — you asked for 3 connections and you got 3. The `+0.061 ms` figure is
the number that measures havuz itself.

## Quick start

```sh
cargo build --release
export HAVUZ_MASTER_KEY=$(./target/release/havuz keygen)
cp havuz.example.toml havuz.toml
./target/release/havuz run
```

Open <http://127.0.0.1:7432>, add a database, create a user, then connect:

```sh
psql "postgresql://svc_orders:yourpassword@127.0.0.1:5432/app_main"
```

The dashboard is served from the binary when built with
`--features havuz-admin/embed-ui`, or from disk via `HAVUZ_UI_DIR=ui/dist`.

## How it is put together

```
crates/
  havuz-registry   Database families as data. UI forms are generated from this,
                   so adding a family never touches the frontend.
  havuz-secrets    AES-256-GCM secret store. Credentials entered in the UI
                   cannot live in an environment variable.
  havuz-core       Bootstrap config, runtime state, atomic persistence, TLS.
  havuz-proto      The seam every protocol family plugs into.
  havuz-pool       Protocol-agnostic pool engine.
  havuz-pg         PostgreSQL: framing, SCRAM, backend, session, relay, cancel.
  havuz-admin      HTTP API, Prometheus, dashboard serving.
  havuz-server     The binary.
ui/                Svelte + Vite dashboard (22 kB gzipped).
```

### The feature that does not exist elsewhere

Transaction-mode pooling degrades silently. A pool configured for 100 clients
over 3 backends will happily run as 100-over-100 if the application issues `SET
application_name` on connect, and every pooler dashboard in existence will show
a healthy pool the whole time.

havuz classifies every statement that leaves something behind on a connection —
`SET`, `LISTEN`, temp tables, session advisory locks, `PREPARE`, holdable
cursors — and reports who did it:

```
GET /api/v1/pins

pin rate 50%: 2 pinned / 2 clean
  session_parameter  2   svc_orders/orders-api
  listen             1   svc_orders/notifier
```

That is a sentence an operator can act on, rather than "your pool is full".
`havuz_session_pin_rate` is the metric to alert on: above a few percent in
transaction mode, the configured fan-in is fiction.

### Read/write split, and why it is off by default

This is the feature most likely to break an application silently. A misrouted
write fails loudly and gets fixed in minutes. A misrouted *read* returns data
from a replica that has not caught up, so the row you just inserted is simply
not there. No error, no log line, and a bug report that says "sometimes it
doesn't save".

havuz makes it safe with three rules:

* **Anything not provably read-only goes to the primary.** `SELECT ... FOR
  UPDATE`, `SELECT nextval()`, data-modifying CTEs and `EXPLAIN ANALYZE` are all
  writes. Ambiguity always resolves to the primary.
* **After a session writes, its reads follow it** for `sticky_after_write`.
  Insert-then-select keeps working.
* **A transaction never changes target midway.** A plain `BEGIN` goes to the
  primary, because the client has not said what is coming.

What it cannot see: a `SELECT` that calls a function which writes. No proxy can,
short of running the statement. That is a documented limit.

A replica is used only while it is healthy *and* its lag has been measured and
is within `max_replica_lag`. Never measured is not the same as caught up.

### Three decisions worth knowing about

**Clients authenticate against havuz, not against PostgreSQL.** Every backend
connection in a pool uses one service account. This is not a shortcut — it is
the mechanism that makes a backend connection reusable at all. If each client's
own database role were carried through, you would need one pool per role and the
fan-in would collapse to the number of roles. It is also forced: SCRAM cannot be
proxied, because the proof is computed over nonces chosen by both endpoints.

havuz stores a SCRAM verifier per user, never a password, and injects the client
identity into `application_name` so `pg_stat_activity` still attributes work to a
real caller.

**Named prepared statements are rewritten, not pinned.** The extended query
protocol lets a client `Parse` under a name and `Bind` later; asyncpg, JDBC,
Npgsql and pgx all do. In transaction mode that `Bind` can land on a different
backend, and the client gets `prepared statement "s1" does not exist` —
intermittently, under load. havuz renames statements to a content-derived global
name and replays the `Parse` onto any backend that has not seen it. Pinning
instead would be safe but would hand back most of the multiplexing.

**Transaction state comes from the wire, not from SQL.** `ReadyForQuery`
carries a status byte that PostgreSQL computes itself. Inferring boundaries by
looking for `BEGIN` and `COMMIT` means reimplementing the server's rules about
implicit transactions, aborted blocks and savepoints, and being wrong
occasionally. There is also no reset between transactions: that would add a
round trip to every one of them, and it is unnecessary because anything that
dirties a connection is classified as a pin, and pinned connections are never
shared.

**The data path has its own codec.** `tokio-postgres` is a client library: it
parses, buffers and reinterprets. A pooler relays frames. Putting a client
library in the middle adds allocation and semantics that then have to be undone.
`tokio-postgres` is used only on the control plane — health probes and Test
Connection — where a round trip more or less does not matter.

## Configuration

Two planes, deliberately separated:

* `havuz.toml` — listen addresses, TLS, state location. Changing these means
  rebinding sockets, so they require a restart.
* `state.json` — pools, users, sealed secrets. Written by the dashboard and the
  API, validated before every write, persisted atomically.

## Observability

`/metrics` exposes per-pool gauges and counters. The one to alert on is
`havuz_pool_checkout_timeouts_total`: it means clients waited out
`queue_timeout` and were rejected, which is the symptom of `max_size` being too
small for the mode you chose.

`havuz_pool_backend_connections` over the client count is the fan-in you
actually got, as opposed to the one you configured.

`havuz_session_pin_rate` tells you whether transaction mode is doing anything at
all. A pool in transaction mode with a pin rate near 1.0 is a session-mode pool
wearing a disguise.

`havuz_routing_statements_total{target="replica"}` staying at zero while
read/write split is enabled means the replicas are idle;
`havuz_routing_primary_total` says why. `havuz_replica_lag_seconds` reports `-1`
for a replica that has never been measured, because a scrape must not confuse
that with zero.

## Development

```sh
cargo test --workspace          # 300+ tests, no database required
cargo clippy --workspace --all-targets
cd ui && pnpm install && pnpm build
```

Integration tests need a real PostgreSQL and are not part of `cargo test`:

```sh
docker compose -f tests/e2e/docker-compose.yml up -d
./tests/e2e/run.sh                  # pooling, prepared statements, pin detection

./tests/e2e/replica-setup.sh up     # a real streaming standby via pg_basebackup
./tests/e2e/split.sh                # read/write split, lag, failover, recovery
./tests/e2e/replica-setup.sh down
```

The replica suite builds an actual standby rather than a second independent
database. That distinction matters: the entire risk in read/write split is
replication lag, and two unrelated servers have none. It is what caught the LSN
comparison bug described in `health.rs`.

## Licence

Apache-2.0
