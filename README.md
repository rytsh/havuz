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
| Query cancellation with remapped keys | working, retargeted per checkout |
| Operator-initiated query cancellation from the dashboard | working |
| Session-mode pooling | working |
| Transaction-mode pooling | working |
| Pin analysis | working |
| Admin API, Prometheus, dashboard | working |
| Prepared statement rewriting | working |
| Read/write split with read-after-write safety | working |
| Replica health, lag gating, circuit breaker | working |
| Per-pool client ports, rebound without a restart | working |
| Client-facing TLS | working |
| Per-user backend authentication | working |
| Passthrough authentication: no havuz user, no stored backend credential | working |
| Multi-family plumbing: registry-driven, `dyn` all the way to the socket | working, one family shipped |
| JDBC bridge (Oracle, DB2, Informix, …) | working, experimental |
| MySQL, Redis | not yet, visible in the UI as planned |

### Measured

Against PostgreSQL 16, release build, `pgbench -S`. All figures are for a pool
with a shared service account; per-user authentication multiplies backend
connections by the number of connected users by design.

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
(cd ui && pnpm install && pnpm build)
cargo build --release
cp havuz.example.toml havuz.toml
HAVUZ_UI_DIR=ui/dist ./target/release/havuz run
```

Open <http://127.0.0.1:7432>, add a database, create a user, then connect:

```sh
psql "postgresql://svc_orders:yourpassword@127.0.0.1:6432/app_main"
```

### The master key

Backend passwords and client verifiers are sealed under an AES-256 key that
lives outside the state file. havuz looks for it in this order, and stops at the
first one that exists:

| | |
|---|---|
| `$HAVUZ_MASTER_KEY` | base64, from `havuz keygen`. First, so a secret manager need not know what the config file looks like |
| `secrets.master_key` | the same string, inline in `havuz.toml` |
| `secrets.master_key_file` | a path the config points at |
| `<state.dir>/master.key` | left behind by an earlier run |
| generated | written to that same path, unless `secrets.auto_generate = false` |

The last row is why the quick start above has no `export`. It is a convenience
and not a security measure: the key then sits in the same directory as the
ciphertext it opens, so it protects a stolen state *file* and not a stolen state
*directory*. Anywhere the key is meant to come from elsewhere, set
`secrets.auto_generate = false` and a missing key goes back to being a startup
failure.

A key that is present but unreadable — bad base64, wrong length, unreadable file
— is always a hard error and never falls through to the next source. Falling
through would generate a second key and silently orphan everything sealed under
the first.

### Ports belong to pools

There is no process-wide client port. Every pool declares the port it is
reached on, which is the one piece of routing an operator actually thinks
about, and it can be changed from **Databases -> Configure** without restarting
havuz.

Pools may share a port, and that is what the database name is for:

| Pools on the port | What the database name does |
|---|---|
| one | ignored — the connection string may omit it entirely |
| several | picks between them; an unknown name is refused with the list of what is there |

A pool name is an operator's label, not a copy of the database name. A pool may
declare **aliases** — extra names clients are allowed to put in the database
field — which is what keeps the two apart:

```
pool orders_rw   database=orders   aliases=[orders]      # dbname=orders
pool orders_ro   database=orders   aliases=[orders_bi]   # dbname=orders_bi
```

Both sit on one port, over one database, with different pooling modes. Without
aliases only one of them could be called `orders`, and the other would be
unreachable under the name its clients already write. Aliases and pool names
share one namespace per port, because a client sends one string and must reach
one pool; a collision is refused before it is stored rather than resolved by
guessing.

Every pool on a port must belong to the same family, because the listener has
to decide which handshake to run before it has read a byte. The admin port is
reserved, and a disabled pool closes its socket rather than accepting and then
refusing.

This is also what makes a second protocol possible at all: the old shared
listener routed on the startup packet's `database` field, which only Postgres
defines, so no other family could ever have had a socket.

The dashboard is served from the binary when built with
`--features havuz-admin/embed-ui`, or from disk via `HAVUZ_UI_DIR=ui/dist`.

## How it is put together

```
agent/             The JDBC sidecar. Java, no dependencies, built by javac.
crates/
  havuz-registry   Database families as data, including which form field means
                   host, port, database, account and password. UI forms are
                   generated from this and submitted back through it, so adding
                   a family never touches the frontend.
  havuz-secrets    AES-256-GCM secret store and the SCRAM verifier format.
                   Credentials entered in the UI cannot live in an environment
                   variable.
  havuz-core       Bootstrap config, runtime state, atomic persistence, TLS.
  havuz-proto      The data-plane seam: given a socket and the pools behind it,
                   serve the client.
  havuz-pool       Protocol-agnostic pool engine.
  havuz-control    The control-plane seam: four methods about pools, plus the
                   process-wide session, pin, holder and trace registries every
                   family shares.
  havuz-pg         PostgreSQL: framing, SCRAM, backend, session, relay, cancel.
  havuz-jdbc       The JDBC bridge. A PostgreSQL frontend, not a relay: it
                   composes result sets rather than copying them.
  havuz-admin      HTTP API, Prometheus, dashboard serving.
  havuz-server     The binary. Owns every listener.
ui/                Svelte + Vite dashboard.
```

Three rules keep the seam honest, and each of them used to be violated.

**No crate above the seam names a protocol crate.** `havuz-admin` depends on
`havuz-control`, not on `havuz-pg` — not even in its tests, which run against a
protocol-less `FakeFamily`. If the admin API could only be exercised against
Postgres, "the admin API does not depend on Postgres" would be an assertion
nobody was checking.

**Families own no sockets.** `havuz-server` binds every port and hands over
accepted connections. A family that owns listeners owns the process.

**The frontend lifts nothing.** The dashboard sends the connection form
verbatim; the server reads host, port, database, account and password back out
of it through the roles the family declared. Before that, the submit handler
hardcoded five Postgres field names, so the claim was true of the rendering and
false of the submitting.

Families are constructed from the registry, so a descriptor promoted out of
`planned` without a driver behind it fails at startup rather than showing an
enabled card that rejects every pool.

### The feature that does not exist elsewhere

Transaction-mode pooling degrades silently. A pool configured for 100 clients
over 3 backends will happily run as 100-over-100, and every pooler dashboard in
existence will show a healthy pool the whole time.

The usual cause is `SET`. Every driver sends two or three on connect — asyncpg,
JDBC, Npgsql and most ORMs all do — and a pooler that pins on them hands the
whole pool to the first few clients that connect.

**havuz carries session parameters instead of pinning on them.** Each client
keeps the parameters it asked for, each backend remembers the ones it has, and a
checkout that finds a difference sends the delta before the client's statement.
A client that lands back on the backend it just used pays nothing. Startup
parameters, including `?options=-c search_path%3Dapp`, are applied the same way.

What is left over genuinely cannot move: `LISTEN`, temp tables, session advisory
locks, `PREPARE`, holdable cursors, and the handful of `SET` spellings that
cannot be replayed — `SET ROLE`, `SET SESSION AUTHORIZATION`, a value passed as
a bind parameter, or a `SET` inside an open transaction that a `ROLLBACK` might
undo. Those pin, and havuz reports who did it:

```
GET /api/v1/pins

pin rate 50%: 2 pinned / 2 clean
  listen             2   svc_orders/notifier
  temp_table         1   svc_reports/etl
```

That is a sentence an operator can act on, rather than "your pool is full".
`havuz_session_pin_rate` is the metric to alert on: above a few percent in
transaction mode, the configured fan-in is fiction.

### Per-user backend authentication

A pool set to `backend_auth = per_user` opens its connections as the client
rather than as a service account. It is a PostgreSQL-family feature: the JDBC
bridge holds one connection string with one identity in it, so it declares the
capability as absent and the admin API refuses the setting rather than accepting
it and pooling everyone through the service account anyway. Each user gets a set of connections of its
own, so `max_size` becomes a per-user budget:

| | shared | per user |
|---|---|---|
| 10 users × 10 clients, `max_size = 3` | 100 clients → 3 backends | 100 clients → 30 backends |
| fan-in | 33:1 | 10:1 **per user**, 3.3:1 overall |

Fan-in does not disappear; it becomes per-user. Whether that is worth it depends
entirely on whether you need the database to know who is asking.

SCRAM cannot be proxied — the proof is computed over nonces chosen by both
endpoints — so havuz has to hold the plaintext to authenticate outward. It gets
it by asking the client for it directly, and three things follow:

* **It is only asked for over TLS.** A cleartext request on an unencrypted
  socket is refused outright, which is why the client-facing listener needs a
  certificate before such a pool can be created. This is the default, and the
  one part an operator can override — see below.
* **It is checked against havuz's own verifier first**, so a wrong password is
  refused here and never reaches the database. Not overridable by anything.
  Without it, the pool would be a credential-stuffing proxy pointed at
  PostgreSQL.
* **It is never stored.** It lives as long as the user has connections, and goes
  when the last one closes. Rotating it drains the connections opened with the
  old one.

#### Running one without TLS

`allow_password_without_tls` on the pool lifts the first rule. It exists because
the safety of the link is not always havuz's to judge — a loopback socket, a
service mesh that already encrypts, a client that cannot speak TLS at all.

Be clear about what it costs. The password such a pool asks for is not a pooler
password, it is that client's **PostgreSQL** password. Leaking it does not let an
eavesdropper open a session through havuz; it lets them connect to the database
directly and leave havuz out of it entirely — past the pool grants, past
`read_only`, past `disabled`. The setting is therefore off by default, raises a
warning on the dashboard for as long as it is on, logs on every connection that
actually takes the unencrypted path, and cannot be switched back off while it is
the only reason clients can still reach the pool.

Two consequences worth planning for. `min_idle` must be `0`: havuz cannot warm a
connection for a user whose password it does not hold. And the service account
does not disappear — health probes and *Test Connection* run on a timer with no
client attached, so they keep using it, as do users who have not been moved
across.

That last part is the migration path. Flipping a pool to `per_user` changes
nothing until each user is switched over individually on the **Users** page, so
you can move one application at a time and watch what it costs.

#### Passthrough: no havuz user, no stored backend credential

`per_user` still needs a havuz user for everyone who connects — the verifier is
what refuses a wrong password locally, and the grant list, `disabled` and
`read_only` all hang off that same record. `backend_auth = passthrough` keeps
every one of those rules and adds the case they cannot cover: **a client havuz
has never heard of**.

There is nothing local to check such a client against, so havuz asks the only
thing that can answer. It opens one backend connection with the credentials the
client just supplied, and sends `AuthenticationOk` only if that worked. The
result is a pool with no service account, no per-user configuration and no
backend password stored anywhere — every identity is the client's own, proved
by the database.

```toml
# not a config file; this is set per pool from the dashboard or the API
backend_auth = "passthrough"
```

Four things are true of this and none of them are negotiable.

**Configured users come first.** A name that *is* in havuz's user list takes the
same path it always did: its stored verifier, its pool grants, its `disabled`
and `read_only` flags, checked before anything reaches the database. Passthrough
is reached only after that lookup misses. Turning it on therefore takes nothing
away, and a pool can carry both kinds of client at once.

**Only the first attempt reaches PostgreSQL.** Once the database has vouched for
an identity, havuz derives a verifier from the password — with its own salt, so
what it holds is not usable against the database — and keeps it **in memory
only**. From the second connection on, that identity is refused locally exactly
like a configured user. The record is not in the state file, not sealed under
the master key, and not restored on restart; it is dropped by the same idle
sweeper that reclaims the identity's connections and its password, so a rotated
credential stops working rather than living on in a cache.

**A failure is refused at the handshake, not at the first query.** The probe
runs before `AuthenticationOk`, so a bad password is an ordinary `28000` at the
point every client and driver expects one. A database that is *unreachable* is
reported separately, as `57P03` — saying "authentication failed" when the
database is merely down sends people to rotate credentials that work.

**The first attempt is a real database login attempt.** This is the cost, and it
does not go away. Anyone who can reach the port can cause one, under havuz's
source address rather than their own, which means `pg_hba` host rules and your
database's own view of where a login came from are both out of the picture for
that attempt. There is no rate limit and no ceiling on distinct identities yet.
The mode raises a warning on the dashboard for as long as it is on, and that
warning is not a misconfiguration notice — it is the deal.

Everything else follows from `per_user` unchanged: `min_idle` must be `0`,
`max_size` is a per-user budget, client-facing TLS is required unless
`allow_password_without_tls` is set, and `read_write_split` needs a service
account to probe with. The JDBC bridge refuses the setting for the same reason
it refuses `per_user`.

The service account is nevertheless *optional* on such a pool: leave the backend
user and password blank and the pool has no shared identity at all. Every client
then connects as itself or not at all, which is the point of the mode taken to
its conclusion — and worth having, because a service account that exists is a
service account someone can use. The price is the things that have no client to
borrow from: *Test Connection* reports that there is nothing to probe with, a
user still on the shared identity is refused with an error saying so, and
`read_write_split` is rejected outright because replica lag cannot be measured.
Under `backend_auth = shared` the account remains mandatory; there is no other
way in.

### The JDBC bridge, and why it is a different kind of thing

Everything above describes a relay. havuz reads a frame, writes it to a backend
and copies the answer back without understanding it, and every number in this
README follows from that.

**The JDBC bridge does not relay.** JDBC is a Java API, not a wire protocol;
nothing comes back that a PostgreSQL client could read. So havuz parses the
client's statements, runs them through a JVM sidecar, and *composes*
`RowDescription`, `DataRow` and `CommandComplete` itself. It is a PostgreSQL
server rather than a pooler, and that is a different job with different costs.

What it buys is the long tail: Oracle, DB2, Informix, Teradata, Snowflake and
everything else with a JDBC driver and no Rust one, reached with `psql` or any
PostgreSQL client.

```sh
./agent/build.sh          # a 20 kB JAR, no dependencies, javac and jar only
```

The sidecar is deliberately small and deliberately not a pool: one JVM per pool,
one JDBC connection per pooled session on it. A second pool inside the agent
would make the number an operator configured stop being the number the database
sees, which is the one promise a pooler exists to keep.

Three things are worth knowing before turning it on.

**A Java runtime is required**, 17 or newer, on `PATH` or named per pool. havuz
says so at startup rather than failing on the first connection.

**A reset query is required to reuse connections.** JDBC has no portable
equivalent of `DISCARD ALL`, so without one havuz closes a connection rather
than returning it: a temporary table or a changed `search_path` reaching the
next client is a correctness bug, not a tuning choice. Set `DISCARD ALL` for
PostgreSQL and whatever your database calls one elsewhere.

**Session mode only.** Transaction mode would need session state — schema,
isolation level, autocommit — carried between backends, and that is a decision
worth making with a second database in hand rather than in advance.

What is checkable, and checked: `tests/e2e/jdbc.sh` puts PostgreSQL behind the
bridge, which looks like a strange choice for a feature about databases that are
not PostgreSQL. It is the only choice that makes the answer verifiable. Every
query runs twice, once natively and once through the bridge, and the outputs
must be byte-identical — integers, text, booleans, `numeric`, `bytea`, dates,
timestamps, `json`, arrays, `uuid`, unicode and nulls all included. Against
Oracle there would be nothing to compare against.

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

**Clients authenticate against havuz, not against PostgreSQL.** By default every
backend connection in a pool uses one service account, and clients prove
themselves to havuz with SCRAM against a verifier havuz stores. That sharing is
what makes a backend connection reusable by any client, which is where the
fan-in comes from. havuz stores a verifier, never a password, so a stolen state
file hands over nothing.

The cost is that the database cannot tell your users apart. A pool can be
switched to per-user authentication instead — see below — which trades fan-in
for `pg_stat_activity.usename`, row-level security and real `GRANT`
enforcement.

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
dirties a connection is either carried over with the client (session
parameters) or classified as a pin, and pinned connections are never shared.

**The data path has its own codec.** `tokio-postgres` is a client library: it
parses, buffers and reinterprets. A pooler relays frames. Putting a client
library in the middle adds allocation and semantics that then have to be undone.
`tokio-postgres` is used only on the control plane — health probes and Test
Connection — where a round trip more or less does not matter.

## Configuration

Two planes, deliberately separated:

* `havuz.toml` — bind address, TLS, state location, the admin listener. These
  decide sockets the process holds for its own lifetime, so they require a
  restart.
* `state.json` — pools, users, sealed secrets, and the client ports. Written by
  the dashboard and the API, validated before every write, persisted
  atomically. Pool ports live here rather than in the config file precisely
  because adding a database must not need a restart.

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

The **Query trace** screen shows queries that are waiting for a backend or
running now, including the havuz user, application name, client address,
target, backend PID and elapsed time. Completed traces include pool wait time,
execution time, command status, PostgreSQL errors and a sample of the actual
result rows. History can be filtered by pool, user, status, SQL/application text
and minimum duration.

How much of that a pool produces is `trace`, chosen when the pool is created and
changeable at any time afterwards:

| | recorded | not recorded |
|---|---|---|
| `off` | nothing; the pool does not appear on the screen at all | everything |
| `statements` (default) | SQL, wait and execution time, target, backend PID, command tag, row count, SQLSTATE | result rows |
| `full` | all of the above | — |

It is two questions rather than a switch because they are two decisions.
Keeping *what ran* is diagnostics and is what a pooler exists to be able to
explain. Keeping *what came back* is a sample of production rows in a second
file with a lifetime of its own, and no amount of usefulness makes that the
same choice. Bind parameter values are never recorded at any level: a `Bind` is
traced through the prepared statement it names, so `$1` stays `$1`.

`statements` is the default, including for pools that predate the setting.
Upgrading therefore stops result capture on existing pools rather than silently
continuing to sample data nobody was asked about; turn it back up per pool where
you want it.

Completed traces are stored for seven days in `traces.sqlite3` beside
`state.json`. The file and its WAL are created with mode `0600` on Unix. Result
capture is capped at 100 rows and 256 KiB per query and marks truncated results
in the UI. SQL text and result values may contain credentials or personal data,
so protect the state directory and never expose the admin listener without
authentication.

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

./tests/e2e/per-user.sh             # per-user backend roles, over real TLS
./tests/e2e/passthrough.sh          # roles havuz was never told about
./tests/e2e/jdbc.sh                 # the JDBC bridge, compared against native

./tests/e2e/replica-setup.sh up     # a real streaming standby via pg_basebackup
./tests/e2e/split.sh                # read/write split, lag, failover, recovery
./tests/e2e/replica-setup.sh down
```

`per-user.sh` creates two real PostgreSQL roles and asserts that
`pg_stat_activity.usename` names the connecting client rather than the service
account, which is the only claim the feature actually makes. It also checks the
parts that are easy to lose while making that true: a wrong password never
reaches the database, an unencrypted client is refused — and accepted once the
pool is told to allow it, and refused again the moment that is withdrawn —
pooling still happens within each user, and the flat pool list stays one row and
one metric series however many identities are live.

`passthrough.sh` creates a PostgreSQL role and then never tells havuz about it,
which is the only claim *that* mode makes. It checks the things that make it
survivable rather than merely convenient: a wrong password is refused at the
handshake, a second wrong password is refused locally without a further database
login, a configured havuz user keeps its own password and its `disabled` flag
and does not fall through to this path, nothing about a vouched-for identity
reaches `state.json`, and everything still works after a restart that discards
all of it.

The replica suite builds an actual standby rather than a second independent
database. That distinction matters: the entire risk in read/write split is
replication lag, and two unrelated servers have none. It is what caught the LSN
comparison bug described in `health.rs`.

## Licence

Apache-2.0
