#!/usr/bin/env bash
#
# End-to-end check against a real PostgreSQL.
#
# Verifies the property the whole project exists for: many client sessions
# served by few backend connections. This is the test that caught the relay
# forwarding Terminate to the backend, which made every session open a fresh
# connection while every metric still looked healthy.

set -euo pipefail

PG_PORT="${PG_PORT:-15432}"
POOL_PORT="${POOL_PORT:-16432}"
ADMIN_PORT="${ADMIN_PORT:-17432}"
DEDICATED_PORT="${DEDICATED_PORT:-16433}"
DEDICATED_PORT_2="${DEDICATED_PORT_2:-16434}"
WORK="${WORK:-$(mktemp -d)}"
MAX_SIZE=3
CLIENTS=20

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HAVUZ="$ROOT/target/debug/havuz"

# psql runs in a container so the host needs no PostgreSQL client installed.
psql_client() {
  psql_on "$POOL_PORT" "$@"
}

# The database name is deliberately not the pool name: a port with one pool
# ignores it entirely, and that is the whole convenience of per-pool ports.
psql_on() {
  local port="$1"
  shift
  docker run --rm --add-host host.docker.internal:host-gateway -e PGPASSWORD=clientpass postgres:16 \
    psql -qtAX -h host.docker.internal -p "$port" -U svc_orders -d ignored "$@"
}

api() {
  curl -sS "http://127.0.0.1:$ADMIN_PORT$1" "${@:2}"
}

wait_trace_id() {
  local search="$1" payload id
  for _ in $(seq 1 30); do
    payload="$(api "/api/v1/traces?q=$search")"
    id="$(python3 -c 'import json,sys; rows=json.loads(sys.argv[1])["traces"]; print(rows[0]["id"] if rows else "")' "$payload")"
    [[ -n "$id" ]] && { echo "$id"; return; }
    sleep 0.1
  done
  return 1
}

assert_trace_contains() {
  local id="$1" expected="$2" detail
  detail="$(api "/api/v1/traces/$id")"
  python3 - "$detail" "$expected" <<'PY'
import json, sys
detail, expected = json.loads(sys.argv[1]), sys.argv[2]
cells = [cell for result in detail["result"]["sets"] for row in result["rows"] for cell in row]
assert expected in cells, f"trace result does not contain {expected!r}: {cells!r}"
PY
}

cleanup() {
  [[ -n "${HAVUZ_PID:-}" ]] && kill "$HAVUZ_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "==> building"
cargo build -q -p havuz-server

echo "==> starting havuz (state in $WORK)"
cat > "$WORK/havuz.toml" <<TOML
[server]
bind = "0.0.0.0"
[admin]
listen = "127.0.0.1:$ADMIN_PORT"
[state]
dir = "$WORK/data"
TOML

HAVUZ_MASTER_KEY="$("$HAVUZ" keygen 2>/dev/null)"
export HAVUZ_MASTER_KEY
"$HAVUZ" run --config "$WORK/havuz.toml" > "$WORK/havuz.log" 2>&1 &
HAVUZ_PID=$!

for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:$ADMIN_PORT/healthz" > /dev/null 2>&1 && break
  sleep 0.3
done

echo "==> configuring pool and user"
# No target, database or account at the top level: the server reads them out of
# the connection form through the roles the registry declares.
# `trace: full` because this script asserts on captured result rows. The default
# is `statements`, which records everything except them.
api /api/v1/pools -H 'content-type: application/json' -d "{
  \"name\": \"app_main\", \"family\": \"postgres\", \"mode\": \"session\",
  \"listen_port\": $DEDICATED_PORT, \"trace\": \"full\",
  \"settings\": {\"host\": \"127.0.0.1\", \"port\": $PG_PORT, \"database\": \"appdb\",
                 \"username\": \"app\", \"password\": \"hunter2\", \"sslmode\": \"disable\"},
  \"limits\": {\"max_size\": $MAX_SIZE, \"max_client_connections\": 100}}" > /dev/null

api /api/v1/users -H 'content-type: application/json' \
  -d '{"name":"svc_orders","password":"clientpass","pools":["app_main"]}' > /dev/null

echo "==> pool port opens, moves and closes without a restart"
port_result="$(psql_on "$DEDICATED_PORT" -c "select 77;")"
[[ "$port_result" == "77" ]] || { echo "FAIL: pool port returned '$port_result'"; exit 1; }
api /api/v1/pools/app_main -X PATCH -H 'content-type: application/json' \
  -d "{\"listen_port\":$DEDICATED_PORT_2}" > /dev/null
if psql_on "$DEDICATED_PORT" -c "select 1;" > /dev/null 2>&1; then
  echo "FAIL: old port stayed open after reconfiguration"
  exit 1
fi
port_result="$(psql_on "$DEDICATED_PORT_2" -c "select 78;")"
[[ "$port_result" == "78" ]] || { echo "FAIL: moved port returned '$port_result'"; exit 1; }

# Everything below talks to POOL_PORT, so settle there.
api /api/v1/pools/app_main -X PATCH -H 'content-type: application/json' \
  -d "{\"listen_port\":$POOL_PORT}" > /dev/null

echo "==> test connection"
api /api/v1/pools/app_main/probe -X POST | grep -q '"ok":true' \
  || { echo "FAIL: probe did not reach the database"; exit 1; }

echo "==> $CLIENTS sequential sessions"
for i in $(seq 1 "$CLIENTS"); do
  result="$(psql_client -c "select $i;")"
  [[ "$result" == "$i" ]] || { echo "FAIL: session $i returned '$result'"; exit 1; }
done

echo "==> session-mode query trace"
session_trace_id="$(wait_trace_id 'select%2020')" \
  || { echo "FAIL: session query was not traced"; exit 1; }
assert_trace_contains "$session_trace_id" "20"

created="$(api /api/v1/summary | python3 -c 'import sys,json; print(json.load(sys.stdin)["pool_snapshots"][0]["created_total"])')"
checkouts="$(api /api/v1/summary | python3 -c 'import sys,json; print(json.load(sys.stdin)["pool_snapshots"][0]["checkout_total"])')"

echo "    $checkouts checkouts served by $created backend connection(s)"
if [[ "$created" -gt "$MAX_SIZE" ]]; then
  echo "FAIL: $CLIENTS sessions opened $created backend connections; connections are not being reused"
  exit 1
fi

echo "==> $((CLIENTS / 2)) concurrent sessions against max_size=$MAX_SIZE"
pids=()
for i in $(seq 1 $((CLIENTS / 2))); do
  psql_client -c "select pg_sleep(1); select $i;" > "$WORK/c$i.out" 2>&1 &
  pids+=($!)
done
sleep 3

open="$(api /api/v1/summary | python3 -c 'import sys,json; print(json.load(sys.stdin)["pool_snapshots"][0]["open"])')"
echo "    backend connections while loaded: $open"
[[ "$open" -le "$MAX_SIZE" ]] || { echo "FAIL: $open backends open, limit is $MAX_SIZE"; exit 1; }

# Only the client jobs. A bare `wait` would also wait on havuz itself, which
# never exits, and the script would hang forever.
for pid in "${pids[@]}"; do wait "$pid"; done

timeouts="$(api /api/v1/summary | python3 -c 'import sys,json; print(json.load(sys.stdin)["pool_snapshots"][0]["timeout_total"])')"
[[ "$timeouts" -eq 0 ]] || { echo "FAIL: $timeouts clients were rejected"; exit 1; }

echo "==> startup checkout timeout is written to history"
pids=()
for i in $(seq 1 "$MAX_SIZE"); do
  psql_client -c "select pg_sleep(7);" > "$WORK/holder$i.out" 2>&1 &
  pids+=($!)
done
sleep 1
if psql_client -c "select 99;" > "$WORK/timeout.out" 2>&1; then
  echo "FAIL: connection succeeded while every session-mode backend was reserved"
  exit 1
fi
for pid in "${pids[@]}"; do wait "$pid"; done

timeout_trace_id="$(wait_trace_id 'connection%20checkout')" \
  || { echo "FAIL: startup checkout timeout was not traced"; exit 1; }
timeout_detail="$(api "/api/v1/traces/$timeout_trace_id")"
python3 - "$timeout_detail" <<'PY'
import json, sys
detail = json.loads(sys.argv[1])
assert detail["status"] == "failed", detail
assert detail["error_code"] == "53300", detail
assert detail["execution_us"] == 0, detail
assert detail["wait_us"] == detail["duration_us"], detail
PY

# ---------------------------------------------------------------------------
# Transaction mode: the same pool, but now a single client session may hand its
# backend back between transactions.
# ---------------------------------------------------------------------------

echo
echo "==> switching app_main to transaction mode"
api /api/v1/pools/app_main -X DELETE > /dev/null
if psql_on "$POOL_PORT" -c "select 1;" > /dev/null 2>&1; then
  echo "FAIL: port stayed open after pool deletion"
  exit 1
fi
api /api/v1/pools -H 'content-type: application/json' -d "{
  \"name\": \"app_main\", \"family\": \"postgres\", \"mode\": \"transaction\",
  \"listen_port\": $POOL_PORT, \"trace\": \"full\",
  \"settings\": {\"host\": \"127.0.0.1\", \"port\": $PG_PORT, \"database\": \"appdb\",
                 \"username\": \"app\", \"password\": \"hunter2\", \"sslmode\": \"disable\"},
  \"limits\": {\"max_size\": $MAX_SIZE, \"max_client_connections\": 100}}" > /dev/null
api /api/v1/users -H 'content-type: application/json' \
  -d '{"name":"svc_orders","password":"clientpass","pools":["app_main"]}' > /dev/null 2>&1 || true

echo "==> one session, many transactions"
psql_client -c "begin; select 1; commit;" -c "begin; select 2; commit;" -c "select 3;" > /dev/null

echo "==> transaction-mode query trace"
transaction_trace_id="$(wait_trace_id 'select%203')" \
  || { echo "FAIL: transaction query was not traced"; exit 1; }
assert_trace_contains "$transaction_trace_id" "3"

echo "==> trace level is honoured per pool"
api /api/v1/pools/app_main -X PATCH -H 'content-type: application/json' \
  -d '{"trace":"statements"}' > /dev/null
psql_client -c "select 987654;" > /dev/null
statements_trace_id="$(wait_trace_id 'select%20987654')" \
  || { echo "FAIL: lowering the level to statements stopped tracing entirely"; exit 1; }
python3 - "$(api "/api/v1/traces/$statements_trace_id")" <<'PY'
import json, sys
detail = json.loads(sys.argv[1])
result = detail["result"]
assert result["omitted"], "an omitted result must say so, or it reads as 'returned nothing'"
assert not result["sets"], f"rows were kept anyway: {result['sets']!r}"
assert detail["row_count"] == 1, f"the row count is metadata and must survive: {detail['row_count']}"
PY

api /api/v1/pools/app_main -X PATCH -H 'content-type: application/json' -d '{"trace":"off"}' > /dev/null
psql_client -c "select 123456;" > /dev/null
sleep 0.5
python3 - "$(api '/api/v1/traces?q=select%20123456')" <<'PY'
import json, sys
rows = json.loads(sys.argv[1])["traces"]
assert not rows, f"a pool with tracing off still recorded a query: {rows!r}"
PY
api /api/v1/pools/app_main -X PATCH -H 'content-type: application/json' -d '{"trace":"full"}' > /dev/null

before="$(api /api/v1/summary | python3 -c 'import sys,json; print(json.load(sys.stdin)["pool_snapshots"][0]["created_total"])')"
echo "    backend connections opened: $before"
[[ "$before" -le "$MAX_SIZE" ]] || { echo "FAIL: transaction mode opened $before connections"; exit 1; }

# ---------------------------------------------------------------------------
# Named prepared statements. asyncpg, JDBC, Npgsql and pgx all use these by
# default, and without name rewriting a Bind lands on a backend that never saw
# the Parse. That failure is intermittent and load-dependent, which is exactly
# the kind that reaches production.
# ---------------------------------------------------------------------------

if command -v docker > /dev/null; then
  echo "==> pgbench with named prepared statements"
  docker run --rm --add-host host.docker.internal:host-gateway -e PGPASSWORD=hunter2 postgres:16 \
    pgbench -q -i -U app -h host.docker.internal -p "$PG_PORT" appdb
  bench="$(docker run --rm --add-host host.docker.internal:host-gateway -e PGPASSWORD=clientpass postgres:16 \
    pgbench -S -M prepared -c 10 -j 2 -T 5 -U svc_orders -h host.docker.internal -p "$POOL_PORT" app_main 2>&1)"

  if echo "$bench" | grep -qi "does not exist"; then
    echo "FAIL: prepared statements did not follow clients across backends"
    echo "$bench" | head -5
    exit 1
  fi
  failed="$(echo "$bench" | sed -n 's/.*number of failed transactions: \([0-9]*\).*/\1/p')"
  [[ "${failed:-0}" -eq 0 ]] || { echo "FAIL: $failed transactions failed"; exit 1; }

  created="$(api /api/v1/summary | python3 -c 'import sys,json; print(json.load(sys.stdin)["pool_snapshots"][0]["created_total"])')"
  echo "    $(echo "$bench" | sed -n 's/^tps = \([0-9.]*\).*/\1 tps/p') over $created backend connection(s)"
  [[ "$created" -le "$MAX_SIZE" ]] || { echo "FAIL: opened $created backends"; exit 1; }
fi

# ---------------------------------------------------------------------------
# Session parameters. An ordinary SET must survive being moved to another
# backend without costing the session its place in the pool. This is what makes
# transaction mode usable with a real driver, all of which SET on connect.
# ---------------------------------------------------------------------------

echo "==> session parameters travel with the client"

# One statement per connection, so the SET and the SELECT that reads it back are
# guaranteed to be separate checkouts.
observed="$(psql_client -t -A -c "SET search_path TO pg_catalog" -c "SHOW search_path" | tail -1)"
[[ "$observed" == "pg_catalog" ]] || {
  echo "FAIL: search_path did not follow the client across checkouts (got '$observed')"
  exit 1
}

# And it must not leak to the next client.
observed="$(psql_client -t -A -c "SHOW search_path" | tail -1)"
[[ "$observed" != "pg_catalog" ]] || {
  echo "FAIL: one client's search_path leaked into the next session"
  exit 1
}
echo "    search_path followed its client and did not leak to the next one"

# ---------------------------------------------------------------------------
# The bug this all exists for. Every driver issues two or three SETs on
# connect; while those pinned, a small pool was owned outright by the first few
# clients and everyone else timed out with "backend slots are held without a
# running query (pinned=N)".
# ---------------------------------------------------------------------------

echo "==> $CLIENTS clients with a driver preamble over max_size=$MAX_SIZE"
api /api/v1/pins -X DELETE > /dev/null
before="$(api /api/v1/summary | python3 -c 'import sys,json; print(json.load(sys.stdin)["pool_snapshots"][0]["created_total"])')"

pids=()
for i in $(seq 1 "$CLIENTS"); do
  psql_client \
    -c "SET application_name = 'client-$i'" \
    -c "SET extra_float_digits = 3" \
    -c "SET search_path TO public" \
    -c "select $i;" > "$WORK/preamble$i.out" 2>&1 &
  pids+=($!)
done
failed=0
for pid in "${pids[@]}"; do wait "$pid" || failed=$((failed + 1)); done
[[ "$failed" -eq 0 ]] || {
  echo "FAIL: $failed of $CLIENTS clients could not complete a driver preamble"
  cat "$WORK"/preamble*.out | grep -i "error\|fatal" | head -5
  exit 1
}

after="$(api /api/v1/summary | python3 -c 'import sys,json; print(json.load(sys.stdin)["pool_snapshots"][0]["created_total"])')"
timeouts="$(api /api/v1/summary | python3 -c 'import sys,json; print(json.load(sys.stdin)["pool_snapshots"][0]["timeout_total"])')"
opened=$((after - before))
echo "    $CLIENTS clients, $opened new backend connection(s), $timeouts timeout(s)"
[[ "$opened" -le "$MAX_SIZE" ]] || {
  echo "FAIL: a driver preamble still costs a backend per client ($opened opened)"
  exit 1
}

pins="$(api /api/v1/pins)"
python3 - "$pins" <<'PY'
import json, sys
report = json.loads(sys.argv[1])
by_reason = {r["reason"]: r["count"] for r in report["by_reason"]}
assert by_reason.get("session_parameter", 0) == 0, \
    f"an ordinary SET must no longer pin: {by_reason}"
assert report["pinned_sessions"] == 0, f"nothing here should pin: {report}"
PY
echo "    no session was pinned"

# ---------------------------------------------------------------------------
# Read-only users. Enforced by setting default_transaction_read_only and
# refusing the statements that would turn it back off, so the refusing is
# PostgreSQL's and covers writes hidden inside functions.
# ---------------------------------------------------------------------------

echo "==> read-only user"
api /api/v1/users -H 'content-type: application/json' \
  -d '{"name":"svc_ro","password":"ropass","pools":["app_main"],"read_only":true}' > /dev/null

psql_ro() {
  docker run --rm --add-host host.docker.internal:host-gateway -e PGPASSWORD=ropass postgres:16 \
    psql -qtAX -h host.docker.internal -p "$POOL_PORT" -U svc_ro -d app_main "$@"
}

[[ "$(psql_ro -c "select 1;" | tail -1)" == "1" ]] || { echo "FAIL: a read-only user cannot read"; exit 1; }
[[ "$(psql_ro -c "show default_transaction_read_only;" | tail -1)" == "on" ]] \
  || { echo "FAIL: the read-only setting did not reach the backend"; exit 1; }

if psql_ro -c "create table e2e_ro_probe (id int);" > "$WORK/ro_write.out" 2>&1; then
  echo "FAIL: a read-only user performed a write"
  exit 1
fi
grep -q "read-only" "$WORK/ro_write.out" || {
  echo "FAIL: the write was refused for the wrong reason:"; cat "$WORK/ro_write.out"; exit 1
}

# Every way out of the setting has to be closed, or it is only a default.
for escape in "SET default_transaction_read_only = off" "RESET ALL" "BEGIN READ WRITE" "SET TRANSACTION READ WRITE"; do
  if psql_ro -c "$escape" > "$WORK/ro_escape.out" 2>&1; then
    echo "FAIL: '$escape' was allowed, so read-only is not enforced"
    exit 1
  fi
done
echo "    reads allowed, writes refused, and the setting cannot be turned off"

# ---------------------------------------------------------------------------
# Disabling and disconnecting a user. Disabling alone only refuses the next
# handshake, which is not what an operator revoking access means.
# ---------------------------------------------------------------------------

echo "==> disable and disconnect"

ro_sessions() {
  api /api/v1/users \
    | python3 -c 'import sys,json; print(next(u["live_sessions"] for u in json.load(sys.stdin)["users"] if u["name"]=="svc_ro"))'
}

# An idle session: one statement, a pause, then another. psql sits blocked on
# its own stdin during the pause and does not read the socket, so the second
# statement is what makes libpq surface what arrived meanwhile.
(echo "select 1;"; sleep 6; echo "select 2;") | docker run --rm -i \
  --add-host host.docker.internal:host-gateway -e PGPASSWORD=ropass postgres:16 \
  psql -qtAX -h host.docker.internal -p "$POOL_PORT" -U svc_ro -d app_main \
  > "$WORK/kicked.out" 2>&1 &
KICK_CLIENT=$!

for _ in $(seq 1 40); do
  live="$(ro_sessions)"
  [[ "$live" -ge 1 ]] && break
  sleep 0.25
done
[[ "$live" -ge 1 ]] || { echo "FAIL: the live session was never registered"; exit 1; }

kicked="$(api /api/v1/users/svc_ro -X PATCH -H 'content-type: application/json' \
  -d '{"disabled":true,"kick":true}' | python3 -c 'import sys,json; print(json.load(sys.stdin)["kicked"])')"
[[ "$kicked" -ge 1 ]] || { echo "FAIL: disabling reported $kicked kicked sessions"; exit 1; }

# The real assertion. A kick that only sets a flag would leave this at 1.
for _ in $(seq 1 40); do
  live="$(ro_sessions)"
  [[ "$live" -eq 0 ]] && break
  sleep 0.25
done
[[ "$live" -eq 0 ]] || { echo "FAIL: the session was flagged but never actually ended"; exit 1; }

wait "$KICK_CLIENT" 2>/dev/null || true
# libpq reports this either as the FATAL havuz sent or as the socket closing
# underneath it, depending on where it was when the message landed. Either way
# the client learns it was disconnected rather than hanging.
grep -qiE "administrator command|server closed the connection|connection to server" "$WORK/kicked.out" || {
  echo "FAIL: the disconnected client never noticed:"; cat "$WORK/kicked.out"; exit 1
}

# And a disabled user cannot come back.
if psql_ro -c "select 1;" > /dev/null 2>&1; then
  echo "FAIL: a disabled user reconnected"
  exit 1
fi
echo "    session ended with 57P01 and the user cannot reconnect"

# Re-enabling restores access, so this is a revocation and not a deletion.
api /api/v1/users/svc_ro -X PATCH -H 'content-type: application/json' -d '{"disabled":false}' > /dev/null
[[ "$(psql_ro -c "select 42;" | tail -1)" == "42" ]] || { echo "FAIL: re-enabling did not restore access"; exit 1; }

# ---------------------------------------------------------------------------
# Per-user connection cap.
# ---------------------------------------------------------------------------

echo "==> per-user connection limit"
api /api/v1/users/svc_ro -X PATCH -H 'content-type: application/json' \
  -d '{"max_client_connections":1}' > /dev/null

(echo "select 1;"; sleep 6) | docker run --rm -i --add-host host.docker.internal:host-gateway \
  -e PGPASSWORD=ropass postgres:16 \
  psql -qtAX -h host.docker.internal -p "$POOL_PORT" -U svc_ro -d app_main \
  > "$WORK/cap_holder.out" 2>&1 &
CAP_HOLDER=$!

for _ in $(seq 1 40); do
  live="$(api /api/v1/users | python3 -c 'import sys,json; print(next(u["live_sessions"] for u in json.load(sys.stdin)["users"] if u["name"]=="svc_ro"))')"
  [[ "$live" -ge 1 ]] && break
  sleep 0.25
done

if psql_ro -c "select 1;" > "$WORK/cap_refused.out" 2>&1; then
  echo "FAIL: the per-user connection cap was not enforced"
  kill "$CAP_HOLDER" 2>/dev/null || true
  exit 1
fi
grep -q "too many connections" "$WORK/cap_refused.out" || {
  echo "FAIL: the second connection failed for the wrong reason:"; cat "$WORK/cap_refused.out"
  kill "$CAP_HOLDER" 2>/dev/null || true
  exit 1
}
wait "$CAP_HOLDER" 2>/dev/null || true

# The slot is freed again when the session ends.
[[ "$(psql_ro -c "select 7;" | tail -1)" == "7" ]] || { echo "FAIL: a closed session did not free its slot"; exit 1; }
echo "    a second connection was refused and the slot was freed on release"

api /api/v1/users/svc_ro -X DELETE > /dev/null

# ---------------------------------------------------------------------------
# Pin detection. Nothing else reports this, so nothing else can be compared
# against; the assertion is that we see exactly what the client did.
# ---------------------------------------------------------------------------

echo "==> pin detection"
api /api/v1/pins -X DELETE > /dev/null

psql_client -c "select 1;" > /dev/null                            # clean
psql_client -c "SET application_name = 'orders-api'" > /dev/null  # replayable: clean
# The backend's own service account, so the statement succeeds and the pin is
# the only thing being measured. Client names are havuz users, not database
# roles, and SET ROLE resolves against the database.
psql_client -c "SET ROLE app" > /dev/null                         # pins
psql_client -c "LISTEN chan" > /dev/null                          # pins

pins="$(api /api/v1/pins)"
python3 - "$pins" <<'PY'
import json, sys
report = json.loads(sys.argv[1])
by_reason = {r["reason"]: r["count"] for r in report["by_reason"]}

assert by_reason.get("session_parameter") == 1, \
    f"SET ROLE must pin and a plain SET must not: {by_reason}"
assert by_reason["listen"] == 1, f"LISTEN was not detected: {by_reason}"
assert report["clean_sessions"] >= 2, \
    f"the plain SET is replayable, so its session is clean: {report}"
assert report["offenders"], "the report must name who did it"

offender = report["offenders"][0]
assert offender["user"] == "svc_orders", offender
assert offender["actionable"], "SET ROLE and LISTEN are both fixable by the application"
print(f"    pin rate {report['pin_rate']*100:.0f}%: "
      f"{by_reason['session_parameter']} SET ROLE, {by_reason['listen']} LISTEN, "
      f"attributed to {offender['user']}/{offender['application']}")
PY

echo
echo "PASS"
