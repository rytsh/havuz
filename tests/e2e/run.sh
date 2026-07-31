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
WORK="${WORK:-$(mktemp -d)}"
MAX_SIZE=3
CLIENTS=20

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HAVUZ="$ROOT/target/debug/havuz"

# psql runs in a container so the host needs no PostgreSQL client installed.
psql_client() {
  docker run --rm --add-host host.docker.internal:host-gateway -e PGPASSWORD=clientpass postgres:16 \
    psql -qtAX -h host.docker.internal -p "$POOL_PORT" -U svc_orders -d app_main "$@"
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
listen = "0.0.0.0:$POOL_PORT"
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
api /api/v1/pools -H 'content-type: application/json' -d "{
  \"name\": \"app_main\", \"family\": \"postgres\", \"mode\": \"session\",
  \"targets\": [{\"host\": \"127.0.0.1\", \"port\": $PG_PORT}],
  \"database\": \"appdb\", \"backend_user\": \"app\", \"backend_password\": \"hunter2\",
  \"settings\": {\"host\": \"127.0.0.1\", \"port\": $PG_PORT, \"database\": \"appdb\",
                 \"username\": \"app\", \"sslmode\": \"disable\"},
  \"limits\": {\"max_size\": $MAX_SIZE, \"max_client_connections\": 100}}" > /dev/null

api /api/v1/users -H 'content-type: application/json' \
  -d '{"name":"svc_orders","password":"clientpass","pools":["app_main"]}' > /dev/null

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

# ---------------------------------------------------------------------------
# Transaction mode: the same pool, but now a single client session may hand its
# backend back between transactions.
# ---------------------------------------------------------------------------

echo
echo "==> switching app_main to transaction mode"
api /api/v1/pools/app_main -X DELETE > /dev/null
api /api/v1/pools -H 'content-type: application/json' -d "{
  \"name\": \"app_main\", \"family\": \"postgres\", \"mode\": \"transaction\",
  \"targets\": [{\"host\": \"127.0.0.1\", \"port\": $PG_PORT}],
  \"database\": \"appdb\", \"backend_user\": \"app\", \"backend_password\": \"hunter2\",
  \"settings\": {\"host\": \"127.0.0.1\", \"port\": $PG_PORT, \"database\": \"appdb\",
                 \"username\": \"app\", \"sslmode\": \"disable\"},
  \"limits\": {\"max_size\": $MAX_SIZE, \"max_client_connections\": 100}}" > /dev/null
api /api/v1/users -H 'content-type: application/json' \
  -d '{"name":"svc_orders","password":"clientpass","pools":["app_main"]}' > /dev/null 2>&1 || true

echo "==> one session, many transactions"
psql_client -c "begin; select 1; commit;" -c "begin; select 2; commit;" -c "select 3;" > /dev/null

echo "==> transaction-mode query trace"
transaction_trace_id="$(wait_trace_id 'select%203')" \
  || { echo "FAIL: transaction query was not traced"; exit 1; }
assert_trace_contains "$transaction_trace_id" "3"

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
# Pin detection. Nothing else reports this, so nothing else can be compared
# against; the assertion is that we see exactly what the client did.
# ---------------------------------------------------------------------------

echo "==> pin detection"
api /api/v1/pins -X DELETE > /dev/null

psql_client -c "select 1;" > /dev/null                            # clean
psql_client -c "SET application_name = 'orders-api'" > /dev/null  # pins
psql_client -c "LISTEN chan" > /dev/null                          # pins

pins="$(api /api/v1/pins)"
python3 - "$pins" <<'PY'
import json, sys
report = json.loads(sys.argv[1])
by_reason = {r["reason"]: r["count"] for r in report["by_reason"]}

assert by_reason["session_parameter"] == 1, f"SET was not detected: {by_reason}"
assert by_reason["listen"] == 1, f"LISTEN was not detected: {by_reason}"
assert report["clean_sessions"] >= 1, "a clean session should have been counted"
assert report["offenders"], "the report must name who did it"

offender = report["offenders"][0]
assert offender["user"] == "svc_orders", offender
assert offender["actionable"], "SET and LISTEN are both fixable by the application"
print(f"    pin rate {report['pin_rate']*100:.0f}%: "
      f"{by_reason['session_parameter']} SET, {by_reason['listen']} LISTEN, "
      f"attributed to {offender['user']}/{offender['application']}")
PY

echo
echo "PASS"
