#!/usr/bin/env bash
#
# Read/write split against a real streaming replica.
#
# Two independent databases would pass every test here trivially, because the
# entire risk is replication lag and unrelated servers have none. This runs
# against a genuine standby built with pg_basebackup, which is what caught the
# LSN comparison bug: a restarted standby reports replay *ahead* of receive, and
# an equality check reads that as six minutes of lag on a caught-up replica.
#
#   ./tests/e2e/replica-setup.sh up
#   ./tests/e2e/split.sh
#   ./tests/e2e/replica-setup.sh down

set -euo pipefail

PRIMARY_PORT="${PRIMARY_PORT:-15432}"
REPLICA_PORT="${REPLICA_PORT:-15433}"
POOL_PORT="${POOL_PORT:-16432}"
ADMIN_PORT="${ADMIN_PORT:-17432}"
REPLICA_CONTAINER="${REPLICA_CONTAINER:-havuz-pg-replica}"
WORK="${WORK:-$(mktemp -d)}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HAVUZ="$ROOT/target/release/havuz"

# `pg_is_in_recovery()` is the perfect probe: it asks the server which server it
# is. `t` means the statement was served by the standby.
where() {
  docker run --rm -e PGPASSWORD=clientpass postgres:16 \
    psql -qtAX -h host.docker.internal -p "$POOL_PORT" -U svc_orders -d app_main \
    -c "select pg_is_in_recovery();" 2>&1
}

psql_pool() {
  docker run --rm -e PGPASSWORD=clientpass postgres:16 \
    psql -qtAX -h host.docker.internal -p "$POOL_PORT" -U svc_orders -d app_main "$@" 2>&1
}

api() { curl -sS "http://127.0.0.1:$ADMIN_PORT$1" "${@:2}"; }

cleanup() { [[ -n "${HAVUZ_PID:-}" ]] && kill "$HAVUZ_PID" 2>/dev/null || true; }
trap cleanup EXIT

echo "==> building"
cargo build -q --release -p havuz-server

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

echo "==> configuring a pool with one replica"
api /api/v1/pools -H 'content-type: application/json' -d "{
  \"name\": \"app_main\", \"family\": \"postgres\", \"mode\": \"transaction\",
  \"targets\": [
    {\"host\": \"127.0.0.1\", \"port\": $PRIMARY_PORT, \"role\": \"primary\"},
    {\"host\": \"127.0.0.1\", \"port\": $REPLICA_PORT, \"role\": \"replica\"}
  ],
  \"database\": \"appdb\", \"backend_user\": \"app\", \"backend_password\": \"hunter2\",
  \"settings\": {\"host\": \"127.0.0.1\", \"port\": $PRIMARY_PORT, \"database\": \"appdb\",
                 \"username\": \"app\", \"sslmode\": \"disable\"},
  \"limits\": {\"max_size\": 3, \"max_client_connections\": 100},
  \"routing\": {\"read_write_split\": true, \"sticky_after_write\": \"1s\",
                \"max_replica_lag\": \"5s\", \"health_interval\": \"2s\",
                \"failure_threshold\": 3, \"recovery_cooldown\": \"5s\"}}" > /dev/null

api /api/v1/users -H 'content-type: application/json' \
  -d '{"name":"svc_orders","password":"clientpass","pools":["app_main"]}' > /dev/null

echo "==> waiting for the first health probe"
for _ in $(seq 1 20); do
  lag="$(api /api/v1/pools/app_main/targets | python3 -c 'import sys,json; print(json.load(sys.stdin)["replicas"][0]["lag_millis"])')"
  [[ "$lag" != "None" ]] && break
  sleep 1
done
[[ "$lag" != "None" ]] || { echo "FAIL: replica lag was never measured"; exit 1; }
echo "    replica lag: ${lag} ms"

echo "==> reads go to the replica"
for i in 1 2 3; do
  [[ "$(where)" == "t" ]] || { echo "FAIL: read $i was not served by the replica"; exit 1; }
done

echo "==> a read after a write stays on the primary"
result="$(psql_pool -c "create table if not exists rw(id int primary key)" \
                    -c "insert into rw values (default) on conflict do nothing" \
                    -c "select pg_is_in_recovery();" | tail -1)"
[[ "$result" == "f" ]] || { echo "FAIL: a read following a write reached the replica"; exit 1; }

echo "==> read-after-write consistency, 20 cycles"
psql_pool -c "drop table if exists rw" -c "create table rw(id int primary key)" > /dev/null
lost=0
for i in $(seq 1 20); do
  got="$(psql_pool -c "insert into rw values ($i)" -c "select count(*) from rw where id = $i" | tail -1)"
  [[ "$got" == "1" ]] || lost=$((lost + 1))
done
[[ "$lost" -eq 0 ]] || { echo "FAIL: $lost of 20 rows were not visible to the client that wrote them"; exit 1; }
echo "    0 rows lost"

echo "==> the sticky window expires"
sleep 2
[[ "$(where)" == "t" ]] || { echo "FAIL: traffic did not return to the replica"; exit 1; }

echo "==> a transaction stays on one target"
result="$(psql_pool -c "begin; select pg_is_in_recovery(); commit;" | tail -1)"
[[ "$result" == "f" ]] || { echo "FAIL: a plain transaction should be pinned to the primary"; exit 1; }

echo "==> killing the replica mid-flight"
docker kill "$REPLICA_CONTAINER" > /dev/null
errors=0
for i in $(seq 1 10); do
  got="$(psql_pool -c "select 42;")"
  [[ "$got" == "42" ]] || { errors=$((errors + 1)); echo "    error on read $i: $got"; }
done
[[ "$errors" -eq 0 ]] || { echo "FAIL: $errors reads failed while the replica was down"; exit 1; }
echo "    10 reads, 0 client-visible errors"

state="$(api /api/v1/pools/app_main/targets | python3 -c 'import sys,json; print(json.load(sys.stdin)["replicas"][0]["breaker"]["state"])')"
[[ "$state" == "open" ]] || { echo "FAIL: breaker should have tripped, got $state"; exit 1; }
echo "    breaker: $state"

echo "==> the replica comes back"
docker start "$REPLICA_CONTAINER" > /dev/null
recovered=""
for _ in $(seq 1 30); do
  sleep 1
  psql_pool -c "select 1;" > /dev/null 2>&1 || true
  if [[ "$(where)" == "t" ]]; then
    recovered=yes
    break
  fi
done
[[ -n "$recovered" ]] || { echo "FAIL: traffic never returned to the recovered replica"; exit 1; }
echo "    reads are back on the replica"

echo
echo "PASS"
