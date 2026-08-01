#!/usr/bin/env bash
#
# End-to-end check for the JDBC bridge.
#
# The database behind the bridge is PostgreSQL, which looks like a strange
# choice for a feature whose point is reaching databases that are not. It is the
# only choice that makes the result checkable: every query runs twice, once
# natively and once through the bridge, and the two outputs must be identical.
# Against Oracle there would be nothing to compare with.
#
# Requires the pg16 service from docker-compose.yml, a Java runtime, and the
# agent built by agent/build.sh.

set -euo pipefail

PG_PORT="${PG_PORT:-15432}"
POOL_PORT="${POOL_PORT:-16452}"
ADMIN_PORT="${ADMIN_PORT:-17452}"
WORK="${WORK:-$(mktemp -d)}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HAVUZ="$ROOT/target/debug/havuz"
AGENT="$ROOT/agent/build/havuz-agent.jar"
DRIVER="$WORK/postgresql.jar"
DRIVER_VERSION="${DRIVER_VERSION:-42.7.4}"

api() {
  curl -sS "http://127.0.0.1:$ADMIN_PORT$1" "${@:2}"
}

# Through the bridge.
bridge() {
  docker run --rm --add-host host.docker.internal:host-gateway -e PGPASSWORD=pw postgres:16 \
    psql -qtAX -h host.docker.internal -p "$POOL_PORT" -U svc -d legacy "$@" 2>&1
}

# Straight at the database, for comparison.
native() {
  docker run --rm --add-host host.docker.internal:host-gateway -e PGPASSWORD=hunter2 postgres:16 \
    psql -qtAX -h host.docker.internal -p "$PG_PORT" -U app -d appdb "$@" 2>&1
}

# Without -q, so psql prints the command tags this asserts on.
tags_through_bridge() {
  docker run --rm --add-host host.docker.internal:host-gateway -e PGPASSWORD=pw -v "$WORK":/w postgres:16 \
    psql -tAX -h host.docker.internal -p "$POOL_PORT" -U svc -d legacy -f "/w/$(basename "$1")" 2>&1
}

# psql reading a file, so backslash commands work.
script_through_bridge() {
  docker run --rm --add-host host.docker.internal:host-gateway -e PGPASSWORD=pw -v "$WORK":/w postgres:16 \
    psql -qtAX -h host.docker.internal -p "$POOL_PORT" -U svc -d legacy -f "/w/$(basename "$1")" 2>&1
}

fail() {
  echo "FAIL: $1"
  [[ -f "$WORK/havuz.log" ]] && tail -25 "$WORK/havuz.log"
  exit 1
}

cleanup() {
  [[ -f "$WORK/pid" ]] && kill "$(cat "$WORK/pid")" 2>/dev/null || true
}
trap cleanup EXIT

echo "==> building"
cargo build -q -p havuz-server
[[ -f "$AGENT" ]] || "$ROOT/agent/build.sh" > /dev/null

command -v java > /dev/null || fail "the JDBC bridge needs a Java runtime on PATH"

echo "==> fetching the PostgreSQL JDBC driver"
# Not vendored: a driver JAR does not belong in source control, and for the
# databases this bridge exists to reach it would not be redistributable anyway.
curl -sSL -o "$DRIVER" \
  "https://repo1.maven.org/maven2/org/postgresql/postgresql/$DRIVER_VERSION/postgresql-$DRIVER_VERSION.jar"

echo "==> starting havuz"
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
setsid "$HAVUZ" run --config "$WORK/havuz.toml" > "$WORK/havuz.log" 2>&1 < /dev/null &
echo $! > "$WORK/pid"

for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:$ADMIN_PORT/healthz" > /dev/null 2>&1 && break
  sleep 0.3
done

echo "==> configuring a JDBC pool"
api /api/v1/pools -H 'content-type: application/json' -d "{
  \"name\": \"legacy\", \"family\": \"jdbc\", \"mode\": \"session\",
  \"listen_port\": $POOL_PORT,
  \"settings\": {
    \"url\": \"jdbc:postgresql://127.0.0.1:$PG_PORT/appdb\",
    \"username\": \"app\", \"password\": \"hunter2\",
    \"driver_class\": \"org.postgresql.Driver\",
    \"driver_paths\": \"$DRIVER\",
    \"agent_jar\": \"$AGENT\",
    \"reset_query\": \"DISCARD ALL\"
  },
  \"limits\": {\"max_size\": 3, \"max_client_connections\": 50}}" > /dev/null

grep -q "jdbc pool ready" "$WORK/havuz.log" || fail "the JDBC pool did not start"

api /api/v1/users -H 'content-type: application/json' \
  -d '{"name":"svc","password":"pw","pools":["legacy"]}' > /dev/null

echo "==> every type comes out exactly as PostgreSQL would render it"
# The claim the whole type-mapping module makes. A difference here means a
# client would see something other than what the database holds.
TYPES="select 1 as n, 'hi' as t, true as b, false as b2, 12.50::numeric as d,
       null::int as nul, '\\x00ff'::bytea as bin, '2026-01-02'::date as dt,
       '2026-01-02 03:04:05.123456'::timestamp as ts, 1.5::float8 as f,
       '{\"a\":1}'::json as j, '{1,2}'::int[] as arr, 'çğü 日本語' as unicode,
       ''::text as empty, repeat('x', 1000) as long"

native -c "$TYPES" > "$WORK/native.txt"
bridge -c "$TYPES" > "$WORK/bridge.txt"
if ! diff -q "$WORK/native.txt" "$WORK/bridge.txt" > /dev/null; then
  echo "the bridge rendered something differently:"
  diff "$WORK/native.txt" "$WORK/bridge.txt" || true
  fail "type mapping does not reproduce the native output"
fi
echo "    identical to the native result"

echo "==> the extended query protocol binds parameters"
# psql's \bind sends Parse/Bind/Execute, which is what every real driver uses.
# It has to come from a file: -c refuses to mix SQL with backslash commands.
cat > "$WORK/bind.sql" <<'SQL'
select $1::int + 1 as answer \bind 41 \g
select $1::text || $1::text || $2::text as repeated \bind ab c \g
SQL
bound="$(script_through_bridge "$WORK/bind.sql")"
echo "$bound" | grep -qx "42" || fail "extended query returned: $bound"
# A repeated placeholder has to be sent twice: JDBC is positional and has no
# way to say "that parameter again".
echo "$bound" | grep -qx "ababc" || fail "a repeated placeholder returned: $bound"

echo "==> a dollar sign inside a literal stays data"
# The rewriting bug that would silently change what a query means.
literal="$(bridge -c "select 'costs \$1 today' as t")"
[[ "$literal" == 'costs $1 today' ]] || fail "a literal was rewritten: '$literal'"

echo "==> DML reports the tags clients parse"
cat > "$WORK/dml.sql" <<'SQL'
create temp table t(x int);
insert into t values (1),(2),(3);
update t set x = 9 where x = 2;
delete from t where x = 1;
SQL
tags="$(tags_through_bridge "$WORK/dml.sql")"
# PostgreSQL reports CREATE TABLE for a temp table too, and a client comparing
# strings would not match CREATE TEMP.
echo "$tags" | grep -qx "CREATE TABLE" || fail "create tag was: $tags"
echo "$tags" | grep -qx "INSERT 0 3" || fail "insert tag was: $tags"
echo "$tags" | grep -qx "UPDATE 1" || fail "update tag was: $tags"
echo "$tags" | grep -qx "DELETE 1" || fail "delete tag was: $tags"

echo "==> transactions are performed, not forwarded"
# The bridge turns BEGIN into setAutoCommit(false), so the JDBC driver knows
# for a fact whether a transaction is open rather than the bridge inferring it.
cat > "$WORK/txn.sql" <<'SQL'
create temp table t(x int);
insert into t values (1);
begin;
insert into t values (2);
select count(*) from t;
rollback;
select count(*) from t;
SQL
counts="$(script_through_bridge "$WORK/txn.sql" | grep -E '^[0-9]+$')"
[[ "$(echo "$counts" | head -1)" == "2" ]] || fail "inside the transaction the count was $(echo "$counts" | head -1)"
[[ "$(echo "$counts" | tail -1)" == "1" ]] || fail "the rollback did not take effect"

echo "==> an error is reported once and the session survives"
error="$(bridge -c "select * from nonexistent_table" || true)"
[[ "$error" == *"does not exist"* ]] || fail "unexpected error text: $error"
[[ "$error" != *"ERROR:  ERROR:"* ]] || fail "the severity was repeated: $error"

alive="$(bridge -c "select 'alive'")"
[[ "$alive" == "alive" ]] || fail "the session did not survive an error"

echo "==> session state does not leak to the next client"
# JDBC has no portable DISCARD ALL, so a pool that reuses connections without
# a reset query would hand one client's temporary tables to the next.
cat > "$WORK/leak.sql" <<'SQL'
create temp table leak(x int);
insert into leak values (1);
SQL
script_through_bridge "$WORK/leak.sql" > /dev/null
still_there="$(bridge -c "select count(*) from leak" || true)"
[[ "$still_there" == *"does not exist"* ]] \
  || fail "a temporary table survived into the next session: $still_there"

echo "==> sessions are pooled, and one JVM serves them all"
for i in $(seq 1 8); do
  bridge -c "select $i" > /dev/null
done

read -r checkouts created < <(api /api/v1/summary | python3 -c '
import sys, json
pool = json.load(sys.stdin)["pool_snapshots"][0]
print(pool["checkout_total"], pool["created_total"])
')
[[ "$checkouts" -ge 8 ]] || fail "only $checkouts checkouts were recorded"
[[ "$created" -le 3 ]] \
  || fail "$checkouts checkouts opened $created backend connections; pooling is not happening"
echo "    $checkouts checkouts served by $created backend connection(s)"

jvms="$(pgrep -fc 'havuz-agent.jar' || echo 0)"
[[ "$jvms" == "1" ]] || fail "expected one JVM for the pool, found $jvms"

echo "==> the client is told what it actually reached"
# The startup ParameterStatus, which psql keeps as SERVER_VERSION_NAME. `SHOW
# server_version` would go to the database and report the database's answer,
# which is a different and equally true thing.
cat > "$WORK/version.sql" <<'SQL'
\echo :SERVER_VERSION_NAME
SQL
version="$(script_through_bridge "$WORK/version.sql")"
[[ "$version" == *"havuz jdbc bridge"* ]] \
  || fail "a client must not be told it reached PostgreSQL directly: $version"
[[ "$version" == *"PostgreSQL 16"* ]] \
  || fail "and must still learn what is behind the bridge: $version"

echo
echo "jdbc bridge: PASS"
