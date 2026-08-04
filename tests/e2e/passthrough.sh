#!/usr/bin/env bash
#
# End-to-end check for passthrough backend authentication.
#
# The property under test: a pool with no service account, no havuz user and no
# stored backend credential still lets a real database role connect — because
# the database, and only the database, decided that it could.
#
# The parts that are easy to lose while making that true are checked too. A
# wrong password is refused at the handshake. A configured havuz user is still
# checked locally and does not fall through to this path. An identity the
# database vouched for is remembered in memory and stops costing a database
# login. Nothing about it survives a restart.
#
# Requires the pg16 service from docker-compose.yml.

set -euo pipefail

PG_PORT="${PG_PORT:-15432}"
POOL_PORT="${POOL_PORT:-16452}"
ADMIN_PORT="${ADMIN_PORT:-17452}"
WORK="${WORK:-$(mktemp -d)}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HAVUZ="$ROOT/target/debug/havuz"

api() {
  curl -sS "http://127.0.0.1:$ADMIN_PORT$1" "${@:2}"
}

# `sslmode=require` because this pool asks for a real database password and
# refuses by default to do so on an unencrypted socket. The certificate is
# self-signed, so the client encrypts without verifying.
pg() {
  local user="$1" password="$2"
  shift 2
  docker run --rm --add-host host.docker.internal:host-gateway -e "PGPASSWORD=$password" postgres:16 \
    psql -qtAX "host=host.docker.internal port=$POOL_PORT user=$user dbname=ignored sslmode=require" "$@"
}

pg_admin() {
  docker run --rm --add-host host.docker.internal:host-gateway -e PGPASSWORD=hunter2 postgres:16 \
    psql -qtAX -h host.docker.internal -p "$PG_PORT" -U app -d appdb "$@"
}

drop_roles() {
  for role in carol dave; do
    pg_admin -c "revoke all on database appdb from $role;" || true
    pg_admin -c "drop role if exists $role;" || true
  done
}

fail() {
  echo "FAIL: $1"
  [[ -f "$WORK/havuz.log" ]] && tail -30 "$WORK/havuz.log"
  exit 1
}

start_havuz() {
  "$HAVUZ" run --config "$WORK/havuz.toml" > "$WORK/havuz.log" 2>&1 &
  HAVUZ_PID=$!
  for _ in $(seq 1 30); do
    curl -sf "http://127.0.0.1:$ADMIN_PORT/healthz" > /dev/null 2>&1 && return
    sleep 0.3
  done
  fail "havuz did not come up"
}

cleanup() {
  [[ -n "${HAVUZ_PID:-}" ]] && kill "$HAVUZ_PID" 2>/dev/null || true
  drop_roles > /dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> building"
cargo build -q -p havuz-server

echo "==> creating a database role havuz will never be told about"
drop_roles > /dev/null
pg_admin -c "create role carol login password 'carolpass'; grant connect on database appdb to carol;" > /dev/null
pg_admin -c "create role dave  login password 'davepass';  grant connect on database appdb to dave;"  > /dev/null

echo "==> generating a client certificate"
openssl req -x509 -newkey rsa:2048 -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
  -days 1 -nodes -subj "/CN=havuz-e2e" 2>/dev/null

cat > "$WORK/havuz.toml" <<TOML
[server]
bind = "0.0.0.0"
[server.tls]
cert = "$WORK/cert.pem"
key = "$WORK/key.pem"
[admin]
listen = "127.0.0.1:$ADMIN_PORT"
[state]
dir = "$WORK/data"
TOML

HAVUZ_MASTER_KEY="$("$HAVUZ" keygen 2>/dev/null)"
export HAVUZ_MASTER_KEY

echo "==> starting havuz with client-facing TLS"
start_havuz

echo "==> a passthrough pool with no backend credential at all"
created="$(api /api/v1/pools -H 'content-type: application/json' -d "{
  \"name\": \"app_main\", \"family\": \"postgres\", \"mode\": \"transaction\",
  \"listen_port\": $POOL_PORT,
  \"backend_auth\": \"passthrough\",
  \"settings\": {\"host\": \"127.0.0.1\", \"port\": $PG_PORT, \"database\": \"appdb\",
                 \"username\": \"\", \"password\": \"\", \"sslmode\": \"disable\"},
  \"limits\": {\"max_size\": 2, \"max_client_connections\": 100}}")"

echo "$created" | grep -q '"backend_auth":"passthrough"' || fail "pool was not created: $created"
echo "$created" | grep -q '"has_backend_password":false' \
  || fail "a passthrough pool must have no stored backend password: $created"

echo "==> a role havuz has never heard of connects as itself"
seen="$(pg carol carolpass -c "select current_user;")"
[[ "$seen" == "carol" ]] || fail "expected current_user=carol with no havuz user configured, got '$seen'"

attributed="$(pg carol carolpass -c "select usename from pg_stat_activity where pid = pg_backend_pid();")"
[[ "$attributed" == "carol" ]] || fail "pg_stat_activity says '$attributed', not carol"

echo "==> a wrong password is refused at the handshake"
if pg carol wrongpass -c "select 1;" > /dev/null 2>&1; then
  fail "a wrong password was accepted"
fi

echo "==> and refused locally from then on, without another database login"
# carol has been vouched for, so havuz now holds a verifier for her. A second
# bad password must not become a second PostgreSQL authentication attempt.
before="$(pg_admin -c "select count(*) from pg_stat_activity where usename = 'carol';")"
pg carol wrongpass -c "select 1;" > /dev/null 2>&1 || true
after="$(pg_admin -c "select count(*) from pg_stat_activity where usename = 'carol';")"
[[ "$before" == "$after" ]] || fail "a rejected password still opened a backend connection"

echo "==> a role that does not exist in the database is refused too"
if pg nosuchrole whatever -c "select 1;" > /dev/null 2>&1; then
  fail "a role PostgreSQL does not have was admitted"
fi

echo "==> the pool says so on the dashboard for as long as it is on"
api /api/v1/summary | grep -q '"kind":"passthrough_pool"' \
  || fail "a pool that tries unseen credentials against the database must stay visible"
api /api/v1/summary | grep -q '"kind":"pool_without_users"' \
  && fail "having no users is this mode working as asked, not a warning"

echo "==> a configured havuz user is still checked by havuz, not by the database"
# dave gets a havuz account whose havuz password differs from his database one.
# The havuz password is what must be accepted, and it must not be forwarded.
api /api/v1/users -H 'content-type: application/json' \
  -d '{"name":"dave","password":"havuzonly","pools":["app_main"]}' > /dev/null

seen="$(pg dave havuzonly -c "select current_user;")"
[[ "$seen" == "app" ]] || fail "a configured user must keep the service account path, got '$seen'"

if pg dave davepass -c "select 1;" > /dev/null 2>&1; then
  fail "a configured user's database password was accepted; passthrough reached past the user list"
fi

echo "==> disabling that user locks him out, as it always did"
api /api/v1/users/dave -X PATCH -H 'content-type: application/json' -d '{"disabled": true}' > /dev/null
if pg dave havuzonly -c "select 1;" > /dev/null 2>&1; then
  fail "a disabled user got in through the passthrough path"
fi
api /api/v1/users/dave -X PATCH -H 'content-type: application/json' -d '{"disabled": false}' > /dev/null

echo "==> plaintext clients are refused, exactly as under per-user auth"
if docker run --rm --add-host host.docker.internal:host-gateway -e PGPASSWORD=carolpass postgres:16 \
  psql -qtAX "host=host.docker.internal port=$POOL_PORT user=carol dbname=ignored sslmode=disable" \
  -c "select 1;" > /dev/null 2>&1; then
  fail "a passthrough pool handed out a password prompt over an unencrypted socket"
fi

echo "==> nothing about a vouched-for identity is written to disk"
grep -q "carol" "$WORK/data/state.json" \
  && fail "a passthrough identity reached the state file; it is supposed to be memory only"

echo "==> and nothing survives a restart"
kill "$HAVUZ_PID"; wait "$HAVUZ_PID" 2>/dev/null || true
start_havuz
seen="$(pg carol carolpass -c "select current_user;")"
[[ "$seen" == "carol" ]] || fail "carol could not reconnect after a restart, got '$seen'"

echo "==> the flat pool list stays one row per pool"
rows="$(api /api/v1/summary | python3 -c 'import sys,json; print(len(json.load(sys.stdin)["pool_snapshots"]))')"
[[ "$rows" == "1" ]] || fail "passthrough identities produced $rows rows in the pool list"

echo
echo "passthrough authentication: PASS"
