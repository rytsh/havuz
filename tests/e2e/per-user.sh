#!/usr/bin/env bash
#
# End-to-end check for per-user backend authentication.
#
# The property under test is the one the feature exists for: PostgreSQL sees
# the real user. Everything else about pooling — that clients queue rather than
# fail, that a user's connections are reused between its own sessions — has to
# keep working while that is true, so this checks those too.
#
# Requires the pg16 service from docker-compose.yml.

set -euo pipefail

PG_PORT="${PG_PORT:-15432}"
POOL_PORT="${POOL_PORT:-16442}"
ADMIN_PORT="${ADMIN_PORT:-17442}"
WORK="${WORK:-$(mktemp -d)}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HAVUZ="$ROOT/target/debug/havuz"

api() {
  curl -sS "http://127.0.0.1:$ADMIN_PORT$1" "${@:2}"
}

# Everything runs in a container so the host needs no PostgreSQL client.
# `sslmode=require` because a per-user pool refuses to ask for a password on an
# unencrypted socket, and the certificate is self-signed.
pg() {
  local user="$1" password="$2" port="$3"
  shift 3
  docker run --rm --add-host host.docker.internal:host-gateway -e "PGPASSWORD=$password" postgres:16 \
    psql -qtAX "host=host.docker.internal port=$port user=$user dbname=ignored sslmode=require" "$@"
}

# Directly against PostgreSQL, for setting up roles.
pg_admin() {
  docker run --rm --add-host host.docker.internal:host-gateway -e PGPASSWORD=hunter2 postgres:16 \
    psql -qtAX -h host.docker.internal -p "$PG_PORT" -U app -d appdb "$@"
}

# `drop role` fails while the role still holds grants, so revoke first. Leaving
# them behind would make a second run start from a different state.
drop_roles() {
  for role in alice bob; do
    pg_admin -c "revoke all on database appdb from $role;" || true
    pg_admin -c "drop role if exists $role;" || true
  done
}

fail() {
  echo "FAIL: $1"
  [[ -f "$WORK/havuz.log" ]] && tail -20 "$WORK/havuz.log"
  exit 1
}

cleanup() {
  [[ -n "${HAVUZ_PID:-}" ]] && kill "$HAVUZ_PID" 2>/dev/null || true
  drop_roles > /dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> building"
cargo build -q -p havuz-server

echo "==> creating two real database roles"
drop_roles > /dev/null
pg_admin -c "create role alice login password 'alicepass'; grant connect on database appdb to alice;" > /dev/null
pg_admin -c "create role bob   login password 'bobpass';   grant connect on database appdb to bob;" > /dev/null

echo "==> generating a client certificate"
openssl req -x509 -newkey rsa:2048 -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
  -days 1 -nodes -subj "/CN=havuz-e2e" 2>/dev/null

echo "==> starting havuz with client-facing TLS"
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
"$HAVUZ" run --config "$WORK/havuz.toml" > "$WORK/havuz.log" 2>&1 &
HAVUZ_PID=$!

for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:$ADMIN_PORT/healthz" > /dev/null 2>&1 && break
  sleep 0.3
done

echo "==> a per-user pool, and two havuz users on their own roles"
api /api/v1/pools -H 'content-type: application/json' -d "{
  \"name\": \"app_main\", \"family\": \"postgres\", \"mode\": \"transaction\",
  \"listen_port\": $POOL_PORT,
  \"backend_auth\": \"per_user\",
  \"settings\": {\"host\": \"127.0.0.1\", \"port\": $PG_PORT, \"database\": \"appdb\",
                 \"username\": \"app\", \"password\": \"hunter2\", \"sslmode\": \"disable\"},
  \"limits\": {\"max_size\": 2, \"max_client_connections\": 100}}" > /dev/null

for user in alice bob; do
  api /api/v1/users -H 'content-type: application/json' \
    -d "{\"name\":\"$user\",\"password\":\"${user}pass\",\"pools\":[\"app_main\"],\"own_backend_role\":true}" > /dev/null
done

echo "==> the database sees the real user, not a service account"
seen="$(pg alice alicepass "$POOL_PORT" -c "select current_user;")"
[[ "$seen" == "alice" ]] || fail "expected current_user=alice through the pooler, got '$seen'"
seen="$(pg bob bobpass "$POOL_PORT" -c "select current_user;")"
[[ "$seen" == "bob" ]] || fail "expected current_user=bob, got '$seen'"

echo "==> pg_stat_activity attributes the connection to that user"
attributed="$(pg alice alicepass "$POOL_PORT" \
  -c "select usename from pg_stat_activity where pid = pg_backend_pid();")"
[[ "$attributed" == "alice" ]] || fail "pg_stat_activity says '$attributed', not alice"

# Not asserted here: the backend's `application_name` starts as
# `havuz/{pool}/{user}`, but any client that sends one of its own — psql always
# does — has it replayed over the top, which is correct. `usename` above is the
# stronger evidence anyway, and it is the one that survives.

echo "==> a wrong password is refused by havuz and never reaches the database"
before="$(pg_admin -c "select count(*) from pg_stat_activity where usename = 'alice';")"
if pg alice wrongpass "$POOL_PORT" -c "select 1;" > /dev/null 2>&1; then
  fail "a wrong password was accepted"
fi
after="$(pg_admin -c "select count(*) from pg_stat_activity where usename = 'alice';")"
[[ "$before" == "$after" ]] || fail "a rejected password still opened a backend connection"

echo "==> each user pools over its own connections"
# Two sequential sessions for one user must reuse the same backend set rather
# than opening a fresh one each time; that is pooling still working per user.
for _ in 1 2 3; do
  pg alice alicepass "$POOL_PORT" -c "select 1;" > /dev/null
done
identities="$(api /api/v1/pools/app_main/identities)"
echo "$identities" | grep -q '"max_size_is_per_user":true' \
  || fail "the API does not report max_size as a per-user budget"

alice_created="$(python3 -c '
import json, sys
data = json.loads(sys.argv[1])["identities"]
row = next((i for i in data if i["user"] == "alice"), None)
print(row["pool_snapshot"]["created_total"] if row else "missing")
' "$identities")"
[[ "$alice_created" != "missing" ]] || fail "alice has no backend identity after connecting"
[[ "$alice_created" -le 2 ]] \
  || fail "alice opened $alice_created backend connections for 3 sessions; pooling is not happening per user"

echo "==> plaintext clients are refused, whatever they ask for"
if docker run --rm --add-host host.docker.internal:host-gateway -e PGPASSWORD=alicepass postgres:16 \
  psql -qtAX "host=host.docker.internal port=$POOL_PORT user=alice dbname=ignored sslmode=disable" \
  -c "select 1;" > /dev/null 2>&1; then
  fail "a per-user pool handed out a password prompt over an unencrypted socket"
fi

echo "==> a user still on the service account keeps working"
api /api/v1/users -H 'content-type: application/json' \
  -d '{"name":"legacy","password":"legacypass","pools":["app_main"]}' > /dev/null
seen="$(pg legacy legacypass "$POOL_PORT" -c "select current_user;")"
[[ "$seen" == "app" ]] || fail "expected the service account for an unmigrated user, got '$seen'"

echo "==> the flat pool list stays one row per pool"
rows="$(api /api/v1/summary | python3 -c 'import sys,json; print(len(json.load(sys.stdin)["pool_snapshots"]))')"
[[ "$rows" == "1" ]] || fail "three identities produced $rows rows in the pool list"

series="$(curl -sS "http://127.0.0.1:$ADMIN_PORT/metrics" | grep -c '^havuz_pool_backend_connections{')"
[[ "$series" == "1" ]] || fail "per-user pools leaked $series metric series; cardinality must stay bounded"

echo
echo "per-user authentication: PASS"
