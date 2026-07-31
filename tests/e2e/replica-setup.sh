#!/usr/bin/env bash
#
# Bring up a real PostgreSQL primary with a streaming replica.
#
# Read/write split cannot be honestly tested against two independent databases:
# the whole risk is replication lag, and two unrelated servers have none. This
# builds an actual standby with pg_basebackup so lag is real and
# `pg_is_in_recovery()` answers truthfully.
#
#   ./tests/e2e/replica-setup.sh up
#   ./tests/e2e/replica-setup.sh down

set -euo pipefail

NET=havuz-net
PRIMARY=havuz-pg-primary
REPLICA=havuz-pg-replica
VOLUME=havuz-replica-data
IMAGE=postgres:16
PRIMARY_PORT=15432
REPLICA_PORT=15433

down() {
  docker rm -f "$PRIMARY" "$REPLICA" > /dev/null 2>&1 || true
  docker volume rm -f "$VOLUME" > /dev/null 2>&1 || true
  docker network rm "$NET" > /dev/null 2>&1 || true
}

wait_ready() {
  local container=$1
  for _ in $(seq 1 60); do
    if docker exec "$container" pg_isready -U app -d appdb > /dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "FAIL: $container never became ready"
  docker logs --tail 30 "$container"
  exit 1
}

up() {
  down
  docker network create "$NET" > /dev/null

  echo "==> primary"
  docker run -d --name "$PRIMARY" --network "$NET" \
    -e POSTGRES_USER=app -e POSTGRES_PASSWORD=hunter2 -e POSTGRES_DB=appdb \
    -e POSTGRES_HOST_AUTH_METHOD=scram-sha-256 \
    -e POSTGRES_INITDB_ARGS="--auth-host=scram-sha-256" \
    -p "$PRIMARY_PORT:5432" "$IMAGE" \
    -c wal_level=replica -c max_wal_senders=10 -c hot_standby=on \
    -c max_replication_slots=10 > /dev/null
  wait_ready "$PRIMARY"

  docker exec "$PRIMARY" psql -U app -d appdb -q \
    -c "CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD 'replpass';"
  docker exec "$PRIMARY" bash -c \
    "echo 'host replication replicator all scram-sha-256' >> /var/lib/postgresql/data/pg_hba.conf"
  docker exec "$PRIMARY" psql -U app -d appdb -qtAX -c "SELECT pg_reload_conf();" > /dev/null

  echo "==> base backup"
  docker volume create "$VOLUME" > /dev/null
  docker run --rm --network "$NET" --user postgres \
    -e PGPASSWORD=replpass -v "$VOLUME:/var/lib/postgresql/data" "$IMAGE" \
    bash -c "rm -rf /var/lib/postgresql/data/* && \
             pg_basebackup -h $PRIMARY -U replicator -D /var/lib/postgresql/data -Fp -Xs -R && \
             chmod 700 /var/lib/postgresql/data" > /dev/null

  echo "==> replica"
  docker run -d --name "$REPLICA" --network "$NET" \
    -v "$VOLUME:/var/lib/postgresql/data" -p "$REPLICA_PORT:5432" "$IMAGE" > /dev/null
  wait_ready "$REPLICA"

  # Prove it is a real standby before any test relies on it.
  local recovery
  recovery="$(docker exec "$REPLICA" psql -U app -d appdb -qtAX -c "SELECT pg_is_in_recovery();")"
  [[ "$recovery" == "t" ]] || { echo "FAIL: replica is not in recovery"; exit 1; }

  local senders
  senders="$(docker exec "$PRIMARY" psql -U app -d appdb -qtAX -c "SELECT count(*) FROM pg_stat_replication;")"
  [[ "$senders" -ge 1 ]] || { echo "FAIL: primary sees no streaming standby"; exit 1; }

  echo "    primary on $PRIMARY_PORT, streaming standby on $REPLICA_PORT"
}

case "${1:-up}" in
  up) up ;;
  down) down ;;
  *) echo "usage: $0 [up|down]"; exit 1 ;;
esac
