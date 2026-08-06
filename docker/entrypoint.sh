#!/bin/sh
#
# Container entrypoint. It does one thing havuz cannot do for itself: make sure
# the admin API on 0.0.0.0 has a token before the process gets there.
#
# The shipped config asks for HAVUZ_ADMIN_TOKEN. Supplying none would leave the
# dashboard open to anything that can reach the port, so one is generated and
# printed. Set the variable yourself for a token that survives a restart.

set -eu

if [ "${1:-run}" = "run" ] && [ -z "${HAVUZ_ADMIN_TOKEN:-}" ]; then
  HAVUZ_ADMIN_TOKEN="$(head -c 24 /dev/urandom | base64 | tr -d '=+/')"
  export HAVUZ_ADMIN_TOKEN
  {
    echo "no HAVUZ_ADMIN_TOKEN set; generated one for this container:"
    echo
    echo "    HAVUZ_ADMIN_TOKEN=${HAVUZ_ADMIN_TOKEN}"
    echo
    echo "It changes on every restart. Pass -e HAVUZ_ADMIN_TOKEN=... to keep it."
  } >&2
fi

exec havuz "$@"
