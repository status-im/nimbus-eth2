#!/bin/sh
# Runs the Nimbus beacon node with a supervised leanVM sidecar. Subcommands
# such as `trustedNodeSync` run without the sidecar.
BIN=/home/user/nimbus-eth2/build/nimbus_beacon_node.bin
case "$1" in
  -*|"") ;;
  *) exec "$BIN" "$@" ;;
esac

SOCK="${PQ_SIDECAR_SOCKET:-/tmp/leanvm-sidecar.sock}"
(
  while true; do
    rm -f "$SOCK"
    /usr/local/bin/leanvm-sidecar --socket "$SOCK" \
      --threads "${LEANVM_THREADS:-0}"
    echo "leanvm-sidecar exited with $?, restarting" >&2
    sleep 1
  done
) &

i=0
while [ ! -S "$SOCK" ] && [ "$i" -lt 600 ]; do
  sleep 0.1
  i=$((i + 1))
done
[ -S "$SOCK" ] || echo "leanvm-sidecar socket $SOCK not ready" >&2

exec "$BIN" "$@" --pq-sidecar-socket="$SOCK"
