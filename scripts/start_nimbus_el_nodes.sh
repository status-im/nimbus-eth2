#!/usr/bin/env bash

# Copyright (c) 2023-2026 Status Research & Development GmbH.
# Licensed under either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed
# except according to those terms.

set -euo pipefail

SCRIPTS_DIR="$(dirname "${BASH_SOURCE[0]}")"

. "${SCRIPTS_DIR}/nimbus_el_vars.sh"

NIMBUS_ETH1_ENODES=()
NIMBUS_ETH1_DATA_DIRS=()

wait_for_port() {
  for EXPONENTIAL_BACKOFF in {1..10}; do
    nc -w 1 -z $1 $2 > /dev/null && break;
    DELAY=$((2**$EXPONENTIAL_BACKOFF))
    echo "Port ${2} not yet available. Waiting ${DELAY} seconds"
    sleep $DELAY
  done
}

if uname | grep -qi darwin; then
  # Ensure dynamically linked libraries (e.g. RocksDB) can be found at runtime.
  # Check Nix paths first, then fall back to Homebrew.
  # See https://github.com/Homebrew/brew/issues/13481 for more details.
  for libdir in /run/current-system/sw/lib /opt/homebrew/lib /usr/local/lib; do
    if [ -d "$libdir" ]; then
      DYLD_LIBRARY_PATH="${DYLD_LIBRARY_PATH:+$DYLD_LIBRARY_PATH:}$libdir"
    fi
  done
  export DYLD_LIBRARY_PATH
fi

for NIMBUS_ETH1_NODE_IDX in $(seq 0 $NIMBUS_ETH1_LAST_NODE_IDX); do
  NIMBUS_ETH1_DATA_DIR=$(mktemp -d "${DATA_DIR}/nimbus-eth1-data-XXXXXX")
  NIMBUS_ETH1_DATA_DIRS+=("${NIMBUS_ETH1_DATA_DIR}")

  ${NIMBUS_ETH1_BINARY} \
    --data-dir="${NIMBUS_ETH1_DATA_DIR}" \
    --network="${EXECUTION_GENESIS_JSON}" \
    --discovery=None \
    --tcp-port="${NIMBUS_ETH1_NET_PORTS[NIMBUS_ETH1_NODE_IDX]}"  \
    --jwt-secret="${JWT_FILE}" \
    --engine-api --engine-api-port="${NIMBUS_ETH1_AUTH_RPC_PORTS[NIMBUS_ETH1_NODE_IDX]}" \
    --rpc --rpc-api=eth,admin --http-port="${NIMBUS_ETH1_RPC_PORTS[NIMBUS_ETH1_NODE_IDX]}" \
      &> "${DATA_DIR}/logs/nimbus_eth1.${NIMBUS_ETH1_NODE_IDX}.txt" &
  PID=$!
  echo $PID > "${DATA_DIR}/pids/nimbus_eth1.${NIMBUS_ETH1_NODE_IDX}"
done

echo "Waiting for the Nimbus ETH1 nodes to come online..."
for NIMBUS_ETH1_NODE_IDX in $(seq 0 $NIMBUS_ETH1_LAST_NODE_IDX); do
  wait_for_port localhost "${NIMBUS_ETH1_RPC_PORTS[NIMBUS_ETH1_NODE_IDX]}"

  NODE_ID=$(
    "${CURL_BINARY}" -sS -X POST \
                     -H 'Content-Type: application/json' \
                     -d '{"jsonrpc":"2.0","id":"id","method":"admin_nodeInfo"}' \
                     "http://localhost:${NIMBUS_ETH1_RPC_PORTS[NIMBUS_ETH1_NODE_IDX]}" | "${JQ_BINARY}" .result.enode)
  log "EL Node ID" "${NODE_ID}"
  NIMBUS_ETH1_ENODES+=("${NODE_ID}")
done

# TODO Here we should connect to the Geth nodes as well
echo "Connect all nodes though the admin_addPeer RPC call..."
for enode in "${NIMBUS_ETH1_ENODES[@]}"
do
  for port in "${NIMBUS_ETH1_RPC_PORTS[@]}"
  do
    "${CURL_BINARY}" -sS -X POST \
                     -H 'Content-Type: application/json' \
                     -d '{"jsonrpc":"2.0","id":"1","method":"admin_addPeer","params": ['"${enode}"']}' \
                     "http://localhost:${port}" &
  done
done

echo "Nimbus ETH1 HTTP Ports: ${NIMBUS_ETH1_RPC_PORTS[*]}"
