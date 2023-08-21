#!/usr/bin/env bash

# Copyright (c) 2023 Status Research & Development GmbH.
# Licensed under either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed
# except according to those terms.

set -euo pipefail

SCRIPTS_DIR="$(dirname "${BASH_SOURCE[0]}")"

source "${SCRIPTS_DIR}/geth_binaries.sh"
source "${SCRIPTS_DIR}/geth_vars.sh"

#These are used in the caller script
GETH_ENODES=()

log "Using ${GETH_BINARY}"

for GETH_NODE_IDX in $(seq 0 $GETH_LAST_NODE_IDX); do
  mkdir -p "${GETH_DATA_DIRS[GETH_NODE_IDX]}"
  GETH_LOG="${DATA_DIR}/logs/geth.${GETH_NODE_IDX}.txt"
  ${GETH_BINARY} version > "$GETH_LOG"
  ${GETH_BINARY} --datadir "${GETH_DATA_DIRS[GETH_NODE_IDX]}" init "${EXECUTION_GENESIS_JSON}" >> "$GETH_LOG" 2>&1
  set -x
  ${GETH_BINARY} \
    --syncmode full \
    --datadir "${GETH_DATA_DIRS[GETH_NODE_IDX]}" \
    ${DISCOVER} \
    --http \
    --http.port ${GETH_RPC_PORTS[GETH_NODE_IDX]} \
    --port ${GETH_NET_PORTS[GETH_NODE_IDX]} \
    --authrpc.port ${GETH_AUTH_RPC_PORTS[GETH_NODE_IDX]} \
    --authrpc.jwtsecret "${JWT_FILE}" \
        >> "${GETH_LOG}" 2>&1 &
  set +x
  PID=$!
  echo $PID > "${DATA_DIR}/pids/geth.${GETH_NODE_IDX}"
done

for GETH_NODE_IDX in $(seq 0 $GETH_LAST_NODE_IDX); do
  GETH_RETRY=0
  while :; do
    if [[ -S "${GETH_DATA_DIRS[GETH_NODE_IDX]}/geth.ipc" ]]; then
        echo "Geth ${GETH_NODE_IDX} started in $(( GETH_RETRY * 100 ))ms"
        break
    fi
    if (( ++GETH_RETRY >= 300 )); then
        echo "Geth ${GETH_NODE_IDX} failed to start"
        exit 1
    fi
    sleep 0.1
  done
  NODE_ID=$(${GETH_BINARY} attach --datadir "${GETH_DATA_DIRS[GETH_NODE_IDX]}" --exec admin.nodeInfo.enode)
  GETH_ENODES+=("${NODE_ID}")
done

#Add all nodes as peers
for dir in "${GETH_DATA_DIRS[@]}"
do
  for enode in "${GETH_ENODES[@]}"
  do
    ${GETH_BINARY} attach --datadir "${dir}" --exec "admin.addPeer(${enode})" &
  done
done

log "GETH RPC Ports: ${GETH_AUTH_RPC_PORTS[*]}"
