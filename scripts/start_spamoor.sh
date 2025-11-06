#!/usr/bin/env bash

# Copyright (c) 2025 Status Research & Development GmbH.
# Licensed under either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed
# except according to those terms.

set -euo pipefail

SCRIPTS_DIR="$(dirname "${BASH_SOURCE[0]}")"

source "${SCRIPTS_DIR}/geth_vars.sh"
source "${SCRIPTS_DIR}/nimbus_el_vars.sh"
source "${SCRIPTS_DIR}/spamoor_binaries.sh"

# This is private key which corresponds to
# 0xC9D2DaA6dd812745B5732aFd0b367dbcB2c38d88 address which was allocated in
# `execution_genesis.json.template`.
SPAMOOR_PRIVATE_KEY="65975debdc6b09ef5d40871d371861e98cbf1582ccf3f5466ed8ca8999f09388"

log "Using ${SPAMOOR_BINARY}"

SPAMOOR_RPC_ENDPOINTS=""

for GETH_NODE_IDX in $(seq 0 $GETH_LAST_NODE_IDX); do
  SPAMOOR_RPC_ENDPOINTS+="--rpchost http://127.0.0.1:${GETH_RPC_PORTS[GETH_NODE_IDX]} "
done

for NIMBUS_ETH1_NODE_IDX in $(seq 0 $NIMBUS_ETH1_LAST_NODE_IDX); do
  SPAMOOR_RPC_ENDPOINTS+="--rpchost http://127.0.0.1:${NIMBUS_ETH1_RPC_PORTS[NIMBUS_ETH1_NODE_IDX]} "
done

${SPAMOOR_BINARY} \
  blobs \
  --privkey "${SPAMOOR_PRIVATE_KEY}" \
  ${SPAMOOR_RPC_ENDPOINTS} \
  --count 100 \
  &> "${DATA_DIR}/logs/spamoor.txt" &

PID=$!
echo $PID > "${DATA_DIR}/pids/spamoor.pid"
