#!/usr/bin/env bash

# Copyright (c) 2025 Status Research & Development GmbH.
# Licensed under either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed
# except according to those terms.

set -euo pipefail

SCRIPTS_DIR="$(dirname "${BASH_SOURCE[0]}")"

source "${SCRIPTS_DIR}/spamoor_binaries.sh"

# This is private key which corresponds to
# 0xC9D2DaA6dd812745B5732aFd0b367dbcB2c38d88 address which was allocated in
# `execution_genesis.json.template`.
SPAMOOR_PRIVATE_KEY="65975debdc6b09ef5d40871d371861e98cbf1582ccf3f5466ed8ca8999f09388"
# Default value.
SPAMOOR_SECONDS_PER_SLOT="12"               # seconds
SPAMOOR_MAX_WALLETS="2000"                  # count
SPAMOOR_TRANSACTIONS_COUNT="1000"           # transactions count
SPAMOOR_THROUGHPUT="10"                     # transactions per second
SPAMOOR_REFILL_AMOUNT="5000"                # ETH
SPAMOOR_REFILL_BALANCE="2"                  # ETH
SPAMOOR_REFILL_INTERVAL="600"               # seconds
SPAMOOR_SIDECARS_PER_TRANSACTION="5"        # count
SPAMOOR_LOG="${DATA_DIR}/logs/spamoor.txt"  # path

log "Using ${SPAMOOR_BINARY}"

SPAMOOR_RPC_ENDPOINTS=""

if [[ "${RUN_GETH}" == "1" ]]; then
  for GETH_NODE_IDX in $(seq 0 $GETH_LAST_NODE_IDX); do
    # GETH_NODE_IDX == 0 has not been used.
    if [[ "${GETH_NODE_IDX}" != "0" ]]; then
      SPAMOOR_RPC_ENDPOINTS+="--rpchost http://127.0.0.1:${GETH_RPC_PORTS[GETH_NODE_IDX]} "
    fi
  done
fi

if [[ "${RUN_NIMBUS_ETH1}" == "1" ]]; then
  for NIMBUS_ETH1_NODE_IDX in $(seq 0 $NIMBUS_ETH1_LAST_NODE_IDX); do
    SPAMOOR_RPC_ENDPOINTS+="--rpchost http://127.0.0.1:${NIMBUS_ETH1_RPC_PORTS[NIMBUS_ETH1_NODE_IDX]} "
  done
fi

if [ -z "$SPAMOOR_RPC_ENDPOINTS" ]; then
  echo "Could not find any supported EL instances for spamoor"
  exit 1
fi

if [[ "${CONST_PRESET}" == "minimal" ]]; then
  SPAMOOR_SECONDS_PER_SLOT="6"
fi

set -x
${SPAMOOR_BINARY} \
  blobs \
  --privkey "${SPAMOOR_PRIVATE_KEY}" \
  ${SPAMOOR_RPC_ENDPOINTS} \
  --seconds-per-slot ${SPAMOOR_SECONDS_PER_SLOT} \
  --sidecars ${SPAMOOR_SIDECARS_PER_TRANSACTION} \
  --count ${SPAMOOR_TRANSACTIONS_COUNT} \
  --throughput ${SPAMOOR_THROUGHPUT} \
  --max-wallets ${SPAMOOR_MAX_WALLETS} \
  --refill-amount ${SPAMOOR_REFILL_AMOUNT} \
  --refill-balance ${SPAMOOR_REFILL_BALANCE} \
  --refill-interval ${SPAMOOR_REFILL_INTERVAL} \
  --log-txs --verbose --trace \
  &> "${SPAMOOR_LOG}" &
set +x

PID=$!
echo $PID > "${DATA_DIR}/pids/spamoor.pid"
