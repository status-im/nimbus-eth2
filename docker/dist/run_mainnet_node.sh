#!/bin/bash

# Copyright (c) 2020 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

set -e

REL_PATH="$(dirname $0)"

# Overridable from the environment.
: ${LOG_LEVEL:="INFO"}
: ${NODE_ID:=0}
: ${NETWORK:="mainnet"}
: ${DATA_DIR:="shared_${NETWORK}_${NODE_ID}"}
: ${BASE_PORT:=9000}
: ${BASE_RPC_PORT:=9190}

# Sanity checks.
if [[ -z "${WEB3_URL}" ]]; then
  echo "WEB3_URL not set in the environment. Aborting."
  exit 1
fi

# Create the data directory with the proper permissions.
"${REL_PATH}"/makedir.sh "${DATA_DIR}"

# Run the beacon node.
"${REL_PATH}"/beacon_node \
  --log-level="${LOG_LEVEL}" \
  --log-file="${DATA_DIR}"/nbc_bn_$(date +"%Y%m%d%H%M%S").log \
  --data-dir="${DATA_DIR}" \
  --web3-url=${WEB3_URL} \
  --tcp-port=$(( ${BASE_PORT} + ${NODE_ID} )) \
  --udp-port=$(( ${BASE_PORT} + ${NODE_ID} )) \
  --rpc \
  --rpc-port=$(( ${BASE_RPC_PORT} +${NODE_ID} )) \
  "$@"

