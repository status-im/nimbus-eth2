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
: ${NETWORK:="medalla"}
: ${DATA_DIR:="shared_${NETWORK}_${NODE_ID}"}
: ${BASE_PORT:=9000}
: ${BASE_RPC_PORT:=9190}
: ${GOERLI_WEB3_URL:="wss://goerli.infura.io/ws/v3/809a18497dd74102b5f37d25aae3c85a"}

# Create the data directory with the proper permissions.
"${REL_PATH}"/makedir.sh "${DATA_DIR}"

# Run the beacon node.
"${REL_PATH}"/${NETWORK}_beacon_node \
  --network="${NETWORK}" \
  --log-level="${LOG_LEVEL}" \
  --log-file="${DATA_DIR}"/nbc_bn_$(date +"%Y%m%d%H%M%S").log \
  --data-dir="${DATA_DIR}" \
  --web3-url=${GOERLI_WEB3_URL} \
  --tcp-port=$(( ${BASE_PORT} + ${NODE_ID} )) \
  --udp-port=$(( ${BASE_PORT} + ${NODE_ID} )) \
  --rpc \
  --rpc-port=$(( ${BASE_RPC_PORT} +${NODE_ID} )) \
  "$@"

