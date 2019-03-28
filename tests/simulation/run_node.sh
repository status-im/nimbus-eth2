#!/bin/bash

set -eu

. $(dirname $0)/vars.sh
cd "$GIT_ROOT"

DATA_DIR="${SIMULATION_DIR}/node-${1}"

V_PREFIX="${VALIDATORS_DIR}/v$(printf '%06d' ${1})"
PORT=$(printf '5%04d' ${1})

NAT_FLAG=""
if [ "${NAT:-}" == "1" ]; then
  NAT_FLAG="--nat:extip:$(curl -s ifconfig.me)"
fi

FIRST_VALIDATOR_IDX=$(printf '%07d' $(( (NUM_VALIDATORS / ($NUM_NODES + $NUM_MISSING_NODES)) * $1 )))
LAST_VALIDATOR_IDX=$(printf '%07d' $(( (NUM_VALIDATORS / ($NUM_NODES + $NUM_MISSING_NODES)) * ($1 + 1) - 1 )))

mkdir -p $DATA_DIR/validators
rm -f $DATA_DIR/validators/*
eval cp ${VALIDATORS_DIR}/v{$FIRST_VALIDATOR_IDX..$LAST_VALIDATOR_IDX}.privkey $DATA_DIR/validators

$BEACON_NODE_BIN \
  --network:$NETWORK_METADATA_FILE \
  --dataDir:$DATA_DIR \
  --nodename:${1} \
  --tcpPort:$PORT \
  --udpPort:$PORT \
  $NAT_FLAG \
  --stateSnapshot:$SNAPSHOT_FILE
