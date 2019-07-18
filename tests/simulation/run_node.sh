#!/bin/bash

set -eu

. $(dirname $0)/vars.sh
cd "$GIT_ROOT"

DATA_DIR="${SIMULATION_DIR}/node-${1}"

V_PREFIX="${VALIDATORS_DIR}/v$(printf '%06d' ${1})"
PORT=$(printf '5%04d' ${1})

NAT_FLAG="--nat:none"
if [ "${NAT:-}" == "1" ]; then
  NAT_FLAG="--nat:any"
fi

FIRST_VALIDATOR_IDX=$(( (NUM_VALIDATORS / ($NUM_NODES + $NUM_MISSING_NODES)) * $1 ))
LAST_VALIDATOR_IDX=$(( (NUM_VALIDATORS / ($NUM_NODES + $NUM_MISSING_NODES)) * ($1 + 1) - 1 ))

mkdir -p $DATA_DIR/validators
rm -f $DATA_DIR/validators/*

pushd $VALIDATORS_DIR
  cp $(seq -s " " -f v%07g.privkey $FIRST_VALIDATOR_IDX $LAST_VALIDATOR_IDX) $DATA_DIR/validators
popd

$BEACON_NODE_BIN \
  --network:$NETWORK_METADATA_FILE \
  --dataDir:$DATA_DIR \
  --nodename:${1} \
  --tcpPort:$PORT \
  --udpPort:$PORT \
  $NAT_FLAG \
  --stateSnapshot:$SNAPSHOT_FILE \
  $DEPOSIT_WEB3_URL_ARG \
  --depositContractAddress=$DEPOSIT_CONTRACT_ADDRESS
