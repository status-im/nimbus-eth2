#!/bin/bash

set -eu

<<<<<<< HEAD
. $(dirname $0)/vars.sh
=======
source "$(dirname "$0")/vars.sh"
>>>>>>> split out genesis generation from running node
cd "$GIT_ROOT"

DATA_DIR="${SIMULATION_DIR}/node-0"

V_PREFIX="${VALIDATORS_DIR}/v$(printf '%06d' 0)"
PORT=$(printf '5%04d' 0)

NAT_FLAG="--nat:none"
if [ "${NAT:-}" == "1" ]; then
  NAT_FLAG="--nat:any"
fi

<<<<<<< HEAD
FIRST_VALIDATOR_IDX=$(( (NUM_VALIDATORS / ($NUM_NODES + $NUM_MISSING_NODES)) * $1 ))
LAST_VALIDATOR_IDX=$(( (NUM_VALIDATORS / ($NUM_NODES + $NUM_MISSING_NODES)) * ($1 + 1) - 1 ))
=======
# FIRST_VALIDATOR_IDX=$(( (NUM_VALIDATORS / ($NUM_NODES + $NUM_MISSING_NODES)) * $1 ))
# LAST_VALIDATOR_IDX=$(( (NUM_VALIDATORS / ($NUM_NODES + $NUM_MISSING_NODES)) * ($1 + 1) - 1 ))

FIRST_VALIDATOR_IDX=0
LAST_VALIDATOR_IDX=5
>>>>>>> split out genesis generation from running node

mkdir -p $DATA_DIR/validators
rm -f $DATA_DIR/validators/*

pushd $VALIDATORS_DIR >/dev/null
  cp $(seq -s " " -f v%07g.privkey $FIRST_VALIDATOR_IDX $LAST_VALIDATOR_IDX) $DATA_DIR/validators
popd >/dev/null

<<<<<<< HEAD
=======
rm -rf "$DATA_DIR/dump"
mkdir -p "$DATA_DIR/dump"

>>>>>>> split out genesis generation from running node
$BEACON_NODE_BIN \
  --network:$NETWORK_METADATA_FILE \
  --dataDir:$DATA_DIR \
  --nodename:0 \
  --tcpPort:$PORT \
  --udpPort:$PORT \
  $NAT_FLAG \
<<<<<<< HEAD
  --stateSnapshot:$SNAPSHOT_FILE
=======
  --stateSnapshot:$SNAPSHOT_FILE \
  $DEPOSIT_WEB3_URL_ARG \
  --depositContractAddress=$DEPOSIT_CONTRACT_ADDRESS
>>>>>>> split out genesis generation from running node
