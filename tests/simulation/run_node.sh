#!/bin/bash

set -e

NODE_ID=${1}
shift

# Read in variables
source "$(dirname "$0")/vars.sh"

# set up the environment
source "${SIM_ROOT}/../../env.sh"

cd "$GIT_ROOT"

DATA_DIR="${SIMULATION_DIR}/node-$NODE_ID"
PORT=$(( BASE_P2P_PORT + NODE_ID ))

NAT_FLAG="--nat:none"
if [ "${NAT:-}" == "1" ]; then
  NAT_FLAG="--nat:any"
fi

mkdir -p $DATA_DIR/validators
rm -f $DATA_DIR/validators/*

if [[ $NODE_ID -lt $TOTAL_NODES ]]; then
  FIRST_VALIDATOR_IDX=$(( (NUM_VALIDATORS / TOTAL_NODES) * NODE_ID ))
  LAST_VALIDATOR_IDX=$(( (NUM_VALIDATORS / TOTAL_NODES) * (NODE_ID + 1) - 1 ))

  pushd $VALIDATORS_DIR >/dev/null
    cp $(seq -s " " -f v%07g.privkey $FIRST_VALIDATOR_IDX $LAST_VALIDATOR_IDX) $DATA_DIR/validators
  popd >/dev/null
fi

$BEACON_NODE_BIN \
  --bootstrap-file=$NETWORK_BOOTSTRAP_FILE \
  --data-dir=$DATA_DIR \
  --node-name=$NODE_ID \
  --tcp-port=$PORT \
  --udp-port=$PORT \
  $NAT_FLAG \
  --state-snapshot=$SNAPSHOT_FILE \
  $DEPOSIT_WEB3_URL_ARG \
  --deposit-contract=$DEPOSIT_CONTRACT_ADDRESS \
  --metrics-server=on \
  --metrics-server-address="127.0.0.1" \
  --metrics-server-port="$(( $BASE_METRICS_PORT + $NODE_ID ))" \
  "$@" | tee "$DATA_DIR/node.log"

