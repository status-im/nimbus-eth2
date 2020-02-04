#!/bin/bash

set -e

NODE_ID=${1}
shift

# Read in variables
# shellcheck source=/dev/null
source "$(dirname "$0")/vars.sh"

if [[ ! -z "$1" ]]; then
  BOOTSTRAP_NODE_ID=$1
  BOOTSTRAP_ADDRESS_FILE="${SIMULATION_DIR}/node-${BOOTSTRAP_NODE_ID}/beacon_node.address"
  shift
else
  BOOTSTRAP_NODE_ID=$MASTER_NODE
  BOOTSTRAP_ADDRESS_FILE=$NETWORK_BOOTSTRAP_FILE
fi

# set up the environment
# shellcheck source=/dev/null
source "${SIM_ROOT}/../../env.sh"

cd "$GIT_ROOT"

DATA_DIR="${SIMULATION_DIR}/node-$NODE_ID"
PORT=$(( BASE_P2P_PORT + NODE_ID ))

NAT_FLAG="--nat:none"
if [ "${NAT:-}" == "1" ]; then
  NAT_FLAG="--nat:any"
fi

mkdir -p "$DATA_DIR/validators"
rm -f $DATA_DIR/validators/*

if [[ $NODE_ID -lt $TOTAL_NODES ]]; then
  FIRST_VALIDATOR_IDX=$(( (NUM_VALIDATORS / TOTAL_NODES) * NODE_ID ))
  LAST_VALIDATOR_IDX=$(( (NUM_VALIDATORS / TOTAL_NODES) * (NODE_ID + 1) - 1 ))

  pushd "$VALIDATORS_DIR" >/dev/null
    cp $(seq -s " " -f v%07g.privkey $FIRST_VALIDATOR_IDX $LAST_VALIDATOR_IDX) "$DATA_DIR/validators"
  popd >/dev/null
fi

rm -rf "$DATA_DIR/dump"
mkdir -p "$DATA_DIR/dump"

NODE_BIN=$BEACON_NODE_BIN
if [[ $NODE_ID == $MASTER_NODE ]]; then
  NODE_BIN=$BOOTSTRAP_NODE_BIN
fi

cd "$DATA_DIR" && $NODE_BIN \
  --bootstrap-file=$BOOTSTRAP_ADDRESS_FILE \
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
  "$@"

