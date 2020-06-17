#!/bin/bash

set -e

NODE_ID=${1}
shift

# Read in variables
# shellcheck source=/dev/null
source "$(dirname "$0")/vars.sh"

# set up the environment
# shellcheck source=/dev/null
source "${SIM_ROOT}/../../env.sh"

cd "$GIT_ROOT"

VC_DATA_DIR="${SIMULATION_DIR}/validator-$NODE_ID"

mkdir -p "$VC_DATA_DIR/validators"
rm -f $VC_DATA_DIR/validators/*

if [[ $NODE_ID -lt $TOTAL_NODES ]]; then
  # we will split the keys for this instance in half between the BN and the VC
  VALIDATORS_PER_NODE=$((NUM_VALIDATORS / TOTAL_NODES))
  VALIDATORS_PER_NODE_HALF=$((VALIDATORS_PER_NODE / 2))
  FIRST_VALIDATOR_IDX=$(( VALIDATORS_PER_NODE * NODE_ID + VALIDATORS_PER_NODE_HALF))
  LAST_VALIDATOR_IDX=$(( FIRST_VALIDATOR_IDX + VALIDATORS_PER_NODE_HALF - 1 ))

  pushd "$VALIDATORS_DIR" >/dev/null
    cp $(seq -s " " -f v%07g.privkey $FIRST_VALIDATOR_IDX $LAST_VALIDATOR_IDX) "$VC_DATA_DIR/validators"
  popd >/dev/null
fi

cd "$VC_DATA_DIR"

$VALIDATOR_CLIENT_BIN \
  --log-level=${LOG_LEVEL:-DEBUG} \
  --data-dir=$VC_DATA_DIR \
  --rpc-port="$(( $BASE_RPC_PORT + $NODE_ID ))"
