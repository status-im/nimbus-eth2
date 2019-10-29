#!/bin/bash

set -eo pipefail

# Read in variables
source "$(dirname "$0")/vars.sh"

# set up the environment
source "${SIM_ROOT}/../env.sh"

cd "$SIM_ROOT"

rm -rf "$SIMULATION_DIR"
mkdir -p "$SIMULATION_DIR"
mkdir -p "$VALIDATORS_DIR"

cd "$GIT_ROOT"

make update deps

NIMFLAGS="-d:chronicles_log_level=DEBUG --warnings:off --hints:off --opt:speed"

# For interop, we run the minimal config
DEFS="-d:const_preset=minimal"

LAST_VALIDATOR_NUM=$(( NUM_VALIDATORS - 1 ))
LAST_VALIDATOR="$VALIDATORS_DIR/v$(printf '%07d' $LAST_VALIDATOR_NUM).deposit.json"

[[ -x "$BEACON_NODE_BIN" ]] || {
  echo "Building $BEACON_NODE_BIN ($DEFS)"
  nim c -o:"$BEACON_NODE_BIN" $NIMFLAGS $DEFS beacon_chain/beacon_node
}

if [ ! -f "${LAST_VALIDATOR}" ]; then
  $BEACON_NODE_BIN makeDeposits \
    --total-deposits="${NUM_VALIDATORS}" \
    --deposits-dir="$VALIDATORS_DIR" \
    --random-keys=no
fi

if [ ! -f "${SNAPSHOT_FILE}" ]; then
  $BEACON_NODE_BIN \
    --data-dir="${SIMULATION_DIR}/node-0" \
    createTestnet \
    --validators-dir="${VALIDATORS_DIR}" \
    --total-validators="${NUM_VALIDATORS}" \
    --output-genesis="${SNAPSHOT_FILE}" \
    --output-bootstrap-file="${SIMULATION_DIR}/bootstrap_nodes.txt" \
    --bootstrap-address=127.0.0.1 \
    --bootstrap-port=50000 \
    --genesis-offset=30 # Delay in seconds
fi

# Delete any leftover address files from a previous session
if [ -f "${MASTER_NODE_ADDRESS_FILE}" ]; then
  rm "${MASTER_NODE_ADDRESS_FILE}"
fi

