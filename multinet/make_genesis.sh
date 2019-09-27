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
    --totalDeposits="${NUM_VALIDATORS}" \
    --depositsDir="$VALIDATORS_DIR" \
    --randomKeys=false
fi

if [ ! -f "${SNAPSHOT_FILE}" ]; then
  $BEACON_NODE_BIN \
    --dataDir="${SIMULATION_DIR}/node-0" \
    createTestnet \
    --validatorsDir="${VALIDATORS_DIR}" \
    --totalValidators="${NUM_VALIDATORS}" \
    --outputGenesis="${SNAPSHOT_FILE}" \
    --outputNetworkMetadata="${NETWORK_METADATA_FILE}" \
    --outputBootstrapNodes="${SIMULATION_DIR}/bootstrap_nodes.txt" \
    --bootstrapAddress=127.0.0.1 \
    --bootstrapPort=50000 \
    --genesisOffset=10 # Delay in seconds
fi

# Delete any leftover address files from a previous session
if [ -f "${MASTER_NODE_ADDRESS_FILE}" ]; then
  rm "${MASTER_NODE_ADDRESS_FILE}"
fi

