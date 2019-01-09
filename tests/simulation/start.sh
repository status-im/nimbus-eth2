#!/bin/bash

set -eu

NUMBER_OF_VALIDATORS=99

cd $(dirname "$0")
SIMULATION_DIR=$PWD

STARTUP_FILE="$SIMULATION_DIR/startup.json"
SNAPSHOT_FILE="$SIMULATION_DIR/state_snapshot.json"

cd $(git rev-parse --show-toplevel)
ROOT_DIR=$PWD

BEACON_NODE_BIN=$BUILD_OUTPUTS_DIR/beacon_node
VALIDATOR_KEYGEN_BIN=$BUILD_OUTPUTS_DIR/validator_keygen

if [[ ! -z "$SKIP_BUILDS" ]]; then
  nim c -o:"$VALIDATOR_KEYGEN_BIN" beacon_chain/validator_keygen
  nim c -o:"$BEACON_NODE_BIN" beacon_chain/beacon_node
fi

if [ ! -f $STARTUP_FILE ]; then
  $VALIDATOR_KEYGEN_BIN $NUMBER_OF_VALIDATORS "$SIMULATION_DIR"
fi

if [ ! -f $SNAPSHOT_FILE ]; then
  $BEACON_NODE_BIN createChain \
    --chainStartupData:$STARTUP_FILE \
    --out:$SNAPSHOT_FILE
fi

MASTER_NODE_ADDRESS_FILE="$SIMULATION_DIR/data-0/beacon_node.address"

# Delete any leftover address files from a previous session
if [ -f $MASTER_NODE_ADDRESS_FILE ]; then
  rm $MASTER_NODE_ADDRESS_FILE
fi

for i in $(seq 0 9); do
  BOOTSTRAP_NODES_FLAG="--bootstrapNodesFile:$MASTER_NODE_ADDRESS_FILE"

  if [[ "$i" == "0" ]]; then
    BOOTSTRAP_NODES_FLAG=""
  else
    # Wait for the master node to write out its address file
    while [ ! -f $MASTER_NODE_ADDRESS_FILE ]; do
      sleep 0.1
    done
  fi

  DATA_DIR=$SIMULATION_DIR/data-$i

  $BEACON_NODE_BIN \
    --dataDir:"$DATA_DIR" \
    --validator:"$SIMULATION_DIR/validator-${i}1.json" \
    --validator:"$SIMULATION_DIR/validator-${i}2.json" \
    --validator:"$SIMULATION_DIR/validator-${i}3.json" \
    --validator:"$SIMULATION_DIR/validator-${i}4.json" \
    --validator:"$SIMULATION_DIR/validator-${i}5.json" \
    --validator:"$SIMULATION_DIR/validator-${i}6.json" \
    --validator:"$SIMULATION_DIR/validator-${i}7.json" \
    --validator:"$SIMULATION_DIR/validator-${i}8.json" \
    --validator:"$SIMULATION_DIR/validator-${i}9.json" \
    --tcpPort:5000$i \
    --udpPort:5000$i \
    --stateSnapshot:"$SNAPSHOT_FILE" \
    $BOOTSTRAP_NODES_FLAG &
done

trap ctrl_c INT

function ctrl_c() {
  killall beacon_node
  exit 0
}

sleep 100000

