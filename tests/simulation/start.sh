#!/bin/bash

set -eu

NUMBER_OF_VALIDATORS=99

cd $(dirname "$0")
SIMULATION_DIR=$PWD

STARTUP_FILE="$SIMULATION_DIR/startup.json"
SNAPSHOT_FILE="$SIMULATION_DIR/state_snapshot.json"

cd $(git rev-parse --show-toplevel)
ROOT_DIR=$PWD

nim c beacon_chain/validator_keygen
nim c beacon_chain/beacon_node

if [ ! -f $STARTUP_FILE ]; then
  beacon_chain/validator_keygen $NUMBER_OF_VALIDATORS "$SIMULATION_DIR"
fi

if [ ! -f $SNAPSHOT_FILE ]; then
  beacon_chain/beacon_node createChain \
    --chainStartupData:$STARTUP_FILE \
    --out:$SNAPSHOT_FILE
fi

for i in $(seq 0 9); do
  DATA_DIR=$SIMULATION_DIR/data-$i
  BOOTSTRAP_NODES_FLAG=--bootstrapNodesFile:"$DATA_DIR/beacon_node.address"

  if [[ "$i" == "0" ]]; then
    BOOTSTRAP_NODES_FLAG=""
  fi

  beacon_chain/beacon_node \
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

