#!/bin/bash

set -eux

. $(dirname $0)/vars.sh

BOOTSTRAP_NODES_FLAG="--bootstrapNodesFile:$MASTER_NODE_ADDRESS_FILE"

if [[ "$1" == "0" ]]; then
  BOOTSTRAP_NODES_FLAG=""
fi

DATA_DIR=$SIMULATION_DIR/node-${1}

$BEACON_NODE_BIN \
  --dataDir:$DATA_DIR \
  --validator:$STARTUP_DIR/validator-${1}1.json \
  --validator:$STARTUP_DIR/validator-${1}2.json \
  --validator:$STARTUP_DIR/validator-${1}3.json \
  --validator:$STARTUP_DIR/validator-${1}4.json \
  --validator:$STARTUP_DIR/validator-${1}5.json \
  --validator:$STARTUP_DIR/validator-${1}6.json \
  --validator:$STARTUP_DIR/validator-${1}7.json \
  --validator:$STARTUP_DIR/validator-${1}8.json \
  --validator:$STARTUP_DIR/validator-${1}9.json \
  --tcpPort:5000${1} \
  --udpPort:5000${1} \
  --stateSnapshot:$SNAPSHOT_FILE \
  $BOOTSTRAP_NODES_FLAG
