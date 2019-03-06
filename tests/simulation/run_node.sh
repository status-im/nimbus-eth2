#!/bin/bash

set -eux

. $(dirname $0)/vars.sh

BOOTSTRAP_NODES_FLAG="--bootstrapNodesFile:$MASTER_NODE_ADDRESS_FILE"

if [[ "$1" == "0" ]]; then
  BOOTSTRAP_NODES_FLAG=""
fi

DATA_DIR=$SIMULATION_DIR/node-${1}

V_PREFIX="$VALIDATORS_DIR/v$(printf '%06d' ${1})"
PORT=$(printf '5%04d' ${1})

$BEACON_NODE_BIN \
  --dataDir:$DATA_DIR \
  --validator:${V_PREFIX}0.privkey.json \
  --validator:${V_PREFIX}1.privkey.json \
  --validator:${V_PREFIX}2.privkey.json \
  --validator:${V_PREFIX}3.privkey.json \
  --validator:${V_PREFIX}4.privkey.json \
  --validator:${V_PREFIX}5.privkey.json \
  --validator:${V_PREFIX}6.privkey.json \
  --validator:${V_PREFIX}7.privkey.json \
  --validator:${V_PREFIX}8.privkey.json \
  --validator:${V_PREFIX}9.privkey.json \
  --tcpPort:$PORT \
  --udpPort:$PORT \
  --stateSnapshot:$SNAPSHOT_FILE \
  $BOOTSTRAP_NODES_FLAG
