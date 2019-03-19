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
MYIP=$(curl -s ifconfig.me)

$BEACON_NODE_BIN \
  --network:ephemeralNetwork \
  --dataDir:$DATA_DIR \
  --validator:${V_PREFIX}0.privkey \
  --validator:${V_PREFIX}1.privkey \
  --validator:${V_PREFIX}2.privkey \
  --validator:${V_PREFIX}3.privkey \
  --validator:${V_PREFIX}4.privkey \
  --validator:${V_PREFIX}5.privkey \
  --validator:${V_PREFIX}6.privkey \
  --validator:${V_PREFIX}7.privkey \
  --validator:${V_PREFIX}8.privkey \
  --validator:${V_PREFIX}9.privkey \
  --tcpPort:$PORT \
  --udpPort:$PORT \
  --nat:extip:$MYIP \
  --stateSnapshot:$SNAPSHOT_FILE \
  $BOOTSTRAP_NODES_FLAG
