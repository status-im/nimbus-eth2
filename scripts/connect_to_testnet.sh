#!/bin/bash

set -eu
cd $(dirname "$0")

NETWORK_NAME=$1
source "$NETWORK_NAME.env"

cd ..

NIM_FLAGS="-d:release --lineTrace:on -d:chronicles_log_level=DEBUG -d:SECONDS_PER_SLOT=$SECONDS_PER_SLOT -d:SHARD_COUNT=$SHARD_COUNT -d:SLOTS_PER_EPOCH=$SLOTS_PER_EPOCH"

BEACON_NODE_BIN=${NETWORK_NAME}_node

nim c $NIM_FLAGS -o:"./$BEACON_NODE_BIN" beacon_chain/beacon_node

if [ ! -d ~/.cache/nimbus/BeaconNode/$NETWORK_NAME/validators ]; then
  ./$BEACON_NODE_BIN --network=$NETWORK_NAME importValidator
fi

./$BEACON_NODE_BIN --network=$NETWORK_NAME --tcpPort:$BOOTSTRAP_PORT --udpPort:$BOOTSTRAP_PORT

