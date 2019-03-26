#!/bin/bash

set -eu
cd $(dirname "$0")

NETWORK_NAME=$1
source "$NETWORK_NAME.env"

cd ..

NIM_FLAGS="-d:release --lineTrace:on -d:SHARD_COUNT=$SHARD_COUNT -d:SLOTS_PER_EPOCH=$SLOTS_PER_EPOCH"
nim c $NIM_FLAGS beacon_chain/beacon_node

if [ ! -d ~/.cache/nimbus/BeaconNode/$NETWORK_NAME/validators ]; then
  beacon_chain/beacon_node --network=$NETWORK_NAME importValidator
fi

beacon_chain/beacon_node --network=$NETWORK_NAME

