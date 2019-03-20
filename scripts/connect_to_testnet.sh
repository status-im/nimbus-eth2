#!/bin/bash

set -eu
cd $(dirname "$0")

NETWORK_NAME=$1
source "$NETWORK_NAME.env"

cd ..

NIM_FLAGS="-d:debug -d:SHARD_COUNT=$SHARD_COUNT -d:SLOTS_PER_EPOCH=$SLOTS_PER_EPOCH"
nim c $NIM_FLAGS -r beacon_chain/beacon_node

