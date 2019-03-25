#!/bin/bash

set -eu

NETWORK_NAME=$1
NODE_ID=$2
FIRST_VALIDATOR=$3
LAST_VALIDATOR=$4

cd $(dirname "$0")
cd ..

if [ -f .env ]; then
  source .env
fi

NETWORK_DIR=$WWW_DIR/$NETWORK_NAME

for i in $(seq $FIRST_VALIDATOR $LAST_VALIDATOR); do
  VALIDATOR=v$(printf '%07d' $i)
  beacon_chain/beacon_node --dataDir="$DATA_DIR/node-$NODE_ID" importValidator \
    --keyfile="$NETWORK_DIR/$VALIDATOR.privkey"
done

