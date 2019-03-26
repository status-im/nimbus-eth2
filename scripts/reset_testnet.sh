#!/bin/bash

set -eu

cd $(dirname "$0")

NETWORK_NAME=$1
source "$NETWORK_NAME.env"

cd ..

if [ -f .env ]; then
  # allow server overrides for WWW_DIR and DATA_DIR
  source .env
fi

PUBLIC_IP=$(curl -s ifconfig.me)
NETWORK_DIR=$WWW_DIR/$NETWORK_NAME

regenTestnetFiles() {
  NIM_FLAGS="-d:release -d:SHARD_COUNT=$SHARD_COUNT -d:SLOTS_PER_EPOCH=$SLOTS_PER_EPOCH ${2:-}"
  NETWORK_FLAVOUR=$1

  if [ ! -f $NETWORK_DIR/genesis.json ]; then
    rm -f $NETWORK_DIR/*
    nim c -r $NIM_FLAGS beacon_chain/validator_keygen \
      --generateFakeKeys=no \
      --validators=$VALIDATOR_COUNT \
      --outputDir="$NETWORK_DIR"
  fi

  nim c -r $NIM_FLAGS beacon_chain/beacon_node \
    --network=$NETWORK_NAME \
    --dataDir=$DATA_DIR/node-0 \
    createTestnet \
    --networkId=$NETWORK_ID \
    --validatorsDir=$NETWORK_DIR \
    --numValidators=$VALIDATOR_COUNT \
    --firstUserValidator=$FIRST_USER_VALIDATOR \
    --outputGenesis=$NETWORK_DIR/genesis.json \
    --outputNetwork=$NETWORK_DIR/$NETWORK_FLAVOUR-network.json \
    --bootstrapAddress=$PUBLIC_IP \
    --bootstrapPort=$BOOTSTRAP_PORT \
    --genesisOffset=600 # Delay in seconds
}

regenTestnetFiles rlpx
# regenTestnetFiles libp2p -d:withLibP2P

