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

NIM_FLAGS="-d:release -d:SECONDS_PER_SLOT=$SECONDS_PER_SLOT -d:SHARD_COUNT=$SHARD_COUNT -d:SLOTS_PER_EPOCH=$SLOTS_PER_EPOCH ${2:-}"

nim c -d:"network_type=$NETWORK_TYPE" $NIM_FLAGS beacon_chain/beacon_node

if [ ! -f $NETWORK_DIR/genesis.json ]; then
  rm -f $NETWORK_DIR/*
  beacon_chain/beacon_node makeDeposits \
    --totalDeposits=$VALIDATOR_COUNT \
    --depositDir="$NETWORK_DIR" \
    --randomKeys=true
fi

beacon_chain/beacon_node \
  --network=$NETWORK_NAME \
  --dataDir=$DATA_DIR/node-0 \
  createTestnet \
  --networkId=$NETWORK_ID \
  --validatorsDir=$NETWORK_DIR \
  --totalValidators=$VALIDATOR_COUNT \
  --lastUserValidator=$LAST_USER_VALIDATOR \
  --outputGenesis=$NETWORK_DIR/genesis.json \
  --outputNetwork=$NETWORK_DIR/network.json \
  --bootstrapAddress=$PUBLIC_IP \
  --bootstrapPort=$BOOTSTRAP_PORT \
  --genesisOffset=600 # Delay in seconds
