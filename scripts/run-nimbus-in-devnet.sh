#!/usr/bin/env bash

if [ -z "$1" ]; then
  echo "Usage: run-nimbus-eth2-in-withdrawal-testnet.sh <network-metadata-dir>"
  exit 1
fi

if [ ! -d "$1" ]; then
  echo "Please supply a valid network metadata directory"
  exit 1
fi

set -Eeu

NETWORK=$(cd "$1"; pwd)

cd $(dirname "$0")

source repo_paths.sh

DATA_DIR="$(create_data_dir_for_network "$NETWORK")"

JWT_TOKEN="$DATA_DIR/jwt-token"
create_jwt_token "$JWT_TOKEN"

"$BUILD_DIR/nimbus_beacon_node" \
  --non-interactive \
  --udp-port=19000 \
  --tcp-port=19000 \
  --network="$NETWORK" \
  --log-level=DEBUG \
  --data-dir="$DATA_DIR/nimbus_bn" \
  --web3-url=http://localhost:18550/ \
  --rest:on \
  --rest-port=15052 \
  --metrics=on \
  --metrics-port=18008 \
  --doppelganger-detection=no \
  --jwt-secret="$JWT_TOKEN"
