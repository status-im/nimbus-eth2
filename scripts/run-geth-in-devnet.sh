#!/usr/bin/env bash
# Via Adrian Sutton

if [ -z "$1" ]; then
  echo "Usage: run-geth-el.sh <network-metadata-dir>"
  exit 1
fi

if [ ! -d "$1" ]; then
  echo "Please supply a valid network metadata directory"
  exit 1
fi

set -Eeu

NETWORK=$(cd "$1"; pwd)

cd $(dirname "$0")

source geth_binaries.sh
source repo_paths.sh

download_geth_capella

: ${GETH_AUTH_RPC_PORT:=18550}
: ${GETH_WS_PORT:=18551}

DATA_DIR="$(create_data_dir_for_network "$NETWORK")"

JWT_TOKEN="$DATA_DIR/jwt-token"
create_jwt_token "$JWT_TOKEN"

NETWORK_ID=$(cat "$NETWORK/genesis.json" | jq '.config.chainId')

EXECUTION_BOOTNODES=""
if [[ -f "$NETWORK/el_bootnode.txt" ]]; then
  EXECUTION_BOOTNODES+=$(awk '{print $1}' "$NETWORK/el_bootnode.txt" "$NETWORK/el_bootnode.txt" | paste -s -d, -)
fi

if [[ -f "$NETWORK/el_bootnodes.txt" ]]; then
  EXECUTION_BOOTNODES+=$(awk '{print $1}' "$NETWORK/el_bootnodes.txt" "$NETWORK/el_bootnodes.txt" | paste -s -d, -)
fi

if [[ -f "$NETWORK/bootnodes.txt" ]]; then
  EXECUTION_BOOTNODES+=$(awk '{print $1}' "$NETWORK/bootnodes.txt" "$NETWORK/bootnodes.txt" | paste -s -d, -)
fi

GETH_DATA_DIR="$DATA_DIR/geth"
EXECUTION_GENESIS_JSON="${NETWORK}/genesis.json"

set -x

if [[ ! -d "$GETH_DATA_DIR/geth" ]]; then
  # Initialize the genesis
  $GETH_CAPELLA_BINARY --http --ws -http.api "engine" --datadir "${GETH_DATA_DIR}" init "${EXECUTION_GENESIS_JSON}"
fi

echo "Logging to $DATA_DIR/geth_output.log"

$GETH_CAPELLA_BINARY \
    --authrpc.port ${GETH_AUTH_RPC_PORT} \
    --authrpc.jwtsecret "$JWT_TOKEN" \
    --allow-insecure-unlock \
    --datadir "${GETH_DATA_DIR}" \
    --bootnodes "${EXECUTION_BOOTNODES}" \
    --port 30308 \
    --password "" \
    --metrics \
    --syncmode snap \
    --networkid $NETWORK_ID 2>&1 | tee "$DATA_DIR/geth_output.log"
