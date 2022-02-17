#!/usr/bin/env bash
# Via Adrian Sutton

if [ -z "$1" ]; then
  echo "Usage: run-geth-el.sh <network-metadata-dir>"
  exit 1
fi

set -Eeu

NETWORK=$1

NETWORK_ID=$(cat "$NETWORK/genesis.json" | jq '.config.chainId')

GETH=${HOME}/execution_clients/go-ethereum/build/bin/geth

# https://github.com/eth2-clients/merge-testnets/tree/main/kintsugi
EXECUTION_BOOTNODES=$(awk '{print $1}' "$NETWORK/el_bootnode.txt" | paste -s -d, -)

GETHDATADIR=$(mktemp -d)
GENESISJSON="${NETWORK}/genesis.json"

echo "GETHDATADIR = ${GETHDATADIR}"

# Initialize the genesis
$GETH --http --ws -http.api "engine" --datadir "${GETHDATADIR}" init "${GENESISJSON}"

# Import the signing key (press enter twice for empty password)
$GETH --http --ws -http.api "engine" --datadir "${GETHDATADIR}" account import <(echo 45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8)

#--password "execution/geth/passfile.txt"
#--nodekey "execution/signer.key"

$GETH \
    --http \
    --http.port 8550 \
    --http.api "engine,eth,net,admin,web3" \
    --http.corsdomain="*" \
    --http.vhosts="*" \
    --ws \
    --ws.port 8551 \
    --ws.api "engine,eth,net,admin,web3" \
    --allow-insecure-unlock \
    --datadir "${GETHDATADIR}" \
    --bootnodes "${EXECUTION_BOOTNODES}" \
    --port 30308 \
    --password "" \
    --syncmode full \
    --unlock "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b" \
    --mine \
    --networkid $NETWORK_ID \
    console
