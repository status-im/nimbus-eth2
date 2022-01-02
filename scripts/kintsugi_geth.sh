#!/usr/bin/env bash
set -Eeu

# Via Adrian Sutton

GETH=${HOME}/go-ethereum/build/bin/geth

# https://github.com/eth2-clients/merge-testnets/tree/main/kintsugi
EXECUTION_BOOTNODE="enode://6f377dd1ef5a3272d7e02fac9064c4f95d74f7edfd866e59ded774ee5b4649ff61c3f24c95f5c3d07d692b447f0569716b8921b6861810b96a705c92e1d27ff9@161.35.67.219:30303"

GETHDATADIR=$(mktemp -d)
GENESISJSON=${HOME}/merge-testnets/kintsugi/genesis.json

echo "GETHDATADIR = ${GETHDATADIR}"

# Initialize the genesis
$GETH --catalyst --http --ws -http.api "engine" --datadir "${GETHDATADIR}" init "${GENESISJSON}"

# Import the signing key (press enter twice for empty password)
$GETH --catalyst --http --ws -http.api "engine" --datadir "${GETHDATADIR}" account import <(echo 45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8)

#--password "execution/geth/passfile.txt"
#--nodekey "execution/signer.key"

$GETH \
    --catalyst \
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
    --bootnodes "$EXECUTION_BOOTNODE" \
    --port 30308 \
    --password "" \
    --syncmode full \
    --unlock "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b" \
    --mine \
    --networkid 1337702 \
    console
