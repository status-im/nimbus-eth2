#!/usr/bin/env bash

set -euo pipefail

BASEDIR="$(dirname "${BASH_SOURCE[0]}")"

GETH_NUM_NODES="${GETH_NUM_NODES:-4}"
GETH_BINARY="${GETH_BINARY:-${HOME}/go-ethereum/build/bin/geth}"
GETH_BASE_HTTP_PORT="${GETH_BASE_HTTP_PORT:-8550}"
GETH_NET_BASE_PORT="${GETH_NET_BASE_PORT:-30303}"
GETH_HTTP_BASE_PORT="${GETH_HTTP_BASE_PORT:-8545}"
GETH_WS_BASE_PORT="${GETH_WS_BASE_PORT:-8546}"
GETH_AUTH_RPC_PORT_BASE="${GETH_AUTH_RPC_PORT_BASE:-8551}"
PORT_OFFSET=100
GENESISJSON="${GENESISJSON:-${BASEDIR}/geth_genesis.json}"
DISCOVER="--nodiscover"

#These are used in the caller script
GETH_ENODES=()
GETH_HTTP_PORTS=()
GETH_NET_PORTS=()
GETH_WS_PORTS=()
GETH_RPC_PORTS=()
GETH_DATA_DIRS=()

for NUM_NODE in $(seq 0 $(( GETH_NUM_NODES - 1 ))); do
    GETH_NET_PORT=$(( NUM_NODE * PORT_OFFSET + GETH_NET_BASE_PORT ))
    GETH_HTTP_PORT=$(( NUM_NODE * PORT_OFFSET + GETH_HTTP_BASE_PORT ))
    GETH_WS_PORT=$(( NUM_NODE * PORT_OFFSET + GETH_WS_BASE_PORT ))
    GETH_AUTH_RPC_PORT=$(( NUM_NODE * PORT_OFFSET + GETH_AUTH_RPC_PORT_BASE ))
    echo "Starting geth node ${NUM_NODE} on net port ${GETH_NET_PORT} HTTP port ${GETH_HTTP_PORT} WS port ${GETH_WS_PORT}"
    GETHDATADIR=$(mktemp -d geth-data-XXX)
    GETH_DATA_DIRS+=(${GETHDATADIR})
    ${GETH_BINARY} --http --ws -http.api "engine" --datadir "${GETHDATADIR}" init "${GENESISJSON}"
    #${GETH_BINARY} --http --ws -http.api "engine" --datadir "${GETHDATADIR}" account import <(echo 45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8)
    #${GETH_BINARY} --http --ws --http.api "eth,net,engine" -ws.api "eth,net,engine" --datadir "${GETHDATADIR}" --allow-insecure-unlock --unlock "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b" --password ${PASSWORDFILE} --nodiscover console
    ${GETH_BINARY} --http --ws --http.api "eth,net,engine" -ws.api "eth,net,engine" --datadir "${GETHDATADIR}" ${DISCOVER} --port ${GETH_NET_PORT} --http.port ${GETH_HTTP_PORT=} --ws.port ${GETH_WS_PORT} --authrpc.port ${GETH_AUTH_RPC_PORT} &>/dev/null &
    sleep 5
    NODE_ID=$(${GETH_BINARY} attach --datadir "${GETHDATADIR}" --exec admin.nodeInfo.enode)
    GETH_ENODES+=(${NODE_ID})
    GETH_HTTP_PORTS+=(${GETH_HTTP_PORT})
    GETH_NET_PORTS+=(${GETH_NET_PORT})
    GETH_WS_PORTS+=(${GETH_WS_PORT})
    GETH_RPC_PORTS+=(${GETH_AUTH_RPC_PORT})
done

#Add all nodes as peers
for dir in "${GETH_DATA_DIRS[@]}"
do
    for enode in "${GETH_ENODES[@]}"
    do
      $(${GETH_BINARY} attach --datadir "${dir}" --exec "admin.addPeer(${enode})")
    done
done

echo "GETH HTTP Ports: ${GETH_HTTP_PORTS[*]}"
