#!/usr/bin/env bash

set -euo pipefail

BASEDIR="$(dirname "${BASH_SOURCE[0]}")"

. "${BASEDIR}/geth_vars.sh"

#These are used in the caller script
GETH_ENODES=()
GETH_HTTP_PORTS=()
GETH_NET_PORTS=()
GETH_WS_PORTS=()
GETH_RPC_PORTS=()
GETH_DATA_DIRS=()

log "Using ${GETH_BINARY}"

for GETH_NUM_NODE in $(seq 0 $(( GETH_NUM_NODES - 1 ))); do
    GETH_NET_PORT=$(( GETH_NUM_NODE * GETH_PORT_OFFSET + GETH_BASE_NET_PORT ))
    GETH_HTTP_PORT=$(( GETH_NUM_NODE * GETH_PORT_OFFSET + GETH_BASE_HTTP_PORT ))
    GETH_WS_PORT=$(( GETH_NUM_NODE * GETH_PORT_OFFSET + GETH_BASE_WS_PORT ))
    GETH_AUTH_RPC_PORT=$(( GETH_NUM_NODE * GETH_PORT_OFFSET + GETH_BASE_AUTH_RPC_PORT ))
    log "Starting geth node ${GETH_NUM_NODE} on net port ${GETH_NET_PORT} HTTP port ${GETH_HTTP_PORT} WS port ${GETH_WS_PORT}"
    GETHDATADIR=$(mktemp -d "${DATA_DIR}"/geth-data-XXX)
    GETH_DATA_DIRS+=(${GETHDATADIR})
    ${GETH_BINARY} --http --ws -http.api "engine" --datadir "${GETHDATADIR}" init "${GENESISJSON}"
    ${GETH_BINARY} --http --ws --http.corsdomain '*' --http.api "eth,net,engine" -ws.api "eth,net,engine" --datadir "${GETHDATADIR}" ${DISCOVER} --port ${GETH_NET_PORT} --http.port ${GETH_HTTP_PORT} --ws.port ${GETH_WS_PORT} --authrpc.port ${GETH_AUTH_RPC_PORT} --authrpc.jwtsecret /tmp/jwtsecret &> "${DATA_DIR}/geth-log${GETH_NUM_NODE}.txt" &
    sleep 5
    NODE_ID=$(${GETH_BINARY} attach --datadir "${GETHDATADIR}" --exec admin.nodeInfo.enode)
    GETH_ENODES+=("${NODE_ID}")
    GETH_HTTP_PORTS+=("${GETH_HTTP_PORT}")
    GETH_NET_PORTS+=("${GETH_NET_PORT}")
    GETH_WS_PORTS+=("${GETH_WS_PORT}")
    GETH_RPC_PORTS+=("${GETH_AUTH_RPC_PORT}")
done

#Add all nodes as peers
for dir in "${GETH_DATA_DIRS[@]}"
do
    for enode in "${GETH_ENODES[@]}"
    do
      ${GETH_BINARY} attach --datadir "${dir}" --exec "admin.addPeer(${enode})"
    done
done

log "GETH HTTP Ports: ${GETH_HTTP_PORTS[*]}"
