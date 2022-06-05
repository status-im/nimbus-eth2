#!/usr/bin/env bash

set -euo pipefail

BASEDIR="$(dirname "${BASH_SOURCE[0]}")"

. "${BASEDIR}/nimbus_el_vars.sh"

#These are used in the caller script
NIMBUSEL_ENODES=()
NIMBUSEL_HTTP_PORTS=()
NIMBUSEL_NET_PORTS=()
NIMBUSEL_WS_PORTS=()
NIMBUSEL_RPC_PORTS=()
NIMBUSEL_DATA_DIRS=()

log "Using ${NIMBUSEL_BINARY}"

for NUM_NODE in $(seq 0 $(( NIMBUSEL_NUM_NODES - 1 ))); do
    NIMBUSEL_NET_PORT=$(( NUM_NODE * NIMBUSEL_PORT_OFFSET + NIMBUSEL_NET_BASE_PORT ))
    NIMBUSEL_HTTP_PORT=$(( NUM_NODE * NIMBUSEL_PORT_OFFSET + NIMBUSEL_HTTP_BASE_PORT ))
    NIMBUSEL_WS_PORT=$(( NUM_NODE * NIMBUSEL_PORT_OFFSET + NIMBUSEL_WS_BASE_PORT ))
    NIMBUSEL_AUTH_RPC_PORT=$(( NUM_NODE * NIMBUSEL_PORT_OFFSET + NIMBUSEL_AUTH_RPC_PORT_BASE ))
    log "Starting nimbus EL node ${NUM_NODE} on net port ${NIMBUSEL_NET_PORT} HTTP port ${NIMBUSEL_HTTP_PORT} WS port ${NIMBUSEL_WS_PORT}"
    NIMBUSEL_DATADIR=$(mktemp -d nimbusel-data-XXX)
    NIMBUSEL_DATA_DIRS+=("${NIMBUSEL_DATADIR}")
    ${NIMBUSEL_BINARY} --data-dir="${NIMBUSEL_DATADIR}" --custom-network="${NIMBUSEL_GENESIS}" "${NIMBUSEL_DISCOVERY}" --tcp-port="${NIMBUSEL_NET_PORT}"  \
                       --rpc --rpc-port="${NIMBUSEL_HTTP_PORT}" &>/dev/null &
    sleep 5
    NODE_ID=$(
      "${CURL_BINARY}" -sS -X POST \
                       -H 'Content-Type: application/json' \
                       -d '{"jsonrpc":"2.0","id":"id","method":"net_nodeInfo"}' \
                       "http://localhost:${NIMBUSEL_HTTP_PORT}" | "${JQ_BINARY}" .result.enode)
    log "EL Node ID" "${NODE_ID}"
    NIMBUSEL_ENODES+=("${NODE_ID}")
    NIMBUSEL_HTTP_PORTS+=("${NIMBUSEL_HTTP_PORT}")
    NIMBUSEL_NET_PORTS+=("${NIMBUSEL_NET_PORT}")
    NIMBUSEL_WS_PORTS+=("${NIMBUSEL_WS_PORT}")
    NIMBUSEL_RPC_PORTS+=("${NIMBUSEL_AUTH_RPC_PORT}")
done

for enode in "${NIMBUSEL_ENODES[@]}"
do
  for port in "${NIMBUSEL_HTTP_PORTS[@]}"
  do
    "${CURL_BINARY}" -sS -X POST \
                     -H 'Content-Type: application/json' \
                     -d '{"jsonrpc":"2.0","id":"1","method":"nimbus_addPeer","params": ['"${enode}"']}' \
                     "http://localhost:${port}"
    done
done

echo "NimbusEL HTTP Ports: ${NIMBUSEL_HTTP_PORTS[*]}"
