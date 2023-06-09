# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

if [ -z "${NIMBUS_ETH1_VARS_SOURCED:-}" ]; then
NIMBUS_ETH1_VARS_SOURCED=1

NIMBUS_ETH1_NUM_NODES="${NIMBUS_ETH1_NUM_NODES:-4}"
NIMBUS_ETH1_BASE_NET_PORT="${BASE_EL_NET_PORT:-40404}"
NIMBUS_ETH1_BASE_RPC_PORT="${BASE_EL_RPC_PORT:-9545}"
NIMBUS_ETH1_BASE_WS_PORT="${BASE_EL_WS_PORT:-9546}"
NIMBUS_ETH1_BASE_AUTH_RPC_PORT="${BASE_EL_AUTH_RPC_PORT:-9551}"
NIMBUS_ETH1_PORT_OFFSET="${EL_PORT_OFFSET:-10}"

CURL_BINARY=${CURL_BINARY:-curl}
JQ_BINARY=${JQ_BINARY:-jq}

NIMBUS_ETH1_NET_PORTS=()
NIMBUS_ETH1_RPC_PORTS=()
NIMBUS_ETH1_AUTH_RPC_PORTS=()

NIMBUS_ETH1_LAST_NODE_IDX=$((NIMBUS_ETH1_NUM_NODES - 1))

for NIMBUS_ETH1_NODE_IDX in $(seq 0 $NIMBUS_ETH1_LAST_NODE_IDX); do
  NIMBUS_ETH1_NET_PORTS+=($(( NIMBUS_ETH1_NODE_IDX * NIMBUS_ETH1_PORT_OFFSET + 1 + NIMBUS_ETH1_BASE_NET_PORT )))
  NIMBUS_ETH1_RPC_PORTS+=($(( NIMBUS_ETH1_NODE_IDX * NIMBUS_ETH1_PORT_OFFSET + 1 + NIMBUS_ETH1_BASE_RPC_PORT )))
  NIMBUS_ETH1_AUTH_RPC_PORTS+=($(( NIMBUS_ETH1_NODE_IDX * NIMBUS_ETH1_PORT_OFFSET + 1 + NIMBUS_ETH1_BASE_AUTH_RPC_PORT )))
done

fi
