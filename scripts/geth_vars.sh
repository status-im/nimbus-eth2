# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

if [ -z "${GETH_VARS_SOURCED:-}" ]; then
GETH_VARS_SOURCED=1

GETH_NUM_NODES="${GETH_NUM_NODES:-4}"
GETH_BASE_NET_PORT="${BASE_EL_NET_PORT:-30303}"
GETH_BASE_RPC_PORT="${BASE_EL_RPC_PORT:-8545}"
GETH_BASE_WS_PORT="${BASE_EL_WS_PORT:-8546}"
GETH_BASE_AUTH_RPC_PORT="${BASE_EL_AUTH_RPC_PORT:-8551}"
GETH_PORT_OFFSET="${EL_PORT_OFFSET:-20}"
DISCOVER="--nodiscover"

GETH_NET_PORTS=()
GETH_AUTH_RPC_PORTS=()
GETH_DATA_DIRS=()

GETH_LAST_NODE_IDX=$((GETH_NUM_NODES - 1))

for GETH_NODE_IDX in $(seq 0 $GETH_LAST_NODE_IDX); do
  GETH_NET_PORTS+=($(( GETH_NODE_IDX * GETH_PORT_OFFSET + GETH_BASE_NET_PORT )))
  GETH_RPC_PORTS+=($(( GETH_NODE_IDX * GETH_PORT_OFFSET + GETH_BASE_RPC_PORT )))
  GETH_AUTH_RPC_PORTS+=($(( GETH_NODE_IDX * GETH_PORT_OFFSET + GETH_BASE_AUTH_RPC_PORT )))
  GETH_DATA_DIRS+=("${DATA_DIR}/geth-${GETH_NODE_IDX}")
done

fi
