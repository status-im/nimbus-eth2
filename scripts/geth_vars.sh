# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

GETH_PORT_OFFSET="${PORT_OFFSET:-100}"
GETH_BINARY="${GETH_BINARY:-"${HOME}/go-ethereum/build/bin/geth"}"
GETH_NUM_NODES="${GETH_NUM_NODES:-4}"
GETH_BINARY="${GETH_BINARY:-${HOME}/go-ethereum/build/bin/geth}"
GETH_NET_BASE_PORT="${GETH_NET_BASE_PORT:-30303}"
GETH_HTTP_BASE_PORT="${GETH_HTTP_BASE_PORT:-8545}"
GETH_WS_BASE_PORT="${GETH_WS_BASE_PORT:-8546}"
GETH_AUTH_RPC_BASE_PORT="${GETH_AUTH_RPC_BASE_PORT:-8551}"
GENESISJSON="${GENESISJSON:-${BASEDIR}/geth_genesis.json}"
DISCOVER="--nodiscover"
