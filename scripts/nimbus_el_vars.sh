# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

NIMBUSEL_DISCOVERY="--discovery=None"

NIMBUSEL_BINARY="${NIMBUSEL_BINARY:-"${HOME}/work/nimbus-eth1/build/nimbus"}"
NIMBUSEL_GENESIS="${NIMBUSEL_GENESIS:-"${HOME}/work/nimbus-eth2/scripts/nimbusel_genesis.json"}"
NIMBUSEL_NUM_NODES="${NIMBUSEL_NUM_NODES:-4}"
NIMBUSEL_BINARY="${NIMBUSEL_BINARY:-${HOME}/go-ethereum/build/bin/geth}"
NIMBUSEL_BASE_NET_PORT="${BASE_EL_NET_PORT:-30303}"
NIMBUSEL_BASE_HTTP_PORT="${BASE_EL_HTTP_PORT:-8545}"
NIMBUSEL_BASE_WS_PORT="${BASE_EL_WS_PORT:-8546}"
NIMBUSEL_BASE_AUTH_RPC_PORT="${BASE_EL_AUTH_RPC_PORT:-8551}"
NIMBUSEL_PORT_OFFSET="${EL_PORT_OFFSET:-10}"
CURL_BINARY=${CURL_BINARY:-curl}
JQ_BINARY=${JQ_BINARY:-jq}
