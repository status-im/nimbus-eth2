# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

NIMBUSEL_DISCOVERY="--discovery=None"

NIMBUSEL_PORT_OFFSET="${PORT_OFFSET:-100}"
NIMBUSEL_BINARY="${NIMBUSEL_BINARY:-"${HOME}/work/nimbus-eth1/build/nimbus"}"
NIMBUSEL_GENESIS="${NIMBUSEL_GENESIS:-"${HOME}/work/nimbus-eth2/scripts/nimbusel_genesis.json"}"
NIMBUSEL_NUM_NODES="${NIMBUSEL_NUM_NODES:-4}"
NIMBUSEL_BINARY="${NIMBUSEL_BINARY:-${HOME}/go-ethereum/build/bin/geth}"
NIMBUSEL_NET_BASE_PORT="${NIMBUSEL_NET_BASE_PORT:-30303}"
NIMBUSEL_HTTP_BASE_PORT="${NIMBUSEL_HTTP_BASE_PORT:-8545}"
NIMBUSEL_WS_BASE_PORT="${NIMBUSEL_WS_BASE_PORT:-8546}"
NIMBUSEL_AUTH_RPC_PORT_BASE="${NIMBUSEL_AUTH_RPC_PORT_BASE:-8551}"
CURL_BINARY=${CURL_BINARY:-curl}
JQ_BINARY=${JQ_BINARY:-jq}
