#!/bin/bash

# Copyright (c) 2020-2021 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

set -e

cd "$(dirname $0)/.."

NBC_BINARY=$1
shift

NETWORK=$1
shift

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
  cat <<HELP

  All supplied options will be forwarded to the beacon node executable.
  Please execute build/$NBC_BINARY --help to get more information.

  To suppress the interactive input required by this script, you can
  specify WEB3_URL as an environment variable.

HELP
  exit 0
fi

: ${NODE_ID:=0}
: ${DATA_DIR_NAME:="shared_${NETWORK}_${NODE_ID}"}
: ${DATA_DIR:="build/data/${DATA_DIR_NAME}"}
: ${BASE_P2P_PORT:=9000}
: ${BASE_RPC_PORT:=9190}

# Windows detection
if uname | grep -qiE "mingw|msys"; then
  MAKE="mingw32-make"
  # This "winpty" wrapper is needed to make Ctrl+C work, on some systems.
  WINPTY="winpty --"
else
  MAKE="make"
  WINPTY=""
fi

if [[ ! -f build/${NBC_BINARY} ]]; then
  cat << MISSING_BINARY_HELP

Please build the beacon node binary by executing the following command:

${MAKE} ${NBC_BINARY}

MISSING_BINARY_HELP

  exit 1
fi

WEB3_URL_OPT_PRESENT=0
for op in "$@"; do
  if [[ "${op}" =~ ^--web3-url=.*$ ]]; then
    WEB3_URL_OPT_PRESENT=1
    break
  fi
done

if [[ "${WEB3_URL}" == "" && "${WEB3_URL_OPT_PRESENT}" == "0" ]]; then
  cat <<WEB3_HELP

To monitor the Eth1 validator deposit contract, you'll need to pair
the Nimbus beacon node with a Web3 provider capable of serving Eth1
event logs. This could be a locally running Eth1 client such as Geth
or a cloud service such as Infura. For more information please see
our setup guides:

https://status-im.github.io/nimbus-eth2/eth1.html

WEB3_HELP

  echo -n "Please enter a Web3 provider URL: "
  read WEB3_URL
fi

EXTRA_ARGS=""
if [[ "${WEB3_URL}" != "" ]]; then
  EXTRA_ARGS="--web3-url=${WEB3_URL}"
fi

# Allow the binary to receive signals directly.
exec ${WINPTY} build/${NBC_BINARY} \
  --network=${NETWORK} \
  --data-dir="${DATA_DIR}" \
  --log-file="${DATA_DIR}/nbc_bn_$(date +"%Y%m%d%H%M%S").log" \
  --tcp-port=$(( ${BASE_P2P_PORT} + ${NODE_ID} )) \
  --udp-port=$(( ${BASE_P2P_PORT} + ${NODE_ID} )) \
  --rpc \
  --rpc-port=$(( ${BASE_RPC_PORT} +${NODE_ID} )) \
  ${EXTRA_ARGS} \
  $@

