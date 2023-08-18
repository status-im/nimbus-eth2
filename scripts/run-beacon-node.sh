#!/usr/bin/env bash

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

HELP
  exit 0
fi

: ${NODE_ID:=0}
: ${DATA_DIR_NAME:="shared_${NETWORK}_${NODE_ID}"}
: ${DATA_DIR:="build/data/${DATA_DIR_NAME}"}
: ${BASE_P2P_PORT:=9000}
: ${BASE_REST_PORT:=5052}

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

WEB3_URL_ARG=""
if [[ "$WEB3_URL" != "" ]]; then
  WEB3_URL_ARG="--web3-url=${WEB3_URL}"
fi

# Allow the binary to receive signals directly.
exec ${WINPTY} build/${NBC_BINARY} \
  --network=${NETWORK} \
  --data-dir="${DATA_DIR}" \
  --tcp-port=$(( ${BASE_P2P_PORT} + ${NODE_ID} )) \
  --udp-port=$(( ${BASE_P2P_PORT} + ${NODE_ID} )) \
  --rest \
  --rest-port=$(( ${BASE_REST_PORT} + ${NODE_ID} )) \
  --metrics \
  ${WEB3_URL_ARG} ${EXTRA_ARGS} \
  "$@"
