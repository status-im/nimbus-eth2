#!/bin/bash

set -e

cd "$(dirname $0)/.."

NBC_BINARY=$1
shift

NETWORK=$1
shift

# Windows detection
if uname | grep -qiE "mingw|msys"; then
  MAKE="mingw32-make"
else
  MAKE="make"
fi

if [[ ! -f build/${NBC_BINARY} ]]; then
  cat << MISSING_BINARY_HELP

Please build the beacon node binary by executing the following command:

${MAKE} ${NBC_BINARY}

MISSING_BINARY_HELP

  exit 1
fi

if [[ "$WEB3_URL" == "" ]]; then
  cat <<WEB3_HELP

To monitor the Eth1 validator deposit contract, you'll need to pair
the Nimbus beacon node with a Web3 provider capable of serving Eth1
event logs. This could be a locally running Eth1 client such as Geth
or a cloud service such as Infura. For more information please see
our setup guides:

https://status-im.github.io/nimbus-eth2/infura-guide.html

WEB3_HELP

  echo -n "Please enter a Web3 provider URL: "
  read WEB3_URL
fi

build/${NBC_BINARY} \
  --network=${NETWORK} \
  --data-dir=build/data/${NETWORK} \
  --web3-url="${WEB3_URL}" \
  $@

