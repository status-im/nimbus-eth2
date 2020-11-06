#!/bin/bash

set -e

cd "$(dirname $0)"

if [[ "$WEB3_URL" == "" ]]; then
  echo -n "Please enter a Web3 provider URL: "
  read WEB3_URL
fi

build/beacon_node \
  --data-dir=build/data/mainnet \
  --web3-url="${WEB3_URL}" \
  $@

