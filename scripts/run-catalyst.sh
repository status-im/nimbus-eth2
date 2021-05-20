#!/usr/bin/env bash
# set -Eeuo pipefail
# https://github.com/prysmaticlabs/bazel-go-ethereum/blob/catalyst/run-catalyst.sh

# To increase verbosity: debug.verbosity(4)
# MetaMask seed phrase for account with balance is:
# lecture manual soon title cloth uncle gesture cereal common fruit tooth crater

echo \{ \
  \"config\": \{ \
    \"chainId\": 220720, \
    \"homesteadBlock\": 0, \
    \"eip150Block\": 0, \
    \"eip155Block\": 0, \
    \"eip158Block\": 0, \
    \"byzantiumBlock\": 0, \
    \"constantinopleBlock\": 0, \
    \"petersburgBlock\": 0, \
    \"istanbulBlock\": 0, \
    \"catalystBlock\": 0 \
  \}, \
  \"alloc\": \{\"0x4A55eF8869af149aea4E07874cd8598044Eea2cb\": \{\"balance\": \"1000000000000000000\"\}\}, \
  \"coinbase\": \"0x0000000000000000000000000000000000000000\", \
  \"difficulty\": \"0x20000\", \
  \"extraData\": \"\", \
  \"gasLimit\": \"0x2fefd8\", \
  \"nonce\": \"0x0000000000220720\", \
  \"mixhash\": \"0x0000000000000000000000000000000000000000000000000000000000000000\", \
  \"parentHash\": \"0x0000000000000000000000000000000000000000000000000000000000000000\", \
  \"timestamp\": \"0x00\" \
\} > /tmp/catalystgenesis.json

# TODO these paths need to be generalized
rm /tmp/catalystchaindata -rvf
~/clients/catalyst/build/bin/catalyst --catalyst --datadir /tmp/catalystchaindata init /tmp/catalystgenesis.json
~/clients/catalyst/build/bin/catalyst --catalyst --rpc --rpcapi net,eth,eth2,consensus,catalyst --nodiscover --miner.etherbase 0x1000000000000000000000000000000000000000 --datadir /tmp/catalystchaindata console
