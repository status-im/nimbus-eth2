#!/bin/bash

ETH2_PM=${ETH2_PM_PATH:-"eth2.0-pm"}

set -eu

echo Locating zcli...
if ! command -v zcli; then
  go get -tags preset_minimal github.com/protolambda/zcli
fi

if [[ ! -d "$ETH2_PM" ]]; then
  git clone https://github.com/ethereum/eth2.0-pm "$ETH2_PM"
fi

# Fetch genesis time, as set up by start.sh
if command -v jq; then
  genesis_time=$(jq '.genesis_time' data/state_snapshot.json)
else
  # grep -P adds json parsing, requires the jq package
  genesis_time=$(grep -oP '(?<=genesis_time": )\w+(?=,)' data/state_snapshot.json)
fi

echo Genesis time was $genesis_time

zcli genesis mock \
  --count 16 \
  --genesis-time $genesis_time \
  --keys "${ETH2_PM}/interop/mocked_start/keygen_10000_validators.yaml" \
  --out data/zcli_genesis.ssz

zcli diff state data/zcli_genesis.ssz data/state_snapshot.ssz

