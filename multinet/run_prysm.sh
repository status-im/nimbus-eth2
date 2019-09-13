#!/bin/bash

# Prerequisites
# - Bazel (Requires java): https://docs.bazel.build/versions/master/install.html

set -eu

PRYSM_validators=$(seq 11 15 | paste -d ',' -s)

bazel_path=$(which bazel)
[[ -x "$bazel_path" ]] || { echo "install bazel build tool first (https://docs.bazel.build/versions/master/install.html)"; exit 1; }

PRYSM=${PRYSM_PATH:-"prysm"}

# This script assumes amd64. Prysm builds for other architectures, but keeping it simple
# for this start script.
OS=""
if [[ "$OSTYPE" == "linux-gnu" ]]; then
  OS+="linux_amd64"
elif [[ "$OSTYPE" == "darwin"* ]]; then
  OS+="darwin_amd64"
else
  # Windows builds do work, but it would make this script more complicated.
  # Allowing for Mac and Linux only for the moment.
  echo "Only Mac and Linux builds supported at this time"
fi

[[ -d "$PRYSM" ]] || {
  git clone git@github.com:prysmaticlabs/prysm.git "$PRYSM"
  pushd "$PRYSM"
  bazel build --define ssz=minimal //beacon-chain //validator
  pushd
}

trap '' SIGTERM
trap 'kill -9 -- -$$' SIGINT EXIT

cd $PRYSM

$(bazel info bazel-bin)/beacon-chain/${OS}_stripped/beacon-chain --datadir /tmp/beacon \
   --pprof --verbosity=debug \
   --clear-db \
   --bootstrap-node= \
   --peer=$(cat ../data/bootstrap_nodes.txt) \
   --interop-eth1data-votes \
   --deposit-contract=0xD775140349E6A5D12524C6ccc3d6A1d4519D4029 \
   --interop-genesis-state ../data/state_snapshot.ssz &

sleep 3

$(bazel info bazel-bin)/validator/${OS}_pure_stripped/validator --interop-start-index=8 --interop-num-validators=4
