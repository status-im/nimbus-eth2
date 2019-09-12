#!/bin/bash

set -eu

PRYSM_validators=$(seq 11 15 | paste -d ',' -s)

PRYSM=${PRYSM_PATH:-"prysm"}

[[ -d "$PRYSM" ]] || {
  echo "TODO"
  exit 1
#  git clone git@github.com:ethereum/PRYSM.git "$PRYSM"
}

trap '' SIGTERM
trap 'kill -9 -- -$$' SIGINT EXIT

cd $PRYSM

./beacon-chain --datadir /tmp/beacon \
   --pprof --verbosity=debug \
   --clear-db \
   --bootstrap-node= \
   --peer=$(cat ../data/bootstrap_nodes.txt) \
   --interop-eth1data-votes \
   --deposit-contract=0xD775140349E6A5D12524C6ccc3d6A1d4519D4029 \
   --interop-genesis-state ../data/state_snapshot.ssz &

sleep 3

./validator --interop-start-index=8 --interop-num-validators=4
