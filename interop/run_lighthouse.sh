#!/bin/bash

# Helper script for running a lighthouse node and connecting to the beacon node
# that's set up by start.sh

# https://github.com/sigp/lighthouse/blob/master/docs/interop.md

cargo_path=$(which cargo)
[[ -x "$cargo_path" ]] || { echo "install rust first (https://rust-lang.org)"; exit 1; }

[[ -d "lighthouse" ]] || {
  git clone https://github.com/sigp/lighthouse.git
  cd lighthouse
  git checkout interop # temporary interop branch - will get merged soon I expect!
  cargo update
  cd ..
}

# Fetch genesis time, as set up by start.sh
genesis_time=$(grep -oP '(?<=genesis_time": )\w+(?=,)' data/state_snapshot.json)

cd lighthouse
cargo build

cd target/debug

#$export RUST_LOG=libp2p=trace,multistream=trace,gossipsub=trace

# fresh start!
rm -rf ~/.lighthouse

./beacon_node --libp2p-addresses="/ip4/127.0.0.1/tcp/50000" --api --rpc testnet --spec minimal quick 16 $genesis_time
