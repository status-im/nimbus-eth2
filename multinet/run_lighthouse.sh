#!/bin/bash

# Helper script for running a lighthouse node and connecting to the beacon node
# that's set up by start.sh

# https://github.com/sigp/lighthouse/blob/master/docs/interop.md

set -eu

echo Locating protoc...
if ! command -v protoc; then
  MSG="protoc (the Google Protobuf compiler) is missing. Please install it manually"
  if [[ "$OSTYPE" == "linux-gnu" ]]; then
    MSG+=" with sudo apt install protobuf-compiler"
  elif [[ "$OSTYPE" == "darwin"* ]]; then
    MSG+=" with 'brew install protobuf'"
  elif [[ "$OSTYPE" == "cygwin" ]]; then
    # POSIX compatibility layer and Linux environment emulation for Windows
    MSG+=""
  elif [[ "$OSTYPE" == "msys" ]]; then
    # Lightweight shell and GNU utilities compiled for Windows (part of MinGW)
    MSG+=""
  elif [[ "$OSTYPE" == "win32" ]]; then
    # I'm not sure this can happen.
    MSG+=""
  elif [[ "$OSTYPE" == "freebsd"* ]]; then
    # ...
    MSG+=""
  else
    # Unknown.
    MSG+=""
  fi
  echo $MSG
  exit 1
fi

cargo_path=$(which cargo)
[[ -x "$cargo_path" ]] || { echo "install rust first (https://rust-lang.org)"; exit 1; }

LIGHTHOUSE=${LIGHTHOUSE_PATH:-"lighthouse"}

[[ -d "$LIGHTHOUSE" ]] || {
  git clone https://github.com/sigp/lighthouse.git "$LIGHTHOUSE"
  pushd "$LIGHTHOUSE"
  git checkout interop # temporary interop branch - will get merged soon I expect!
  cargo update
  popd
}

pushd "$LIGHTHOUSE"
cargo build --release
popd

# Fetch genesis time, as set up by start.sh
if command -v jq; then
  genesis_time=$(jq '.genesis_time' data/state_snapshot.json)
else
  genesis_time=$(grep -oP '(?<=genesis_time": )\w+(?=,)' data/state_snapshot.json)
fi

echo Genesis time was $genesis_time

cd "$LIGHTHOUSE/target/release"

#$export RUST_LOG=libp2p=trace,multistream=trace,gossipsub=trace

trap '' SIGTERM
trap 'kill -9 -- -$$' SIGINT EXIT

# fresh start!
rm -rf ~/.lighthouse

./beacon_node --libp2p-addresses="$(cat ../data/bootstrap_nodes.txt)" testnet --spec minimal quick 16 $genesis_time &

./validator_client testnet -b insecure 0 4
