#!/bin/bash

# https://github.com/sigp/lighthouse/blob/master/docs/interop.md

set -eu

VALIDATORS_START=${1:-0}
VALIDATORS_NUM=${2:-5}
VALIDATORS_TOTAL=${3:-30}

SRCDIR=${LIGHTHOUSE_PATH:-"lighthouse"}

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

command -v cargo > /dev/null || { echo "install rust first (https://rust-lang.org)"; exit 1; }

[[ -d "$SRCDIR" ]] || {
  git clone https://github.com/sigp/lighthouse.git "$SRCDIR"
  pushd "$SRCDIR"
  git checkout interop # temporary interop branch - will get merged soon I expect!
  cargo update
  popd
}

pushd "$SRCDIR"
cargo build --release
popd

# Fetch genesis time, as set up by start.sh
if command -v jq > /dev/null; then
  GENESIS_TIME=$(jq '.genesis_time' data/state_snapshot.json)
else
  GENESIS_TIME=$(grep -oP '(?<=genesis_time": )\w+(?=,)' data/state_snapshot.json)
fi

echo Genesis time was $GENESIS_TIME

set -x
trap 'kill -9 -- -$$' SIGINT EXIT SIGTERM

cd "$SRCDIR/target/release"

#$export RUST_LOG=libp2p=trace,multistream=trace,gossipsub=trace

# fresh start!
rm -rf ~/.lighthouse

./beacon_node --libp2p-addresses="/ip4/127.0.0.1/tcp/50000" testnet --spec minimal quick $VALIDATORS_TOTAL $GENESIS_TIME &

./validator_client testnet -b insecure $VALIDATORS_START $VALIDATORS_NUM
