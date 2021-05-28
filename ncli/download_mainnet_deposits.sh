#!/usr/bin/env bash

set -eu

cd "$(dirname "$0")"

WEB3_URL=wss://mainnet.infura.io/ws/v3/809a18497dd74102b5f37d25aae3c85a

../env.sh nim c -r deposit_downloader.nim \
  --web3-url="$WEB3_URL" \
  --deposit-contract=0x00000000219ab540356cBB839Cbe05303d7705Fa \
  --start-block=11052984

