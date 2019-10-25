#!/bin/bash

set -eu

NETWORK_NAME=$1
FIRST_VALIDATOR=$2
LAST_VALIDATOR=$3
DATA_DIR=${4:-~/.cache/nimbus/BeaconNode/$NETWORK_NAME}
VALIDATORS_DIR=$DATA_DIR/validators

mkdir -p $VALIDATORS_DIR

FIRST_IDX=$(printf '%07d' $FIRST_VALIDATOR)
LAST_IDX=$(printf '%07d' $LAST_VALIDATOR)

curl "https://raw.githubusercontent.com/status-im/nim-eth2-testnet-data/master/www/${NETWORK_NAME}/v[$FIRST_IDX-$LAST_IDX].privkey" \
  -o "$VALIDATORS_DIR/v#1.privkey" -s -w '%{url_effective} > %{filename_effective}\n'

