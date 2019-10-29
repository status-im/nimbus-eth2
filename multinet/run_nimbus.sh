#!/bin/bash

set -eu

VALIDATORS_START=${1:-20}
VALIDATORS_NUM=${2:-5}
VALIDATORS_TOTAL=${3:-30}

source "$(dirname "$0")/vars.sh"

cd "$GIT_ROOT"

DATA_DIR="${SIMULATION_DIR}/node-0"

V_PREFIX="${VALIDATORS_DIR}/v$(printf '%06d' 0)"
PORT=$(printf '5%04d' 0)

NAT_FLAG="--nat:none"
if [ "${NAT:-}" == "1" ]; then
  NAT_FLAG="--nat:any"
fi

mkdir -p $DATA_DIR/validators
rm -f $DATA_DIR/validators/*

pushd $VALIDATORS_DIR >/dev/null
  cp $(seq -s " " -f v%07g.privkey $VALIDATORS_START $(($VALIDATORS_START+$VALIDATORS_NUM-1))) $DATA_DIR/validators
popd >/dev/null

rm -rf "$DATA_DIR/dump"
mkdir -p "$DATA_DIR/dump"

set -x
trap 'kill -9 -- -$$' SIGINT EXIT SIGTERM

./env.sh $BEACON_NODE_BIN \
  --status-bar:off \
  --data-dir:$DATA_DIR \
  --node-name:0 \
  --tcp-port:$PORT \
  --udp-port:$PORT \
  $NAT_FLAG \
  --state-snapshot:$SNAPSHOT_FILE
