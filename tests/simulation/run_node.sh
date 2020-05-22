#!/bin/bash

set -e

NODE_ID=${1}
shift

# Read in variables
# shellcheck source=/dev/null
source "$(dirname "$0")/vars.sh"

if [[ ! -z "$1" ]]; then
  ADDITIONAL_BEACON_NODE_ARGS=$1
  shift
else
  ADDITIONAL_BEACON_NODE_ARGS=""
fi

if [[ ! -z "$1" ]]; then
  BOOTSTRAP_NODE_ID=$1
  BOOTSTRAP_ADDRESS_FILE="${SIMULATION_DIR}/node-${BOOTSTRAP_NODE_ID}/beacon_node.address"
  shift
else
  BOOTSTRAP_NODE_ID=$MASTER_NODE
  BOOTSTRAP_ADDRESS_FILE=$NETWORK_BOOTSTRAP_FILE
fi

# set up the environment
# shellcheck source=/dev/null
source "${SIM_ROOT}/../../env.sh"

cd "$GIT_ROOT"

DATA_DIR="${SIMULATION_DIR}/node-$NODE_ID"
PORT=$(( BASE_P2P_PORT + NODE_ID ))

NAT_ARG="--nat:extip:127.0.0.1"
if [ "${NAT:-}" == "1" ]; then
  NAT_ARG="--nat:any"
fi

mkdir -p "$DATA_DIR/validators"
rm -f $DATA_DIR/validators/*

if [[ $NODE_ID -lt $TOTAL_NODES ]]; then
  FIRST_VALIDATOR_IDX=$(( (NUM_VALIDATORS / TOTAL_NODES) * NODE_ID ))
  LAST_VALIDATOR_IDX=$(( (NUM_VALIDATORS / TOTAL_NODES) * (NODE_ID + 1) - 1 ))

  pushd "$VALIDATORS_DIR" >/dev/null
    cp $(seq -s " " -f v%07g.privkey $FIRST_VALIDATOR_IDX $LAST_VALIDATOR_IDX) "$DATA_DIR/validators"
  popd >/dev/null
fi

rm -rf "$DATA_DIR/dump"
mkdir -p "$DATA_DIR/dump"

SNAPSHOT_ARG=""
if [ -f "${SNAPSHOT_FILE}" ]; then
  SNAPSHOT_ARG="--state-snapshot=${SNAPSHOT_FILE}"
fi

cd "$DATA_DIR"

# uncomment to force always using an external VC binary for VC duties
# TODO remove this when done with implementing the VC - here just for convenience during dev
#EXTERNAL_VALIDATORS="yes"

EXTERNAL_VALIDATORS_ARG=""
if [ "${EXTERNAL_VALIDATORS:-}" == "yes" ]; then
  EXTERNAL_VALIDATORS_ARG="--external-validators"
  # we lass a few seconds as delay for the start ==> that way we can start the
  # beacon node before the VC - otherwise we would have to add "&" conditionally to
  # the command which starts the BN - makes the shell script much more complicated
  $VALIDATOR_CLIENT_BIN \
    --data-dir=$DATA_DIR \
    --rpc-port="$(( $BASE_RPC_PORT + $NODE_ID ))" \
    --delay-start=5 &
fi

# if you want tracing messages, add "--log-level=TRACE" below
$BEACON_NODE_BIN \
  --log-level=${LOG_LEVEL:-DEBUG} \
  --bootstrap-file=$BOOTSTRAP_ADDRESS_FILE \
  --data-dir=$DATA_DIR \
  --node-name=$NODE_ID \
  --tcp-port=$PORT \
  --udp-port=$PORT \
  $SNAPSHOT_ARG \
  $EXTERNAL_VALIDATORS_ARG \
  $NAT_ARG \
  $WEB3_ARG \
  --deposit-contract=$DEPOSIT_CONTRACT_ADDRESS \
  --rpc \
  --rpc-address="127.0.0.1" \
  --rpc-port="$(( $BASE_RPC_PORT + $NODE_ID ))" \
  --metrics \
  --metrics-address="127.0.0.1" \
  --metrics-port="$(( $BASE_METRICS_PORT + $NODE_ID ))" \
  ${ADDITIONAL_BEACON_NODE_ARGS} \
  "$@"
