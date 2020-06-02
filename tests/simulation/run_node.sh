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

NODE_DATA_DIR="${SIMULATION_DIR}/node-$NODE_ID"
NODE_VALIDATORS_DIR=$NODE_DATA_DIR/validators/
NODE_SECRETS_DIR=$NODE_DATA_DIR/secrets/

PORT=$(( BASE_P2P_PORT + NODE_ID ))

NAT_ARG="--nat:extip:127.0.0.1"
if [ "${NAT:-}" == "1" ]; then
  NAT_ARG="--nat:any"
fi

rm -rf "$NODE_VALIDATORS_DIR"
mkdir -p "$NODE_VALIDATORS_DIR"

rm -rf "$NODE_SECRETS_DIR"
mkdir -p "$NODE_SECRETS_DIR"

VALIDATORS_PER_NODE=$((NUM_VALIDATORS / TOTAL_NODES))

if [[ $NODE_ID -lt $TOTAL_NODES ]]; then
  # if using validator client binaries in addition to beacon nodes
  # we will split the keys for this instance in half between the BN and the VC
  if [ "${SPLIT_VALIDATORS_BETWEEN_BN_AND_VC:-}" == "yes" ]; then
    ATTACHED_VALIDATORS=$((VALIDATORS_PER_NODE / 2))
  else
    ATTACHED_VALIDATORS=$VALIDATORS_PER_NODE
  fi

  pushd "$VALIDATORS_DIR" >/dev/null
  for VALIDATOR in $(ls | tail -n +$(( ($VALIDATORS_PER_NODE * $NODE_ID) + 1 )) | head -n $ATTACHED_VALIDATORS); do
      cp -ar "$VALIDATOR" "$NODE_VALIDATORS_DIR"
      cp -a "$SECRETS_DIR/$VALIDATOR" "$NODE_SECRETS_DIR"
    done
  popd >/dev/null
fi

rm -rf "$NODE_DATA_DIR/dump"
mkdir -p "$NODE_DATA_DIR/dump"

SNAPSHOT_ARG=""
if [ -f "${SNAPSHOT_FILE}" ]; then
  SNAPSHOT_ARG="--state-snapshot=${SNAPSHOT_FILE}"
fi

cd "$NODE_DATA_DIR"

# if you want tracing messages, add "--log-level=TRACE" below
$BEACON_NODE_BIN \
  --log-level=${LOG_LEVEL:-DEBUG} \
  --bootstrap-file=$BOOTSTRAP_ADDRESS_FILE \
  --data-dir=$NODE_DATA_DIR \
  --secrets-dir=$NODE_SECRETS_DIR \
  --node-name=$NODE_ID \
  --tcp-port=$PORT \
  --udp-port=$PORT \
  $SNAPSHOT_ARG \
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
