#!/bin/sh

GIT_CMD="git rev-parse --show-toplevel"
GIT_ROOT="$($GIT_CMD)"
PWD_CMD="pwd"
TEST_ROOT="$($PWD_CMD)"
NUM_VALIDATORS=${VALIDATORS:-32}
TOTAL_NODES=${NODES:-1}
TEST_DIR="${TEST_ROOT}/testrest"
VALIDATORS_DIR="${TEST_DIR}/validators"
SECRETS_DIR="${TEST_DIR}/secrets"
SNAPSHOT_FILE="${TEST_DIR}/state_snapshot.ssz"
NETWORK_BOOTSTRAP_FILE="${TEST_DIR}/bootstrap_hidden_nodes.txt"
BEACON_NODE_BIN="${GIT_ROOT}/build/nimbus_beacon_node"
RESTTEST_BIN="${GIT_ROOT}/build/resttest"
RESTTEST_RULES="${GIT_ROOT}/ncli/resttest-rules.json"
DEPOSIT_CONTRACT_BIN="${GIT_ROOT}/build/deposit_contract"
BOOTSTRAP_ENR_FILE="${TEST_DIR}/beacon_node.enr"
NETWORK_METADATA_FILE="${TEST_DIR}/network.json"
DEPOSITS_FILE="${TEST_DIR}/deposits.json"
REST_ADDRESS="127.0.0.1"
REST_PORT="5052"

# Windows detection
if uname | grep -qiE "mingw|msys"; then
  MAKE="mingw32-make"
else
  MAKE="make"
fi

# number of CPU cores
if uname | grep -qi darwin; then
  NPROC="$(sysctl -n hw.logicalcpu)"
else
  NPROC="$(nproc)"
fi

make_once () {
  target_flag_var="$1_name"
  if [[ -z "${!target_flag_var}" ]]; then
    export $target_flag_var=1
    $MAKE -j ${NPROC} $1
  fi
}

EXISTING_VALIDATORS=0
if [[ -f "$DEPOSITS_FILE" ]]; then
  # We count the number of deposits by counting the number of
  # occurrences of the 'deposit_data_root' field:
  EXISTING_VALIDATORS=$(grep -o -i deposit_data_root "$DEPOSITS_FILE" | wc -l)
fi

if [[ $EXISTING_VALIDATORS -ne $NUM_VALIDATORS ]]; then
  make_once deposit_contract
  make_once resttest

  rm -rf "$VALIDATORS_DIR"
  rm -rf "$SECRETS_DIR"

  build/deposit_contract generateSimulationDeposits \
    --count="${NUM_VALIDATORS}" \
    --out-validators-dir="$VALIDATORS_DIR" \
    --out-secrets-dir="$SECRETS_DIR" \
    --out-deposits-file="$DEPOSITS_FILE"

  echo "All deposits prepared"
fi

if [ ! -f "${SNAPSHOT_FILE}" ]; then
  echo Creating testnet genesis...
  $BEACON_NODE_BIN \
    --data-dir="${TEST_DIR}" \
    createTestnet \
    --deposits-file="${DEPOSITS_FILE}" \
    --total-validators="${NUM_VALIDATORS}" \
    --output-genesis="${SNAPSHOT_FILE}" \
    --output-bootstrap-file="${NETWORK_BOOTSTRAP_FILE}" \
    --netkey-file=network_key.json \
    --insecure-netkey-password=true \
    --genesis-offset=30 # Delay in seconds
fi

DEPOSIT_CONTRACT_ADDRESS="0x0000000000000000000000000000000000000000"
DEPOSIT_CONTRACT_BLOCK="0x0000000000000000000000000000000000000000000000000000000000000000"

echo Wrote $NETWORK_METADATA_FILE:
tee "$NETWORK_METADATA_FILE" <<EOF
{
  "runtimePreset": {
    "MIN_GENESIS_ACTIVE_VALIDATOR_COUNT": ${NUM_VALIDATORS},
    "MIN_GENESIS_TIME": 0,
    "GENESIS_DELAY": 10,
    "GENESIS_FORK_VERSION": "0x00000000",
    "ETH1_FOLLOW_DISTANCE": 1,
  },
  "depositContractAddress": "${DEPOSIT_CONTRACT_ADDRESS}",
  "depositContractDeployedAt": "${DEPOSIT_CONTRACT_BLOCK}"
}
EOF

cd "$TEST_ROOT"

SNAPSHOT_ARG=""
if [ -f "${SNAPSHOT_FILE}" ]; then
  SNAPSHOT_ARG="--finalized-checkpoint-state=${SNAPSHOT_FILE}"
fi

$BEACON_NODE_BIN \
  --log-level=${LOG_LEVEL:-DEBUG} \
  --network=$NETWORK_METADATA_FILE \
  --data-dir=$TEST_DIR \
  --secrets-dir=$SECRETS_DIR \
  $SNAPSHOT_ARG \
  --doppelganger-detection=off \
  --nat=none \
  --rest=true \
  --rest-address=$REST_ADDRESS \
  --rest-port= $REST_PORT \
  ${ADDITIONAL_BEACON_NODE_ARGS} \
  "$@" > bbbb.log 2>&1 &

BEACON_NODE_STATUS=$?

if [ $BEACON_NODE_STATUS -eq 0 ]; then
  echo "$BEACON_NODE_BIN has been successfully started"

  BEACON_NODE_PID="$(jobs -p)"

  $RESTTEST_BIN \
    --delay=60 \
    --timeout=60 \
    --skip-topic=slow \
    --connections=4 \
    --rules-file=$RESTTEST_RULES \
    http://$REST_ADDRESS:$REST_PORT/api

  RESTTEST_STATUS=$?
  kill -2 $BEACON_NODE_PID

  if [ $RESTTEST_STATUS -eq 0 ]; then
    echo "All tests are completed successfully!"
  else
    echo "Some of the tests are failed!"
    exit 1
  fi
else
  echo "$BEACON_NODE_BIN failed to start"
fi
