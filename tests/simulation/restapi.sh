#!/usr/bin/env bash

set -e

# DEFAULTS
BASE_PORT="49000"
BASE_METRICS_PORT="48008"
BASE_REST_PORT="47000"
TIMEOUT_DURATION="30"
TEST_DIRNAME="build/resttest_sim"

####################
# argument parsing #
####################

GETOPT_BINARY="getopt"
if uname | grep -qi darwin; then
  # macOS
  GETOPT_BINARY="/usr/local/opt/gnu-getopt/bin/getopt"
  [[ -f "$GETOPT_BINARY" ]] || { echo "GNU getopt not installed. Please run 'brew install gnu-getopt'. Aborting."; exit 1; }
fi

! ${GETOPT_BINARY} --test > /dev/null
if [ ${PIPESTATUS[0]} != 4 ]; then
  echo '`getopt --test` failed in this environment.'
  exit 1
fi

OPTS="h"
LONGOPTS="help,test-dir:,base-port:,base-rest-port:,base-metrics-port:,timeout:"

print_help() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS] -- [BEACON NODE OPTIONS]

  -h, --help                  this help message
  --test-dir                  node's data directory (default: GIT_ROOT/${TEST_DIRNAME})
  --base-port                 bootstrap node's Eth2 traffic port (default: ${BASE_PORT})
  --base-rest-port            bootstrap node's REST port (default: ${BASE_REST_PORT})
  --base-metrics-port         bootstrap node's metrics server port (default: ${BASE_METRICS_PORT})
  --timeout                   timeout in seconds (default: ${TIMEOUT_DURATION} seconds)
EOF
}

! PARSED=$(${GETOPT_BINARY} --options=${OPTS} --longoptions=${LONGOPTS} --name "$0" -- "$@")
if [ ${PIPESTATUS[0]} != 0 ]; then
  # getopt has complained about wrong arguments to stdout
  exit 1
fi

eval set -- "$PARSED"

while true; do
  case "$1" in
    -h|--help)
      print_help
      exit
      ;;
    --test-dir)
      TEST_DIRNAME="$2"
      shift 2
      ;;
    --base-port)
      BASE_PORT="$2"
      shift 2
      ;;
    --base-rest-port)
      BASE_REST_PORT="$2"
      shift 2
      ;;
    --base-metrics-port)
      BASE_METRICS_PORT="$2"
      shift 2
      ;;
    --timeout)
      TIMEOUT_DURATION="$2"
      shift 2
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "argument parsing error"
      print_help
      exit 1
  esac
done

NUM_VALIDATORS=${VALIDATORS:-32}
TOTAL_NODES=${NODES:-1}
GIT_ROOT="$(git rev-parse --show-toplevel)"
TEST_DIR="${GIT_ROOT}/${TEST_DIRNAME}"
LOG_FILE="${TEST_DIR}/resttest_node.log"
VALIDATORS_DIR="${TEST_DIR}/validators"
SECRETS_DIR="${TEST_DIR}/secrets"
SNAPSHOT_FILE="${TEST_DIR}/state_snapshot.ssz"
NETWORK_BOOTSTRAP_FILE="${TEST_DIR}/bootstrap_hidden_nodes.txt"
RESTTEST_RULES="${GIT_ROOT}/ncli/resttest-rules.json"
DEPOSIT_CONTRACT_BIN="${GIT_ROOT}/build/deposit_contract"
BOOTSTRAP_ENR_FILE="${TEST_DIR}/beacon_node.enr"
NETWORK_METADATA_FILE="${TEST_DIR}/network.json"
DEPOSITS_FILE="${TEST_DIR}/deposits.json"
REST_ADDRESS="127.0.0.1"
METRICS_ADDRESS="127.0.0.1"
MKDIR_SCRIPT="${GIT_ROOT}/scripts/makedir.sh"

$MKDIR_SCRIPT "${TEST_DIR}"
cd "${TEST_DIR}"

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

build_if_missing () {
  if [[ ! -e "${GIT_ROOT}/build/${1}" ]]; then
    ${MAKE} -C "${GIT_ROOT}" -j ${NPROC} ${1}
  fi
}

EXISTING_VALIDATORS=0
if [[ -f "${DEPOSITS_FILE}" ]]; then
  # We count the number of deposits by counting the number of
  # occurrences of the 'deposit_data_root' field:
  EXISTING_VALIDATORS=$(grep -o -i deposit_data_root "${DEPOSITS_FILE}" | wc -l)
fi

if [[ ${EXISTING_VALIDATORS} -ne ${NUM_VALIDATORS} ]]; then
  build_if_missing deposit_contract
  rm -rf "${VALIDATORS_DIR}" "${SECRETS_DIR}"
  ../deposit_contract generateSimulationDeposits \
    --count="${NUM_VALIDATORS}" \
    --out-validators-dir="${VALIDATORS_DIR}" \
    --out-secrets-dir="${SECRETS_DIR}" \
    --out-deposits-file="${DEPOSITS_FILE}"
  echo "All deposits prepared"
fi

build_if_missing nimbus_beacon_node
build_if_missing resttest

if [[ ! -f "${SNAPSHOT_FILE}" ]]; then
  echo "Creating testnet genesis..."
  ../nimbus_beacon_node \
    --data-dir="${TEST_DIR}" \
    createTestnet \
    --deposits-file="${DEPOSITS_FILE}" \
    --total-validators="${NUM_VALIDATORS}" \
    --output-genesis="${SNAPSHOT_FILE}" \
    --output-bootstrap-file="${NETWORK_BOOTSTRAP_FILE}" \
    --netkey-file=network_key.json \
    --insecure-netkey-password=true \
    --genesis-offset=0 # Delay in seconds
fi

DEPOSIT_CONTRACT_ADDRESS="0x0000000000000000000000000000000000000000"
DEPOSIT_CONTRACT_BLOCK="0x0000000000000000000000000000000000000000000000000000000000000000"

echo "Writing ${NETWORK_METADATA_FILE}:"
tee "${NETWORK_METADATA_FILE}" <<EOF
{
  "runtimePreset": {
    "MIN_GENESIS_ACTIVE_VALIDATOR_COUNT": ${NUM_VALIDATORS},
    "MIN_GENESIS_TIME": 0,
    "GENESIS_DELAY": 0,
    "GENESIS_FORK_VERSION": "0x00000000",
    "ETH1_FOLLOW_DISTANCE": 1,
  },
  "depositContractAddress": "${DEPOSIT_CONTRACT_ADDRESS}",
  "depositContractDeployedAt": "${DEPOSIT_CONTRACT_BLOCK}"
}
EOF

SNAPSHOT_ARG=""
if [[ -f "${SNAPSHOT_FILE}" ]]; then
  SNAPSHOT_ARG="--finalized-checkpoint-state=${SNAPSHOT_FILE}"
fi

../nimbus_beacon_node \
  --tcp-port=${BASE_PORT} \
  --udp-port=${BASE_PORT} \
  --log-level=${LOG_LEVEL:-DEBUG} \
  --network="${NETWORK_METADATA_FILE}" \
  --data-dir="${TEST_DIR}" \
  --secrets-dir="${SECRETS_DIR}" \
  ${SNAPSHOT_ARG} \
  --doppelganger-detection=off \
  --nat=none \
  --metrics \
  --metrics-address=${METRICS_ADDRESS} \
  --metrics-port=${BASE_METRICS_PORT} \
  --rest \
  --rest-address=${REST_ADDRESS} \
  --rest-port= ${BASE_REST_PORT} \
  ${ADDITIONAL_BEACON_NODE_ARGS} \
  "$@" > ${LOG_FILE} 2>&1 &
BEACON_NODE_STATUS=$?

if [[ ${BEACON_NODE_STATUS} -eq 0 ]]; then
  echo "nimbus_beacon_node has been successfully started"

  BEACON_NODE_PID="$(jobs -p)"

  ../resttest \
    --delay=${TIMEOUT_DURATION} \
    --timeout=60 \
    --skip-topic=slow \
    --connections=4 \
    --rules-file="${RESTTEST_RULES}" \
    http://${REST_ADDRESS}:${BASE_REST_PORT}/api
  RESTTEST_STATUS=$?

  kill -SIGINT ${BEACON_NODE_PID}

  if [[ ${RESTTEST_STATUS} -eq 0 ]]; then
    echo "All tests were completed successfully!"
  else
    echo "Some of the tests failed!"
    tail -n 100 ${LOG_FILE}
    exit 1
  fi
else
  echo "nimbus_beacon_node failed to start"
fi
