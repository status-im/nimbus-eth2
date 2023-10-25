#!/usr/bin/env bash
#
# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

set -e

# DEFAULTS
BASE_PORT="49000"
BASE_METRICS_PORT="48008"
BASE_REST_PORT="47000"
RESTTEST_DELAY="30"
TEST_DIRNAME="resttest0_data"
KILL_OLD_PROCESSES="0"

####################
# argument parsing #
####################

GETOPT_BINARY="getopt"
if uname | grep -qi darwin; then
  # macOS
  # Without the head -n1 constraint, it gets confused by multiple matches
  GETOPT_BINARY=$(find /opt/homebrew/opt/gnu-getopt/bin/getopt /usr/local/opt/gnu-getopt/bin/getopt 2> /dev/null | head -n1 || true)
  [[ -f "$GETOPT_BINARY" ]] || { echo "GNU getopt not installed. Please run 'brew install gnu-getopt'. Aborting."; exit 1; }
fi

! ${GETOPT_BINARY} --test > /dev/null
if [ ${PIPESTATUS[0]} != 4 ]; then
  echo '`getopt --test` failed in this environment.'
  exit 1
fi

OPTS="h"
LONGOPTS="help,data-dir:,base-port:,base-rest-port:,base-metrics-port:,resttest-delay:,kill-old-processes"

print_help() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS] -- [BEACON NODE OPTIONS]

  -h, --help                  this help message
  --data-dir                  node's data directory (default: ${TEST_DIRNAME})
  --base-port                 bootstrap node's Eth2 traffic port (default: ${BASE_PORT})
  --base-rest-port            bootstrap node's REST port (default: ${BASE_REST_PORT})
  --base-metrics-port         bootstrap node's metrics server port (default: ${BASE_METRICS_PORT})
  --resttest-delay            resttest delay in seconds (default: ${RESTTEST_DELAY} seconds)
  --kill-old-processes        if any process is found listening on a port we use, kill it (default: disabled)
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
    --data-dir)
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
    --resttest-delay)
      RESTTEST_DELAY="$2"
      shift 2
      ;;
    --kill-old-processes)
      KILL_OLD_PROCESSES="1"
      shift
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
GIT_ROOT="$(git rev-parse --show-toplevel)"
TEST_DIR="${TEST_DIRNAME}"
LOG_NODE_FILE="${TEST_DIR}/node_log.txt"
LOG_TEST_FILE="${TEST_DIR}/client_log.txt"
VALIDATORS_DIR="${TEST_DIR}/validators"
SECRETS_DIR="${TEST_DIR}/secrets"
SNAPSHOT_FILE="${TEST_DIR}/genesis.ssz"
DEPOSIT_TREE_SNAPSHOT_FILE="${TEST_DIR}/deposit_tree_snapshot.ssz"
NETWORK_BOOTSTRAP_FILE="${TEST_DIR}/bootstrap_nodes.txt"
RESTTEST_RULES="${GIT_ROOT}/ncli/resttest-rules.json"
RESTTEST_BIN="${GIT_ROOT}/build/resttest"
NIMBUS_BEACON_NODE_BIN="${GIT_ROOT}/build/nimbus_beacon_node"
LOCAL_TESTNET_SIMULATION_BIN="${GIT_ROOT}/build/ncli_testnet"
BOOTSTRAP_ENR_FILE="${TEST_DIR}/beacon_node.enr"
RUNTIME_CONFIG_FILE="${TEST_DIR}/config.yaml"
DEPOSITS_FILE="${TEST_DIR}/deposits.json"
REST_ADDRESS="127.0.0.1"
METRICS_ADDRESS="127.0.0.1"
MKDIR_SCRIPT="${GIT_ROOT}/scripts/makedir.sh"
TOKEN_FILE="${TEST_DIR}/testTokenFile.txt"

$MKDIR_SCRIPT "${TEST_DIR}"
printf "testToken" > "${TOKEN_FILE}"

HAVE_LSOF=0

# Windows detection
if uname | grep -qiE "mingw|msys"; then
  MAKE="mingw32-make"
else
  MAKE="make"
  which lsof &>/dev/null && HAVE_LSOF=1 || { echo "'lsof' not installed and we need it to check for ports already in use. Aborting."; exit 1; }
fi

# number of CPU cores
if uname | grep -qi darwin; then
  NPROC="$(sysctl -n hw.logicalcpu)"
else
  NPROC="$(nproc)"
fi

# kill lingering processes from a previous run
if [[ "${HAVE_LSOF}" == "1" ]]; then
  for PORT in ${BASE_PORT} ${BASE_METRICS_PORT} ${BASE_REST_PORT}; do
    for PID in $(lsof -n -i tcp:${PORT} -sTCP:LISTEN -t); do
      echo -n "Found old process listening on port ${PORT}, with PID ${PID}. "
      if [[ "${KILL_OLD_PROCESSES}" == "1" ]]; then
	echo "Killing it."
	kill -9 ${PID} || true
      else
	echo "Aborting."
	exit 1
      fi
    done
  done
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

build_if_missing nimbus_beacon_node
build_if_missing ncli_testnet
build_if_missing resttest

if [[ ${EXISTING_VALIDATORS} -ne ${NUM_VALIDATORS} ]]; then
  rm -rf "${VALIDATORS_DIR}" "${SECRETS_DIR}"
  ${LOCAL_TESTNET_SIMULATION_BIN} generateDeposits \
    --count="${NUM_VALIDATORS}" \
    --out-validators-dir="${VALIDATORS_DIR}" \
    --out-secrets-dir="${SECRETS_DIR}" \
    --out-deposits-file="${DEPOSITS_FILE}"
  echo "All deposits prepared"
fi

# Kill child processes on Ctrl-C/SIGTERM/exit, passing the PID of this shell
# instance as the parent and the target process name as a pattern to the
# "pkill" command.
cleanup() {
  pkill -f -P $$ nimbus_beacon_node &>/dev/null || true
  pkill -f -P $$ resttest &>/dev/null || true
  sleep 2
  pkill -f -9 -P $$ nimbus_beacon_node &>/dev/null || true
  pkill -f -9 -P $$ resttest &>/dev/null || true
}
trap 'cleanup' SIGINT SIGTERM EXIT

DEPOSIT_CONTRACT_ADDRESS="0x0000000000000000000000000000000000000000"
DEPOSIT_CONTRACT_BLOCK="0x0000000000000000000000000000000000000000000000000000000000000000"

echo Wrote $RUNTIME_CONFIG_FILE:

# DENEB_FORK_EPOCH must be non-FAR_FUTURE_EPOCH to trigger creation of blob
# sidecar database table.
tee "$RUNTIME_CONFIG_FILE" <<EOF
PRESET_BASE: "mainnet"
MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: ${NUM_VALIDATORS}
MIN_GENESIS_TIME: 0
GENESIS_DELAY: 10
GENESIS_FORK_VERSION: 0x00000000
DEPOSIT_CONTRACT_ADDRESS: ${DEPOSIT_CONTRACT_ADDRESS}
ETH1_FOLLOW_DISTANCE: 1
ALTAIR_FORK_EPOCH: 0
BELLATRIX_FORK_EPOCH: 0
CAPELLA_FORK_EPOCH: 9000
DENEB_FORK_EPOCH: 10000
EOF

echo "Creating testnet genesis..."
${LOCAL_TESTNET_SIMULATION_BIN} \
  createTestnet \
  --data-dir="${TEST_DIR}" \
  --deposits-file="${DEPOSITS_FILE}" \
  --total-validators="${NUM_VALIDATORS}" \
  --output-genesis="${SNAPSHOT_FILE}" \
  --output-deposit-tree-snapshot="${DEPOSIT_TREE_SNAPSHOT_FILE}" \
  --output-bootstrap-file="${NETWORK_BOOTSTRAP_FILE}" \
  --netkey-file=network_key.json \
  --capella-fork-epoch=9000 \
  --deneb-fork-epoch=10000 \
  --insecure-netkey-password=true \
  --genesis-offset=-60 # Chain that has already started allows testing empty slots
# Make sure we use the newly generated genesis
echo "Removing existing database..."
rm -rf "${TEST_DIR}/db" "${TEST_DIR}/validators/slashing_protection.sqlite3"

${NIMBUS_BEACON_NODE_BIN} \
  --tcp-port=${BASE_PORT} \
  --udp-port=${BASE_PORT} \
  --log-level=${LOG_LEVEL:-DEBUG} \
  --network="${TEST_DIR}" \
  --data-dir="${TEST_DIR}" \
  --secrets-dir="${SECRETS_DIR}" \
  --doppelganger-detection=off \
  --nat=none \
  --no-el \
  --metrics \
  --metrics-address=${METRICS_ADDRESS} \
  --metrics-port=${BASE_METRICS_PORT} \
  --rest \
  --rest-address=${REST_ADDRESS} \
  --rest-port=${BASE_REST_PORT} \
  --keymanager \
  --keymanager-address=${REST_ADDRESS} \
  --keymanager-port=${BASE_REST_PORT} \
  --keymanager-token-file="${TOKEN_FILE}" \
  --discv5=no \
  ${ADDITIONAL_BEACON_NODE_ARGS} \
  "$@" > ${LOG_NODE_FILE} 2>&1 &
BEACON_NODE_STATUS=$?

if [[ ${BEACON_NODE_STATUS} -eq 0 ]]; then
  echo "nimbus_beacon_node has been successfully started"

  BEACON_NODE_PID="$(jobs -p)"

  ${RESTTEST_BIN} \
    --delay=${RESTTEST_DELAY} \
    --timeout=60 \
    --skip-topic=slow \
    --connections=4 \
    --rules-file="${RESTTEST_RULES}" \
    http://${REST_ADDRESS}:${BASE_REST_PORT} \
    > ${LOG_TEST_FILE} 2>&1
  RESTTEST_STATUS=$?

  kill -SIGINT ${BEACON_NODE_PID}

  if [[ ${RESTTEST_STATUS} -eq 0 ]]; then
    echo "All tests were completed successfully!"
  else
    echo "Some of the tests failed!"
    tail -n 100 ${LOG_NODE_FILE}
    exit 1
  fi
else
  echo "nimbus_beacon_node failed to start"
fi
