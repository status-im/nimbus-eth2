#!/bin/bash

# Copyright (c) 2020 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

# Mostly a duplication of "tests/simulation/{start.sh,run_node.sh}", but with a focus on
# replicating testnets as closely as possible, which means following the Docker execution labyrinth.

set -e

cd "$(dirname "${BASH_SOURCE[0]}")"/..

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

OPTS="hgt:n:d:"
LONGOPTS="help,testnet:,nodes:,data-dir:,disable-htop,log-level:,base-port:,base-metrics-port:,with-ganache,reuse-existing-data-dir"

# default values
TESTNET="1"
NUM_NODES="10"
DATA_DIR="local_testnet_data"
USE_HTOP="1"
USE_GANACHE="0"
LOG_LEVEL="DEBUG"
BASE_PORT="9000"
BASE_METRICS_PORT="8008"
REUSE_EXISTING_DATA_DIR="0"

print_help() {
  cat <<EOF
Usage: $(basename $0) --testnet <testnet number> [OTHER OPTIONS] -- [BEACON NODE OPTIONS]
E.g.: $(basename $0) --testnet ${TESTNET} --nodes ${NUM_NODES} --data-dir "${DATA_DIR}" # defaults
CI run: $(basename $0) --disable-htop -- --verify-finalization --stop-at-epoch=5

  -h, --help                  this help message
  -t, --testnet               testnet number (default: ${TESTNET})
  -n, --nodes                 number of nodes to launch (default: ${NUM_NODES})
  -g, --with-ganache          simulate a genesis event based on a deposit contract
  -d, --data-dir              directory where all the node data and logs will end up
                              (default: "${DATA_DIR}")
  --base-port                 bootstrap node's Eth2 traffic port (default: ${BASE_PORT})
  --base-metrics-port         bootstrap node's metrics server port (default: ${BASE_METRICS_PORT})
  --disable-htop              don't use "htop" to see the beacon_node processes
  --log-level                 set the log level (default: ${LOG_LEVEL})
  --reuse-existing-data-dir   instead of deleting and recreating the data dir, keep it and reuse everything we can from it
EOF
}

! PARSED=$(${GETOPT_BINARY} --options=${OPTS} --longoptions=${LONGOPTS} --name "$0" -- "$@")
if [ ${PIPESTATUS[0]} != 0 ]; then
  # getopt has complained about wrong arguments to stdout
  exit 1
fi

# read getopt's output this way to handle the quoting right
eval set -- "$PARSED"
while true; do
  case "$1" in
    -h|--help)
      print_help
      exit
      ;;
    -t|--testnet)
      TESTNET="$2"
      shift 2
      ;;
    -n|--nodes)
      NUM_NODES="$2"
      shift 2
      ;;
    -d|--data-dir)
      DATA_DIR="$2"
      shift 2
      ;;
    --disable-htop)
      USE_HTOP="0"
      shift
      ;;
    -g|--with-ganache)
      USE_GANACHE="1"
      shift
      ;;
    --log-level)
      LOG_LEVEL="$2"
      shift 2
      ;;
    --base-port)
      BASE_PORT="$2"
      shift 2
      ;;
    --base-metrics-port)
      BASE_METRICS_PORT="$2"
      shift 2
      ;;
    --reuse-existing-data-dir)
      REUSE_EXISTING_DATA_DIR="1"
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

# when sourcing env.sh, it will try to execute $@, so empty it
EXTRA_ARGS="$@"
if [[ $# != 0 ]]; then
  shift $#
fi
NETWORK="testnet${TESTNET}"

if [[ "$REUSE_EXISTING_DATA_DIR" == "0" ]]; then
  rm -rf "${DATA_DIR}"
fi

DEPOSITS_FILE="${DATA_DIR}/deposits.json"

VALIDATORS_DIR="${DATA_DIR}/validators"
mkdir -p "${VALIDATORS_DIR}"

SECRETS_DIR="${DATA_DIR}/secrets"
mkdir -p "${SECRETS_DIR}"

NETWORK_DIR="${DATA_DIR}/network_dir"
mkdir -p "${NETWORK_DIR}"

set -a
source "scripts/${NETWORK}.env"
set +a

# Windows detection
if uname | grep -qiE "mingw|msys"; then
  MAKE="mingw32-make"
else
  MAKE="make"
fi

NETWORK_NIM_FLAGS=$(scripts/load-testnet-nim-flags.sh ${NETWORK})
$MAKE -j2 LOG_LEVEL="${LOG_LEVEL}" NIMFLAGS="-d:insecure -d:testnet_servers_image -d:local_testnet ${NETWORK_NIM_FLAGS}" beacon_node deposit_contract

PIDS=""
WEB3_ARG=""
STATE_SNAPSHOT_ARG=""
BOOTSTRAP_TIMEOUT=30 # in seconds
DEPOSIT_CONTRACT_ADDRESS="0x0000000000000000000000000000000000000000"
DEPOSIT_CONTRACT_BLOCK="0x0000000000000000000000000000000000000000000000000000000000000000"
NETWORK_METADATA_FILE="${DATA_DIR}/network.json"

if [[ "$REUSE_EXISTING_DATA_DIR" == "0" ]]; then
  ./build/deposit_contract generateSimulationDeposits \
    --count=${TOTAL_VALIDATORS} \
    --out-validators-dir="${VALIDATORS_DIR}" \
    --out-secrets-dir="${SECRETS_DIR}" \
    --out-deposits-file="${DEPOSITS_FILE}"
fi

if [[ $USE_GANACHE == "0" ]]; then
  GENESIS_OFFSET=30
  BOOTSTRAP_IP="127.0.0.1"

  ./build/beacon_node createTestnet \
    --deposits-file="${DEPOSITS_FILE}" \
    --total-validators=${TOTAL_VALIDATORS} \
    --last-user-validator=${USER_VALIDATORS} \
    --output-genesis="${NETWORK_DIR}/genesis.ssz" \
    --output-bootstrap-file="${NETWORK_DIR}/bootstrap_nodes.txt" \
    --bootstrap-address=${BOOTSTRAP_IP} \
    --bootstrap-port=${BASE_PORT} \
    --genesis-offset=${GENESIS_OFFSET} # Delay in seconds

  STATE_SNAPSHOT_ARG="--state-snapshot=${NETWORK_DIR}/genesis.ssz"
else
  echo "Launching ganache"
  ganache-cli --blockTime 17 --gasLimit 100000000 -e 100000 --verbose > "${DATA_DIR}/log_ganache.txt" 2>&1 &
  PIDS="${PIDS},$!"

  WEB3_ARG="--web3-url=ws://localhost:8545"

  echo "Deploying deposit contract"
  DEPLOY_CMD_OUTPUT=$(./build/deposit_contract deploy $WEB3_ARG)
  # https://stackoverflow.com/questions/918886/how-do-i-split-a-string-on-a-delimiter-in-bash
  OUTPUT_PIECES=(${DEPLOY_CMD_OUTPUT//;/ })
  DEPOSIT_CONTRACT_ADDRESS=${OUTPUT_PIECES[0]}
  DEPOSIT_CONTRACT_BLOCK=${OUTPUT_PIECES[1]}

  echo Contract deployed at $DEPOSIT_CONTRACT_ADDRESS:$DEPOSIT_CONTRACT_BLOCK

  MIN_DELAY=1
  MAX_DELAY=5

  BOOTSTRAP_TIMEOUT=$(( MAX_DELAY * TOTAL_VALIDATORS ))

  ./build/deposit_contract sendDeposits \
    --deposits-file="${DEPOSITS_FILE}" \
    --min-delay=$MIN_DELAY --max-delay=$MAX_DELAY \
    $WEB3_ARG \
    --deposit-contract=${DEPOSIT_CONTRACT_ADDRESS} > "${DATA_DIR}/log_deposit_maker.txt" 2>&1 &

  PIDS="${PIDS},$!"
fi

./scripts/make_prometheus_config.sh \
    --nodes ${NUM_NODES} \
    --base-metrics-port ${BASE_METRICS_PORT} \
    --config-file "${DATA_DIR}/prometheus.yml" || true # TODO: this currently fails on macOS,
                                                       # but it can be considered non-critical

echo Wrote $NETWORK_METADATA_FILE:
tee "$NETWORK_METADATA_FILE" <<EOF
{
  "runtimePreset": {
    "MIN_GENESIS_ACTIVE_VALIDATOR_COUNT": ${TOTAL_VALIDATORS},
    "MIN_GENESIS_TIME": 0,
    "GENESIS_DELAY": 10,
    "GENESIS_FORK_VERSION": "0x00000000"
  },
  "depositContractAddress": "${DEPOSIT_CONTRACT_ADDRESS}",
  "depositContractDeployedAt": "${DEPOSIT_CONTRACT_BLOCK}"
}
EOF

# Kill child processes on Ctrl-C/SIGTERM/exit, passing the PID of this shell
# instance as the parent and the target process name as a pattern to the
# "pkill" command.
cleanup() {
  pkill -P $$ beacon_node &>/dev/null || true
  sleep 2
  pkill -9 -P $$ beacon_node &>/dev/null || true
}
trap 'cleanup' SIGINT SIGTERM EXIT

dump_logs() {
  LOG_LINES=20
  for LOG in "${DATA_DIR}"/log*.txt; do
    echo "Last ${LOG_LINES} lines of ${LOG}:"
    tail -n ${LOG_LINES} "${LOG}"
    echo "======"
  done
}

NODES_WITH_VALIDATORS=${NODES_WITH_VALIDATORS:-4}
BOOTSTRAP_NODE=0
SYSTEM_VALIDATORS=$(( TOTAL_VALIDATORS - USER_VALIDATORS ))
VALIDATORS_PER_NODE=$(( SYSTEM_VALIDATORS / NODES_WITH_VALIDATORS ))
BOOTSTRAP_ENR="${DATA_DIR}/node${BOOTSTRAP_NODE}/beacon_node.enr"

for NUM_NODE in $(seq 0 $(( NUM_NODES - 1 ))); do
  if [[ ${NUM_NODE} == ${BOOTSTRAP_NODE} ]]; then
    BOOTSTRAP_ARG=""
  else
    BOOTSTRAP_ARG="--bootstrap-file=${BOOTSTRAP_ENR}"
    # Wait for the master node to write out its address file
    START_TIMESTAMP=$(date +%s)
    while [[ ! -f "${BOOTSTRAP_ENR}" ]]; do
      sleep 0.1
      NOW_TIMESTAMP=$(date +%s)
      if [[ "$(( NOW_TIMESTAMP - START_TIMESTAMP - GENESIS_OFFSET ))" -ge "$BOOTSTRAP_TIMEOUT" ]]; then
        echo "Bootstrap node failed to start in ${BOOTSTRAP_TIMEOUT} seconds. Aborting."
        dump_logs
        exit 1
      fi
    done
  fi

  # Copy validators to individual nodes.
  # The first $NODES_WITH_VALIDATORS nodes split them equally between them, after skipping the first $USER_VALIDATORS.
  NODE_DATA_DIR="${DATA_DIR}/node${NUM_NODE}"
  rm -rf "${NODE_DATA_DIR}"
  mkdir -p "${NODE_DATA_DIR}/validators"
  mkdir -p "${NODE_DATA_DIR}/secrets"

  if [[ $NUM_NODE -lt $NODES_WITH_VALIDATORS ]]; then
    for VALIDATOR in $(ls ${VALIDATORS_DIR} | tail -n +$(( $USER_VALIDATORS + ($VALIDATORS_PER_NODE * $NUM_NODE) + 1 )) | head -n $VALIDATORS_PER_NODE); do
      cp -a "${VALIDATORS_DIR}/$VALIDATOR" "${NODE_DATA_DIR}/validators/"
      cp -a "${SECRETS_DIR}/${VALIDATOR}" "${NODE_DATA_DIR}/secrets/"
    done
  fi

  ./build/beacon_node \
    --non-interactive \
    --nat:extip:127.0.0.1 \
    --network="${NETWORK_METADATA_FILE}" \
    --log-level="${LOG_LEVEL}" \
    --tcp-port=$(( BASE_PORT + NUM_NODE )) \
    --udp-port=$(( BASE_PORT + NUM_NODE )) \
    --data-dir="${NODE_DATA_DIR}" \
    ${BOOTSTRAP_ARG} \
    ${STATE_SNAPSHOT_ARG} \
    ${WEB3_ARG} \
    --metrics \
    --metrics-address="127.0.0.1" \
    --metrics-port="$(( BASE_METRICS_PORT + NUM_NODE ))" \
    ${EXTRA_ARGS} \
    > "${DATA_DIR}/log${NUM_NODE}.txt" 2>&1 &

  if [[ "${PIDS}" == "" ]]; then
    PIDS="$!"
  else
    PIDS="${PIDS},$!"
  fi
done

# give the regular nodes time to crash
sleep 5
BG_JOBS="$(jobs | wc -l | tr -d ' ')"
if [[ "$BG_JOBS" != "$NUM_NODES" ]]; then
  echo "$((NUM_NODES - BG_JOBS)) beacon_node instance(s) exited early. Aborting."
  dump_logs
  exit 1
fi

if [[ "$USE_HTOP" == "1" ]]; then
  htop -p "$PIDS"
  cleanup
else
  FAILED=0
  for PID in $(echo "$PIDS" | tr ',' ' '); do
    wait $PID || FAILED="$(( FAILED += 1 ))"
  done
  if [[ "$FAILED" != "0" ]]; then
    echo "${FAILED} child processes had non-zero exit codes (or exited early)."
    dump_logs
    exit 1
  fi
fi

