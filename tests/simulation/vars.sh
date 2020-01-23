#!/bin/bash

# https://github.com/koalaman/shellcheck/wiki/SC2034
# shellcheck disable=2034
true

PWD_CMD="pwd"
# get native Windows paths on Mingw
uname | grep -qi mingw && PWD_CMD="pwd -W"

cd "$(dirname "$0")"

SIM_ROOT="$($PWD_CMD)"

# Set a default value for the env vars usually supplied by a Makefile
cd "$(git rev-parse --show-toplevel)"
: ${GIT_ROOT:="$($PWD_CMD)"}
cd - &>/dev/null

# When changing these, also update the readme section on running simulation
# so that the run_node example is correct!
NUM_VALIDATORS=${VALIDATORS:-192}
TOTAL_NODES=${NODES:-4}
TOTAL_USER_NODES=${USER_NODES:-0}
TOTAL_SYSTEM_NODES=$(( TOTAL_NODES - TOTAL_USER_NODES ))
MASTER_NODE=$(( TOTAL_NODES - 1 ))

# You can run a mixed simulation of daemon and native libp2p nodes
# by changing the variables below:
NETWORK_TYPE=libp2p
BOOTSTRAP_NODE_NETWORK_TYPE=libp2p

SIMULATION_DIR="${SIM_ROOT}/data"
METRICS_DIR="${SIM_ROOT}/prometheus"
VALIDATORS_DIR="${SIM_ROOT}/validators"
SNAPSHOT_FILE="${SIMULATION_DIR}/state_snapshot.ssz"
NETWORK_BOOTSTRAP_FILE="${SIMULATION_DIR}/bootstrap_nodes.txt"
BEACON_NODE_BIN="${SIMULATION_DIR}/beacon_node"
BOOTSTRAP_NODE_BIN="${SIMULATION_DIR}/bootstrap_node"
DEPLOY_DEPOSIT_CONTRACT_BIN="${SIMULATION_DIR}/deploy_deposit_contract"
MASTER_NODE_ADDRESS_FILE="${SIMULATION_DIR}/node-${MASTER_NODE}/beacon_node.address"

BASE_P2P_PORT=30000
BASE_METRICS_PORT=8008
# Set DEPOSIT_WEB3_URL_ARG to empty to get genesis state from file, not using web3
# DEPOSIT_WEB3_URL_ARG=--web3-url=ws://localhost:8545
DEPOSIT_WEB3_URL_ARG=""
DEPOSIT_CONTRACT_ADDRESS="0x"

