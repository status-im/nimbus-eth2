#!/bin/bash

PWD_CMD="pwd"
# get native Windows paths on Mingw
uname | grep -qi mingw && PWD_CMD="pwd -W"

cd $(dirname $0)

SIM_ROOT="$($PWD_CMD)"

# Set a default value for the env vars usually supplied by a Makefile
cd $(git rev-parse --show-toplevel)
: ${GIT_ROOT:="$($PWD_CMD)"}
cd - &>/dev/null

# When changing these, also update the readme section on running simulation
# so that the run_node example is correct!
NUM_VALIDATORS=${VALIDATORS:-192}
NUM_NODES=${NODES:-6}
NUM_MISSING_NODES=${MISSING_NODES:-1}

SIMULATION_DIR="${SIM_ROOT}/data"
METRICS_DIR="${SIM_ROOT}/prometheus"
VALIDATORS_DIR="${SIM_ROOT}/validators"
SNAPSHOT_FILE="${SIMULATION_DIR}/state_snapshot.ssz"
NETWORK_BOOTSTRAP_FILE="${SIMULATION_DIR}/bootstrap_nodes.txt"
BEACON_NODE_BIN="${SIMULATION_DIR}/beacon_node"
DEPLOY_DEPOSIT_CONTRACT_BIN="${SIMULATION_DIR}/deploy_deposit_contract"
MASTER_NODE_ADDRESS_FILE="${SIMULATION_DIR}/node-0/beacon_node.address"
BASE_METRICS_PORT=8008

