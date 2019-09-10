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

NUM_VALIDATORS=${VALIDATORS:-16}
NUM_NODES=${NODES:-1}
NUM_MISSING_NODES=${MISSING_NODES:-2}

SIMULATION_DIR="${SIM_ROOT}/data"
VALIDATORS_DIR="${SIM_ROOT}/validators"
SNAPSHOT_FILE="${SIMULATION_DIR}/state_snapshot.json"
NETWORK_METADATA_FILE="${SIMULATION_DIR}/network.json"
BEACON_NODE_BIN="${SIMULATION_DIR}/beacon_node"
MASTER_NODE_ADDRESS_FILE="${SIMULATION_DIR}/node-0/beacon_node.address"
