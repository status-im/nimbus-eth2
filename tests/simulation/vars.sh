#!/bin/bash

PWD_CMD="pwd"
# get native Windows paths on Mingw
uname | grep -qi mingw && PWD_CMD="pwd -W"

cd $(dirname $0)
SIM_ROOT="$($PWD_CMD)"
cd $(git rev-parse --show-toplevel)
GIT_ROOT="$($PWD_CMD)"

# Set a default value for the env vars usually supplied by nimbus Makefile
: ${SKIP_BUILDS:=""}
: ${BUILD_OUTPUTS_DIR:="$GIT_ROOT/build"}

SIMULATION_DIR="$SIM_ROOT/data"
VALIDATORS_DIR="$SIM_ROOT/validators"
SNAPSHOT_FILE="$SIMULATION_DIR/state_snapshot.json"
BEACON_NODE_BIN=$BUILD_OUTPUTS_DIR/beacon_node
VALIDATOR_KEYGEN_BIN=$BUILD_OUTPUTS_DIR/validator_keygen
MASTER_NODE_ADDRESS_FILE="$SIMULATION_DIR/node-0/beacon_node.address"
