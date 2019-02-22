#!/bin/bash

set -eux

# Kill children on ctrl-c
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

# Set a default value for the env vars usually supplied by nimbus Makefile
: ${SKIP_BUILDS:=""}
: ${BUILD_OUTPUTS_DIR:="./build"}

NUMBER_OF_VALIDATORS=99

cd $(dirname "$0")
SIMULATION_DIR=$PWD/data
mkdir -p "$SIMULATION_DIR"

STARTUP_FILE="$SIMULATION_DIR/startup.json"
SNAPSHOT_FILE="$SIMULATION_DIR/state_snapshot.json"

cd $(git rev-parse --show-toplevel)
ROOT_DIR=$PWD

mkdir -p $BUILD_OUTPUTS_DIR

BEACON_NODE_BIN=$BUILD_OUTPUTS_DIR/beacon_node
VALIDATOR_KEYGEN_BIN=$BUILD_OUTPUTS_DIR/validator_keygen

# Run with "SHARD_COUNT=4 ./start.sh" to change these
DEFS="-d:SHARD_COUNT=${SHARD_COUNT:-4} "      # Spec default: 1024
DEFS+="-d:EPOCH_LENGTH=${EPOCH_LENGTH:-8} "   # Spec default: 64
DEFS+="-d:SECONDS_PER_SLOT=${SECONDS_PER_SLOT:-6} " # Spec default: 6

if [[ -z "$SKIP_BUILDS" ]]; then
  nim c -o:"$VALIDATOR_KEYGEN_BIN" $DEFS -d:release beacon_chain/validator_keygen
  nim c -o:"$BEACON_NODE_BIN" $DEFS --opt:speed beacon_chain/beacon_node
fi

if [ ! -f $STARTUP_FILE ]; then
  $VALIDATOR_KEYGEN_BIN --validators=$NUMBER_OF_VALIDATORS --outputDir="$SIMULATION_DIR"
fi

if [ ! -f $SNAPSHOT_FILE ]; then
  $BEACON_NODE_BIN createChain \
    --chainStartupData:$STARTUP_FILE \
    --out:$SNAPSHOT_FILE --genesisOffset=5 # Delay in seconds
fi

MASTER_NODE_ADDRESS_FILE="$SIMULATION_DIR/node-0/beacon_node.address"

# Delete any leftover address files from a previous session
if [ -f $MASTER_NODE_ADDRESS_FILE ]; then
  rm $MASTER_NODE_ADDRESS_FILE
fi

# multitail support
MULTITAIL="${MULTITAIL:-multitail}" # to allow overriding the program name
USE_MULTITAIL="${USE_MULTITAIL:-no}" # make it an opt-in
type "$MULTITAIL" &>/dev/null || USE_MULTITAIL="no"
COMMANDS=()

for i in $(seq 0 9); do
  BOOTSTRAP_NODES_FLAG="--bootstrapNodesFile:$MASTER_NODE_ADDRESS_FILE"

  if [[ "$i" == "0" ]]; then
    BOOTSTRAP_NODES_FLAG=""
  elif [ "$USE_MULTITAIL" = "no" ]; then
    # Wait for the master node to write out its address file
    while [ ! -f $MASTER_NODE_ADDRESS_FILE ]; do
      sleep 0.1
    done
  fi

  DATA_DIR=$SIMULATION_DIR/node-$i

  CMD="$BEACON_NODE_BIN \
    --dataDir:\"$DATA_DIR\" \
    --validator:\"$SIMULATION_DIR/validator-${i}1.json\" \
    --validator:\"$SIMULATION_DIR/validator-${i}2.json\" \
    --validator:\"$SIMULATION_DIR/validator-${i}3.json\" \
    --validator:\"$SIMULATION_DIR/validator-${i}4.json\" \
    --validator:\"$SIMULATION_DIR/validator-${i}5.json\" \
    --validator:\"$SIMULATION_DIR/validator-${i}6.json\" \
    --validator:\"$SIMULATION_DIR/validator-${i}7.json\" \
    --validator:\"$SIMULATION_DIR/validator-${i}8.json\" \
    --validator:\"$SIMULATION_DIR/validator-${i}9.json\" \
    --tcpPort:5000$i \
    --udpPort:5000$i \
    --stateSnapshot:\"$SNAPSHOT_FILE\" \
    $BOOTSTRAP_NODES_FLAG"

  if [ "$USE_MULTITAIL" != "no" ]; then
    if [ "$i" = "0" ]; then
      SLEEP="0"
    else
      SLEEP="2"
    fi
    # "multitail" closes the corresponding panel when a command exits, so let's make sure it doesn't exit
    COMMANDS+=( " -cT ansi -t 'node #$i' -l 'sleep $SLEEP; $CMD; echo [node execution completed]; while true; do sleep 100; done'" )
  else
    eval $CMD &
  fi
done

if [ "$USE_MULTITAIL" != "no" ]; then
  eval $MULTITAIL -s 2 -M 0 -x \"beacon chain simulation\" "${COMMANDS[@]}"
else
  wait # Stop when all nodes have gone down
fi

