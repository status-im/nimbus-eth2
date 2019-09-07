#!/bin/bash

set -eo pipefail

# Read in variables
source "$(dirname "$0")/vars.sh"

# set up the environment
source "${SIM_ROOT}/../env.sh"

cd "$SIM_ROOT"
mkdir -p "$SIMULATION_DIR"
mkdir -p "$VALIDATORS_DIR"

cd "$GIT_ROOT"

make update deps

NIMFLAGS="-d:chronicles_log_level=DEBUG --hints:off --warnings:off --opt:speed --debuginfo -d:serialization_tracing"

# For interop, we run the minimal config
DEFS="-d:const_preset=minimal"

LAST_VALIDATOR_NUM=$(( NUM_VALIDATORS - 1 ))
LAST_VALIDATOR="$VALIDATORS_DIR/v$(printf '%07d' $LAST_VALIDATOR_NUM).deposit.json"

[[ -x "$BEACON_NODE_BIN" ]] || {
  echo "Building $BEACON_NODE_BIN ($DEFS)"
  nim c -o:"$BEACON_NODE_BIN" $NIMFLAGS $DEFS beacon_chain/beacon_node
}

if [ ! -f "${LAST_VALIDATOR}" ]; then
  $BEACON_NODE_BIN makeDeposits \
    --totalDeposits="${NUM_VALIDATORS}" \
    --depositDir="$VALIDATORS_DIR" \
    --randomKeys=false
fi

if [ ! -f "${SNAPSHOT_FILE}" ]; then
  $BEACON_NODE_BIN \
    --dataDir="${SIMULATION_DIR}/node-0" \
    createTestnet \
    --networkId=1000 \
    --validatorsDir="${VALIDATORS_DIR}" \
    --totalValidators="${NUM_VALIDATORS}" \
    --outputGenesis="${SNAPSHOT_FILE}" \
    --outputNetwork="${NETWORK_METADATA_FILE}" \
    --bootstrapAddress=127.0.0.1 \
    --bootstrapPort=50000 \
    --genesisOffset=5 # Delay in seconds
fi

# Delete any leftover address files from a previous session
if [ -f "${MASTER_NODE_ADDRESS_FILE}" ]; then
  rm "${MASTER_NODE_ADDRESS_FILE}"
fi

# multitail support
MULTITAIL="${MULTITAIL:-multitail}" # to allow overriding the program name
USE_MULTITAIL="${USE_MULTITAIL:-no}" # make it an opt-in
type "$MULTITAIL" &>/dev/null || USE_MULTITAIL="no"

# Kill child processes on Ctrl-C by sending SIGTERM to the whole process group,
# passing the negative PID of this shell instance to the "kill" command.
# Trap and ignore SIGTERM, so we don't kill this process along with its children.
if [ "$USE_MULTITAIL" = "no" ]; then
  trap '' SIGTERM
  trap 'kill -- -$$' SIGINT EXIT
fi

COMMANDS=()
LAST_NODE=$(( NUM_NODES - 1 ))

for i in $(seq 0 $LAST_NODE); do
  if [[ "$i" == "0" ]]; then
    sleep 0
  elif [ "$USE_MULTITAIL" = "no" ]; then
    # Wait for the master node to write out its address file
    while [ ! -f "${MASTER_NODE_ADDRESS_FILE}" ]; do
      sleep 0.1
    done
  fi

  CMD="${SIM_ROOT}/run_node.sh $i"

  if [ "$USE_MULTITAIL" != "no" ]; then
    if [ "$i" = "0" ]; then
      SLEEP="0"
    else
      SLEEP="2"
    fi
    # "multitail" closes the corresponding panel when a command exits, so let's make sure it doesn't exit
    COMMANDS+=( " -cT ansi -t 'node #$i' -l 'sleep $SLEEP; $CMD; echo [node execution completed]; while true; do sleep 100; done'" )
  else
    eval "${CMD}" &
  fi
done

if [ "$USE_MULTITAIL" != "no" ]; then
  eval $MULTITAIL -s 3 -M 0 -x \"Nimbus beacon chain\" "${COMMANDS[@]}"
else
  wait # Stop when all nodes have gone down
fi
