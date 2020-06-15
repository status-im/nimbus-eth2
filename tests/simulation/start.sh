#!/bin/bash

set -eo pipefail

# To allow overriding the program names
MULTITAIL="${MULTITAIL:-multitail}"
TMUX="${TMUX:-tmux}"
GANACHE="${GANACHE:-ganache-cli}"
PROMETHEUS="${PROMETHEUS:-prometheus}"
CTAIL="${CTAIL:-ctail}"

# Using tmux or multitail is an opt-in
USE_MULTITAIL="${USE_MULTITAIL:-no}"
type "$MULTITAIL" &>/dev/null || { echo "${MULTITAIL}" is missing; USE_MULTITAIL="no"; }

USE_TMUX="${USE_TMUX:-no}"
type "$TMUX" &>/dev/null || { echo "${TMUX}" is missing; USE_TMUX="no"; }

WAIT_GENESIS="${WAIT_GENESIS:-no}"

USE_GANACHE="${USE_GANACHE:-yes}"
type "$GANACHE" &>/dev/null || { echo $GANACHE is missing; USE_GANACHE="no"; WAIT_GENESIS="no"; }

USE_PROMETHEUS="${USE_PROMETHEUS:-yes}"
type "$PROMETHEUS" &>/dev/null || { echo $PROMETHEUS is missing; USE_PROMETHEUS="no"; }

USE_CTAIL="${USE_CTAIL:-yes}"
type "$CTAIL" &>/dev/null || { echo $CTAIL is missing; USE_CTAIL="no"; }

# Read in variables
# shellcheck source=/dev/null
source "$(dirname "$0")/vars.sh"

cd "$SIM_ROOT"
mkdir -p "$SIMULATION_DIR"
mkdir -p "$VALIDATORS_DIR"
mkdir -p "$SECRETS_DIR"

cd "$GIT_ROOT"

CUSTOM_NIMFLAGS="${NIMFLAGS} -d:useSysAsserts -d:chronicles_sinks:textlines,json[file] -d:const_preset=mainnet -d:insecure"

# Run with "SLOTS_PER_EPOCH=8 ./start.sh" to change these
DEFS=""
DEFS+="-d:MAX_COMMITTEES_PER_SLOT=${MAX_COMMITTEES_PER_SLOT:-1} "      # Spec default: 64
DEFS+="-d:SLOTS_PER_EPOCH=${SLOTS_PER_EPOCH:-6} "   # Spec default: 32
DEFS+="-d:SECONDS_PER_SLOT=${SECONDS_PER_SLOT:-6} "  # Spec default: 12

# Windows detection
if uname | grep -qiE "mingw|msys"; then
  MAKE="mingw32-make"
else
  MAKE="make"
fi

TMUX_SESSION_NAME="${TMUX_SESSION_NAME:-nbc-sim}"

WAIT_GENESIS="${WAIT_GENESIS:-no}"

# Using tmux or multitail is an opt-in
USE_MULTITAIL="${USE_MULTITAIL:-no}"
if [[ "$USE_MULTITAIL" != "no" ]]; then
  type "$MULTITAIL" &>/dev/null || { echo "${MULTITAIL}" is missing; USE_MULTITAIL="no"; }
fi

USE_TMUX="${USE_TMUX:-yes}"
if [[ "$USE_TMUX" == "yes" ]]; then
  type "$TMUX" &>/dev/null || { echo "${TMUX}" is missing; USE_TMUX="no"; }
fi

USE_GANACHE="${USE_GANACHE:-yes}"
if [[ "$USE_GANACHE" == "yes" ]]; then
  type "$GANACHE" &>/dev/null || { echo $GANACHE is missing; USE_GANACHE="no"; }
fi

USE_PROMETHEUS="${USE_PROMETHEUS:-yes}"
if [[ "$USE_PROMETHEUS" == "yes" ]]; then
  type "$PROMETHEUS" &>/dev/null || { echo $PROMETHEUS is missing; USE_PROMETHEUS="no"; }
fi

mkdir -p "${METRICS_DIR}"
./scripts/make_prometheus_config.sh \
	--nodes ${TOTAL_NODES} \
	--base-metrics-port ${BASE_METRICS_PORT} \
	--config-file "${METRICS_DIR}/prometheus.yml"

COMMANDS=()

if [[ "$USE_TMUX" != "no" ]]; then
  $TMUX new-session -s "${TMUX_SESSION_NAME}" -d

  # maybe these should be moved to a user config file
  $TMUX set-option -t "${TMUX_SESSION_NAME}" history-limit 999999
  $TMUX set-option -t "${TMUX_SESSION_NAME}" remain-on-exit on
  $TMUX set -t "${TMUX_SESSION_NAME}" mouse on

  # We create a new window, so the above settings can take place
  $TMUX new-window -d -t "${TMUX_SESSION_NAME}" -n "sim"

  trap 'tmux kill-session -t "${TMUX_SESSION_NAME}"' SIGINT EXIT
fi

if [[ "$USE_GANACHE" != "no" ]]; then
  if [[ "$USE_TMUX" != "no" ]]; then
    $TMUX new-window -d -t $TMUX_SESSION_NAME -n "$GANACHE" "$GANACHE"
  else
    echo NOTICE: $GANACHE will be started automatically only with USE_TMUX=1
    USE_GANACHE="no"
  fi
fi

if [[ "$USE_PROMETHEUS" != "no" ]]; then
  if [[ "$USE_TMUX" != "no" ]]; then
    PROMETHEUS_FLAGS="--config.file=./prometheus.yml --storage.tsdb.path=./data"
    $TMUX new-window -d -t $TMUX_SESSION_NAME -n "$PROMETHEUS" "cd '$METRICS_DIR' && $PROMETHEUS $PROMETHEUS_FLAGS"
  else
    echo NOTICE: $PROMETHEUS will be started automatically only with USE_TMUX=1
    USE_PROMETHEUS="no"
  fi
fi

if [[ "$USE_TMUX" != "no" ]]; then
  $TMUX select-window -t "${TMUX_SESSION_NAME}:sim"
fi

$MAKE -j3 --no-print-directory NIMFLAGS="$CUSTOM_NIMFLAGS $DEFS" LOG_LEVEL="${LOG_LEVEL:-DEBUG}" beacon_node validator_client

count_files () {
  { ls -1q $1 2> /dev/null || true ; } | wc -l
}

EXISTING_VALIDATORS=$(count_files "$VALIDATORS_DIR/*/deposit.json")

if [[ $EXISTING_VALIDATORS -lt $NUM_VALIDATORS ]]; then
  rm -rf "$VALIDATORS_DIR"
  rm -rf "$SECRETS_DIR"

  $BEACON_NODE_BIN deposits create \
    --count="${NUM_VALIDATORS}" \
    --non-interactive \
    --out-validators-dir="$VALIDATORS_DIR" \
    --out-secrets-dir="$SECRETS_DIR" \
    --dont-send

  echo "All deposits prepared"
fi

function run_cmd {
  i=$1
  CMD=$2
  bin_name=$3
  if [[ "$USE_TMUX" != "no" ]]; then
    echo "Starting node $i..."
    echo $TMUX split-window -t "${TMUX_SESSION_NAME}" "$CMD"
    $TMUX split-window -t "${TMUX_SESSION_NAME}" "$CMD"
    $TMUX select-layout -t "${TMUX_SESSION_NAME}" tiled
  elif [[ "$USE_MULTITAIL" != "no" ]]; then
    if [[ "$i" == "$MASTER_NODE" ]]; then
      SLEEP="0"
    else
      SLEEP="3"
    fi
    # "multitail" closes the corresponding panel when a command exits, so let's make sure it doesn't exit
    COMMANDS+=( " -cT ansi -t '$bin_name #$i' -l 'sleep $SLEEP; $CMD; echo [node execution completed]; while true; do sleep 100; done'" )
  else
    eval "${CMD}" &
  fi
}

if [ "$WEB3_ARG" != "" ]; then
  make deposit_contract
  echo Deploying the validator deposit contract...
  echo $DEPLOY_DEPOSIT_CONTRACT_BIN deploy $WEB3_ARG
  DEPOSIT_CONTRACT_ADDRESS=$($DEPLOY_DEPOSIT_CONTRACT_BIN deploy $WEB3_ARG)
  echo Contract deployed at $DEPOSIT_CONTRACT_ADDRESS
  export DEPOSIT_CONTRACT_ADDRESS

  if [[ "$WAIT_GENESIS" != "no" ]]; then
    echo "(deposit maker)" "$BEACON_NODE_BIN deposits send \
      --non-interactive \
      --validators-dir='$VALIDATORS_DIR' \
      --min-delay=1 --max-delay=5 \
      $WEB3_ARG \
      --deposit-contract=${DEPOSIT_CONTRACT_ADDRESS}"

    run_cmd "(deposit maker)" "$BEACON_NODE_BIN deposits send \
      --non-interactive \
      --validators-dir='$VALIDATORS_DIR' \
      --min-delay=1 --max-delay=5 \
      $WEB3_ARG \
      --deposit-contract=${DEPOSIT_CONTRACT_ADDRESS}"
  fi
fi

if [ ! -f "${SNAPSHOT_FILE}" ]; then
  if [[ "${WAIT_GENESIS}" == "no" ]]; then
    echo Creating testnet genesis...
    $BEACON_NODE_BIN \
      --data-dir="${SIMULATION_DIR}/node-$MASTER_NODE" \
      createTestnet \
      --validators-dir="${VALIDATORS_DIR}" \
      --total-validators="${NUM_VALIDATORS}" \
      --output-genesis="${SNAPSHOT_FILE}" \
      --output-bootstrap-file="${NETWORK_BOOTSTRAP_FILE}" \
      --bootstrap-address=127.0.0.1 \
      --bootstrap-port=$(( BASE_P2P_PORT + MASTER_NODE )) \
      --genesis-offset=15 # Delay in seconds
  fi
fi

# Delete any leftover address files from a previous session
if [ -f "${MASTER_NODE_ADDRESS_FILE}" ]; then
  rm "${MASTER_NODE_ADDRESS_FILE}"
fi

# Kill child processes on Ctrl-C/SIGTERM/exit, passing the PID of this shell
# instance as the parent and the target process name as a pattern to the
# "pkill" command.
if [[ "$USE_MULTITAIL" == "no" && "$USE_TMUX" == "no" ]]; then
  trap 'pkill -P $$ beacon_node' SIGINT EXIT
fi

LAST_WAITING_NODE=0

for i in $(seq $MASTER_NODE -1 $TOTAL_USER_NODES); do
  if [[ "$i" != "$MASTER_NODE" && "$USE_MULTITAIL" == "no" ]]; then
    # Wait for the master node to write out its address file
    while [ ! -f "${MASTER_NODE_ADDRESS_FILE}" ]; do
      if (( LAST_WAITING_NODE != i )); then
        echo Waiting for $MASTER_NODE_ADDRESS_FILE to appear...
        LAST_WAITING_NODE=i
      fi
      sleep 0.1
    done
  fi

  run_cmd $i "${SIM_ROOT}/run_node.sh ${i} --verify-finalization" "node"

  if [ "${BN_VC_VALIDATOR_SPLIT:-}" == "yes" ]; then
    # start the VC with a few seconds of delay so that we can connect through RPC
    run_cmd $i "sleep 3 && ${SIM_ROOT}/run_validator.sh ${i}" "validator"
  fi
done

if [[ "$USE_CTAIL" != "no" ]]; then
  if [[ "$USE_TMUX" != "no" ]]; then
    $TMUX new-window -d -t $TMUX_SESSION_NAME -n "$CTAIL" "$CTAIL tail -q -n +1 -f ${SIMULATION_DIR}/node-*/beacon_node.log"
  else
    echo NOTICE: $CTAIL will be started automatically only with USE_TMUX=1
    USE_CTAIL="no"
  fi
fi

if [[ "$USE_TMUX" != "no" ]]; then
  # kill the console window in the pane where the simulation is running
  $TMUX kill-pane -t $TMUX_SESSION_NAME:sim.0
  # kill the original console window
  # (this one doesn't have the right history-limit)
  $TMUX kill-pane -t $TMUX_SESSION_NAME:0.0
  $TMUX select-layout -t "${TMUX_SESSION_NAME}" tiled
  $TMUX attach-session -t "${TMUX_SESSION_NAME}" -d
elif [[ "$USE_MULTITAIL" != "no" ]]; then
  eval $MULTITAIL -s 3 -M 0 -x \"Nimbus beacon chain\" "${COMMANDS[@]}"
else
  wait # Stop when all nodes have gone down
fi
