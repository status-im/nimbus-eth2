#!/bin/bash

set -eo pipefail

# Read in variables
# shellcheck source=/dev/null
source "$(dirname "$0")/vars.sh"

cd "$SIM_ROOT"
mkdir -p "$SIMULATION_DIR"
mkdir -p "$VALIDATORS_DIR"

cd "$GIT_ROOT"

CUSTOM_NIMFLAGS="${NIMFLAGS} -d:useSysAsserts -d:chronicles_sinks:textlines,json[file] -d:const_preset=mainnet -d:insecure"

# Run with "SLOTS_PER_EPOCH=8 ./start.sh" to change these
DEFS=""
DEFS+="-d:MAX_COMMITTEES_PER_SLOT=${MAX_COMMITTEES_PER_SLOT:-1} "      # Spec default: 64
DEFS+="-d:SLOTS_PER_EPOCH=${SLOTS_PER_EPOCH:-6} "   # Spec default: 32
DEFS+="-d:SECONDS_PER_SLOT=${SECONDS_PER_SLOT:-6} "  # Spec default: 12

LAST_VALIDATOR_NUM=$(( NUM_VALIDATORS - 1 ))
LAST_VALIDATOR="$VALIDATORS_DIR/v$(printf '%07d' $LAST_VALIDATOR_NUM).deposit.json"

# Windows detection
if uname | grep -qiE "mingw|msys"; then
  MAKE="mingw32-make"
else
  MAKE="make"
fi

# to allow overriding the program names
MULTITAIL="${MULTITAIL:-multitail}"
TMUX="${TMUX:-tmux}"
GANACHE="${GANACHE:-ganache-cli}"
PROMETHEUS="${PROMETHEUS:-prometheus}"
TMUX_SESSION_NAME="${TMUX_SESSION_NAME:-nbc-sim}"

WAIT_GENESIS="${WAIT_GENESIS:-no}"

# Using tmux or multitail is an opt-in
USE_MULTITAIL="${USE_MULTITAIL:-no}"
type "$MULTITAIL" &>/dev/null || { echo "${MULTITAIL}" is missing; USE_MULTITAIL="no"; }

USE_TMUX="${USE_TMUX:-no}"
type "$TMUX" &>/dev/null || { echo "${TMUX}" is missing; USE_TMUX="no"; }

USE_GANACHE="${USE_GANACHE:-no}"
type "$GANACHE" &>/dev/null || { echo $GANACHE is missing; USE_GANACHE="no"; }

USE_PROMETHEUS="${LAUNCH_PROMETHEUS:-no}"
type "$PROMETHEUS" &>/dev/null || { echo $PROMETHEUS is missing; USE_PROMETHEUS="no"; }

# Prometheus config (continued inside the loop)
mkdir -p "${METRICS_DIR}"
cat > "${METRICS_DIR}/prometheus.yml" <<EOF
global:
  scrape_interval: 1s

scrape_configs:
  - job_name: "nimbus"
    static_configs:
EOF

for i in $(seq $MASTER_NODE -1 $TOTAL_USER_NODES); do
  # Prometheus config
  cat >> "${METRICS_DIR}/prometheus.yml" <<EOF
      - targets: ['127.0.0.1:$(( BASE_METRICS_PORT + i ))']
        labels:
          node: '$i'
EOF
done

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
  elif [[ "$USE_MULTITAIL" != "no" ]]; then
    COMMANDS+=( " -cT ansi -t '$GANACHE'" )
  else
    $GANACHE &
  fi
fi

if [[ "$USE_PROMETHEUS" != "no" ]]; then
  if [[ "$USE_TMUX" != "no" ]]; then
    $TMUX new-window -d -t $TMUX_SESSION_NAME -n "$PROMETHEUS" "cd '$METRICS_DIR' && $PROMETHEUS"
  else
    echo "$PROMETHEUS can be used currently only with USE_TMUX=1"
  fi
fi

if [[ "$USE_TMUX" != "no" ]]; then
  $TMUX select-window -t "${TMUX_SESSION_NAME}:sim"
fi

$MAKE -j3 --no-print-directory NIMFLAGS="$CUSTOM_NIMFLAGS $DEFS" LOG_LEVEL="${LOG_LEVEL:-DEBUG}" beacon_node validator_client process_dashboard deposit_contract

if [ ! -f "${LAST_VALIDATOR}" ]; then
  if [ "$WEB3_ARG" != "" ]; then
    echo Deploying the validator deposit contract...
    DEPOSIT_CONTRACT_ADDRESS=$($DEPLOY_DEPOSIT_CONTRACT_BIN deploy $WEB3_ARG)
    echo Contract deployed at $DEPOSIT_CONTRACT_ADDRESS
    export DEPOSIT_CONTRACT_ADDRESS
  fi

  DELAY_ARGS=""

  # Uncomment this line to slow down the initial deposits.
  # This will spread them across multiple blocks which is
  # a more realistic scenario.
  DELAY_ARGS="--min-delay=1 --max-delay=5"

  MAKE_DEPOSITS_WEB3_ARG=$WEB3_ARG
  if [[ "$WAIT_GENESIS" == "no" ]]; then
    MAKE_DEPOSITS_WEB3_ARG=""
  fi

  $BEACON_NODE_BIN makeDeposits \
    --quickstart-deposits="${NUM_VALIDATORS}" \
    --deposits-dir="$VALIDATORS_DIR" \
    $MAKE_DEPOSITS_WEB3_ARG $DELAY_ARGS \
    --deposit-contract="${DEPOSIT_CONTRACT_ADDRESS}"

  echo "All deposits prepared"
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

rm -f beacon_node.log

# Delete any leftover address files from a previous session
if [ -f "${MASTER_NODE_ADDRESS_FILE}" ]; then
  rm "${MASTER_NODE_ADDRESS_FILE}"
fi

# use the exported Grafana dashboard for a single node to create one for all nodes
echo Creating grafana dashboards...
./build/process_dashboard \
  --in="${SIM_ROOT}/beacon-chain-sim-node0-Grafana-dashboard.json" \
  --out="${SIM_ROOT}/beacon-chain-sim-all-nodes-Grafana-dashboard.json"

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

  CMD="${SIM_ROOT}/run_node.sh ${i} --verify-finalization"

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
    COMMANDS+=( " -cT ansi -t 'node #$i' -l 'sleep $SLEEP; $CMD; echo [node execution completed]; while true; do sleep 100; done'" )
  else
    eval "${CMD}" &
  fi
done

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
