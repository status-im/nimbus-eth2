#!/bin/bash

set -eo pipefail

# Read in variables
# shellcheck source=/dev/null
source "$(dirname "$0")/vars.sh"

# set up the environment
# shellcheck source=/dev/null
source "${SIM_ROOT}/../../env.sh"

cd "$SIM_ROOT"
mkdir -p "$SIMULATION_DIR"
mkdir -p "$VALIDATORS_DIR"

cd "$GIT_ROOT"

NIMFLAGS="-d:chronicles_log_level=TRACE -d:chronicles_sinks:textlines,json[file] --hints:off --warnings:off --verbosity:0 --opt:speed --debuginfo"

# Run with "SLOTS_PER_EPOCH=8 ./start.sh" to change these
DEFS=""

DEFS+="-d:MAX_COMMITTEES_PER_SLOT=${MAX_COMMITTEES_PER_SLOT:-1} "      # Spec default: 64
DEFS+="-d:SLOTS_PER_EPOCH=${SLOTS_PER_EPOCH:-6} "   # Spec default: 32
DEFS+="-d:SECONDS_PER_SLOT=${SECONDS_PER_SLOT:-6} "  # Spec default: 12

LAST_VALIDATOR_NUM=$(( NUM_VALIDATORS - 1 ))
LAST_VALIDATOR="$VALIDATORS_DIR/v$(printf '%07d' $LAST_VALIDATOR_NUM).deposit.json"

build_beacon_node () {
  OUTPUT_BIN=$1; shift
  PARAMS="$NIMFLAGS $DEFS $@"
  echo "Building $OUTPUT_BIN ($PARAMS)"
  nim c -o:$OUTPUT_BIN $PARAMS beacon_chain/beacon_node
}

build_beacon_node $BEACON_NODE_BIN -d:"NETWORK_TYPE=$NETWORK_TYPE"

if [[ "$BOOTSTRAP_NODE_NETWORK_TYPE" != "$NETWORK_TYPE" ]]; then
  build_beacon_node $BOOTSTRAP_NODE_BIN \
    --nimcache:nimcache/bootstrap_node \
    -d:"NETWORK_TYPE=$BOOTSTRAP_NODE_NETWORK_TYPE"
else
  cp $BEACON_NODE_BIN $BOOTSTRAP_NODE_BIN
fi

if [ ! -f "${LAST_VALIDATOR}" ]; then
  echo Building $DEPLOY_DEPOSIT_CONTRACT_BIN
  nim c -o:"$DEPLOY_DEPOSIT_CONTRACT_BIN" $NIMFLAGS $DEFS -d:release beacon_chain/deposit_contract

  if [ "$DEPOSIT_WEB3_URL_ARG" != "" ]; then
    DEPOSIT_CONTRACT_ADDRESS=$($DEPLOY_DEPOSIT_CONTRACT_BIN deploy $DEPOSIT_WEB3_URL_ARG)
    export DEPOSIT_CONTRACT_ADDRESS
  fi

  $BEACON_NODE_BIN makeDeposits \
    --quickstart-deposits="${NUM_VALIDATORS}" \
    --deposits-dir="$VALIDATORS_DIR" \
    $DEPOSIT_WEB3_URL_ARG \
    --deposit-contract="${DEPOSIT_CONTRACT_ADDRESS}"
fi

if [ ! -f "${SNAPSHOT_FILE}" ]; then
  $BEACON_NODE_BIN \
    --data-dir="${SIMULATION_DIR}/node-$MASTER_NODE" \
    createTestnet \
    --validators-dir="${VALIDATORS_DIR}" \
    --total-validators="${NUM_VALIDATORS}" \
    --output-genesis="${SNAPSHOT_FILE}" \
    --output-bootstrap-file="${NETWORK_BOOTSTRAP_FILE}" \
    --bootstrap-address=127.0.0.1 \
    --bootstrap-port=$(( BASE_P2P_PORT + MASTER_NODE )) \
    --genesis-offset=5 # Delay in seconds
fi

# Delete any leftover address files from a previous session
if [ -f "${MASTER_NODE_ADDRESS_FILE}" ]; then
  rm "${MASTER_NODE_ADDRESS_FILE}"
fi

# to allow overriding the program names
MULTITAIL="${MULTITAIL:-multitail}"
TMUX="${TMUX:-tmux}"
TMUX_SESSION_NAME="${TMUX_SESSION_NAME:-nbc-network-sim}"

# Using tmux or multitail is an opt-in
USE_MULTITAIL="${USE_MULTITAIL:-no}"
type "$MULTITAIL" &>/dev/null || { echo $MULTITAIL is missing; USE_MULTITAIL="no"; }

USE_TMUX="${USE_TMUX:-no}"
type "$TMUX" &>/dev/null || { echo $TMUX is missing; USE_TMUX="no"; }

# Prometheus config (continued inside the loop)
mkdir -p "${METRICS_DIR}"
cat > "${METRICS_DIR}/prometheus.yml" <<EOF
global:
  scrape_interval: 1s

scrape_configs:
  - job_name: "nimbus"
    static_configs:
EOF

PROCESS_DASHBOARD_BIN="${SIM_ROOT}/../../build/process_dashboard"

if [ ! -f "$PROCESS_DASHBOARD_BIN" ]; then
  nim c -d:release --outdir:build tests/simulation/process_dashboard.nim
fi

# use the exported Grafana dashboard for a single node to create one for all nodes
"${SIM_ROOT}/../../build/process_dashboard" \
  --nodes=${TOTAL_NODES} \
  --in="${SIM_ROOT}/beacon-chain-sim-node0-Grafana-dashboard.json" \
  --out="${SIM_ROOT}/beacon-chain-sim-all-nodes-Grafana-dashboard.json"

# Kill child processes on Ctrl-C by sending SIGTERM to the whole process group,
# passing the negative PID of this shell instance to the "kill" command.
# Trap and ignore SIGTERM, so we don't kill this process along with its children.
if [ "$USE_MULTITAIL" = "no" ]; then
  trap '' SIGTERM
  trap 'kill -- -$$' SIGINT EXIT
fi

COMMANDS=()

if [[ "$USE_TMUX" != "no" ]]; then
  $TMUX new-session -s $TMUX_SESSION_NAME -d

  # maybe these should be moved to a user config file
  $TMUX set-option -t $TMUX_SESSION_NAME history-limit 999999
  $TMUX set-option -t $TMUX_SESSION_NAME remain-on-exit on
  $TMUX set -t $TMUX_SESSION_NAME mouse on
fi

for i in $(seq $MASTER_NODE -1 $TOTAL_USER_NODES); do
  if [[ "$i" != "$MASTER_NODE" && "$USE_MULTITAIL" == "no" ]]; then
    # Wait for the master node to write out its address file
    while [ ! -f "${MASTER_NODE_ADDRESS_FILE}" ]; do
      sleep 0.1
    done
  fi

  CMD="${SIM_ROOT}/run_node.sh $i"

  if [[ "$USE_TMUX" != "no" ]]; then
    $TMUX split-window -t $TMUX_SESSION_NAME "$CMD"
    $TMUX select-layout -t $TMUX_SESSION_NAME tiled
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

  # Prometheus config
  cat >> "${METRICS_DIR}/prometheus.yml" <<EOF
      - targets: ['127.0.0.1:$(( $BASE_METRICS_PORT + $i ))']
        labels:
          node: '$i'
EOF
done

if [[ "$USE_TMUX" != "no" ]]; then
  $TMUX kill-pane -t $TMUX_SESSION_NAME:0.0
  $TMUX select-layout -t $TMUX_SESSION_NAME tiled
  $TMUX attach-session -t $TMUX_SESSION_NAME -d
elif [[ "$USE_MULTITAIL" != "no" ]]; then
  eval $MULTITAIL -s 3 -M 0 -x \"Nimbus beacon chain\" "${COMMANDS[@]}"
else
  wait # Stop when all nodes have gone down
fi
