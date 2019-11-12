#!/bin/bash

set -eo pipefail

# Read in variables
source "$(dirname "$0")/vars.sh"

# set up the environment
source "${SIM_ROOT}/../../env.sh"

cd "$SIM_ROOT"
mkdir -p "$SIMULATION_DIR"
mkdir -p "$VALIDATORS_DIR"

cd "$GIT_ROOT"

NIMFLAGS="-d:chronicles_log_level=DEBUG --hints:off --warnings:off --verbosity:0 --opt:speed --debuginfo"

# Run with "SLOTS_PER_EPOCH=8 ./start.sh" to change these
DEFS=""

DEFS+="-d:MAX_COMMITTEES_PER_SLOT=${MAX_COMMITTEES_PER_SLOT:-1} "      # Spec default: 64
DEFS+="-d:SLOTS_PER_EPOCH=${SLOTS_PER_EPOCH:-16} "   # Spec default: 32
DEFS+="-d:SECONDS_PER_SLOT=${SECONDS_PER_SLOT:-6} "  # Spec default: 12

LAST_VALIDATOR_NUM=$(( NUM_VALIDATORS - 1 ))
LAST_VALIDATOR="$VALIDATORS_DIR/v$(printf '%07d' $LAST_VALIDATOR_NUM).deposit.json"

echo "Building $BEACON_NODE_BIN ($DEFS)"
nim c -o:"$BEACON_NODE_BIN" $NIMFLAGS $DEFS beacon_chain/beacon_node

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

# multitail support
MULTITAIL="${MULTITAIL:-multitail}" # to allow overriding the program name
USE_MULTITAIL="${USE_MULTITAIL:-no}" # make it an opt-in
type "$MULTITAIL" &>/dev/null || USE_MULTITAIL="no"

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

for i in $(seq $MASTER_NODE -1 $TOTAL_USER_NODES); do
  if [[ "$i" != "$MASTER_NODE" && "$USE_MULTITAIL" == "no" ]]; then
    # Wait for the master node to write out its address file
    while [ ! -f "${MASTER_NODE_ADDRESS_FILE}" ]; do
      sleep 0.1
    done
  fi

  CMD="${SIM_ROOT}/run_node.sh $i"

  if [[ "$USE_MULTITAIL" != "no" ]]; then
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

if [[ "$USE_MULTITAIL" != "no" ]]; then
  eval $MULTITAIL -s 3 -M 0 -x \"Nimbus beacon chain\" "${COMMANDS[@]}"
else
  wait # Stop when all nodes have gone down
fi
