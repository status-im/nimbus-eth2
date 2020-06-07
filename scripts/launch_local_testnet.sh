#!/bin/bash

# Copyright (c) 2020 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

# Mostly a duplication of "tests/simulation/{start.sh,run_node.sh}", but with a focus on
# replicating testnets as closely as possible, which means following the Docker execution labyrinth.

set -e

cd "$(dirname "${BASH_SOURCE[0]}")"/..

####################
# argument parsing #
####################
! getopt --test > /dev/null
if [ ${PIPESTATUS[0]} != 4 ]; then
	echo '`getopt --test` failed in this environment.'
	exit 1
fi

OPTS="ht:n:d:"
LONGOPTS="help,testnet:,nodes:,data-dir:,disable-htop,log-level:,grafana,base-port:,base-metrics-port:"

# default values
TESTNET="1"
NUM_NODES="10"
DATA_DIR="local_testnet_data"
USE_HTOP="1"
LOG_LEVEL="DEBUG"
ENABLE_GRAFANA="0"
BASE_PORT="9000"
BASE_METRICS_PORT="8008"

print_help() {
	cat <<EOF
Usage: $(basename $0) --testnet <testnet number> [OTHER OPTIONS] -- [BEACON NODE OPTIONS]
E.g.: $(basename $0) --testnet ${TESTNET} --nodes ${NUM_NODES} --data-dir "${DATA_DIR}" # defaults
CI run: $(basename $0) --disable-htop -- --verify-finalization --stop-at-epoch=5

  -h, --help			this help message
  -t, --testnet			testnet number (default: ${TESTNET})
  -n, --nodes			number of nodes to launch (default: ${NUM_NODES})
  -d, --data-dir		directory where all the node data and logs will end up
				(default: "${DATA_DIR}")
      --base-port		bootstrap node's Eth2 traffic port (default: ${BASE_PORT})
      --base-metrics-port	bootstrap node's metrics server port (default: ${BASE_METRICS_PORT})
      --disable-htop		don't use "htop" to see the beacon_node processes
      --log-level		set the log level (default: ${LOG_LEVEL})
      --grafana			generate Grafana dashboards (and Prometheus config file)
EOF
}

! PARSED=$(getopt --options=${OPTS} --longoptions=${LONGOPTS} --name "$0" -- "$@")
if [ ${PIPESTATUS[0]} != 0 ]; then
	# getopt has complained about wrong arguments to stdout
	exit 1
fi

# read getopt's output this way to handle the quoting right
eval set -- "$PARSED"
while true; do
	case "$1" in
		-h|--help)
			print_help
			exit
			;;
		-t|--testnet)
			TESTNET="$2"
			shift 2
			;;
		-n|--nodes)
			NUM_NODES="$2"
			shift 2
			;;
		-d|--data-dir)
			DATA_DIR="$2"
			shift 2
			;;
		--disable-htop)
			USE_HTOP="0"
			shift
			;;
		--log-level)
			LOG_LEVEL="$2"
			shift 2
			;;
		--grafana)
			ENABLE_GRAFANA="1"
			shift
			;;
		--base-port)
			BASE_PORT="$2"
			shift 2
			;;
		--base-metrics-port)
			BASE_METRICS_PORT="$2"
			shift 2
			;;
		--)
			shift
			break
			;;
		*)
			echo "argument parsing error"
			print_help
			exit 1
	esac
done

# when sourcing env.sh, it will try to execute $@, so empty it
EXTRA_ARGS="$@"
if [[ $# != 0 ]]; then
	shift $#
fi
NETWORK="testnet${TESTNET}"

rm -rf "${DATA_DIR}"
DEPOSITS_DIR="${DATA_DIR}/deposits_dir"
mkdir -p "${DEPOSITS_DIR}"
NETWORK_DIR="${DATA_DIR}/network_dir"
mkdir -p "${NETWORK_DIR}"

set -a
source "scripts/${NETWORK}.env"
set +a

# Windows detection
if uname | grep -qiE "mingw|msys"; then
	MAKE="mingw32-make"
else
	MAKE="make"
fi

NETWORK_NIM_FLAGS=$(scripts/load-testnet-nim-flags.sh ${NETWORK})
$MAKE -j2 LOG_LEVEL="${LOG_LEVEL}" NIMFLAGS="-d:insecure -d:testnet_servers_image ${NETWORK_NIM_FLAGS}" beacon_node process_dashboard

./build/beacon_node makeDeposits \
	--quickstart-deposits=${QUICKSTART_VALIDATORS} \
	--random-deposits=${RANDOM_VALIDATORS} \
	--deposits-dir="${DEPOSITS_DIR}"

TOTAL_VALIDATORS="$(( $QUICKSTART_VALIDATORS + $RANDOM_VALIDATORS ))"
BOOTSTRAP_IP="127.0.0.1"
./build/beacon_node createTestnet \
	--data-dir="${DATA_DIR}/node0" \
	--validators-dir="${DEPOSITS_DIR}" \
	--total-validators=${TOTAL_VALIDATORS} \
	--last-user-validator=${QUICKSTART_VALIDATORS} \
	--output-genesis="${NETWORK_DIR}/genesis.ssz" \
	--output-bootstrap-file="${NETWORK_DIR}/bootstrap_nodes.txt" \
	--bootstrap-address=${BOOTSTRAP_IP} \
	--bootstrap-port=${BASE_PORT} \
	--genesis-offset=30 # Delay in seconds

if [[ "$ENABLE_GRAFANA" == "1" ]]; then
	# Prometheus config
	cat > "${DATA_DIR}/prometheus.yml" <<EOF
global:
  scrape_interval: 1s

scrape_configs:
  - job_name: "nimbus"
    static_configs:
EOF
	for NUM_NODE in $(seq 0 $(( ${NUM_NODES} - 1 ))); do
		cat >> "${DATA_DIR}/prometheus.yml" <<EOF
      - targets: ['127.0.0.1:$(( BASE_METRICS_PORT + NUM_NODE ))']
        labels:
          node: '$NUM_NODE'
EOF
	done

	# use the exported Grafana dashboard for a single node to create one for all nodes
	./build/process_dashboard \
	  --in="tests/simulation/beacon-chain-sim-node0-Grafana-dashboard.json" \
	  --out="${DATA_DIR}/local-testnet-all-nodes-Grafana-dashboard.json"
fi

# Kill child processes on Ctrl-C/SIGTERM/exit, passing the PID of this shell
# instance as the parent and the target process name as a pattern to the
# "pkill" command.
cleanup() {
	pkill -P $$ beacon_node &>/dev/null || true
	sleep 2
	pkill -9 -P $$ beacon_node &>/dev/null || true
}
trap 'cleanup' SIGINT SIGTERM EXIT

dump_logs() {
	LOG_LINES=20
	for LOG in "${DATA_DIR}"/log*.txt; do
		echo "Last ${LOG_LINES} lines of ${LOG}:"
		tail -n ${LOG_LINES} "${LOG}"
		echo "======"
	done
}

PIDS=""
NODES_WITH_VALIDATORS=${NODES_WITH_VALIDATORS:-4}
VALIDATORS_PER_NODE=$(( $RANDOM_VALIDATORS / $NODES_WITH_VALIDATORS ))
BOOTSTRAP_TIMEOUT=10 # in seconds

for NUM_NODE in $(seq 0 $(( ${NUM_NODES} - 1 ))); do
	if [[ ${NUM_NODE} == 0 ]]; then
		BOOTSTRAP_ARG=""
	else
		BOOTSTRAP_ARG="--bootstrap-file=${NETWORK_DIR}/bootstrap_nodes.txt"
		# Wait for the master node to write out its address file
		START_TIMESTAMP=$(date +%s)
		while [ ! -f "${DATA_DIR}/node0/beacon_node.address" ]; do
			sleep 0.1
			NOW_TIMESTAMP=$(date +%s)
			if [[ "$(( NOW_TIMESTAMP - START_TIMESTAMP ))" -ge "$BOOTSTRAP_TIMEOUT" ]]; then
				echo "Bootstrap node failed to start in ${BOOTSTRAP_TIMEOUT} seconds. Aborting."
				dump_logs
				exit 1
			fi
		done
	fi

	# Copy validators to individual nodes.
	# The first $NODES_WITH_VALIDATORS nodes split them equally between them, after skipping the first $QUICKSTART_VALIDATORS.
	NODE_DATA_DIR="${DATA_DIR}/node${NUM_NODE}"
	mkdir -p "${NODE_DATA_DIR}/validators"
	if [[ $NUM_NODE -lt $NODES_WITH_VALIDATORS ]]; then
		for KEYFILE in $(ls ${DEPOSITS_DIR}/*.privkey | tail -n +$(( $QUICKSTART_VALIDATORS + ($VALIDATORS_PER_NODE * $NUM_NODE) + 1 )) | head -n $VALIDATORS_PER_NODE); do
			cp -a "$KEYFILE" "${NODE_DATA_DIR}/validators/"
		done
	fi

	./build/beacon_node \
		--nat:extip:127.0.0.1 \
		--log-level="${LOG_LEVEL}" \
		--tcp-port=$(( BASE_PORT + NUM_NODE )) \
		--udp-port=$(( BASE_PORT + NUM_NODE )) \
		--data-dir="${NODE_DATA_DIR}" \
		${BOOTSTRAP_ARG} \
		--state-snapshot="${NETWORK_DIR}/genesis.ssz" \
		--metrics \
		--metrics-address="127.0.0.1" \
		--metrics-port="$(( BASE_METRICS_PORT + NUM_NODE ))" \
		${EXTRA_ARGS} \
		> "${DATA_DIR}/log${NUM_NODE}.txt" 2>&1 &

	if [[ "${PIDS}" == "" ]]; then
		PIDS="$!"
	else
		PIDS="${PIDS},$!"
	fi
done

# give the regular nodes time to crash
sleep 5
BG_JOBS="$(jobs | wc -l)"
if [[ "$BG_JOBS" != "$NUM_NODES" ]]; then
	echo "$((NUM_NODES - BG_JOBS)) beacon_node instance(s) exited early. Aborting."
	dump_logs
	exit 1
fi

if [[ "$USE_HTOP" == "1" ]]; then
	htop -p "$PIDS"
	cleanup
else
	FAILED=0
	for PID in $(echo "$PIDS" | tr ',' ' '); do
		wait $PID || FAILED="$(( FAILED += 1 ))"
	done
	if [[ "$FAILED" != "0" ]]; then
		echo "${FAILED} child processes had non-zero exit codes (or exited early)."
		dump_logs
		exit 1
	fi
fi

