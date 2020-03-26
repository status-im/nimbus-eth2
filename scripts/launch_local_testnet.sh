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
LONGOPTS="help,testnet:,nodes:,data-dir:,disable-htop,log-level:"

# default values
TESTNET="1"
NUM_NODES="10"
DATA_DIR="local_testnet_data"
USE_HTOP="1"
LOG_LEVEL="DEBUG"

print_help() {
	cat <<EOF
Usage: $(basename $0) --testnet <testnet number> [OTHER OPTIONS] -- [BEACON NODE OPTIONS]
E.g.: $(basename $0) --testnet ${TESTNET} --nodes ${NUM_NODES} --data-dir "${DATA_DIR}" # defaults
CI run: $(basename $0) --disable-htop -- --verify-finalization --stop-at-epoch=5

  -h, --help            this help message
  -t, --testnet         testnet number (default: ${TESTNET})
  -n, --nodes		number of nodes to launch (default: ${NUM_NODES})
  -d, --data-dir	directory where all the node data and logs will end up
			(default: "${DATA_DIR}")
      --disable-htop	don't use "htop" to see the beacon_node processes
      --log-level	set the log level (default: ${LOG_LEVEL})
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
$MAKE LOG_LEVEL="${LOG_LEVEL}" NIMFLAGS="-d:insecure -d:testnet_servers_image ${NETWORK_NIM_FLAGS}" beacon_node

rm -rf "${DEPOSITS_DIR}"
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
	--bootstrap-port=${BOOTSTRAP_PORT} \
	--genesis-offset=5 # Delay in seconds

cleanup() {
	killall beacon_node &>/dev/null || true
	sleep 2
	killall -9 beacon_node &>/dev/null || true
}
cleanup

PIDS=""
NODES_WITH_VALIDATORS=${NODES_WITH_VALIDATORS:-4}
VALIDATORS_PER_NODE=$(( $RANDOM_VALIDATORS / $NODES_WITH_VALIDATORS ))

for NUM_NODE in $(seq 0 $(( ${NUM_NODES} - 1 ))); do
	if [[ ${NUM_NODE} == 0 ]]; then
		BOOTSTRAP_ARG=""
	else
		BOOTSTRAP_ARG="--bootstrap-file=${NETWORK_DIR}/bootstrap_nodes.txt"
		# Wait for the master node to write out its address file
		while [ ! -f "${DATA_DIR}/node0/beacon_node.address" ]; do
			sleep 0.1
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

	stdbuf -o0 build/beacon_node \
		--nat:extip:127.0.0.1 \
		--log-level="${LOG_LEVEL}" \
		--tcp-port=$(( ${BOOTSTRAP_PORT} + ${NUM_NODE} )) \
		--udp-port=$(( ${BOOTSTRAP_PORT} + ${NUM_NODE} )) \
		--data-dir="${NODE_DATA_DIR}" \
		${BOOTSTRAP_ARG} \
		--state-snapshot="${NETWORK_DIR}/genesis.ssz" \
		--verify-finalization \
		${EXTRA_ARGS} \
		> "${DATA_DIR}/log${NUM_NODE}.txt" 2>&1 &
	if [[ "${PIDS}" == "" ]]; then
		PIDS="$!"
	else
		PIDS="${PIDS},$!"
	fi
done

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
		exit 1
	fi
fi

