#!/bin/bash

# Mostly a duplication of "tests/simulation/{start.sh,run_node.sh}", but with a focus on
# replicating testnets as close as possible, which means following the Docker execution labyrinth.

set -e

cd "$(dirname "${BASH_SOURCE[0]}")"/..

NETWORK=${1:-"testnet1"}
NUM_NODES=10

DATA_DIR="local_testnet_data"
rm -rf "${DATA_DIR}"
DEPOSITS_DIR="${DATA_DIR}/deposits_dir"
mkdir -p "${DEPOSITS_DIR}"
NETWORK_DIR="${DATA_DIR}/network_dir"
mkdir -p "${NETWORK_DIR}"

set -a
source "scripts/${NETWORK}.env"
set +a

NETWORK_NIM_FLAGS=$(scripts/load-testnet-nim-flags.sh ${NETWORK})
make LOG_LEVEL=DEBUG NIMFLAGS="-d:debug -d:insecure -d:testnet_servers_image ${NETWORK_NIM_FLAGS}" beacon_node

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
	killall beacon_node p2pd &>/dev/null || true
	sleep 2
	killall -9 beacon_node p2pd &>/dev/null || true
	rm -f /tmp/nim-p2pd-*.sock || true
}
cleanup

PIDS=""
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

	stdbuf -o0 ./env.sh build/beacon_node \
		--nat=none \
		--log-level=TRACE \
		--tcp-port=$(( ${BOOTSTRAP_PORT} + ${NUM_NODE} )) \
		--udp-port=$(( ${BOOTSTRAP_PORT} + ${NUM_NODE} )) \
		--data-dir="${DATA_DIR}/node${NUM_NODE}" \
		${BOOTSTRAP_ARG} \
		--state-snapshot="${NETWORK_DIR}/genesis.ssz" \
		> "${DATA_DIR}/log${NUM_NODE}.txt" 2>&1 &
	if [[ "${PIDS}" == "" ]]; then
		PIDS="$!"
	else
		PIDS="${PIDS},$!"
	fi
done

htop -p "$PIDS"
cleanup

