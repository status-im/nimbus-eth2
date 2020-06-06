#!/bin/bash

set -e

cd $(dirname "$0")

export NETWORK=$1
export NETWORK_NIM_FLAGS=$(./load-testnet-nim-flags.sh $NETWORK)
export GIT_REVISION=$(git rev-parse HEAD)

set -a
source $NETWORK.env
set +a

cd ..

if [ -f .env ]; then
  # allow server overrides for ETH2_TESTNETS, DATA_DIR and ETH1_PRIVATE_KEY
  source .env
fi

echo Execution plan:

echo "Testnet name            : $NETWORK"
echo "Bootstrap node hostname : ${BOOTSTRAP_HOST:="master-01.aws-eu-central-1a.nimbus.test.statusim.net"}"
echo "Bootstrap node ip       : ${BOOTSTRAP_IP:="$(dig +short $BOOTSTRAP_HOST)"}"
echo "Bootstrap node port     : ${BOOTSTRAP_PORT:=9000}"
echo "Reset testnet at end    : ${PUBLISH_TESTNET_RESETS:="1"}"
echo "Testnet metadata repo   : ${ETH2_TESTNETS_GIT_URL:="git@github.com:${ETH2_TESTNETS_ORG:=eth2-clients}/eth2-testnets"}"
echo "Testnet metadata dir    : ${ETH2_TESTNETS:="build/eth2-testnets"}"
echo "Beacon node data dir    : ${DATA_DIR:="build/testnet-reset-data/$NETWORK"}"
echo "Nim build flags         : $NETWORK_NIM_FLAGS"

while true; do
    read -p "Continue? [Yn] " yn
    case $yn in
        * ) break;;
        [Nn]* ) exit 1;;
    esac
done

rm -rf "$ETH2_TESTNETS"
git clone --quiet --depth=1 $ETH2_TESTNETS_GIT_URL "$ETH2_TESTNETS"

ETH2_TESTNETS_ABS=$(cd "$ETH2_TESTNETS"; pwd)
NETWORK_DIR_ABS="$ETH2_TESTNETS_ABS/nimbus/$NETWORK"
DATA_DIR_ABS=$(mkdir -p "$DATA_DIR"; cd "$DATA_DIR"; pwd)
DEPOSITS_DIR_ABS="$DATA_DIR_ABS/deposits"
DEPOSIT_CONTRACT_ADDRESS=""
DEPOSIT_CONTRACT_ADDRESS_ARG=""

if [ "$WEB3_URL" != "" ]; then
  WEB3_URL_ARG="--web3-url=$WEB3_URL"
fi

mkdir -p "$DEPOSITS_DIR_ABS"

if [ "$ETH1_PRIVATE_KEY" != "" ]; then
  make deposit_contract
  echo "Deploying deposit contract through $WEB3_URL_ARG..."
  DEPOSIT_CONTRACT_ADDRESS=$(./build/deposit_contract deploy $WEB3_URL_ARG --private-key=$ETH1_PRIVATE_KEY)
  DEPOSIT_CONTRACT_ADDRESS_ARG="--deposit-contract=$DEPOSIT_CONTRACT_ADDRESS"
  echo "Done: $DEPOSIT_CONTRACT_ADDRESS"
fi

echo "Building a local beacon_node instance for 'makeDeposits' and 'createTestnet'"
make -j2 NIMFLAGS="-d:insecure -d:testnet_servers_image ${NETWORK_NIM_FLAGS}" beacon_node process_dashboard

echo "Generating Grafana dashboards for remote testnet servers"
for testnet in 0 1; do
  ./build/process_dashboard \
    --in="tests/simulation/beacon-chain-sim-node0-Grafana-dashboard.json" \
    --out="docker/beacon-chain-sim-remote-testnet${testnet}-Grafana-dashboard.json" \
    --type="remote" \
    --testnet="${testnet}"
done

cd docker

echo "Building Docker image..."
# CPU-specific CFLAGS that work on the servers are in MARCH_NIM_FLAGS,
# in docker/Makefile, and are enabled by default.
make build

../build/beacon_node makeDeposits \
  --quickstart-deposits=$QUICKSTART_VALIDATORS \
  --random-deposits=$RANDOM_VALIDATORS \
  --deposits-dir="$DEPOSITS_DIR_ABS"

TOTAL_VALIDATORS="$(( $QUICKSTART_VALIDATORS + $RANDOM_VALIDATORS ))"

../build/beacon_node createTestnet \
  --data-dir="$DATA_DIR_ABS" \
  --validators-dir="$DEPOSITS_DIR_ABS" \
  --total-validators=$TOTAL_VALIDATORS \
  --last-user-validator=$QUICKSTART_VALIDATORS \
  --output-genesis="$NETWORK_DIR_ABS/genesis.ssz" \
  --output-bootstrap-file="$NETWORK_DIR_ABS/bootstrap_nodes.txt" \
  --bootstrap-address=$BOOTSTRAP_IP \
  --bootstrap-port=$BOOTSTRAP_PORT \
  $WEB3_URL_ARG $DEPOSIT_CONTRACT_ADDRESS_ARG \
  --genesis-offset=300 # Delay in seconds

COMMITTED_FILES=" genesis.ssz bootstrap_nodes.txt "

if [[ ! -z "$DEPOSIT_CONTRACT_ADDRESS" ]]; then
  echo $DEPOSIT_CONTRACT_ADDRESS > "$ETH2_TESTNETS_ABS/nimbus/$NETWORK/deposit_contract.txt"
  COMMITTED_FILES+=" deposit_contract.txt "
fi

if [[ $PUBLISH_TESTNET_RESETS != "0" ]]; then
  echo Redistributing validator keys to server nodes...
  # TODO If we try to use direct piping here, bash doesn't execute all of the commands.
  #      The reasons for this are unclear at the moment.

  ../env.sh nim --verbosity:0 --hints:off manage_testnet_hosts.nims reset_network \
    --network=$NETWORK \
    --deposits-dir="$DEPOSITS_DIR_ABS" \
    --network-data-dir="$NETWORK_DIR_ABS" \
    --user-validators=$QUICKSTART_VALIDATORS \
    --total-validators=$TOTAL_VALIDATORS \
    > /tmp/reset-network.sh

  bash /tmp/reset-network.sh
  rm /tmp/reset-network.sh

  echo Uploading bootstrap node network key
  BOOTSTRAP_NODE_DOCKER_PATH=/docker/beacon-node-$NETWORK-1/data/BeaconNode/
  scp "$DATA_DIR_ABS/privkey.protobuf" $BOOTSTRAP_HOST:/tmp/
  ssh $BOOTSTRAP_HOST "sudo install -o dockremap -g docker /tmp/privkey.protobuf $BOOTSTRAP_NODE_DOCKER_PATH"

  echo "Publishing Docker image..."
  make push-last

  echo Persisting testnet data to git...
  pushd "$NETWORK_DIR_ABS"
    git add $COMMITTED_FILES
    git commit -m "Reset of Nimbus $NETWORK"
    git push
  popd

  ../env.sh nim --verbosity:0 --hints:off manage_testnet_hosts.nims restart_nodes \
    --network=$NETWORK \
    > /tmp/restart-nodes.sh

  bash /tmp/restart-nodes.sh
  rm /tmp/restart-nodes.sh
fi
