#!/bin/bash

set -eu

cd $(dirname "$0")

NETWORK_NAME=$1
source "$NETWORK_NAME.env"

cd ..

if [ -f .env ]; then
  # allow server overrides for ETH2_TESTNETS, DATA_DIR and ETH1_PRIVATE_KEY
  source .env
fi

echo ${BOOTSTRAP_HOST:="master-01.do-ams3.nimbus.test.statusim.net"} > /dev/null

echo Execution plan:

echo "Testnet name          : $NETWORK_NAME"
echo "Testnet files repo    : ${ETH2_TESTNETS:="build/eth2-testnets"}"
echo "Beacon node data dir  : ${DATA_DIR:="build/testnet-reset-data"}"
echo "Bootstrap node ip     : ${BOOTSTRAP_IP:="$(dig +short $BOOTSTRAP_HOST)"}"
echo "Reset testnet at end  : ${PUBLISH_TESTNET_RESETS:="1"}"

while true; do
    read -p "Continue?" yn
    case $yn in
        [Yy]* ) break;;
        [Nn]* ) exit 1;;
        * ) echo "Please answer yes or no.";;
    esac
done

if [[ ! -d "$ETH2_TESTNETS"  ]]; then
  git clone git@github.com:zah/eth2-testnets "$ETH2_TESTNETS"
fi

ETH2_TESTNETS_ABS=$(cd "$ETH2_TESTNETS"; pwd)
NETWORK_DIR_ABS="$ETH2_TESTNETS_ABS/nimbus/$NETWORK_NAME"
DATA_DIR_ABS=$(mkdir -p "$DATA_DIR"; cd "$DATA_DIR"; pwd)
DEPOSITS_DIR_ABS="$DATA_DIR_ABS/deposits"

if [ "$WEB3_URL" != "" ]; then
  WEB3_URL_ARG="--web3-url=$WEB3_URL"
fi

mkdir -p "$DEPOSITS_DIR_ABS"

DOCKER_BEACON_NODE="docker run -v $DEPOSITS_DIR_ABS:/deposits_dir -v $NETWORK_DIR_ABS:/network_dir -v $DATA_DIR_ABS:/data_dir statusteam/nimbus_beacon_node:$NETWORK_NAME"

make deposit_contract

DEPOSIT_CONTRACT_ADDRESS_ARG=""

if [ "$ETH1_PRIVATE_KEY" != "" ]; then
  DEPOSIT_CONTRACT_ADDRESS=$(./build/deposit_contract deploy $WEB3_URL_ARG --private-key=$ETH1_PRIVATE_KEY)
  DEPOSIT_CONTRACT_ADDRESS_ARG="--deposit-contract=$DEPOSIT_CONTRACT_ADDRESS"
fi

cd docker

make build NETWORK=$NETWORK_NAME GIT_REVISION=$(git rev-parse HEAD)

if [ ! -f $NETWORK_DIR_ABS/genesis.ssz ]; then
  rm -f $NETWORK_DIR_ABS/*
  $DOCKER_BEACON_NODE makeDeposits \
    --quickstart-deposits=$QUICKSTART_VALIDATORS \
    --random-deposits=$RANDOM_VALIDATORS \
    --deposits-dir=/deposits_dir
fi

TOTAL_VALIDATORS="$(( $QUICKSTART_VALIDATORS + $RANDOM_VALIDATORS ))"

$DOCKER_BEACON_NODE \
  --data-dir=/data_dir \
  createTestnet \
  --validators-dir=/deposits_dir \
  --total-validators=$TOTAL_VALIDATORS \
  --last-user-validator=$QUICKSTART_VALIDATORS \
  --output-genesis=/network_dir/genesis.ssz \
  --output-bootstrap-file=/network_dir/bootstrap_nodes.txt \
  --bootstrap-address=$BOOTSTRAP_IP \
  --bootstrap-port=$BOOTSTRAP_PORT \
  $WEB3_URL_ARG $DEPOSIT_CONTRACT_ADDRESS_ARG \
  --genesis-offset=60 # Delay in seconds

if [[ ! -z "$DEPOSIT_CONTRACT_ADDRESS" ]]; then
  echo $DEPOSIT_CONTRACT_ADDRESS > "$ETH2_TESTNETS_ABS/deposit_contract.txt"
fi

if [[ $PUBLISH_TESTNET_RESETS != "0" ]]; then
  echo Persisting testnet data to git...
  pushd "$ETH2_TESTNETS_ABS"
    git add genesis.ssz bootstrap_nodes.txt deposit_contract.txt
    git commit -m "Reset of Nimbus $NETWORK_NAME"
    git push
  popd

  echo Redistributing validator keys to server nodes...
  # TODO If we try to use direct piping here, bash doesn't execute all of the commands.
  #      The reasons for this are unclear at the moment.
  nim --verbosity:0 manage_testnet_hosts.nims $NETWORK_NAME redist-validators $DEPOSITS_DIR_ABS > /tmp/reset-network.sh
  bash /tmp/reset-network.sh

  echo Uploading bootstrap node network key
  BOOTSTRAP_NODE_DOCKER_PATH=/docker/beacon-node-$NETWORK_NAME-1/data/BeaconNode/$NETWORK_NAME/
  scp "$DATA_DIR_ABS/privkey.protobuf" $BOOTSTRAP_HOST:/tmp/
  ssh $BOOTSTRAP_HOST "sudo install -o dockremap -g docker /tmp/privkey.protobuf $BOOTSTRAP_NODE_DOCKER_PATH"

  echo Publishing docker image...
  make push
fi
