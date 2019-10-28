#!/bin/bash

set -eu

cd $(dirname "$0")

NETWORK_NAME=$1
source "$NETWORK_NAME.env"

cd ..

if [ -f .env ]; then
  # allow server overrides for ETH2_TESTNET_DATA_DIR, DATA_DIR and ETH1_PRIVATE_KEY
  source .env
fi

echo ${BOOTSTRAP_HOST:="master-01.do-ams3.nimbus.test.statusim.net"} > /dev/null

echo Execution plan:

echo "Testnet name          : $NETWORK_NAME"
echo "Testnet files repo    : ${ETH2_TESTNET_DATA_DIR:="nim-eth2-testnet-data"}"
echo "Beacon node data dir  : ${DATA_DIR:="testnet-reset-data"}"
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

if [[ ! -d "$ETH2_TESTNET_DATA_DIR"  ]]; then
  git clone git@github.com:status-im/nim-eth2-testnet-data "$ETH2_TESTNET_DATA_DIR"
fi

ETH2_TESTNET_DATA_DIR_ABS=$(cd "$ETH2_TESTNET_DATA_DIR"; pwd)
DATA_DIR_ABS=$(mkdir -p "$DATA_DIR"; cd "$DATA_DIR"; pwd)
NETWORK_DIR_ABS="$ETH2_TESTNET_DATA_DIR_ABS/www/$NETWORK_NAME"

if [ "$WEB3_URL" != "" ]; then
  WEB3_URL_ARG="--web3-url=$WEB3_URL"
fi

DOCKER_BEACON_NODE="docker run -v $NETWORK_DIR_ABS:/network_dir -v $DATA_DIR_ABS:/data_dir statusteam/nimbus_beacon_node:$NETWORK_NAME"

make deposit_contract

if [ "$ETH1_PRIVATE_KEY" != "" ]; then
  DEPOSIT_CONTRACT_ADDRESS=$(./build/deposit_contract deploy $WEB3_URL_ARG --privateKey=$ETH1_PRIVATE_KEY)
  DEPOSIT_CONTRACT_ADDRESS_ARG="--deposit_contract=$DEPOSIT_CONTRACT_ADDRESS"
fi

cd docker

export GIT_REVISION=$(git rev-parse HEAD)
make build

if [ ! -f $NETWORK_DIR_ABS/genesis.ssz ]; then
  rm -f $NETWORK_DIR_ABS/*
  $DOCKER_BEACON_NODE makeDeposits \
    --total-deposits=$VALIDATOR_COUNT \
    --deposits-dir=/network_dir \
    --random-keys=no
fi

$DOCKER_BEACON_NODE \
  --network=$NETWORK_NAME \
  --data-dir=/data_dir \
  createTestnet \
  --validators-dir=/network_dir \
  --total-validators=$VALIDATOR_COUNT \
  --last-user-validator=$LAST_USER_VALIDATOR \
  --output-genesis=/network_dir/genesis.json \
  --output-bootstrap-file=/network_dir/bootstrap_nodes.txt \
  --bootstrap-address=$BOOTSTRAP_IP \
  --bootstrap-port=$BOOTSTRAP_PORT \
  $WEB3_URL_ARG $DEPOSIT_CONTRACT_ADDRESS_ARG \
  --genesis-offset=60 # Delay in seconds

if [[ $PUBLISH_TESTNET_RESETS != "0" ]]; then
  echo Persisting testnet data to git...
  pushd "$ETH2_TESTNET_DATA_DIR_ABS"
    git add --all
    git commit -m "Testnet reset"
    git push
  popd

  echo Redistributing validator keys to server nodes...
  # TODO If we try to use direct piping here, bash doesn't execute all of the commands.
  #      The reasons for this are unclear at the moment.
  nim --verbosity:0 manage_testnet_hosts.nims $NETWORK_NAME redist-validators > /tmp/reset-network.sh
  bash /tmp/reset-network.sh

  echo Uploading bootstrap node network key
  BOOTSTRAP_NODE_DOCKER_PATH=/docker/beacon-node-$NETWORK_NAME-1/data/BeaconNode/$NETWORK_NAME/
  scp "$DATA_DIR_ABS/privkey.protobuf" $BOOTSTRAP_HOST:/tmp/
  ssh $BOOTSTRAP_HOST "sudo install -o dockremap -g docker /tmp/privkey.protobuf $BOOTSTRAP_NODE_DOCKER_PATH"

  echo Publishing docker image...
  make push
fi
