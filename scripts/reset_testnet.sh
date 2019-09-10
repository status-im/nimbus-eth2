#!/bin/bash

set -eu

cd $(dirname "$0")

NETWORK_NAME=$1
source "$NETWORK_NAME.env"

cd ..

if [ -f .env ]; then
  # allow server overrides for ETH2_TESTNET_DATA_DIR and DATA_DIR
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

DOCKER_BEACON_NODE="docker run -v $NETWORK_DIR_ABS:/network_dir -v $DATA_DIR_ABS:/data_dir statusteam/nimbus_beacon_node:$NETWORK_NAME"

cd docker

export GIT_REVISION=$(git rev-parse HEAD)
make build

if [ ! -f $NETWORK_DIR_ABS/genesis.ssz ]; then
  rm -f $NETWORK_DIR_ABS/*
  $DOCKER_BEACON_NODE makeDeposits \
    --totalDeposits=$VALIDATOR_COUNT \
    --depositsDir=/network_dir \
    --randomKeys=true
fi

$DOCKER_BEACON_NODE \
  --network=$NETWORK_NAME \
  --dataDir=/data_dir \
  createTestnet \
  --networkId=$NETWORK_ID \
  --validatorsDir=/network_dir \
  --totalValidators=$VALIDATOR_COUNT \
  --lastUserValidator=$LAST_USER_VALIDATOR \
  --outputGenesis=/network_dir/genesis.ssz \
  --outputBootstrapNodes=/network_dir/bootstrap_nodes.txt \
  --outputNetworkMetadata=/network_dir/network.json \
  --bootstrapAddress=$BOOTSTRAP_IP \
  --bootstrapPort=$BOOTSTRAP_PORT \
  --genesisOffset=60 # Delay in seconds

if [[ $PUBLISH_TESTNET_RESETS != "0" ]]; then
  pushd "$ETH2_TESTNET_DATA_DIR_ABS"
  git add --all
  git commit -m "Testnet reset"
  git push

  ssh $BOOTSTRAP_HOST <<-SSH
    cd /opt/nim-eth2-testnet-data
    git reset --hard HEAD
    git checkout master
    git pull
SSH
  popd

  make push
fi
