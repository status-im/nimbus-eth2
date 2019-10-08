#!/bin/bash

# https://github.com/PegaSysEng/artemis#build-instructions

set -eu

VALIDATORS_START=${1:-0}
VALIDATORS_NUM=${2:-5}
VALIDATORS_TOTAL=${3:-25}

SRCDIR=${ARTEMIS_PATH:-"artemis"}
CWD=`pwd`
echo $CWD

print_java_install_msg() {

    MSG+="OpenJDK 11 is missing.  Please install it "
    if [[ "$OSTYPE" == "linux-gnu" ]]; then
        MSG+=" with 'sudo apt install openjdk-11-jdk'"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        MSG+=" with 'brew tap AdoptOpenJDK/openjdk && brew cask install adoptopenjdk11'"
    fi
    echo MSG;
}

# Is Java installed?
if ! command -v java; then
    print_java_install_msg;
    exit 1;
fi

# Is openjdk-11-jdk installed?
if [[ $(java -version 2>&1) != *"OpenJDK"* ]]; then
    print_java_install_msg;
    exit 1;
fi

command -v gradle > /dev/null || { echo "install gradle (https://gradle.org/install/)"; exit 1; }

[[ -d "$SRCDIR" ]] || {
  bash <(curl -s https://raw.githubusercontent.com/PegaSysEng/artemis/master/scripts/clone-repo.sh)
  pushd "$SRCDIR"
  ./gradlew distTar installDist
  popd
}

if command -v jq > /dev/null; then
  GENESIS_TIME=$(jq '.genesis_time' data/state_snapshot.json)
else
  GENESIS_TIME=$(grep '"genesis_time"' data/state_snapshot.json | grep -o '[0-9]*,' | sed 's/.$//')
fi

pushd "$SRCDIR"

NUM_NODES=1
GENESIS_FILE="$CWD/data/state_snapshot.ssz"

sh scripts/configurator.sh "config/config.toml" networkMode "\"jvmlibp2p"\"
sh scripts/configurator.sh "config/config.toml" numValidators $VALIDATORS_TOTAL
sh scripts/configurator.sh "config/config.toml" numNodes $NUM_NODES
sh scripts/configurator.sh "config/config.toml" active true
sh scripts/configurator.sh "config/config.toml" genesisTime $GENESIS_TIME
sh scripts/configurator.sh "config/config.toml" ownedValidatorStartIndex $VALIDATORS_START
sh scripts/configurator.sh "config/config.toml" ownedValidatorCount $VALIDATORS_NUM
sh scripts/configurator.sh "config/config.toml" startState "\"$GENESIS_FILE"\"

PEERS="$(cat ../data/bootstrap_nodes.txt)"
ARTEMIS_PEERS=$(echo [\"$PEERS\"] )
sed -i.bak 's/bootnodes/peers/g' config/config.toml
rm -f config/config.toml.bak
sh scripts/configurator.sh "config/config.toml" peers $ARTEMIS_PEERS
sh scripts/configurator.sh "config/config.toml" discovery "\"static\""
sh scripts/configurator.sh "config/config.toml" isBootnode false
cp config/config.toml build/install/artemis/bin/
popd

set -x

cd "$SRCDIR/build/install/artemis/bin/" && ./artemis --config=config.toml --logging=DEBUG;
