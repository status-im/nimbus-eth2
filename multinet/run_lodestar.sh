#!/bin/bash

set -eu

VALIDATORS_START=${1:-5}
VALIDATORS_NUM=${2:-5}
VALIDATORS_TOTAL=${3:-25}

SRCDIR=${LODESTAR_PATH:-"lodestar"}

export NVM_DIR="$([ -z "${XDG_CONFIG_HOME-}" ] && printf %s "${HOME}/.nvm" || printf %s "${XDG_CONFIG_HOME}/nvm")"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh" # This loads nvm

command -v nvm > /dev/null || { echo "install nvm first (https://github.com/nvm-sh/nvm#installation-and-update)"; exit 1; }

# Install node 10 LTS
echo Switching to node 10..
nvm install 10 && nvm use 10

[[ -d "$SRCDIR" ]] || {
  git clone git@github.com:ChainSafe/lodestar.git "$SRCDIR"

  pushd "$SRCDIR"

  command -v yarn > /dev/null || { npm install --global yarn ; }

  yarn install
  npx lerna bootstrap

  popd
}

set -x
trap 'kill -9 -- -$$' SIGINT EXIT SIGTERM

cd "$SRCDIR/packages/lodestar"

# Start
# -v is optional
./bin/lodestar interop -p minimal --db l1 \
  -q ../../../data/state_snapshot.ssz \
  --multiaddrs "$(cat ../../../data/bootstrap_nodes.txt)" \
  -r -v $VALIDATORS_START,$(($VALIDATORS_START+$VALIDATORS_NUM))
