#!/bin/bash

set -eu

# Fetch genesis time, as set up by start.sh
if command -v jq; then
  genesis_time=$(jq '.genesis_time' data/state_snapshot.json)
  peer=$(jq -r '.addresses[0] + "/p2p/" + .peer' data/node-0/beacon_node.address)
else
  genesis_time=$(grep -oP '(?<=genesis_time": )\w+(?=,)' data/state_snapshot.json)
fi

echo Genesis time was $genesis_time

trinity_validators=$(seq 11 15 | paste -d ',' -s)

TRINITY=${TRINITY_PATH:-"trinity"}

[[ -d "$TRINITY" ]] || {
  git clone git@github.com:ethereum/trinity.git "$TRINITY"
  pushd "$TRINITY"
  git checkout interop # temporary interop branch - will get merged soon I expect!

  python3 -m venv _ve

  . _ve/bin/activate

  pip install -e .[eth2-dev]
  popd
}

cd $TRINITY

. _ve/bin/activate

PYTHONWARNINGS=ignore::DeprecationWarning trinity-beacon -l DEBUG \
  --trinity-root-dir /tmp/bb --preferred_nodes=$peer interop \
  --validators $trinity_validators \
  --start-time $genesis_time --wipedb
