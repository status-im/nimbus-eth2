#!/bin/bash

set -eu

# Fetch genesis time, as set up by start.sh
if command -v jq; then
  genesis_time=$(jq '.genesis_time' data/state_snapshot.json)
else
  genesis_time=$(grep -oP '(?<=genesis_time": )\w+(?=,)' data/state_snapshot.json)
fi

echo Genesis time was $genesis_time

trinity_validators=$(seq 12 15 | paste -d ',' -s)

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

rm -rf /tmp/bb

PYTHONWARNINGS=ignore::DeprecationWarning trinity-beacon -l DEBUG \
  --trinity-root-dir /tmp/bb \
  --preferred_nodes="$(cat ../data/bootstrap_nodes.txt)" interop \
  --validators $trinity_validators \
  --start-time $genesis_time --wipedb
