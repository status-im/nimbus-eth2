#!/bin/bash

set -eu

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
  --trinity-root-dir /tmp/aa --beacon-nodekey='aaaaaaaa' \
  --preferred_nodes="$(cat ../data/bootstrap_nodes.txt)" interop --wipedb \
  --validators $trinity_validators \
  --genesis-state-ssz-path ../data/state_snapshot.ssz
