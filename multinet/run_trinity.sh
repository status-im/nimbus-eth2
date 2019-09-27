#!/bin/bash

set -eu

VALIDATORS_START=${1:-10}
VALIDATORS_NUM=${2:-5}
VALIDATORS_TOTAL=${3:-25}

SRCDIR=${TRINITY_PATH:-"trinity"}

command -v python3 > /dev/null || { echo "install python3 first (https://wiki.python.org/moin/BeginnersGuide/Download)"; exit 1; }

[[ -d "$SRCDIR" ]] || {
  git clone git@github.com:ethereum/trinity.git "$SRCDIR"
  pushd "$SRCDIR"

  git checkout interop # temporary interop branch - will get merged soon I expect!

  python3 -m venv _ve

  . _ve/bin/activate

  pip install -e .[eth2-dev]
  popd
}

set -x
trap 'kill -9 -- -$$' SIGINT EXIT SIGTERM

cd "$SRCDIR"

. _ve/bin/activate

rm -rf /tmp/bb

VALIDATORS=$(seq $VALIDATORS_START $(($VALIDATORS_START+$VALIDATORS_NUM-1)) | paste -d ',' -s -)

PYTHONWARNINGS=ignore::DeprecationWarning trinity-beacon \
  -l DEBUG \
  --trinity-root-dir /tmp/bb \
  --beacon-nodekey='aaaaaaaa' \
  --preferred_nodes="$(cat ../data/bootstrap_nodes.txt)" \
  interop \
  --validators $VALIDATORS \
  --genesis-state-ssz-path ../data/state_snapshot.ssz
