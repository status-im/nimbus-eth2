#!/bin/bash


[ -z "$1" ] && { echo "Usage: `basename $0` testnetX"; exit 1; }

set -eu

cd $(dirname "$0")

NETWORK_NAME="$1"
source "$NETWORK_NAME.env"

cd ..

NIM_FLAGS="-d:release --lineTrace:on -d:chronicles_log_level=DEBUG -d:network_type=$NETWORK_TYPE -d:SECONDS_PER_SLOT=$SECONDS_PER_SLOT -d:SHARD_COUNT=$SHARD_COUNT -d:SLOTS_PER_EPOCH=$SLOTS_PER_EPOCH -d:DEFAULT_NETWORK=$NETWORK_NAME --hints:off --verbosity:0"

BEACON_NODE_BIN="build/${NETWORK_NAME}_node"

CMD="nim c $NIM_FLAGS -o:$BEACON_NODE_BIN beacon_chain/beacon_node"
echo "$CMD"
$CMD

if [ ! -d ~/.cache/nimbus/BeaconNode/${NETWORK_NAME}/validators ]; then
  $BEACON_NODE_BIN --network=$NETWORK_NAME importValidator
fi

echo
echo "Done! You're now ready to connect to $NETWORK_NAME by running:"
echo
echo "    $BEACON_NODE_BIN"
echo
echo "Database and configuration files will be placed in:"
echo
echo "    ${HOME}/.cache/nimbus/BeaconNode/${NETWORK_NAME}"
echo
