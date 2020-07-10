#!/bin/bash

# This script creates validator keys and uploads them to remote servers,
# assuming your local username is the same as the remote one.

set -e

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

[[ -z "$1" ]] && { echo "Usage: $(basename $0) YOUR_ETH1_PRIVATE_GOERLI_KEY"; exit 1; }

echo -ne "About to delete \"build/data/shared_witti_0\".\nMake a backup, if you need to, then press Enter. >"
read TMP
make clean-altona
make beacon_node

for N in $(seq 6 9); do
  build/beacon_node deposits create --deposit-private-key=$1 --dont-send && \
    ssh node-0${N}.aws-eu-central-1a.nimbus.test.statusim.net "sudo rm -rf /docker/beacon-node-testnet2-1/data/nim-beacon-chain/build/data/shared_witti_0/secrets" && \
    ssh node-0${N}.aws-eu-central-1a.nimbus.test.statusim.net "sudo rm -rf /docker/beacon-node-testnet2-1/data/nim-beacon-chain/build/data/shared_witti_0/validators" && \
    rsync -a -zz --rsync-path="sudo rsync" build/data/shared_witti_0/{secrets,validators} node-0${N}.aws-eu-central-1a.nimbus.test.statusim.net:/docker/beacon-node-testnet2-1/data/nim-beacon-chain/build/data/shared_witti_0/ && \
    ssh node-0${N}.aws-eu-central-1a.nimbus.test.statusim.net "sudo chown -R dockremap:dockremap /docker/beacon-node-testnet2-1/data/nim-beacon-chain/build/data/shared_witti_0/secrets" && \
    ssh node-0${N}.aws-eu-central-1a.nimbus.test.statusim.net "sudo chown -R dockremap:dockremap /docker/beacon-node-testnet2-1/data/nim-beacon-chain/build/data/shared_witti_0/validators"
  rm -rf build/data/shared_witti_0/{secrets,validators}
  # if we're doing it too fast, we get {"code":-32000,"message":"replacement transaction underpriced"}
  # or {"code":-32000,"message":"nonce too low"}
  echo "Sleeping..."
  sleep 120
done

