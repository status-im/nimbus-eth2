#!/bin/bash

set -e

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

GROUP=0
TOTAL=$(ls -d ../nimbus-private/altona_deposits/validators/* | wc -l)
#echo "TOTAL=${TOTAL}"
PER_GROUP=$((TOTAL / 4))
#echo "PER_GROUP=${PER_GROUP}"
for N in $(seq 6 9); do
  ssh node-0${N}.aws-eu-central-1a.nimbus.test.statusim.net "sudo rm -rf /docker/beacon-node-testnet2-1/data/nim-beacon-chain/build/data/shared_altona_0/secrets"
  ssh node-0${N}.aws-eu-central-1a.nimbus.test.statusim.net "sudo rm -rf /docker/beacon-node-testnet2-1/data/nim-beacon-chain/build/data/shared_altona_0/validators"
  #echo GROUP="${GROUP}"
  for TARGET in "validators" "secrets"; do
    DIR_NO=0
    ls -d ../nimbus-private/altona_deposits/${TARGET}/* | while read DIR; do
      if [[ $DIR_NO -ge $((GROUP * PER_GROUP)) && $DIR_NO -lt $(( (GROUP + 1) * PER_GROUP )) ]]; then
        #echo "DIR_NO=${DIR_NO}"
        #echo "$DIR"
        rsync -a -zz --rsync-path="sudo rsync" "$DIR" node-0${N}.aws-eu-central-1a.nimbus.test.statusim.net:/docker/beacon-node-testnet2-1/data/nim-beacon-chain/build/data/shared_altona_0/${TARGET}/
      fi
      DIR_NO=$((DIR_NO + 1))
    done
  done
  GROUP=$((GROUP + 1))

  ssh node-0${N}.aws-eu-central-1a.nimbus.test.statusim.net "sudo chown -R dockremap:dockremap /docker/beacon-node-testnet2-1/data/nim-beacon-chain/build/data/shared_altona_0/secrets"
  ssh node-0${N}.aws-eu-central-1a.nimbus.test.statusim.net "sudo chown -R dockremap:dockremap /docker/beacon-node-testnet2-1/data/nim-beacon-chain/build/data/shared_altona_0/validators"
done

