#!/bin/bash

set -e

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

GROUP=0
TOTAL=$(ls -d ../nimbus-private/medalla_deposits/validators/* | wc -l)
HOSTS=(
  "master-01.aws-eu-central-1a.nimbus.test.statusim.net"
  "node-01.aws-eu-central-1a.nimbus.test.statusim.net"
  "node-02.aws-eu-central-1a.nimbus.test.statusim.net"
  "node-03.aws-eu-central-1a.nimbus.test.statusim.net"
  "node-04.aws-eu-central-1a.nimbus.test.statusim.net"
  "node-05.aws-eu-central-1a.nimbus.test.statusim.net"
)
PER_GROUP=$(( TOTAL / ${#HOSTS[@]} ))
for HOST in "${HOSTS[@]}"; do
  ssh ${HOST} "sudo rm -rf /docker/beacon-node-testnet3/data/nim-beacon-chain/build/data/shared_medalla_0/secrets"
  ssh ${HOST} "sudo rm -rf /docker/beacon-node-testnet3/data/nim-beacon-chain/build/data/shared_medalla_0/validators"
  for TARGET in "validators" "secrets"; do
    DIR_NO=0
    ls -d ../nimbus-private/medalla_deposits/${TARGET}/* | while read DIR; do
      if [[ $DIR_NO -ge $((GROUP * PER_GROUP)) && $DIR_NO -lt $(( (GROUP + 1) * PER_GROUP )) ]]; then
        rsync -a -zz --rsync-path="sudo rsync" "$DIR" ${HOST}:/docker/beacon-node-testnet3/data/nim-beacon-chain/build/data/shared_medalla_0/${TARGET}/
      elif [[ $(( GROUP + 1 )) == ${#HOSTS[@]} && $DIR_NO -ge $(( (GROUP + 1) * PER_GROUP )) ]]; then
        # extra validators from the integer division remainder
        rsync -a -zz --rsync-path="sudo rsync" "$DIR" ${HOST}:/docker/beacon-node-testnet3/data/nim-beacon-chain/build/data/shared_medalla_0/${TARGET}/
      fi
      DIR_NO=$((DIR_NO + 1))
    done
  done
  GROUP=$((GROUP + 1))

  ssh ${HOST} "sudo chown -R dockremap:dockremap /docker/beacon-node-testnet3/data/nim-beacon-chain/build/data/shared_medalla_0/secrets"
  ssh ${HOST} "sudo chown -R dockremap:dockremap /docker/beacon-node-testnet3/data/nim-beacon-chain/build/data/shared_medalla_0/validators"
done

