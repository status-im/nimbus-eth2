#!/bin/bash

set -e

cd /home/user/nimbus-eth2

PREFIX="nimbus-eth2_Linux_amd64_"

NUM_ARCHIVES=$(ls "dist/${PREFIX}"*.tar.gz 2>/dev/null | wc -l)
if [[ $NUM_ARCHIVES -eq 0 ]]; then
  echo "No archive found matching \"dist/${PREFIX}*.tar.gz\". Aborting."
  exit 1
elif [[ $NUM_ARCHIVES -gt 1 ]]; then
  echo "More than one archive found matching \"dist/${PREFIX}*.tar.gz\". Aborting."
  exit 1
fi

cd dist
ARCHIVE=$(echo ${PREFIX}*.tar.gz)
ARCHIVE_DIR="${ARCHIVE%.tar.gz}"
rm -rf ${ARCHIVE_DIR}
tar xzf "${ARCHIVE}"
cd "${ARCHIVE_DIR}"
./nimbus_beacon_node --help
cd ..
rm -rf ${ARCHIVE_DIR}

