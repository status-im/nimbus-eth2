#!/bin/bash

set -e

cd /home/user/nimbus-eth2

BINARIES="beacon_node beacon_node_spec_0_12_3"

# we need to build everything against libraries available inside this container, including the Nim compiler
make clean
make -j$(nproc) LOG_LEVEL="TRACE" NIMFLAGS="-d:disableMarchNative" PARTIAL_STATIC_LINKING=1 ${BINARIES}

# archive directory (we need the Nim compiler in here)
PREFIX="nimbus-eth2_Linux_amd64_"
GIT_COMMIT="$(git rev-parse --short HEAD)"
VERSION="$(./env.sh nim --verbosity:0 --hints:off --warnings:off scripts/print_version.nims)"
TIMESTAMP="$(date --utc +'%Y%m%d%H%M%S')"
DIR="${PREFIX}${VERSION}_${GIT_COMMIT}_${TIMESTAMP}"
DIST_PATH="dist/${DIR}"
# delete old artefacts
rm -rf "dist/${PREFIX}"*.tar.gz
mkdir -p "${DIST_PATH}"

# copy and checksum binaries, copy scripts and docs
for BINARY in ${BINARIES}; do
  cp -a ./build/${BINARY} "${DIST_PATH}/"
  cd "${DIST_PATH}"
  md5sum ${BINARY} > ${BINARY}.md5sum
  sha512sum ${BINARY} > ${BINARY}.sha512sum
  cd - >/dev/null
done
sed -e "s/GIT_COMMIT/${GIT_COMMIT}/" docker/dist/README.md > "${DIST_PATH}/README.md"
cp -a scripts/makedir.sh docker/dist/run_medalla_node.sh "${DIST_PATH}/"
cp -a docs/the_nimbus_book "${DIST_PATH}/"

# create the tarball
cd dist
tar czf "${DIR}.tar.gz" "${DIR}"
# don't leave the directory hanging around
rm -rf "${DIR}"
cd - >/dev/null

