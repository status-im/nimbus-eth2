#!/bin/bash

set -e

cd /home/user/nimbus-eth2
git config --global core.abbrev 8

BINARIES="nimbus_beacon_node nimbus_beacon_node_spec_0_12_3 nimbus_signing_process"

# we need to build everything against libraries available inside this container, including the Nim compiler
make clean
make -j$(nproc) LOG_LEVEL="TRACE" NIMFLAGS="-d:disableMarchNative" PARTIAL_STATIC_LINKING=1 ${BINARIES}

# archive directory (we need the Nim compiler in here)
PREFIX="nimbus-eth2_Linux_amd64_"
GIT_COMMIT="$(git rev-parse --short HEAD)"
VERSION="$(./env.sh nim --verbosity:0 --hints:off --warnings:off scripts/print_version.nims)"
#TIMESTAMP="$(date --utc +'%Y%m%d%H%M%S')"
DIR="${PREFIX}${VERSION}_${GIT_COMMIT}"
DIST_PATH="dist/${DIR}"
# delete old artefacts
rm -rf "dist/${PREFIX}"*.tar.gz
if [[ -d "${DIST_PATH}" ]]; then
  rm -rf "${DIST_PATH}"
fi
mkdir -p "${DIST_PATH}"
mkdir "${DIST_PATH}/scripts"
mkdir "${DIST_PATH}/build"

# copy and checksum binaries, copy scripts and docs
for BINARY in ${BINARIES}; do
  cp -a ./build/${BINARY} "${DIST_PATH}/build/"
  cd "${DIST_PATH}/build"
  md5sum ${BINARY} > ${BINARY}.md5sum
  sha512sum ${BINARY} > ${BINARY}.sha512sum
  cd - >/dev/null
done
sed -e "s/GIT_COMMIT/${GIT_COMMIT}/" docker/dist/README.md > "${DIST_PATH}/README.md"
cp -a scripts/makedir.sh scripts/run-beacon-node.sh "${DIST_PATH}/scripts"
cp -a ./run-*-beacon-node.sh "${DIST_PATH}/"
#cp -a docs/the_nimbus_book "${DIST_PATH}/"

# create the tarball
cd dist
tar czf "${DIR}.tar.gz" "${DIR}"
# don't leave the directory hanging around
rm -rf "${DIR}"
cd - >/dev/null

