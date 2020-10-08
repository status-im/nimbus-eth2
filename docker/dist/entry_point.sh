#!/bin/bash

set -e

cd /home/user/nimbus-eth2

PREFIX="nimbus-eth2_Linux_amd64_"
GIT_COMMIT="$(git rev-parse --short HEAD)"
DIR="${PREFIX}${GIT_COMMIT}_$(date +'%Y%m%d%H%M%S')"
DIST_PATH="dist/${DIR}"
BINARIES="beacon_node"

# delete old artefacts
rm -rf "dist/${PREFIX}"*

mkdir -p "${DIST_PATH}"

# we need to build everything against libraries available inside this container, including the Nim compiler
make clean
make -j$(nproc) NIMFLAGS="-d:disableMarchNative" PARTIAL_STATIC_LINKING=1 ${BINARIES}
for BINARY in ${BINARIES}; do
  cp -a ./build/${BINARY} "${DIST_PATH}/"
  cd "${DIST_PATH}"
  md5sum ${BINARY} > ${BINARY}.md5sum
  sha512sum ${BINARY} > ${BINARY}.sha512sum
  cd - >/dev/null
done
sed -e "s/GIT_COMMIT/${GIT_COMMIT}/" docker/dist/README.md > "${DIST_PATH}/README.md"

# create the tarball
cd dist
tar czf "${DIR}.tar.gz" "${DIR}"
# don't leave the directory hanging around
rm -rf "${DIR}"
cd - >/dev/null

