#!/bin/bash

# Copyright (c) 2020-2021 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

set -e

cd /home/user/nimbus-eth2
git config --global core.abbrev 8

if [[ -z "${1}" ]]; then
  echo "Usage: $(basename ${0}) PLATFORM"
  exit 1
fi
PLATFORM="${1}"
BINARIES="nimbus_beacon_node nimbus_signing_process"

#- we need to build everything against libraries available inside this container, including the Nim compiler
#- we disable the log file and log colours; the user only has to worry about logging stdout now
make clean
if [[ "${PLATFORM}" == "Windows_amd64" ]]; then
  # Cross-compilation using the MXE distribution of Mingw-w64
  export PATH="/usr/lib/mxe/usr/bin:${PATH}"
  CC=x86_64-w64-mingw32.static-gcc
  CXX=x86_64-w64-mingw32.static-g++
  make \
    -j$(nproc) \
    USE_LIBBACKTRACE=0 \
    QUICK_AND_DIRTY_COMPILER=1 \
    deps-common build/generate_makefile
  make \
    -j$(nproc) \
    -C vendor/nim-nat-traversal/vendor/miniupnp/miniupnpc \
    -f Makefile.mingw \
    CC="${CC}" \
    libminiupnpc.a &>/dev/null
  make \
    -j$(nproc) \
    -C vendor/nim-nat-traversal/vendor/libnatpmp-upstream \
    CC="${CC}" \
    CFLAGS="-Wall -Os -DWIN32 -DNATPMP_STATICLIB -DENABLE_STRNATPMPERR -DNATPMP_MAX_RETRIES=4 ${CFLAGS}" \
    libnatpmp.a &>/dev/null
  # We set CXX and add CXXFLAGS for libunwind's C++ code, even though we don't
  # use those C++ objects. I don't see an easy way of disabling the C++ parts in
  # libunwind itself.
  #
  # "libunwind.a" combines objects produced from C and C++ code. Even though we
  # don't link any C++-generated objects, the linker still checks them for
  # undefined symbols, so we're forced to use g++ as a linker wrapper.
  # For some reason, macOS's Clang doesn't need this trick, nor do native (and
  # newer) Mingw-w64 toolchains on Windows.
  make \
    -j$(nproc) \
    CC="${CC}" \
    CXX="${CXX}" \
    CXXFLAGS="${CXXFLAGS} -D__STDC_FORMAT_MACROS -D_WIN32_WINNT=0x0600" \
    USE_VENDORED_LIBUNWIND=1 \
    LOG_LEVEL="TRACE" \
    NIMFLAGS="-d:disableMarchNative -d:chronicles_sinks=textlines -d:chronicles_colors=none --os:windows --gcc.exe=${CC} --gcc.linkerexe=${CXX} --passL:-static" \
    ${BINARIES}
elif [[ "${PLATFORM}" == "Linux_arm32v7" ]]; then
  CC="arm-linux-gnueabihf-gcc"
  make \
    -j$(nproc) \
    USE_LIBBACKTRACE=0 \
    QUICK_AND_DIRTY_COMPILER=1 \
    deps-common build/generate_makefile
  make \
    -j$(nproc) \
    LOG_LEVEL="TRACE" \
    CC="${CC}" \
    NIMFLAGS="-d:disableMarchNative -d:chronicles_sinks=textlines -d:chronicles_colors=none --cpu:arm --gcc.exe=${CC} --gcc.linkerexe=${CC}" \
    PARTIAL_STATIC_LINKING=1 \
    ${BINARIES}
elif [[ "${PLATFORM}" == "Linux_arm64v8" ]]; then
  CC="aarch64-linux-gnu-gcc"
  make \
    -j$(nproc) \
    USE_LIBBACKTRACE=0 \
    QUICK_AND_DIRTY_COMPILER=1 \
    deps-common build/generate_makefile
  make \
    -j$(nproc) \
    LOG_LEVEL="TRACE" \
    CC="${CC}" \
    NIMFLAGS="-d:disableMarchNative -d:chronicles_sinks=textlines -d:chronicles_colors=none --cpu:arm64 --gcc.exe=${CC} --gcc.linkerexe=${CC}" \
    PARTIAL_STATIC_LINKING=1 \
    ${BINARIES}
elif [[ "${PLATFORM}" == "macOS_amd64" ]]; then
  export PATH="/opt/osxcross/bin:${PATH}"
  export OSXCROSS_MP_INC=1 # sets up include and library paths
  export ZERO_AR_DATE=1 # avoid timestamps in binaries
  DARWIN_VER="20.4"
  CC="o64-clang"
  make \
    -j$(nproc) \
    USE_LIBBACKTRACE=0 \
    QUICK_AND_DIRTY_COMPILER=1 \
    deps-common build/generate_makefile
  make \
    -j$(nproc) \
    CC="${CC}" \
    LIBTOOL="x86_64-apple-darwin${DARWIN_VER}-libtool" \
    OS="darwin" \
    NIMFLAGS="-d:disableMarchNative -d:chronicles_sinks=textlines -d:chronicles_colors=none --os:macosx --clang.exe=${CC}" \
    nat-libs
  make \
    -j$(nproc) \
    LOG_LEVEL="TRACE" \
    CC="${CC}" \
    AR="x86_64-apple-darwin${DARWIN_VER}-ar" \
    RANLIB="x86_64-apple-darwin${DARWIN_VER}-ranlib" \
    CMAKE="x86_64-apple-darwin${DARWIN_VER}-cmake" \
    DSYMUTIL="x86_64-apple-darwin${DARWIN_VER}-dsymutil" \
    FORCE_DSYMUTIL=1 \
    USE_VENDORED_LIBUNWIND=1 \
    NIMFLAGS="-d:disableMarchNative -d:chronicles_sinks=textlines -d:chronicles_colors=none --os:macosx --clang.exe=${CC} --clang.linkerexe=${CC}" \
    ${BINARIES}
elif [[ "${PLATFORM}" == "macOS_arm64" ]]; then
  export PATH="/opt/osxcross/bin:${PATH}"
  export OSXCROSS_MP_INC=1 # sets up include and library paths
  export ZERO_AR_DATE=1 # avoid timestamps in binaries
  DARWIN_VER="20.4"
  CC="oa64-clang"
  make \
    -j$(nproc) \
    USE_LIBBACKTRACE=0 \
    QUICK_AND_DIRTY_COMPILER=1 \
    deps-common build/generate_makefile
  make \
    -j$(nproc) \
    CC="${CC}" \
    LIBTOOL="arm64-apple-darwin${DARWIN_VER}-libtool" \
    OS="darwin" \
    NIMFLAGS="-d:disableMarchNative -d:chronicles_sinks=textlines -d:chronicles_colors=none --os:macosx --cpu:arm64 --clang.exe=${CC}" \
    nat-libs
  make \
    -j$(nproc) \
    LOG_LEVEL="TRACE" \
    CC="${CC}" \
    AR="arm64-apple-darwin${DARWIN_VER}-ar" \
    RANLIB="arm64-apple-darwin${DARWIN_VER}-ranlib" \
    CMAKE="arm64-apple-darwin${DARWIN_VER}-cmake" \
    DSYMUTIL="arm64-apple-darwin${DARWIN_VER}-dsymutil" \
    FORCE_DSYMUTIL=1 \
    USE_VENDORED_LIBUNWIND=1 \
    NIMFLAGS="-d:disableMarchNative -d:chronicles_sinks=textlines -d:chronicles_colors=none --os:macosx --cpu:arm64 --clang.exe=${CC} --clang.linkerexe=${CC}" \
    ${BINARIES}
else
  make \
    -j$(nproc) \
    LOG_LEVEL="TRACE" \
    NIMFLAGS="-d:disableMarchNative -d:chronicles_sinks=textlines -d:chronicles_colors=none" \
    PARTIAL_STATIC_LINKING=1 \
    QUICK_AND_DIRTY_COMPILER=1 \
    ${BINARIES}
fi

# archive directory (we need the Nim compiler in here)
PREFIX="nimbus-eth2_${PLATFORM}_"
GIT_COMMIT="$(git rev-parse --short HEAD)"
VERSION="$(./env.sh nim --verbosity:0 --hints:off --warnings:off scripts/print_version.nims)"
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
  cp -a "./build/${BINARY}" "${DIST_PATH}/build/"
  if [[ "${PLATFORM}" =~ macOS ]]; then
    # debug info
    cp -a "./build/${BINARY}.dSYM" "${DIST_PATH}/build/"
  fi
  cd "${DIST_PATH}/build"
  sha512sum "${BINARY}" > "${BINARY}.sha512sum"
  if [[ "${PLATFORM}" == "Windows_amd64" ]]; then
    mv "${BINARY}" "${BINARY}.exe"
  fi
  cd - >/dev/null
done
sed -e "s/GIT_COMMIT/${GIT_COMMIT}/" docker/dist/README.md > "${DIST_PATH}/README.md"

if [[ "${PLATFORM}" == "Linux_amd64" ]]; then
  sed -i -e 's/^make dist$/make dist-amd64/' "${DIST_PATH}/README.md"
elif [[ "${PLATFORM}" == "Linux_arm32v7" ]]; then
  sed -i -e 's/^make dist$/make dist-arm/' "${DIST_PATH}/README.md"
elif [[ "${PLATFORM}" == "Linux_arm64v8" ]]; then
  sed -i -e 's/^make dist$/make dist-arm64/' "${DIST_PATH}/README.md"
elif [[ "${PLATFORM}" == "Windows_amd64" ]]; then
  sed -i -e 's/^make dist$/make dist-win64/' "${DIST_PATH}/README.md"
  cp -a docker/dist/README-Windows.md "${DIST_PATH}/"
elif [[ "${PLATFORM}" == "macOS_amd64" ]]; then
  sed -i -e 's/^make dist$/make dist-macos/' "${DIST_PATH}/README.md"
elif [[ "${PLATFORM}" == "macOS_arm64" ]]; then
  sed -i -e 's/^make dist$/make dist-macos-arm64/' "${DIST_PATH}/README.md"
fi

cp -a scripts/run-beacon-node.sh "${DIST_PATH}/scripts"
cp -a ./run-*-beacon-node.sh "${DIST_PATH}/"

# create the tarball
cd dist
tar czf "${DIR}.tar.gz" "${DIR}"
# don't leave the directory hanging around
rm -rf "${DIR}"
cd - >/dev/null

