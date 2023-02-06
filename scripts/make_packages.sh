#!/bin/bash

# Copyright (c) 2020-2021 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

set -e

####################
# argument parsing #
####################

GETOPT_BINARY="getopt"
if uname | grep -qi darwin; then
  # macOS
  GETOPT_BINARY=$(find /opt/homebrew/opt/gnu-getopt/bin/getopt /usr/local/opt/gnu-getopt/bin/getopt 2> /dev/null || true)
  [[ -f "$GETOPT_BINARY" ]] || { echo "GNU getopt not installed. Please run 'brew install gnu-getopt'. Aborting."; exit 1; }
fi

! ${GETOPT_BINARY} --test > /dev/null
if [ ${PIPESTATUS[0]} != 4 ]; then
  echo '`getopt --test` failed in this environment.'
  exit 1
fi

OPTS="hb:t:"
LONGOPTS="help,binary:,tarball:,install-fpm"

# default values
BINARY=""
TARBALL=""
PKG_ARCH=""

print_help() {
  cat <<EOF
Usage: $(basename "$0") --tarball dist/nimbus-eth2_Linux_amd64_1.5.4_382be3fd.tar.gz

  -h, --help                  this help message
  -b, --binary                which binary to package (nimbus_beacon_node, nimbus_validator_client, ...)
  -t, --tarball               tarball produced by "make dist-..."
  --install-fpm               install the appropriate fpm version with "gem'
EOF
}

! PARSED=$(${GETOPT_BINARY} --options=${OPTS} --longoptions=${LONGOPTS} --name "$0" -- "$@")
if [ ${PIPESTATUS[0]} != 0 ]; then
  # getopt has complained about wrong arguments to stdout
  exit 1
fi

# read getopt's output this way to handle the quoting right
eval set -- "$PARSED"
while true; do
  case "$1" in
    -h|--help)
      print_help
      exit
      ;;
    -b|--binary)
      BINARY="$2"
      shift 2
      ;;
    -t|--tarball)
      TARBALL="$2"
      shift 2
      ;;
    --install-fpm)
      INSTALL_FPM="1"
      shift 1
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "argument parsing error"
      print_help
      exit 1
  esac
done

case "${TARBALL}" in
  *_Linux_amd64_*)
    PKG_ARCH_DEB="amd64"
    PKG_ARCH_RPM="x86_64"
    ;;
  *_Linux_arm32v7_*)
    PKG_ARCH_DEB="armhf"
    PKG_ARCH_RPM="armv7hl"
    ;;
  *_Linux_arm64v8_*)
    PKG_ARCH_DEB="arm64"
    PKG_ARCH_RPM="aarch64"
    ;;
  *)
    echo "unsupported tarball type"
    exit 1
    ;;
esac

SCRIPT_DIR="$(dirname "${BASH_SOURCE[0]}")"
PKG_NAME="$(echo ${BINARY} | tr '_' '-')"
PKG_IMG_DIR="${SCRIPT_DIR}/package_image/${BINARY}"
PKG_SRC_DIR="${SCRIPT_DIR}/package_src/${BINARY}"
PKG_VERSION="$(echo "${TARBALL}" | sed 's/^.*_\([^_]\+\)_[^_]\+$/\1/')"
TARBALL_TOP_DIR="$(echo "${TARBALL}" | sed 's#^.*/\([^/]\+\)\.tar\.gz$#\1#')"
PKG_PATH_DEB="${SCRIPT_DIR}/../dist/${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH_DEB}.deb"
PKG_PATH_RPM="${SCRIPT_DIR}/../dist/${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH_RPM}.rpm"

[ -d $PKG_SRC_DIR ] || { echo Unsupported binary "${BINARY}"; exit 1; }

FPM_VERSION=1.14.2
if [[ "$(fpm -v)" != "$FPM_VERSION" ]] ; then
  if [[ "$INSTALL_FPM" == "1" ]] ; then
    gem install fpm -v $FPM_VERSION
  else
    cat << EOF
Please install FPM $FPM_VERSION (https://fpm.readthedocs.io/en/latest/installation.html):

gem install fpm -v $FPM_VERSION
EOF
    exit 1
  fi
fi

rm -rf  "${PKG_IMG_DIR}"
BIN_DIR="${PKG_IMG_DIR}/usr/bin"
rm -rf "${BIN_DIR}"
mkdir -p "${BIN_DIR}"
tar -xzf "${TARBALL}" --strip-components 2 -C "${BIN_DIR}" "${TARBALL_TOP_DIR}/build/${BINARY}"
cp -ar ${PKG_SRC_DIR}/image/* ${PKG_IMG_DIR}

# delete existing packages
rm -f "${PKG_PATH_DEB}" "${PKG_PATH_RPM}"

fpm -s dir -t deb -n "${PKG_NAME}" \
  --deb-no-default-config-files \
  -v "${PKG_VERSION}" \
  -C "${PKG_IMG_DIR}" \
  -p "${PKG_PATH_DEB}" \
  -a "${PKG_ARCH_DEB}" \
  --after-install "${PKG_SRC_DIR}/after_install" \
  --before-remove "${PKG_SRC_DIR}/before_remove" \
  --after-remove "${PKG_SRC_DIR}/after_remove" \
  --after-upgrade "${PKG_SRC_DIR}/after_upgrade" \
  --deb-after-purge "${PKG_SRC_DIR}/deb_after_purge" \
  --license "Apache 2.0 + MIT" \
  --maintainer "The Nimbus Team" \
  --description "$(cat ${PKG_SRC_DIR}/description)" \
  --url "https://nimbus.team/" \
  2>/dev/null

fpm -s dir -t rpm -n "${PKG_NAME}" \
  -v "${PKG_VERSION}" \
  -C "${PKG_IMG_DIR}" \
  -p "${PKG_PATH_RPM}" \
  -a "${PKG_ARCH_RPM}" \
  --after-install "${PKG_SRC_DIR}/after_install" \
  --before-remove "${PKG_SRC_DIR}/before_remove" \
  --after-remove "${PKG_SRC_DIR}/after_remove" \
  --after-upgrade "${PKG_SRC_DIR}/after_upgrade" \
  --license "Apache 2.0 + MIT" \
  --maintainer "The Nimbus Team" \
  --description "$(cat ${PKG_SRC_DIR}/description)" \
  --url "https://nimbus.team/" \
  2>/dev/null

ls -l "${PKG_PATH_DEB}" "${PKG_PATH_RPM}"
