#!/bin/bash

# Copyright (c) 2020 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

# Build base Docker images for making distributable binaries, using Qemu for
# foreign architectures.
# Should be used from "build-*" Make targets, passing the target architecture's
# name and Docker image tag as parameters.

set -e

cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ -z "${2}" ]]; then
  echo "Usage: $(basename ${0}) ARCH DOCKER_TAG"
  exit 1
fi
ARCH="${1}"
DOCKER_TAG="${2}"

if [[ "${ARCH}" == "amd64" ]]; then
  USE_QEMU=0
else
  USE_QEMU=1
  if [[ "${ARCH}" == "arm64" ]]; then
    BINFMT_NAME="aarch64"
  elif [[ "${ARCH}" == "arm" ]]; then
    BINFMT_NAME="arm"
  fi
fi

DOCKER_EXTRA_ARGS=""
if [[ "${USE_QEMU}" == "1" ]]; then
  # We need qemu-user-static installed and registered in binfmt_misc, on the host
  # (`apt install qemu binfmt-support qemu-user-static` should do the trick on Debian-based distros).
  # The actual binary name varies from one distro to another and we need a copy inside the container.

  if [[ ! -f /proc/sys/fs/binfmt_misc/qemu-${BINFMT_NAME} ]]; then
    echo "binfmt_misc not set up properly. Aborting."
    echo "You may have to run 'apt install qemu binfmt-support qemu-user-static' on a Debian-based distro."
    exit 1
  fi

  QEMU_PATH="$(grep '^interpreter' /proc/sys/fs/binfmt_misc/qemu-${BINFMT_NAME} | cut -d ' ' -f 2)"
  QEMU_NAME="$(basename ${QEMU_PATH})"
  QEMU_DIR="$(dirname ${QEMU_PATH})"
  DOCKER_EXTRA_ARGS="\
    --build-arg QEMU_NAME=${QEMU_NAME} \
    --build-arg QEMU_DIR=${QEMU_DIR} \
  "
fi

if [[ "${USE_QEMU}" == "1" ]]; then
  cp -a "${QEMU_PATH}" .
fi

DOCKER_BUILDKIT=1 \
  docker build \
  -t ${DOCKER_TAG} \
  --progress=plain \
  --build-arg USER_ID=$(id -u) \
  --build-arg GROUP_ID=$(id -g) \
  ${DOCKER_EXTRA_ARGS} \
  -f Dockerfile.${ARCH} .

if [[ "${USE_QEMU}" == "1" ]]; then
  rm "${QEMU_NAME}"
fi

