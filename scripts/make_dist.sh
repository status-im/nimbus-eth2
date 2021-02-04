#!/bin/bash

# Copyright (c) 2020-2021 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

# Build release binaries fit for public distribution, using Docker and Qemu.
# Should be used from "dist-*" Make targets, passing the target architecture's name as a parameter.

set -e

cd "$(dirname "${BASH_SOURCE[0]}")"/..
CURDIR="${PWD}"

ARCH="${1:-amd64}"
if [[ "${ARCH}" == "amd64" || "${ARCH}" == "win64" ]]; then
  USE_QEMU=0
else
  USE_QEMU=1
  if [[ "${ARCH}" == "arm64" ]]; then
    BINFMT_NAME="aarch64"
  elif [[ "${ARCH}" == "arm" ]]; then
    BINFMT_NAME="arm"
  fi
fi
DOCKER_TAG="nimbus-eth2-dist-${ARCH}"

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

docker rm ${DOCKER_TAG} &>/dev/null || true

cd docker/dist

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

docker run --rm --name ${DOCKER_TAG} -v ${CURDIR}:/home/user/nimbus-eth2 ${DOCKER_TAG}

if [[ "${USE_QEMU}" == "1" ]]; then
  rm "${QEMU_NAME}"
fi

cd - &>/dev/null

ls -l dist

# We rebuild everything inside the container, so we need to clean up afterwards.
${MAKE} --no-print-directory clean

