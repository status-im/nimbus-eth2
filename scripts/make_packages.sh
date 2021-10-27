#!/bin/bash

# Copyright (c) 2020-2021 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

cd "$(dirname $0)"

PKG_NAME=nimbus_beacon_node
PKG_ARCH=amd64
PKG_IMG_DIR=package_image

NBC_BIN=../build/nimbus_beacon_node
NSP_BIN=../build/nimbus_signing_process

if [ ! -f $NBC_BIN -o ! -f $NSP_BIN ]; then
  printf "Please build nimbus_beacon_node and nimbus_signing_process\n"
  printf "This script needs to be run from the scripts folder\n"

  exit 1
fi

PKG_VERSION=$(./$NBC_BIN --version | awk -F[-v] 'NR==1{print $2}')

if [ -z $1 ]; then
  printf "Please provide a Package Architecture!\n"
  exit 1
else
  PKG_ARCH=$1
  if [ $PKG_ARCH != "amd64" -a $PKG_ARCH != "arm64" -a $PKG_ARCH != "arm" ]; then
    printf "Package Architecture options:\n-amd64\n-arm64\n-arm\n"
    exit 1
  fi
fi

if ! command -v fpm &> /dev/null;then
  printf "Please install FPM! \nhttps://fpm.readthedocs.io/en/latest/installing.html\n"
  exit 1
fi

mkdir -p $PKG_IMG_DIR/var/lib/nimbus
mkdir -p $PKG_IMG_DIR/usr/bin

cp $NBC_BIN $PKG_IMG_DIR/usr/bin
cp $NSP_BIN $PKG_IMG_DIR/usr/bin

fpm -s dir -t deb -n $PKG_NAME \
   --deb-no-default-config-files \
  -v $PKG_VERSION \
  -C $PKG_IMG_DIR \
  -p ${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.deb \
  --after-install $PKG_IMG_DIR/postinst \
  --before-remove $PKG_IMG_DIR/prerm \
  --after-remove $PKG_IMG_DIR/postrm \
  --license "Apache 2.0 + MIT" \
  --maintainer "The Nimbus Team" \
  --description "Nimbus Beacon Chain / Ethereum Consensus client" \
  --url "https://nimbus.team/"

fpm -s dir -t rpm -n $PKG_NAME \
    -v $PKG_VERSION \
    -C $PKG_IMG_DIR \
    -p ${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.rpm \
    --after-install $PKG_IMG_DIR/postinst \
    --before-remove $PKG_IMG_DIR/prerm \
    --after-remove $PKG_IMG_DIR/postrm \
    --license "Apache 2.0 + MIT" \
    --maintainer "The Nimbus Team" \
    --description "Nimbus Beacon Chain / Ethereum Consensus client" \
    --url "https://nimbus.team/"

# clean up to avoid committing binaries to the repository
rm -rf $PKG_IMG_DIR/usr/bin/

exit 0
