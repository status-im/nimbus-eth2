#!/bin/bash

set -e


git clone https://github.com/tpoechtrager/osxcross.git

# macOS SDK
cd osxcross/tarballs
MACOS_SDK_VER="11.3"
MACOS_SDK_TARBALL="MacOSX${MACOS_SDK_VER}.sdk.tar.xz"
curl -OLsS https://github.com/phracker/MacOSX-SDKs/releases/download/${MACOS_SDK_VER}/${MACOS_SDK_TARBALL}
cd ..

# build OSXCross toolchain
export TARGET_DIR="/opt/osxcross"
UNATTENDED=1 ./build.sh
# "tools/osxcross_conf.sh" ignores TARGET_DIR and uses "target" instead, so do a symlink
ln -s ${TARGET_DIR} target
./build_llvm_dsymutil.sh
# ridiculous amount of uncompressed man pages
rm -rf ${TARGET_DIR}/SDK/MacOSX${MACOS_SDK_VER}.sdk/usr/share

# cleanup
cd ..
rm -rf osxcross

