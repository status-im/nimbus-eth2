#!/bin/bash

# Simple build script to produce an Emscripten-based wasm version of the state
# sim.
# Assumes you have emcc latest-upstream in you PATH, per their install
# instructions (https://emscripten.org/docs/getting_started/downloads.html)
#
# git clone https://github.com/emscripten-core/emsdk.git
# cd emsdk
# git pull
# ./emsdk install latest-upstream
# ./emsdk activate latest-upstream
# source ./emsdk_env.sh

# Clean build every time - we use wildcards below so this keeps it simple
rm -rf ncli/nimcache

# GC + emcc optimizer leads to crashes - for now, we disable the GC here
../env.sh nim c \
  --cpu:i386 --os:linux --gc:none --threads:off \
  -d:release -d:clang -d:emscripten -d:noSignalHandler -d:usemalloc \
  --nimcache:ncli/nimcache -d:"network_type=none" \
  -u:metrics \
  -c ncli

../env.sh emcc \
  -I ../vendor/nimbus-build-system/vendor/Nim/lib \
  ncli/nimcache/*.c \
  ../vendor/nim-blscurve/blscurve/csources/32/{big_384_29.c,ecp2_BLS381.c,rom_curve_BLS381.c,ecp_BLS381.c,fp2_BLS381.c,fp_BLS381.c,rom_field_BLS381.c,pair_BLS381.c,fp12_BLS381.c,fp4_BLS381.c} \
  -s ERROR_ON_UNDEFINED_SYMBOLS=0 \
  -s TOTAL_MEMORY=1073741824 \
  -s EXTRA_EXPORTED_RUNTIME_METHODS=FS \
  -s WASM=1 \
  --shell-file ncli_shell.html \
  -O3 \
  -o ncli/ncli.html
