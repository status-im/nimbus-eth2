#!/usr/bin/env bash

# Copyright (c) 2020-2026 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

set -Eeo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"/..

BINARY="$1"
SOURCE="$2"
# the rest are NIM_PARAMS
shift 2

NIMC="${NIMC:-nim}"

# verbosity level
[[ -z "$V" ]] && V=0

PROJECT_NAME="$(basename "${BINARY%.nim}")"

# The default nimcache dir is "nimcache/release/${PROJECT_NAME}" which doesn't
# allow building different binaries from the same main source file, in
# parallel.
# We can't use '--nimcache:...' here, because the same path is being used by
# LTO on macOS, in "config.nims"
# We have to use the `-f` flag here because running nim compile with
# different -d defines (as we do when for mainnet/minimal in CI) does
# not lead to a rebuild of changed deps - nim uses the cached
# version. The specific instance here is `-d:FIELD_ELEMENTS_PER_BLOB`
# that is used in the nim-kzg library and its dependency.
# TODO find a way not to have to -f here.
"$NIMC" c -f --compileOnly -o:build/"${BINARY}" "$@" -d:nimCachePathOverride=nimcache/release/"${BINARY}" "${SOURCE}"
build/generate_makefile "nimcache/release/${BINARY}/${PROJECT_NAME}.json" "nimcache/release/${BINARY}/${BINARY}.makefile"
# Don't swallow stderr, in case it's important.
[[ "$V" == "0" ]] && exec >/dev/null
"${MAKE}" -f "nimcache/release/${BINARY}/${BINARY}.makefile" --no-print-directory build

if uname | grep -qi darwin || [[ -n "${FORCE_DSYMUTIL}" ]]; then
  [[ -z "${DSYMUTIL}" ]] && DSYMUTIL="dsymutil"
  # Scary warnings in large volume: https://github.com/status-im/nimbus-eth2/issues/3076
  "${DSYMUTIL}" build/"${BINARY}" 2>&1 \
    | grep -v "failed to insert symbol" \
    | grep -v "could not find object file symbol for symbol" \
    || true
fi
