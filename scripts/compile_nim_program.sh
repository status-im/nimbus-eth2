#!/usr/bin/env bash

set -e

cd "$(dirname "${BASH_SOURCE[0]}")"/..

BINARY="$1"
SOURCE="$2"
# the rest are NIM_PARAMS
shift 2

# verbosity level
[[ -z "$V" ]] && V=0

# Nim version (formatted as "{MAJOR}{MINOR}").
# This weird "sed" invocation is because of macOS.
NIM_VERSION=$(nim --version | head -n1 | sed -E 's/^.* ([0-9])\.([0-9]+).*$/\1\2/')

# According to old Nim compiler versions, the project name comes from the main
# source file, not the output binary.
if [[ "${NIM_VERSION}" -ge "16" ]]; then
  PROJECT_NAME="$(basename ${BINARY%.nim})"
else
  PROJECT_NAME="$(basename ${SOURCE%.nim})"
fi

# The default nimcache dir is "nimcache/release/${PROJECT_NAME}" which doesn't
# allow building different binaries from the same main source file, in
# parallel.
# We can't use '--nimcache:...' here, because the same path is being used by
# LTO on macOS, in "config.nims"
nim c --compileOnly -o:build/${BINARY} "$@" -d:nimCachePathOverride=nimcache/release/${BINARY} "${SOURCE}"
build/generate_makefile "nimcache/release/${BINARY}/${PROJECT_NAME}.json" "nimcache/release/${BINARY}/${BINARY}.makefile"
# Don't swallow stderr, in case it's important.
[[ "$V" == "0" ]] && exec >/dev/null
"${MAKE}" -f "nimcache/release/${BINARY}/${BINARY}.makefile" --no-print-directory build

if uname | grep -qi darwin || [[ -n "${FORCE_DSYMUTIL}" ]]; then
  [[ -z "${DSYMUTIL}" ]] && DSYMUTIL="dsymutil"
  # Scary warnings in large volume: https://github.com/status-im/nimbus-eth2/issues/3076
  "${DSYMUTIL}" build/${BINARY} 2>&1 \
    | grep -v "failed to insert symbol" \
    | grep -v "could not find object file symbol for symbol" \
    || true
fi
