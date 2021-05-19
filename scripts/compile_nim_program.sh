#!/usr/bin/env bash

set -e

cd "$(dirname "${BASH_SOURCE[0]}")"/..

BINARY="$1"
SOURCE="$2"
# the rest are NIM_PARAMS
shift 2

# verbosity level
[[ -z "$V" ]] && V=0

# According to the Nim compiler, the project name comes from the main source
# file, not the output binary.
PROJECT_NAME="$(basename ${SOURCE%.nim})"

# The default nimcache dir is "nimcache/release/${PROJECT_NAME}" which doesn't
# allow building different binaries from the same main source file, in
# parallel.
# We can't use '--nimcache:...' here, because the same path is being used by
# LTO on macOS, in "config.nims"
nim c --compileOnly -o:build/${BINARY} "$@" -d:nimCachePathOverride=nimcache/release/${BINARY} "${SOURCE}"
build/generate_makefile "nimcache/release/${BINARY}/${PROJECT_NAME}.json" "nimcache/release/${BINARY}/${BINARY}.makefile"
[[ "$V" == "0" ]] && exec &>/dev/null
"${MAKE}" -f "nimcache/release/${BINARY}/${BINARY}.makefile" --no-print-directory build

if uname | grep -qi darwin || [[ -n "${FORCE_DSYMUTIL}" ]]; then
  [[ -z "${DSYMUTIL}" ]] && DSYMUTIL="dsymutil"
  "${DSYMUTIL}" build/${BINARY}
fi
