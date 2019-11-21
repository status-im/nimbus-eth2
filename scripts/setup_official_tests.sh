#!/bin/bash

# Copyright (c) 2018-2019 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

set -e

SUBREPO_DIR="tests/official/fixtures"
# verbosity level
[[ -z "$V" ]] && V=0
[[ -z "$BUILD_MSG" ]] && BUILD_MSG="Downloading official test vectors"
CACHE_DIR="$1" # optional parameter pointing to a CI cache dir. Without it, we just download the LFS files for a local `make test`.

[[ -d "${SUBREPO_DIR}" ]] || { echo "This script should be run from the \"nim-beacon-chain\" repo top dir."; exit 1; }

# script output
echo -e "$BUILD_MSG"
[[ "$V" == "0" ]] && exec 3>&1 4>&2 &>/dev/null # save stdout and stderr before sending them into oblivion

#############################################
# Main()

if [[ -n "${CACHE_DIR}" ]]; then
	# Ethereum Foundation test vectors
	mkdir -p "${CACHE_DIR}/tarballs"
	rm -rf "${SUBREPO_DIR}/tarballs"
	ln -s "$(pwd -P)/${CACHE_DIR}/tarballs" "${SUBREPO_DIR}"
fi

pushd "${SUBREPO_DIR}"
./download_test_vectors.sh
popd
