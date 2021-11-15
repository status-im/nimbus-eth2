#!/usr/bin/env bash

# Copyright (c) 2018-2019 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

set -e

SUBREPO_DIR="vendor/nim-eth2-scenarios"
# verbosity level
[[ -z "$V" ]] && V=0
[[ -z "$BUILD_MSG" ]] && BUILD_MSG="Downloading consensus spec test vectors"
CACHE_DIR="$1" # optional parameter pointing to a CI cache dir. Without it, we just download the test vectors for a local `make test`.

[[ -d "${SUBREPO_DIR}" ]] || { echo "This script should be run from the \"nimbus-eth2\" repo top dir."; exit 1; }

# script output
echo -e "$BUILD_MSG"
[[ "$V" == "0" ]] && exec 3>&1 4>&2 &>/dev/null # save stdout and stderr before sending them into oblivion

#############################################
# Main()

if [[ -n "${CACHE_DIR}" ]]; then
	# delete old cache entries we no longer use (let this run for a month or so)
	rm -f "${CACHE_DIR}"/*.tar.xz

	# Ethereum Foundation test vectors
	mkdir -p "${CACHE_DIR}/tarballs"
	rm -rf "${SUBREPO_DIR}/tarballs"
	ln -s "$(pwd -P)/${CACHE_DIR}/tarballs" "${SUBREPO_DIR}"
	# (the dir symlink above also takes care of updating the cache)
fi

pushd "${SUBREPO_DIR}"
./download_test_vectors.sh
./download_slashing_interchange_tests.sh
popd
