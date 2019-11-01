#!/bin/bash

# Copyright (c) 2018-2019 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

set -e

TMP_CACHE_DIR="tmpcache"
SUBREPO_DIR="tests/official/fixtures"
# verbosity level
[[ -z "$V" ]] && V=0
[[ -z "$BUILD_MSG" ]] && BUILD_MSG="Downloading official test vectors"
CACHE_DIR="$1" # optional parameter pointing to a CI cache dir. Without it, we just download the LFS files for a local `make test`.

[[ -d "${SUBREPO_DIR}" ]] || { echo "This script should be run from the \"nim-beacon-chain\" repo top dir."; exit 1; }

# macOS quirks
if uname | grep -qi "darwin"; then
	ON_MACOS=1
	STAT_FORMAT="-f %m"
else
	ON_MACOS=0
	STAT_FORMAT="-c %Y"
fi

# to and from stdout
DECOMPRESS_XZ="false"
COMPRESS_XZ="false"
which 7z &>/dev/null && { DECOMPRESS_XZ="7z e -txz -bd -so"; COMPRESS_XZ="7z a -txz -an -bd -si -so"; }
which xz &>/dev/null && { DECOMPRESS_XZ="xz -d -c -T 0"; COMPRESS_XZ="xz -c -T 0"; }

# script output
echo -e "$BUILD_MSG"
[[ "$V" == "0" ]] && exec 3>&1 4>&2 &>/dev/null # save stdout and stderr before sending them into oblivion

#############################################
# JSON test files (SSZ v0.8.1) - TODO migrate

download_lfs_json_files() {
	[[ -z "$1" ]] && { echo "usage: download_lfs_json_files() subdir_name"; exit 1; }
	LFS_DIR="$1"

	# restore stdout and stderr to make sure this error message is shown
	which git-lfs &>/dev/null || { [[ "$V" == "0" ]] && exec 1>&3 2>&4; echo "Error: 'git-lfs' not found. Please install the corresponding package."; exit 1; }

	pushd "${SUBREPO_DIR}"
	git lfs install # redundant after running it once per repo, but fast enough not to worry about detecting whether it ran before
	git lfs pull -I "${LFS_DIR}" # we just care about test fixtures converted from YAML to JSON
	popd
}

process_json_subdir() {
	[[ -z "$1" ]] && { echo "usage: process_json_subdir subdir_name"; exit 1; }
	LFS_DIR="$1"
	ARCHIVE_NAME="${LFS_DIR}.tar.xz"

	UPDATE_CACHE=0
	if [[ -e "${CACHE_DIR}/${ARCHIVE_NAME}" ]]; then
		# compare the archive's mtime to the date of the last commit
		if [[ $(stat ${STAT_FORMAT} "${CACHE_DIR}/${ARCHIVE_NAME}") -gt $(cd "${SUBREPO_DIR}"; git log --pretty=format:%cd -n 1 --date=unix "${LFS_DIR}") ]]; then
			# the cache is valid
			echo "Copying cached json files into ${SUBREPO_DIR}/${LFS_DIR}/"
			mkdir -p "${TMP_CACHE_DIR}"
			${DECOMPRESS_XZ} "${CACHE_DIR}/${ARCHIVE_NAME}" | tar -x -C "${TMP_CACHE_DIR}" -f -
			cp -a "${TMP_CACHE_DIR}/${LFS_DIR}"/* "${SUBREPO_DIR}/${LFS_DIR}/"
			rm -rf "${TMP_CACHE_DIR}"
		else
			# old cache
			echo "Invalidating cache."
			UPDATE_CACHE=1
		fi
	else
		# creating the archive for the first time
		mkdir -p "${CACHE_DIR}"
		UPDATE_CACHE=1
	fi
	if [[ "${UPDATE_CACHE}" == "1" ]]; then
		if [[ "${ON_MACOS}" == "1" ]]; then
			HOMEBREW_NO_AUTO_UPDATE=1 brew install git-lfs # this takes almost 5 minutes on Travis, so only run it if needed
		fi
		download_lfs_json_files "$LFS_DIR"
		echo "Updating the cache."
		pushd "${SUBREPO_DIR}"
		# the archive will contain ${LFS_DIR} as its top dir
		git archive --format=tar HEAD "${LFS_DIR}" | ${COMPRESS_XZ} > "${ARCHIVE_NAME}"
		popd
		mv "${SUBREPO_DIR}/${ARCHIVE_NAME}" "${CACHE_DIR}/"
	fi
}

if [[ -n "${CACHE_DIR}" ]]; then
	process_json_subdir "json_tests_v0.8.1"
	process_json_subdir "json_tests_v0.8.3"

	# Ethereum Foundation test vectors
	mkdir -p "${CACHE_DIR}/tarballs"
	rm -rf "${SUBREPO_DIR}/tarballs"
	ln -s "$(pwd -P)/${CACHE_DIR}/tarballs" "${SUBREPO_DIR}"
else
	# no caching
	download_lfs_json_files "json_tests_v0.8.1"
	download_lfs_json_files "json_tests_v0.8.3"
fi

pushd "${SUBREPO_DIR}"
./download_test_vectors.sh
popd

