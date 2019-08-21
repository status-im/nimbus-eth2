#!/bin/bash

# Copyright (c) 2018-2019 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

set -e

SUBREPO_DIR="vendor/go/src/github.com/libp2p/go-libp2p-daemon"
CACHE_DIR="$1" # optional parameter pointing to a CI cache dir.

## env vars
# verbosity level
[[ -z "$V" ]] && V=0
[[ -z "$BUILD_MSG" ]] && BUILD_MSG="Building p2pd"

# Windows detection
if uname | grep -qiE "mingw|msys"; then
	EXE_SUFFIX=".exe"
else
	EXE_SUFFIX=""
fi

# macOS
if uname | grep -qi "darwin"; then
	STAT_FORMAT="-f %m"
else
	STAT_FORMAT="-c %Y"
fi

TARGET_DIR="vendor/go/bin"
TARGET_BINARY="${TARGET_DIR}/p2pd${EXE_SUFFIX}"

target_needs_rebuilding() {
	REBUILD=0
	NO_REBUILD=1

	if [[ -n "$CACHE_DIR" && -e "${CACHE_DIR}/p2pd${EXE_SUFFIX}" ]]; then
		mkdir -p "${TARGET_DIR}"
		cp -a "$CACHE_DIR"/* "${TARGET_DIR}/"
	fi

	# compare binary mtime to the date of the last commit (keep in mind that Git doesn't preserve file timestamps)
	if [[ -e "$TARGET_BINARY" && $(stat $STAT_FORMAT "$TARGET_BINARY") -gt $(cd "$SUBREPO_DIR"; git log --pretty=format:%cd -n 1 --date=unix) ]]; then
		return $NO_REBUILD
	else
		return $REBUILD
	fi
}

build_target() {
	echo -e "$BUILD_MSG"
	[[ "$V" == "0" ]] && exec &>/dev/null

	pushd "$SUBREPO_DIR"
	go get ./...
	go install ./...
	popd

	# update the CI cache
	if [[ -n "$CACHE_DIR" ]]; then
		rm -rf "$CACHE_DIR"
		mkdir "$CACHE_DIR"
		cp -a "$TARGET_DIR"/* "$CACHE_DIR"/
	fi
}

if target_needs_rebuilding; then
	build_target
fi

