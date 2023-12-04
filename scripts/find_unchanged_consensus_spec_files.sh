#!/usr/bin/env bash
# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

set -Eeuo pipefail

PREV_VERSION=${1}
NEXT_VERSION=${2}
NIMBUS_SOURCE_DIR=${3}

TMPDIR1=$(mktemp -d)
TMPDIR2=$(mktemp -d)
REPO_URL=https://github.com/ethereum/consensus-specs.git
VALID=".*\\.\\(md\\|py\\|yaml\\|sol\\)"
UNCHANGED_SPEC_FILES=$(comm -12 --check-order <(git clone --branch "${PREV_VERSION}" --config advice.detachedHead=false --depth 1 --quiet "${REPO_URL}" "${TMPDIR1}" && cd "${TMPDIR1}" && find . -type f -regex "${VALID}" -print0 | xargs -0 sha256sum | sort) <(git clone --branch "${NEXT_VERSION}" --config advice.detachedHead=false --depth 1 --quiet "${REPO_URL}" "${TMPDIR2}" && cd "${TMPDIR2}" && find . -type f -regex "${VALID}" -print0 | xargs -0 sha256sum | sort) | awk '{print $2}' | sed -e"s/^\.\///" | shuf)

# One can use this to automate the search and replace with a tool such as
# https://github.com/kcoyner/rpl/, or just a find/sed combination, e.g.,:
URL_BASE=https://github.com/ethereum/consensus-specs/blob/
FROM=${URL_BASE}${PREV_VERSION}/
TO=${URL_BASE}${NEXT_VERSION}/
echo "${UNCHANGED_SPEC_FILES}" | xargs -I{} printf "echo Replacing {}\nrpl --quiet --recursive -x.nim -x.md -x.c -x.h ${FROM}{} ${TO}{} ${NIMBUS_SOURCE_DIR} 2>/dev/null\n"

# rpl's --quiet option does seem broken though.
