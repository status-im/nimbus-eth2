#!/usr/bin/env bash
set -Eeuo pipefail

PREV_VERSION=${1}
NEXT_VERSION=${2}
NIMBUS_SOURCE_DIR=${3}

TMPDIR1=$(mktemp -d)
TMPDIR2=$(mktemp -d)
REPO_URL=https://github.com/ethereum/consensus-specs.git
VALID=".*\\.\\(md\\|py\\)"
UNCHANGED_SPEC_FILES=$(comm -12 --check-order <(git clone --branch "${PREV_VERSION}" --config advice.detachedHead=false --depth 1 --quiet "${REPO_URL}" "${TMPDIR1}" && cd "${TMPDIR1}" && find . -type f -regex "${VALID}" -print0 | xargs -0 sha256sum | sort) <(git clone --branch "${NEXT_VERSION}" --config advice.detachedHead=false --depth 1 --quiet "${REPO_URL}" "${TMPDIR2}" && cd "${TMPDIR2}" && find . -type f -regex "${VALID}" -print0 | xargs -0 sha256sum | sort) | awk '{print $2}' | sed -e"s/^\.\///" | shuf)

# One can use this to automate the search andreplace with a tool such as
# https://github.com/kcoyner/rpl/ or just a find/sed combination, e.g.,:
URL_BASE=https://github.com/ethereum/consensus-specs/blob/
FROM=${URL_BASE}${PREV_VERSION}/
TO=${URL_BASE}${NEXT_VERSION}/
echo "${UNCHANGED_SPEC_FILES}" | xargs -I{} printf "echo Replacing {}\nrpl --quiet --recursive -x.nim -x.md ${FROM}{} ${TO}{} ${NIMBUS_SOURCE_DIR} 2>/dev/null\n"

# rpl's --quiet option does seem broken though.
