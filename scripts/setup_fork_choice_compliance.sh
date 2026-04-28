#!/usr/bin/env bash

# Copyright (c) 2026 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.
#
# Fetches the fork-choice compliance test artifact produced by
# https://github.com/ethereum/consensus-specs/blob/master/.github/workflows
# (uploaded as small.tar.gz) and extracts it into the existing
# nim-eth2-scenarios test-vectors tree, so that test_fixture_fork_choice's
# ForkChoiceCompliance suite can pick it up.
#
# Usage:
#   scripts/setup_fork_choice_compliance.sh                 # latest run on master
#   scripts/setup_fork_choice_compliance.sh --run-id 24754336017
#   scripts/setup_fork_choice_compliance.sh --tarball path/to/small.tar.gz
#   scripts/setup_fork_choice_compliance.sh --url https://.../small.tar.gz
#
# Honours $GH_TOKEN / $GITHUB_TOKEN; otherwise uses the gh CLI.

set -euo pipefail

REPO="ethereum/consensus-specs"
ARTIFACT_NAME="small.tar.gz"
WORKFLOW_FILE="comptests.yml"

RUN_ID=""
TARBALL=""
URL=""
KEEP_TARBALL=0

usage() {
  sed -n '2,20p' "$0"
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id) RUN_ID="$2"; shift 2 ;;
    --tarball) TARBALL="$2"; shift 2 ;;
    --url) URL="$2"; shift 2 ;;
    --keep-tarball) KEEP_TARBALL=1; shift ;;
    -h|--help) usage 0 ;;
    *) echo "Unknown argument: $1" >&2; usage 1 ;;
  esac
done

if [[ ! -d vendor/nim-eth2-scenarios ]]; then
  echo "Run from the nimbus-eth2 repo top dir (vendor/nim-eth2-scenarios missing)." >&2
  exit 1
fi

# Resolve SPEC_VERSION from beacon_chain/spec/datatypes/base.nim
SPEC_VERSION="$(awk -F'"' '/SPEC_VERSION\* =/ {print $2; exit}' beacon_chain/spec/datatypes/base.nim)"
if [[ -z "${SPEC_VERSION}" ]]; then
  echo "Unable to read SPEC_VERSION from beacon_chain/spec/datatypes/base.nim" >&2
  exit 1
fi

DEST_DIR="vendor/nim-eth2-scenarios/tests-v${SPEC_VERSION}"
mkdir -p "${DEST_DIR}"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

LOCAL_TARBALL=""

if [[ -n "${TARBALL}" ]]; then
  LOCAL_TARBALL="${TARBALL}"
elif [[ -n "${URL}" ]]; then
  echo "Fetching ${URL}"
  LOCAL_TARBALL="${WORK_DIR}/small.tar.gz"
  curl -sSL -o "${LOCAL_TARBALL}" "${URL}"
else
  if ! command -v gh >/dev/null; then
    echo "gh CLI is required (or pass --tarball / --url). Install: https://cli.github.com/" >&2
    exit 1
  fi
  if [[ -z "${RUN_ID}" ]]; then
    echo "Looking up latest successful run of ${WORKFLOW_FILE} on ${REPO}..."
    RUN_ID="$(gh run list --repo "${REPO}" --workflow "${WORKFLOW_FILE}" \
      --branch master --status success --limit 1 --json databaseId \
      --jq '.[0].databaseId' 2>/dev/null || true)"
    if [[ -z "${RUN_ID}" ]]; then
      echo "Could not resolve a workflow run id. Pass --run-id <id> explicitly." >&2
      exit 1
    fi
  fi
  echo "Resolving artifact for run ${RUN_ID}..."
  ARTIFACT_ID="$(gh api "repos/${REPO}/actions/runs/${RUN_ID}/artifacts" \
    --jq ".artifacts[] | select(.name==\"${ARTIFACT_NAME}\") | .id")"
  if [[ -z "${ARTIFACT_ID}" ]]; then
    echo "No artifact named ${ARTIFACT_NAME} on run ${RUN_ID}" >&2
    exit 1
  fi
  LOCAL_TARBALL="${WORK_DIR}/small.tar.gz"
  echo "Downloading artifact ${ARTIFACT_ID} -> ${LOCAL_TARBALL}"
  # `gh api` refuses non-JSON Accept headers and `gh run download` tries to
  # unzip the tarball. Hit the artifacts endpoint with curl, following the
  # redirect to the signed URL that returns the raw gzip bytes.
  TOKEN="$(gh auth token)"
  curl -sSL -H "Authorization: Bearer ${TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    -o "${LOCAL_TARBALL}" \
    "https://api.github.com/repos/${REPO}/actions/artifacts/${ARTIFACT_ID}/zip"
fi

# Sanity check: the artifact should be a gzip
if ! gzip -t "${LOCAL_TARBALL}" 2>/dev/null; then
  echo "Downloaded file is not a valid gzip: ${LOCAL_TARBALL}" >&2
  exit 1
fi

# The tarball lays out as `tests/<preset>/<fork>/fork_choice_compliance/...`.
# Strip the leading `tests/` so it merges into tests-v$SPEC_VERSION/<preset>/...
echo "Extracting into ${DEST_DIR}..."
tar -xzf "${LOCAL_TARBALL}" --strip-components=1 -C "${DEST_DIR}"

if [[ "${KEEP_TARBALL}" -eq 1 && -z "${TARBALL}" ]]; then
  cp "${LOCAL_TARBALL}" "vendor/nim-eth2-scenarios/${ARTIFACT_NAME}"
  echo "Tarball preserved at vendor/nim-eth2-scenarios/${ARTIFACT_NAME}"
fi

# Quick summary of what landed
COUNT="$(find "${DEST_DIR}" -mindepth 6 -maxdepth 6 -type d \
  -path '*/fork_choice_compliance/*/pyspec_tests/*' 2>/dev/null | wc -l | tr -d ' ')"
echo "Installed ${COUNT} fork-choice compliance test cases under ${DEST_DIR}"
