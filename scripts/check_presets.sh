#!/usr/bin/env bash
# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Checks that every spec preset matches its upstream YAML.

set -Eeuo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

tmp="$(mktemp -d "${TMPDIR:-/tmp}/check-presets.XXXXXX")"
trap 'rm -rf "${tmp}"' EXIT

nim_to_yaml() {  # $1: nim preset file
  local first
  first="$(grep -m1 -nE '^# [A-Za-z]+ preset - ' "$1" | cut -d: -f1 || true)"
  tail -n "+${first:-1}" "$1" \
    | sed '/^# https:\/\//d; s/^const$//; s/^  //' \
    | sed -E 's/^([A-Z][A-Z0-9_]*)\*.* = ([0-9]+).*$/\1: \2/'
}

yaml_expected() {  # $1: yaml file, $2: title
  printf '%s\n' "$2"
  tail -n +2 "$1"
}

capitalize() {  # $1: string
  printf '%s%s' "$(printf %s "${1:0:1}" | tr '[:lower:]' '[:upper:]')" "${1:1}"
}

status=0
compare() {  # $1: nim file, $2: title, $tmp/yaml must contain downloaded yaml
  nim_to_yaml "$1" >"${tmp}/nim"
  yaml_expected "${tmp}/yaml" "$2" >"${tmp}/expected"
  if ! git diff --no-index "${tmp}/nim" "${tmp}/expected" >"${tmp}/diff"; then
    if (( !status )); then
      echo "The following preset files do not match the specs:" >&2
    fi
    echo >&2
    echo "================================================================================" >&2
    echo "   $1" >&2
    echo "================================================================================" >&2
    tail -n +5 "${tmp}/diff" >&2
    status=1
  fi
}

SPEC_REPO="ethereum/consensus-specs"
SPEC_VERSION="$(sed -n 's/^const SPEC_VERSION\* = "\(.*\)"$/\1/p' \
  beacon_chain/spec/datatypes/base.nim)"
if [[ -z "${SPEC_VERSION}" ]]; then
  echo "Error: could not read SPEC_VERSION from base.nim" >&2
  exit 1
fi

for preset in mainnet minimal; do
  for nim in beacon_chain/spec/presets/"${preset}"/*_preset.nim; do
    fork="$(basename "${nim}" _preset.nim)"
    yaml="presets/${preset}/${fork}.yaml"
    if curl -fsSL --retry 3 "https://raw.githubusercontent.com/${SPEC_REPO}/v${SPEC_VERSION}/${yaml}" -o "${tmp}/yaml"; then
      compare "${nim}" "# $(capitalize "${preset}") preset - $(capitalize "${fork}")"
    else
      echo "Error: cannot fetch ${preset} ${fork}" >&2
      status=1
    fi
  done
done

GNOSIS_REPO="gnosischain/specs"
GNOSIS_VERSION="$(git ls-remote "https://github.com/${GNOSIS_REPO}.git" refs/heads/master | cut -f1 || true)"
if [[ -z "${GNOSIS_VERSION}" ]]; then
  echo "Error: could not resolve ${GNOSIS_REPO} master commit" >&2
  exit 1
fi

for nim in beacon_chain/spec/presets/gnosis/*_preset.nim; do
  fork="$(basename "${nim}" _preset.nim)"
  yaml="consensus/preset/gnosis/${fork}.yaml"
  if curl -fsSL --retry 3 "https://raw.githubusercontent.com/${GNOSIS_REPO}/${GNOSIS_VERSION}/${yaml}" -o "${tmp}/yaml" 2>/dev/null; then
    compare "${nim}" "# Gnosis preset - $(capitalize "${fork}")"
  else
    yaml="presets/mainnet/${fork}.yaml"
    if curl -fsSL --retry 3 "https://raw.githubusercontent.com/${SPEC_REPO}/v${SPEC_VERSION}/${yaml}" -o "${tmp}/yaml"; then
      compare "${nim}" \
        "# Mainnet preset - $(capitalize "${fork}") (Gnosis version not available yet; EF mainnet for now)"
    else
      echo "Error: cannot fetch gnosis ${fork}" >&2
      status=1
    fi
  fi
done

exit "${status}"
