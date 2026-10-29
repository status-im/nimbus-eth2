#!/usr/bin/env bash
# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Checks that every flake.lock input that mirrors a submodule is locked to the
# same commit as that submodule.

set -Eeuo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

INPUTS=(  # <flake input>=<submodule path>
  nimbusBuildSystem=vendor/nimbus-build-system
)

status=0
for entry in "${INPUTS[@]}"; do
  input="${entry%%=*}"
  path="${entry#*=}"
  locked="$(jq -r --arg input "${input}" '.nodes[$input].locked.rev // empty' flake.lock)"
  pinned="$(git rev-parse "HEAD:${path}")"
  if [[ "${locked}" != "${pinned}" ]]; then
    if (( !status )); then
      echo "The following flake.lock inputs do not match their submodules:" >&2
    fi
    echo "- ${input}: locked at ${locked:-<none>}, ${path} at ${pinned}" >&2
    echo "  Run: nix flake update ${input}" >&2
    status=1
  fi
done

exit "${status}"
