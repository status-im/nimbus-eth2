#!/usr/bin/env bash
# Build the `nimbus-eth2/pq-devnet-0` image (override with PQ_IMAGE) for the PQ devnet:
# the host-built beacon node plus a leanVM sidecar built from the pinned
# commit. Run `make nimbus_beacon_node` first.
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
if [[ ! -x "$repo/build/nimbus_beacon_node" ]]; then
  echo "build/nimbus_beacon_node is missing: run 'make nimbus_beacon_node'" >&2
  exit 1
fi
docker build -f "$repo/docker/pq-devnet/Dockerfile" \
  -t "${PQ_IMAGE:-nimbus-eth2/pq-devnet-0}" "$@" "$repo"
