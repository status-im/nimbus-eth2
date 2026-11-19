#!/usr/bin/env bash
# Build the `nimbus-pq:dev` image for the PQ devnet from locally built
# binaries.
#
#   make -j nimbus_beacon_node
#   docker/pq-devnet/build-image.sh /path/to/leanVM/target/release/leanvm-sidecar
#
# The sidecar is built from leanVM@283686575c4e81790591d2c6e3ed21c69c0e3bbe:
#   cargo build --release -p leanvm-sidecar --features experimental_prover
set -euo pipefail

sidecar=${1:?usage: build-image.sh <path to leanvm-sidecar>}
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo=$(cd -- "$here/../.." && pwd -P)
context=$(mktemp -d)
trap 'rm -rf "$context"' EXIT

cp "$repo/build/nimbus_beacon_node" "$context/nimbus_beacon_node"
cp "$sidecar" "$context/leanvm-sidecar"
cp "$here/Dockerfile" "$here/nimbus-pq-bn.sh" "$context/"
docker build -t "${PQ_IMAGE:-nimbus-pq:dev}" "$context"
