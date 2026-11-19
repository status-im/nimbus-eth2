#!/usr/bin/env bash
# Launch the single-client Nimbus PQ devnet in Kurtosis: the pinned PQ
# ethereum-package with network.yaml. Requires Git, Kurtosis, Docker and the
# `nimbus-pq:dev` image from build-image.sh. Extra arguments go to
# `kurtosis run`.
#
# The package uses `plan.get_cluster_type()` and `GpuConfig`, which the
# Kurtosis 2.1.0 packaged at apt.fury.io/kurtosis-tech does not have.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
package_revision=580ca2ff182eb23145039483e58eccca7f59ac5f
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/nimbus-pq-kurtosis.XXXXXX")
run_dir=$(cd -- "$run_dir" && pwd -P)
package_dir="$run_dir/ethereum-package"

git init --quiet "$package_dir"
git -C "$package_dir" remote add origin \
  https://github.com/ethpandaops/ethereum-package.git
git -C "$package_dir" fetch --quiet --depth 1 origin "$package_revision"
git -C "$package_dir" checkout --quiet --detach "$package_revision"

exec kurtosis run \
  --enclave "${PQ_ENCLAVE:-nimbus-pq}" \
  --image-download missing \
  --args-file "$here/network.yaml" \
  "$@" "$package_dir"
