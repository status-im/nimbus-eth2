# PQ devnet image and Kurtosis network

Tooling for the PQ (post-quantum) devnet prototype, consensus-specs
`2f43bc0f989f47af81df390a90bc1f78e2436323`.

- `Dockerfile`, `nimbus-pq-bn.sh`: an image with the beacon node and the
  leanVM sidecar that proves and verifies PQ signature aggregates. The
  sidecar is built in the image from the pinned leanVM commit; the beacon
  node is the host build. The wrapper sits at the path the ethereum-package
  launches, supervises `leanvm-sidecar` and passes `--pq-sidecar-socket` to
  the node.
- `build-image.sh`: builds `nimbus-eth2/pq-devnet-0`. Run `make nimbus_beacon_node`
  first, then either the script or, from the repository root,
  `docker build -f docker/pq-devnet/Dockerfile -t nimbus-eth2/pq-devnet-0 .`.
  The host build targets the host CPU (`-march=native`); build the node with
  `NIMFLAGS="-d:disableMarchNative"` for an image to run elsewhere.
- `network.yaml`, `launch.sh`: a single-client devnet (geth, 2 x 32
  validators inside the beacon nodes, mainnet preset, PQ at genesis, Heze
  disabled) on the pinned ethereum-package.

`network.yaml` pins the genesis generator image built with
eth-beacon-genesis `ff42fce`, which hashes all 2**31 leaves of the VRF tree
with keccak256. The beacon node hashes the leaves of the first 2**20 slots
only and takes the rest of each tree from the precomputed states of
`--vrf-state-url`, which `network.yaml` points at the states of the default
mnemonic in the ethereum-package. Without them, or with an older genesis
generator image, validators cannot propose; the startup log says which.

The pinned ethereum-package does not load in the Kurtosis 2.1.0 packaged at
apt.fury.io/kurtosis-tech: it calls `plan.get_cluster_type()` and `GpuConfig`,
which that release lacks. `launch.sh` has not completed a run yet for that
reason.
