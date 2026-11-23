# PQ devnet image and Kurtosis network

Tooling for the PQ (post-quantum) devnet prototype, consensus-specs
`2f43bc0f989f47af81df390a90bc1f78e2436323`.

- `Dockerfile`, `nimbus-pq-bn.sh`: an image with the beacon node and the
  leanVM sidecar that proves and verifies PQ signature aggregates. The
  sidecar is built in the image from the pinned leanVM commit, the
  `bindings-v0.16.0` tag that `beacon_chain/pq/leanxmss_ffi` pins as well:
  all clients of a devnet have to be on one leanVM version, as proofs of
  another do not verify. The beacon node is the host build. The wrapper sits at the path the ethereum-package
  launches, supervises `leanvm-sidecar` and passes `--pq-sidecar-socket` to
  the node.
- `build-image.sh`: builds `nimbus-eth2/pq-devnet-0`. Run `make nimbus_beacon_node`
  first, then either the script or, from the repository root,
  `docker build -f docker/pq-devnet/Dockerfile -t nimbus-eth2/pq-devnet-0 .`.
  The host build targets the host CPU (`-march=native`); build the node with
  `NIMFLAGS="-d:disableMarchNative"` for an image to run elsewhere. Such a
  build still needs AVX2 on x86-64 for the leanXMSS code, which is several
  times slower without it; the node says so at startup on a CPU that lacks
  it, and `-d:leanXmssRustFlags=...` sets other Rust compiler flags.
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

`--xmss-cache-url` likewise points at precomputed XMSS trees of the default
mnemonic, 14696 bytes per validator index: the top tree of a key and the
bottom trees of its first attestations and slot duties. The node fetches the
records of its own validators with range requests and loads their keys in
milliseconds; a key whose record is missing or does not match it has its
trees hashed at startup, which takes a few seconds per key on all cores.
Without the option, the node looks for the caches in the `.xmss` file beside
the `.vrf` file of `--vrf-state-url`, where the devnet tooling publishes them.

XMSS signatures are made in the threads of `--num-threads`: a signature
takes about 100 ms, and a node with 625 validators makes some 40 per slot.
With the 4 threads that the ethereum-package sets, that is a second of work
per slot beside the event loop; a node with a few thousand validators wants
more threads.

The pinned ethereum-package does not load in the Kurtosis 2.1.0 packaged at
apt.fury.io/kurtosis-tech: it calls `plan.get_cluster_type()` and `GpuConfig`,
which that release lacks. `launch.sh` has not completed a run yet for that
reason.
