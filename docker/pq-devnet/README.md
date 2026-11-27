# PQ devnet image and Kurtosis network

Tooling for the PQ (post-quantum) devnet prototype, consensus-specs
`4c296784bb6ff54cbdcf72ebdda2a1057cce8893` (pq-devnet-1: staggered
aggregators, VRF leaves that commit to secrets).

- `Dockerfile`: an image with the beacon node, which signs with leanXMSS and
  proves and verifies PQ signature aggregates with leanVM in its own process.
  `beacon_chain/pq/leanxmss_ffi` pins leanVM to the `bindings-v0.19.0` tag:
  all clients of a devnet have to be on one leanVM version, as proofs of
  another do not verify. Building needs Rust 1.99 or later. The beacon node
  is the host build.
- `build-image.sh`: builds `nimbus-eth2/pq-devnet-1`. Run `make nimbus_beacon_node`
  first, then either the script or, from the repository root,
  `docker build -f docker/pq-devnet/Dockerfile -t nimbus-eth2/pq-devnet-1 .`.
  The host build targets the host CPU (`-march=native`); build the node with
  `NIMFLAGS="-d:disableMarchNative"` for an image to run elsewhere. Such a
  build still needs AVX2 on x86-64 for the leanXMSS code, which is several
  times slower without it; the node says so at startup on a CPU that lacks
  it, and `-d:leanXmssRustFlags=...` sets other Rust compiler flags. The
  prover picks the fastest of its variants that the CPU supports when the
  node starts; `--pq-prover-threads` sets its number of threads, one per
  physical core by default.
- `network.yaml`, `launch.sh`: a single-client devnet (geth, 2 x 32
  validators inside the beacon nodes, mainnet preset, PQ at genesis, Heze
  disabled) on the pinned ethereum-package.

`network.yaml` pins a genesis generator image that hashes all 2**31 leaves of
the VRF tree with keccak256; for pq-devnet-1 it has to be one built with
eth-beacon-genesis `d1a8253d` or later, whose leaves commit to secrets. The beacon node hashes the leaves of the first 2**20 slots
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

Those files hold the trees a key signs with at the start of the network. A
key moves to another bottom tree for its slot duties at slot 4096 and every
8192 slots from there, and the node builds that tree 128 epochs ahead, in the
background. The trees a node has hashed or built are written to
`pq_tree_cache.bin` in the validators directory, once built and when the node
stops, and are read from it when the node starts again: a restart then takes
no hashing. The file holds no secret and can be deleted; it has to be on
storage that outlives the container for a restart to find it. Without it, a
node that starts after slot 4096 builds the current bottom tree of every key
before its validators do any duty, several seconds per key on all cores.

XMSS signatures are made in the threads of `--num-threads`: a signature
takes about 100 ms, and a node with 625 validators makes some 40 per slot.
With the 4 threads that the ethereum-package sets, that is a second of work
per slot beside the event loop; a node with a few thousand validators wants
more threads.

The aggregators of a committee take turns in the order of its aggregation
committee: the one at position `p` proves the attestations it has 40% + 5% x
`p` into the slot and broadcasts its aggregate at 60% + 5% x `p`, unless an
aggregate it received by then has all of its attesters. Of the aggregators
that a node has in one committee, the first in that order aggregates.

The pinned ethereum-package does not load in the Kurtosis 2.1.0 packaged at
apt.fury.io/kurtosis-tech: it calls `plan.get_cluster_type()` and `GpuConfig`,
which that release lacks. `launch.sh` has not completed a run yet for that
reason.
