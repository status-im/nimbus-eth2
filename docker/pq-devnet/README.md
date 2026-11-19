# PQ devnet image and Kurtosis network

Tooling for the PQ (post-quantum) devnet prototype, consensus-specs
`2f43bc0f989f47af81df390a90bc1f78e2436323`.

- `Dockerfile`, `nimbus-pq-bn.sh`: an image with the beacon node and the
  leanVM sidecar that proves and verifies PQ signature aggregates. The
  wrapper sits at the path the ethereum-package launches, supervises
  `leanvm-sidecar` and passes `--pq-sidecar-socket` to the node.
- `build-image.sh`: builds `nimbus-pq:dev` from `build/nimbus_beacon_node`
  and a `leanvm-sidecar` binary.
- `network.yaml`, `launch.sh`: a single-client devnet (geth, 2 x 32
  validators inside the beacon nodes, mainnet preset, PQ at genesis, Heze
  disabled) on the pinned ethereum-package.

The genesis generator image pinned in `network.yaml` predates the keccak256
VRF tree; use an image built from eth-beacon-genesis `4566af0` or later, or
proposals fail the VRF root check logged at startup.

These files have not been run yet: no Docker daemon was available where they
were written. The same network was run natively instead (geth master, two
beacon nodes, two sidecars), to finality.
