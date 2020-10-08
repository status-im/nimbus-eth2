# Binary Nimbus beacon_node distribution

This binary distribution was created from https://github.com/status-im/nimbus-eth2

Tarball naming scheme: "nimbus-eth2\_Linux\_amd64\_<GIT COMMIT>\_<YYYYMMDDHHMMSS>.tar.gz"

## Reproducing the build

Besides the generic build requirements, you also need [Docker](https://www.docker.com/).

```bash
git clone https://github.com/status-im/nimbus-eth2.git
cd nimbus-eth2
git checkout GIT_COMMIT
make update
make dist
```

## Significant differences from self-built binaries

No `-march=native` and no metrics support.

