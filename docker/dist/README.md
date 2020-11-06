# Binary Nimbus beacon_node distribution

This binary distribution was created from https://github.com/status-im/nimbus-eth2

Tarball naming scheme: "nimbus-eth2\_Linux\_amd64\_<VERSION>\_<GIT COMMIT>\_<YYYYMMDDHHMMSS>.tar.gz" (the date is in UTC).

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

## Running a Medalla node

With default options:

```bash
./run_medalla_node.sh
```

Change options implemented as shell variables inside the script:

```bash
LOG_LEVEL=DEBUG BASE_PORT=9100 ./run_medalla_node.sh
```

Add arbitrary `beacon_node` parameters (yes, you can combine this with env vars):

```bash
./run_medalla_node.sh --log-level=DEBUG --rpc-port=9290
```

Use your own Infura endpoint, because the default one is probably throttled:

```bash
GOERLI_WEB3_URL="wss://goerli.infura.io/ws/v3/<YOUR PROJECT ID>" ./run_medalla_node.sh
```

## Running a mainnet node

Same conventions as the Medalla script described above, plus the requirement of specifying a Web3 URL:

```bash
# using a local Geth instance
WEB3_URL="ws://localhost:8545" ./run_mainnet_node.sh
# using Infura
WEB3_URL="wss://mainnet.infura.io/ws/v3/<YOUR PROJECT ID>" ./run_mainnet_node.sh
```

