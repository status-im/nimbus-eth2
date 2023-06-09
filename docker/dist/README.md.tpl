# Binary Nimbus beacon node distribution

This binary distribution of the Nimbus eth2 package is compiled
in a [reproducible way](https://reproducible-builds.org/) from source files
hosted at https://github.com/status-im/nimbus-eth2.

The tarball containing this README uses the following naming scheme:

```bash
nimbus-eth2_<TARGET OS>_<TARGET CPU>_<VERSION>_<GIT COMMIT>.tar.gz
```

For a more complete and up-to-date documentation, please refer to the [Nimbus book](https://status-im.github.io/nimbus-eth2/).

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

Binary builds are configured to maximise portability, disabling the use of
advanced CPU features which may result in lower performance on some hardware.

## Running a node

See https://nimbus.guide for full instructions on running a node.

To connect to mainnet with default options:

```bash
./run-mainnet-beacon-node.sh
```

The script will forward all supplied options to the beacon node executable:

```bash
./run-mainnet-beacon-node.sh --log-level=DEBUG --tcp-port=9050
```

To monitor the Eth1 validator deposit contract, you'll need to pair
the Nimbus beacon node with a Web3 provider capable of serving Eth1
event logs. This could be a locally running Eth1 client such as Geth
or a cloud service such as Infura. For more information please see
our setup guides:

https://status-im.github.io/nimbus-eth2/eth1.html

By default, the script will ask you to enter a web3 provider URL interactively,
but this can be bypassed by specifying a websocket `WEB3_URL` environment variable:

```bash
# using a local mainnet instance
WEB3_URL="ws://localhost:8545" ./run-mainnet-beacon-node.sh
```

## Testnet

The `prater` testnet runs on

```bash
# using a local Goerli instance
WEB3_URL="ws://localhost:8545" ./run-prater-node.sh --max-peers=150
```
