# Nimbus Eth2 (Beacon Chain)

[![Github Actions CI](https://github.com/status-im/nimbus-eth2/workflows/Nimbus%20nimbus-eth2%20CI/badge.svg)](https://github.com/status-im/nim-blscurve/actions?query=workflow%3A%22BLSCurve+CI%22)
[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
![Stability: experimental](https://img.shields.io/badge/stability-experimental-orange.svg)

[![Discord: Nimbus](https://img.shields.io/badge/discord-nimbus-orange.svg)](https://discord.gg/XRxWahP)
[![Status: #nimbus-general](https://img.shields.io/badge/status-nimbus--general-orange.svg)](https://join.status.im/nimbus-general)

Nimbus-eth2 is a extremely efficient Beacon Chain client for participating in the Ethereum Proof of Stake protocol. It performs well on embedded systems, resource-restricted devices -- including Raspberry Pis and mobile devices -- the low resource usage also makes it an excellet choice for running together with an Ethereum client on a server or a desktop where it simply takes up less resources.

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Documentation](#documentation)
- [Related projects](#related-projects)
- [Donations](#donations)
- [Branch guide](#branch-guide)
- [Developer resources](#developer-resources)
- [Tooling and utilities](#tooling-and-utilities)
- [For researchers](#for-researchers)
  - [State transition simulation](#state-transition-simulation)
  - [Local network simulation](#local-network-simulation)
  - [Visualising simulation metrics](#visualising-simulation-metrics)
  - [Network inspection](#network-inspection)
  - [CI setup](#ci-setup)
- [License](#license)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Documentation

You can find the information you need to run a beacon node and operate as a validator in [The Book](https://nimbus.guide/).

The [Quickstart](https://nimbus.guide/quick-start.html) in particular will help you get connected to the Pyrmont Testnet and eth2 Mainnet quickly!

## Related projects

* [status-im/nimbus-eth1](https://github.com/status-im/nimbus-eth1/): Nimbus for Ethereum 1
* [ethereum/eth2.0-specs](https://github.com/ethereum/eth2.0-specs/tree/v1.0.1#phase-0): Serenity specification that this project implements

You can check where the beacon chain fits in the Ethereum ecosystem our Two-Point-Oh series: https://our.status.im/tag/two-point-oh/

## Donations

If you'd like to contribute to Nimbus development, our donation address is [`0x70E47C843E0F6ab0991A3189c28F2957eb6d3842`](https://etherscan.io/address/0x70E47C843E0F6ab0991A3189c28F2957eb6d3842)

## Branch guide

* `stable` - latest stable release - **this branch is recommended for most users**
* `testing` - pre-release branch with features and bugfixes slated for the next stable release - this branch is suitable for use on testnets and for adventerous users that want to live on the edge.
* `unstable` - main development branch against which PR's are merged - if you want to contribute to Nimbus, start here.

## Developer resources

To build tools that interact with Nimbus while it's running, we expose an [RPC API](https://nimbus.guide/api.html).

To get started with developing Nimbus itself, see the [developer handbook](https://nimbus.guide/developers.html). The code follows the [Status Nim Style Guide](https://status-im.github.io/nim-style-guide/).

Nimbus is built in the [Nim language](https://nim-lang.org) - the compiler is automatically installed when building the project for the first time. More information - in particular security-related information about the language - can be found in the [Auditor Handbook](https://nimbus.guide/auditors-book/).

## Tooling and utilities

We provide several tools to interact with ETH2 and the data in the beacon chain:

* [ncli](ncli/ncli.nim) - command line tool with pretty printers, SSZ decoders, state transition helpers to interact with Eth2 data structures and functions
* [ncli_db](ncli/ncli_db.nim) - command line tool to perform surgery on the Nimbus sqlite database
* [inspector](ncli/inspector.nim) - command line tool for interacting with the peer to peer protocols in eth2
* [multinet](https://github.com/status-im/nimbus-eth2/tree/master/multinet) - a set of scripts to build and run several Eth2 clients locally

## For researchers

### State transition simulation

The state transition simulator can quickly run the Beacon chain state transition function in isolation and output JSON snapshots of the state. The simulation runs without networking and blocks are processed without slot time delays.

```bash
# build and run the state simulator, then display its help ("-d:release" speeds it
# up substantially, allowing the simulation of longer runs in reasonable time)
make NIMFLAGS="-d:release" state_sim
build/state_sim --help
```

### Local network simulation

The local network simulation will create a full peer-to-peer network of beacon nodes and validators on a single machine, and run the beacon chain in real time.

Parameters such as shard, validator counts, and data folders are configured [vars.sh](tests/simulation/vars.sh). They can be set in as environment variables before launching the simulation.

```bash
# Clear data files from your last run and start the simulation with a new genesis block:
make VALIDATORS=192 NODES=6 USER_NODES=1 eth2_network_simulation

# In another terminal, get a shell with the right environment variables set:
./env.sh bash

# In the above example, the network is prepared for 7 beacon nodes but one of
# them is not started by default (`USER_NODES`) - this is useful to test
# catching up to the consensus. The following command will start the missing node.
./tests/simulation/run_node.sh 0 # (or the index (0-based) of the missing node)

# Running a separate node allows you to test sync as well as see what the action
# looks like from a single nodes' perspective.
```

By default, validators will be split in half between beacon node and validator
client processes (50/50), communicating through the
[official validator API](https://ethereum.github.io/eth2.0-APIs/#/ValidatorRequiredApi)
(for example with `192` validators and `6` nodes you will roughly end up with 6
beacon node and 6 validator client processes, where each of them will handle 16
validators), but if you don't want to use external validator clients and instead
want to have all the validators handled by the beacon nodes you may use
`BN_VC_VALIDATOR_SPLIT=no` as an additional argument to `make eth2_network_simulation`.

By default, the simulation will start from a pre-generated genesis state. If you wish to
simulate the bootstrap process with a Ethereum 1.0 validator deposit contract, start the
simulation with `WAIT_GENESIS=yes`

```
make eth2_network_simulation WAIT_GENESIS=yes
```

You can also separate the output from each beacon node in its own panel, using [multitail](http://www.vanheusden.com/multitail/):

```bash
make eth2_network_simulation USE_MULTITAIL="yes"
```

You can find out more about it in the [development update](https://our.status.im/nimbus-development-update-2018-12-2/).

_Alternatively, fire up our [experimental Vagrant instance with Nim pre-installed](https://our.status.im/setting-up-a-local-vagrant-environment-for-nim-development/) and give us yout feedback about the process!_

### Visualising simulation metrics

The [generic instructions from the Nimbus repo](https://github.com/status-im/nimbus/#metric-visualisation) apply here as well.

Specific steps:

```bash
# This will generate the Prometheus config on the fly, based on the number of
# nodes (which you can control by passing something like NODES=6 to `make`).
make VALIDATORS=192 NODES=6 USER_NODES=0 eth2_network_simulation

# In another terminal tab, after the sim started:
cd tests/simulation/prometheus
prometheus
```

The dashboard you need to import in Grafana is "grafana/beacon\_nodes\_Grafana\_dashboard.json".

![monitoring dashboard](./media/monitoring.png)

### Network inspection

The [inspector tool](./ncli/inspector.nim) can help monitor the libp2p network and the various channels where blocks and attestations are being transmitted, showing message and connectivity metadata. By default, it will monitor all ethereum 2 gossip traffic.

```bash
. ./env.sh
# Build inspector for minimal config:
./env.sh nim c -d:const_preset=minimal -o:build/inspector_minimal ncli/inspector.nim

# Build inspector for mainnet config:
./env.sh nim c -d:const_preset=mainnet -o:build/inspector_mainnet ncli/inspector.nim

# See available options
build/inspector_minimal --help

# Connect to a network from eth2 testnet repo bootstrap file - --decode option attempts to decode the messages as well
build/inspector_minimal --decode -b:$(curl -s https://raw.githubusercontent.com/eth2-clients/eth2-testnets/master/nimbus/testnet0/bootstrap_nodes.txt | head -n1)
```

### CI setup

Local testnets run for 4 epochs each, to test finalization. That happens only on Jenkins Linux hosts, and their logs are available for download as artifacts, from the job's page. Don't expect these artifacts to be kept more than a day after the corresponding branch is deleted.

![Jenkins artifacts](./media/jenkins_artifacts.png)

## License

Licensed and distributed under either of

* MIT license: [LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT

or

* Apache License, Version 2.0, ([LICENSE-APACHEv2](LICENSE-APACHEv2) or http://www.apache.org/licenses/LICENSE-2.0)

at your option. These files may not be copied, modified, or distributed except according to those terms.
