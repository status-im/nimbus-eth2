# Ethereum Beacon Chain
[![Build Status (Travis)](https://img.shields.io/travis/status-im/nim-beacon-chain/master.svg?label=Linux%20/%20macOS "Linux/macOS build status (Travis)")](https://travis-ci.org/status-im/nim-beacon-chain)
[![Windows build status (Appveyor)](https://img.shields.io/appveyor/ci/nimbus/nim-beacon-chain/master.svg?label=Windows "Windows build status (Appveyor)")](https://ci.appveyor.com/project/nimbus/nim-beacon-chain)
[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
![Stability: experimental](https://img.shields.io/badge/stability-experimental-orange.svg)

Nimbus beacon chain is a research implementation of the beacon chain component of the upcoming Ethereum Serenity upgrade, aka eth2. See the main [Nimbus](https://github.com/status-im/nimbus/) project for the bigger picture.

## Related

* [status-im/nimbus](https://github.com/status-im/nimbus/): main Nimbus repository - start here to learn more about the Nimbus eco-system
* [ethereum/eth2.0-specs](https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md): Serenity specification that this project implements
* [ethereum/beacon_chain](https://github.com/ethereum/beacon_chain): reference implementation from the Ethereum foundation

You can check where the beacon chain fits in the Ethereum research ecosystem in the [Status Athenaeum](https://github.com/status-im/athenaeum/blob/b465626cc551e361492e56d32517b2cdadd7493f/ethereum_research_records.json#L38).

## Test vectors

The Eth 2.0 test vectors and their generators are available in a [dedicated repository](https://github.com/status-im/eth2-testgen).

## Building and Testing

The beacon chain components require that you have Nim installed - the easiest way to get started is to head over to the main [Nimbus](https://github.com/status-im/nimbus/) repository and follow the build instructions there.

```bash
# Clone main nimbus repository
git clone https://github.com/status-im/nimbus.git
cd nimbus

# Prep environment
make update

# Start a shell that uses the Nimbus compile environment
./env.sh bash

# You're now in a shell environment that has the right Nim version available.
# Head over to the vendor repo where you should have a checkout of this project
cd vendor/nim-beacon-chain

# You can now run the test suite:
nim c -d:release -r tests/all_tests
```

## Beacon node simulation

The beacon node simulation is will create a full peer-to-peer network of beacon nodes and validators, and run the beacon chain in real time. To change network parameters such as shard and validator counts, see [start.sh](tests/simulation/start.sh).

```bash
# Start beacon chain simulation, resuming from the previous state (if any)
./tests/simulation/start.sh

# Clear data from last run and restart simulation with a new genesis block
rf -rf tests/simulation/data ; ./tests/simulation/start.sh

# Run an extra node - by default the network will launch with 9 nodes, each
# hosting 10 validators. The last 10 validators are lazy bums that hid from the
# startup script, but you can command them back to work in a separate terminal
# with:
./tests/simulation/run_node.sh 9
```

You can also separate the output from each beacon node in its own panel, using [multitail](http://www.vanheusden.com/multitail/):

```bash
USE_MULTITAIL="yes" ./tests/simulation/start.sh
```

You can find out more about it in the [development update](https://our.status.im/nimbus-development-update-2018-12-2/).

_Alternatively, fire up our [experimental Vagrant instance with Nim pre-installed](https://our.status.im/setting-up-a-local-vagrant-environment-for-nim-development/) and give us yout feedback about the process!_

## State transition simulation

The state transition simulator can quickly run the Beacon chain state transition function in isolation and output JSON snapshots of the state. The simulation runs without networking and blocks are processed without slot time delays.

```bash
cd research
# build and run state simulator, then display its help - -d:release speeds it
# up substantially, allowing the simulation of longer runs in reasonable time
nim c -d:release -r state_sim --help
```

## Convention

Ethereum Foundation uses:
  - snake_case for fields and procedure names
  - MACRO_CASE for constants
  - PascalCase for types

Nim NEP-1 recommends:
  - camelCase for fields and procedure names
  - PascalCase for constants
  - PascalCase for types

To facilitate collaboration and comparison, Nim-beacon-chain uses the Ethereum Foundation convention.

## License

Licensed and distributed under either of

* MIT license: [LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT

or

* Apache License, Version 2.0, ([LICENSE-APACHEv2](LICENSE-APACHEv2) or http://www.apache.org/licenses/LICENSE-2.0)

at your option. This file may not be copied, modified, or distributed except according to those terms.
