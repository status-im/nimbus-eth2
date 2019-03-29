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

## Building and Testing

The beacon chain components need to be built with the Nim compiler - the easiest way to get started is to head over to the main [Nimbus](https://github.com/status-im/nimbus/) repository and follow the build instructions there or just execute the commands below in order.

_Note: This is because this repository is actually pulled in as a dependency of Nimbus - the Ethereum 1.0 + 2.0 client - so it makes sense to start from there even if you are only interested in testing the Ethereum 2.0 side of things (contained almost entirely in this repository)._

```bash
# Clone main nimbus repository:
git clone https://github.com/status-im/nimbus.git
cd nimbus

# Prep environment (assuming you have 4 CPU cores and want to take advantage of them):
make update
make -j4 deps

# Head over to the vendor repo where you should have a checkout of this project:
cd vendor/nim-beacon-chain

# You can now run the test suite:
make test
```

## Beacon node simulation

The beacon node simulation is will create a full peer-to-peer network of beacon nodes and validators, and run the beacon chain in real time. To change network parameters such as shard and validator counts, see [start.sh](tests/simulation/start.sh).


```bash
# get a shell with the right environment vars set:
../../env.sh bash

# Start the beacon chain simulation, resuming from a previous state (if any):
./tests/simulation/start.sh # if starting from Nimbus, make sure you're in vendor/nim-beacon-chain!

# Clear data files from your last run and restart the simulation with a new genesis block:
rm -rf tests/simulation/data; ./tests/simulation/start.sh

# Run an extra node - by default the network will launch with 9 nodes, each
# hosting 10 validators. The last 10 validators are lazy bums that hid from the
# startup script, but you can command them back to work in a separate terminal
# with:
./tests/simulation/run_node.sh 9
```

Alternatively, a Makefile-based flow is available:

```bash
# From "vendor/nim-beacon-chain/",
# clear all data from the last run and restart the simulation with a new genesis block:
make eth2_network_simulation
```

You can also separate the output from each beacon node in its own panel, using [multitail](http://www.vanheusden.com/multitail/):

```bash
USE_MULTITAIL="yes" ./tests/simulation/start.sh

# OR

make USE_MULTITAIL="yes" eth2_network_simulation
```

You can find out more about it in the [development update](https://our.status.im/nimbus-development-update-2018-12-2/).

_Alternatively, fire up our [experimental Vagrant instance with Nim pre-installed](https://our.status.im/setting-up-a-local-vagrant-environment-for-nim-development/) and give us yout feedback about the process!_

### Makefile tips and tricks for developers

- build all those tools known to the Makefile:

```bash
make
```

- build a specific tool:

```bash
make state_sim
```

- you can control the Makefile's verbosity with the V variable (defaults to 1):

```bash
make V=0 # quiet
make V=2 test # more verbose than usual
```

- same for the [Chronicles log level](https://github.com/status-im/nim-chronicles#chronicles_log_level):

```bash
make LOG_LEVEL=DEBUG bench_bls_sig_agggregation # this is the default
make LOG_LEVEL=TRACE beacon_node # log everything
```

- pass arbitrary parameters to the Nim compiler:

```bash
make NIMFLAGS="-d:release"
```

- you can freely combine those variables on the `make` command line:

```bash
make -j8 V=0 NIMFLAGS="-d:release" USE_MULTITAIL=yes eth2_network_simulation
```

## State transition simulation

The state transition simulator can quickly run the Beacon chain state transition function in isolation and output JSON snapshots of the state. The simulation runs without networking and blocks are processed without slot time delays.

```bash
# build and run the state simulator, then display its help ("-d:release" speeds it
# up substantially, allowing the simulation of longer runs in reasonable time)
make V=0 NIMFLAGS="-d:release" state_sim
./build/state_sim --help
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

To facilitate collaboration and comparison, nim-beacon-chain uses the Ethereum Foundation convention.

## License

Licensed and distributed under either of

* MIT license: [LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT

or

* Apache License, Version 2.0, ([LICENSE-APACHEv2](LICENSE-APACHEv2) or http://www.apache.org/licenses/LICENSE-2.0)

at your option. These files may not be copied, modified, or distributed except according to those terms.

