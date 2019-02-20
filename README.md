# Ethereum Beacon Chain
[![Build Status (Travis)](https://img.shields.io/travis/status-im/nim-beacon-chain/master.svg?label=Linux%20/%20macOS "Linux/macOS build status (Travis)")](https://travis-ci.org/status-im/nim-beacon-chain)
[![Windows build status (Appveyor)](https://img.shields.io/appveyor/ci/nimbus/nim-beacon-chain/master.svg?label=Windows "Windows build status (Appveyor)")](https://ci.appveyor.com/project/nimbus/nim-beacon-chain)
[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
![Stability: experimental](https://img.shields.io/badge/stability-experimental-orange.svg)

An alternative implementation of the Ethereum beacon chain in Nim.

Please see [Full Beacon chain](https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md) specs and the Ethereum Foundation [reference implementation](https://github.com/ethereum/beacon_chain).

You can check where the beacon chain fits in the Ethereum research ecosystem in the [Status Athenaeum](https://github.com/status-im/athenaeum/blob/b465626cc551e361492e56d32517b2cdadd7493f/ethereum_research_records.json#L38).

## Test vectors

The Eth 2.0 test vectors and their generators are available in a [dedicated repository](https://github.com/status-im/eth2-testgen).

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

## Installation

You can install the developement version of the library through nimble with the following command
```
nimble install https://github.com/status-im/nim-beacon-chain@#master
```

## Building and Testing

To try out the implementation, please first make sure you have a [Nim environment configured](https://bitfalls.com/2018/10/09/introduction-into-the-nim-language/).

_Alternatively, fire up our [experimental Vagrant instance with Nim pre-installed](https://our.status.im/setting-up-a-local-vagrant-environment-for-nim-development/) and give us yout feedback about the process!_

Then:

```bash
git clone https://github.com/status-im/nim-beacon-chain
cd nim-beacon-chain
nimble install
nimble test
```

This should produce some passing tests.

Additionally, you can run our simulation which generates a genesis file from some randomly generated validators. It then fires up 10 beacon nodes (each hosting 9 validators) which talk to each other and try to do state transitions. The simulation can be run by executing:

```bash
bash tests/simulation/start.sh
```

You can also separate the output from each beacon node in its own panel, using [multitail](http://www.vanheusden.com/multitail/):

```bash
USE_MULTITAIL="yes" ./tests/simulation/start.sh
```

You can find out more about it in the [development update](https://our.status.im/nimbus-development-update-2018-12-2/).

## License

Licensed and distributed under either of

* MIT license: [LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT

or

* Apache License, Version 2.0, ([LICENSE-APACHEv2](LICENSE-APACHEv2) or http://www.apache.org/licenses/LICENSE-2.0)

at your option. This file may not be copied, modified, or distributed except according to those terms.
