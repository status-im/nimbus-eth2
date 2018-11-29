# Ethereum Beacon Chain
[![Build Status (Travis)](https://img.shields.io/travis/status-im/nim-beacon-chain/master.svg?label=Linux%20/%20macOS "Linux/macOS build status (Travis)")](https://travis-ci.org/status-im/nim-beacon-chain)
[![Windows build status (Appveyor)](https://img.shields.io/appveyor/ci/nimbus/nim-beacon-chain/master.svg?label=Windows "Windows build status (Appveyor)")](https://ci.appveyor.com/project/nimbus/nim-beacon-chain)
[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
![Stability: experimental](https://img.shields.io/badge/stability-experimental-orange.svg)

An alternative implementation of the Ethereum beacon chain in Nim.

Please see [Full Casper chain v2.1](https://notes.ethereum.org/SCIg8AH5SA-O4C1G1LYZHQ?view) specs and the Ethereum Foundation [reference implementation](https://github.com/ethereum/beacon_chain).

You can check where the beacon chain fits in the Ethereum research ecosystem in the [Status Athenaeum](https://github.com/status-im/athenaeum/blob/b465626cc551e361492e56d32517b2cdadd7493f/ethereum_research_records.json#L38).

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

## License

Licensed and distributed under either of

* MIT license: [LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT
* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option. This file may not be copied, modified, or distributed except according to those terms.

