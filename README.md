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
* [ethereum/beacon\_chain](https://github.com/ethereum/beacon_chain): reference implementation from the Ethereum foundation

You can check where the beacon chain fits in the Ethereum research ecosystem in the [Status Athenaeum](https://github.com/status-im/athenaeum/blob/b465626cc551e361492e56d32517b2cdadd7493f/ethereum_research_records.json#L38).

## Building and Testing

### Prerequisites

(On Windows, a precompiled DLL collection download is available through the `fetch-dlls` Makefile target: ([Windows instructions](#windows)).)

#### Rocksdb

A recent version of Facebook's [RocksDB](https://github.com/facebook/rocksdb/) is needed - it can usually be installed using your system's package manager:

```bash
# MacOS with Homebrew
brew install rocksdb

# Fedora
dnf install rocksdb-devel

# Debian and Ubuntu
sudo apt-get install librocksdb-dev

# Arch (AUR)
pakku -S rocksdb
```

You can also build and install it by following [their instructions](https://github.com/facebook/rocksdb/blob/master/INSTALL.md).

#### PCRE

If you don't already have it, you will also need PCRE to build nim-beacon-chain.

```bash
# MacOS with Homebrew
brew install pcre

# Fedora
dnf install pcre

# Ubuntu
sudo apt-get install libpcre-dev

# Debian
apt-get install libpcre3-dev

# Arch (AUR)
pakku -S pcre-static
```

#### Developer tools

GNU Make, Bash and the usual POSIX utilities

### Build & Develop

#### POSIX-compatible OS

```bash
make # The first `make` invocation will update all Git submodules and prompt you to run `make` again.
     # It's only required once per Git clone. You'll run `make update` after each `git pull`, in the future,
     # to keep those submodules up to date.

make test # run the test suite
```

To pull the latest changes in all the Git repositories involved:
```bash
git pull
make update
```

To run a command that might use binaries from the Status Nim fork:
```bash
./env.sh bash # start a new interactive shell with the right env vars set
which nim
nim --version

# or without starting a new interactive shell:
./env.sh which nim
./env.sh nim --version
```

#### Windows

_(Experimental support!)_

Install Mingw-w64 for your architecture using the "[MinGW-W64 Online
Installer](https://sourceforge.net/projects/mingw-w64/files/)" (first link
under the directory listing). Run it and select your architecture in the setup
menu ("i686" on 32-bit, "x86\_64" on 64-bit), set the threads to "win32" and
the exceptions to "dwarf" on 32-bit and "seh" on 64-bit. Change the
installation directory to "C:\mingw-w64" and add it to your system PATH in "My
Computer"/"This PC" -> Properties -> Advanced system settings -> Environment
Variables -> Path -> Edit -> New -> C:\mingw-w64\mingw64\bin (it's "C:\mingw-w64\mingw32\bin" on 32-bit)

Install [Git for Windows](https://gitforwindows.org/) and use a "Git Bash" shell to clone and build nim-beacon-chain.

If you don't want to compile RocksDB and SQLite separately, you can fetch pre-compiled DLLs with:
```bash
mingw32-make # this first invocation will update the Git submodules
mingw32-make fetch-dlls # this will place the right DLLs for your architecture in the "build/" directory
```

You can now follow those instructions in the previous section by replacing `make` with `mingw32-make` (regardless of your 32-bit or 64-bit architecture):

```bash
mingw32-make test # run the test suite
```

## Beacon node simulation

The beacon node simulation will create a full peer-to-peer network of beacon nodes and validators, and run the beacon chain in real time. To change network parameters such as shard and validator counts, see [start.sh](tests/simulation/start.sh).


```bash
# Clear data files from your last run and start the simulation with a new genesis block:
make eth2_network_simulation

# In another terminal, get a shell with the right environment variables set:
./env.sh bash

# Run an extra node - by default the network will launch with 9 nodes, each
# hosting 10 validators. The last 10 validators are lazy bums that hid from the
# startup script, but you can command them back to work with:
./tests/simulation/run_node.sh 9

# (yes, it's 0-based indexing)
```

You can also separate the output from each beacon node in its own panel, using [multitail](http://www.vanheusden.com/multitail/):

```bash
make USE_MULTITAIL="yes" eth2_network_simulation
```

You can find out more about it in the [development update](https://our.status.im/nimbus-development-update-2018-12-2/).

_Alternatively, fire up our [experimental Vagrant instance with Nim pre-installed](https://our.status.im/setting-up-a-local-vagrant-environment-for-nim-development/) and give us yout feedback about the process!_

### Makefile tips and tricks for developers

- build all those tools known to the Makefile:

```bash
# (assuming you have 4 CPU cores and want to take advantage of them):
make -j4
```

- build a specific tool:

```bash
make state_sim
```

- you can control the Makefile's verbosity with the V variable (defaults to 0):

```bash
make V=1 # verbose
make V=2 test # even more verbose
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
make -j8 NIMFLAGS="-d:release" USE_MULTITAIL=yes eth2_network_simulation
```

## State transition simulation

The state transition simulator can quickly run the Beacon chain state transition function in isolation and output JSON snapshots of the state. The simulation runs without networking and blocks are processed without slot time delays.

```bash
# build and run the state simulator, then display its help ("-d:release" speeds it
# up substantially, allowing the simulation of longer runs in reasonable time)
make NIMFLAGS="-d:release" state_sim
build/state_sim --help
```

## Testnet

The beacon chain now has a public testnet available. Connect to it with:

```bash
make testnet0
scripts/testnet0.sh # this launches the testnet0-specific node you just built
```

For more information about the testnet and to find out how to launch your own, see [this announcement](https://our.status.im/the-nimbus-mvp-testnet-is-here/) and the [official docs on launching the testnets](https://nimbus.status.im/docs/t0.html).

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

