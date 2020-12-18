# For Developers

This page contains tips and tricks for developers, further resources, along with information on how to set up your build environment on your platform.

Before building Nimbus for the first time, make sure to install the [prerequisites](./install.md).

## Branch lifecycle

The git repository has 3 main branches, `stable`, `testing` and `unstable` as well as feature and bugfix branches.

### Unstable

The `unstable` branch contains features and bugfixes that are actively being tested and worked on.

* Features and bugfixes are generally pushed to individual branches, each with their own pull request against the `unstable` branch.
* Once the branch has been reviewed and passed CI, the developer or reviewer merges the branch to `unstable`.
* The `unstable` branch is regularly deployed to the Nimbus pyrmont fleet where additional testing happens.

### Testing

The `testing` branch contains features and bugfixes that have gone through CI and initial testing on the `unstable` branch and are ready to be included in the next release.

* After testing a bugfix or feature on `unstable`, the features and fixes that are planned for the next release get merged to the `testing` branch either by the release manager or team members.
* The `testing` branch is regularly deployed to the Nimbus pyrmont fleet as well as a smaller mainnet fleet.
* The branch should remain release-ready at most times.

### Stable

The `stable` branch tracks the latest released version of Nimbus and is suitable for mainnet staking.

## Build system

### Windows

```bash
mingw32-make # this first invocation will update the Git submodules
```

You can now follow the instructions in this this book by replacing `make` with `mingw32-make` (you should run `mingw32` regardless of whether you're running 32-bit or 64-bit architecture):

```bash
mingw32-make test # run the test suite
```

### Linux, macOS

After cloning the repo:

```bash
# Build nimbus_beacon_node and all the tools, using 4 parallel Make jobs
make -j4

# Run tests
make test

# Update to latest version
git pull
make update
```

## Environment

Nimbus comes with a build environment similar to Python venv - this helps ensure that the correct version of Nim is used and that all dependencies can be found.

```bash
./env.sh bash # start a new interactive shell with the right env vars set
which nim
nim --version # Nimbus is tested and supported on 1.0.2 at the moment

# or without starting a new interactive shell:
./env.sh which nim
./env.sh nim --version

# Start Visual Studio code with environment
./env.sh code

```

## Makefile tips and tricks for developers

- build all those tools known to the Makefile:

```bash
# $(nproc) corresponds to the number of cores you have
make -j $(nproc)
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
make LOG_LEVEL=TRACE nimbus_beacon_node # log everything
```

- pass arbitrary parameters to the Nim compiler:

```bash
make NIMFLAGS="-d:release"
```

- you can freely combine those variables on the `make` command line:

```bash
make -j$(nproc) NIMFLAGS="-d:release" USE_MULTITAIL=yes eth2_network_simulation
```

- don't use the [lightweight stack tracing implementation from nim-libbacktrace](https://github.com/status-im/nimbus-eth2/pull/745):

```bash
make USE_LIBBACKTRACE=0 # expect the resulting binaries to be 2-3 times slower
```

- disable `-march=native` because you want to run the binary on a different machine than the one you're building it on:

```bash
make NIMFLAGS="-d:disableMarchNative" nimbus_beacon_node
```

- disable link-time optimisation (LTO):

```bash
make NIMFLAGS="-d:disableLTO" nimbus_beacon_node
```

- build a static binary

```bash
make NIMFLAGS="--passL:-static" nimbus_beacon_node
```

- publish a book using [mdBook](https://github.com/rust-lang/mdBook) from sources in "docs/" to GitHub pages:

```bash
make publish-book
```

- create a binary distribution

```bash
make dist
```

- test the binaries

```bash
make dist-test
```

## Multi-client interop scripts

[This repository](https://github.com/eth2-clients/multinet) contains a set of scripts used by the client implementation teams to test interop between the clients (in certain simplified scenarios). It mostly helps us find and debug issues.

## Stress-testing the client by limiting the CPU power

```bash
make pyrmont CPU_LIMIT=20
```

The limiting is provided by the cpulimit utility, available on Linux and macOS.
The specified value is a percentage of a single CPU core. Usually 1 - 100, but can be higher on multi-core CPUs.
