# For Developers

Latest updates happen in the `devel` branch which is merged into `master` every week on Tuesday.

This page contains tips and tricks for developers, further resources, along with information on how to set up your build environment on your platform.

### Ubuntu guide

> ⚠️  Parts of this guide may now be out-of-date.

See [this excellent resource](https://medium.com/@SomerEsat/guide-to-staking-on-ethereum-2-0-ubuntu-medalla-nimbus-5f4b2b0f2d7c) for detailed step-by-step guide on how to stake on eth2 with Ubuntu.

It contains instructions on how to:

- Configure a newly running Ubuntu server instance
- Configure and run an eth1 node as a service
- Compile and configure the Nimbus client for eth 2, phase 0 (Medalla testnet)
- Install and configure [Prometheus](https://prometheus.io/) metrics and set up a [Grafana](https://grafana.com/) dashboard

### Windows dev environment

Install Mingw-w64 for your architecture using the "[MinGW-W64 Online
Installer](https://sourceforge.net/projects/mingw-w64/files/)" (first link
under the directory listing). Run it and select your architecture in the setup
menu (`i686` on 32-bit, `x86_64` on 64-bit), set the threads to `win32` and
the exceptions to "dwarf" on 32-bit and "seh" on 64-bit. Change the
installation directory to "C:\mingw-w64" and add it to your system PATH in "My
Computer"/"This PC" -> Properties -> Advanced system settings -> Environment
Variables -> Path -> Edit -> New -> C:\mingw-w64\mingw64\bin (it's "C:\mingw-w64\mingw32\bin" on 32-bit)

Install [Git for Windows](https://gitforwindows.org/) and use a "Git Bash" shell to clone and build nimbus-eth2.

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

To run a command that might use binaries from the Status Nim fork:

```bash
./env.sh bash # start a new interactive shell with the right env vars set
which nim
nim --version # Nimbus is tested and supported on 1.0.2 at the moment

# or without starting a new interactive shell:
./env.sh which nim
./env.sh nim --version
```

### Makefile tips and tricks for developers

- build all those tools known to the Makefile:

```bash
# $(nproc) corresponds to the number of cores you have
make -j$(nproc)
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

### Multi-client interop scripts

[This repository](https://github.com/eth2-clients/multinet) contains a set of scripts used by the client implementation teams to test interop between the clients (in certain simplified scenarios). It mostly helps us find and debug issues.
