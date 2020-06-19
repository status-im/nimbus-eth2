# Advanced Usage for Developers

Latest updates happen in the `devel` branch which is merged into `master` every week on Tuesday before deploying a new testnets
The following sections explain how to setup your build environment on your platform.

### Windows dev environment

Install Mingw-w64 for your architecture using the "[MinGW-W64 Online
Installer](https://sourceforge.net/projects/mingw-w64/files/)" (first link
under the directory listing). Run it and select your architecture in the setup
menu ("i686" on 32-bit, "x86_64" on 64-bit), set the threads to "win32" and
the exceptions to "dwarf" on 32-bit and "seh" on 64-bit. Change the
installation directory to "C:\mingw-w64" and add it to your system PATH in "My
Computer"/"This PC" -> Properties -> Advanced system settings -> Environment
Variables -> Path -> Edit -> New -> C:\mingw-w64\mingw64\bin (it's "C:\mingw-w64\mingw32\bin" on 32-bit)

Install [Git for Windows](https://gitforwindows.org/) and use a "Git Bash" shell to clone and build nim-beacon-chain.

If you don't want to compile PCRE separately, you can fetch pre-compiled DLLs with:

```bash
mingw32-make # this first invocation will update the Git submodules
mingw32-make fetch-dlls # this will place the right DLLs for your architecture in the "build/" directory
```

> If you were following the Windows testnet instructions, you can jump back to [Connecting to testnets](#connecting-to-testnets) now

You can now follow those instructions in the previous section by replacing `make` with `mingw32-make` (regardless of your 32-bit or 64-bit architecture):

```bash
mingw32-make test # run the test suite
```

### Linux, macOS

After cloning the repo:

```bash
make # The first `make` invocation will update all Git submodules and prompt you to run `make` again.
     # It's only required once per Git clone. You'll run `make update` after each `git pull`, in the future,
     # to keep those submodules up to date.

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

### Raspberry Pi

We recommend you remove any cover or use a fan; the Raspberry Pi will get hot (85°C) and throttle.

- Raspberry PI 3b+ or Raspberry Pi 4b.
- 64gb SD Card (less might work too, but the default recommended 4-8GB will probably be too small)
- [Raspbian Buster Lite](https://www.raspberrypi.org/downloads/raspbian/) - Lite version is enough to get going and will save some disk space!

Assuming you're working with a freshly written image:

```bash

# Start by increasing swap size to 2gb:
sudo vi /etc/dphys-swapfile
# Set CONF_SWAPSIZE=2048
# :wq
sudo reboot

# Install prerequisites
sudo apt-get install git libgflags-dev libsnappy-dev libpcre3-dev

# Then you can follow instructions for Linux.

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
make LOG_LEVEL=TRACE beacon_node # log everything
```

- pass arbitrary parameters to the Nim compiler:

```bash
make NIMFLAGS="-d:release"
```

- you can freely combine those variables on the `make` command line:

```bash
make -j$(nproc) NIMFLAGS="-d:release" USE_MULTITAIL=yes eth2_network_simulation
```

- don't use the [lightweight stack tracing implementation from nim-libbacktrace](https://github.com/status-im/nim-beacon-chain/pull/745):

```bash
make USE_LIBBACKTRACE=0 # expect the resulting binaries to be 2-3 times slower
```
