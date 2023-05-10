# Build from source

Building Nimbus from source ensures that all hardware-specific optimizations are turned on.
The build process itself is simple and fully automated, but may take a few minutes.

!!! note "Nim"
    Nimbus is written in the [Nim](https://nim-lang.org) programming language.
    The correct version will automatically be downloaded as part of the build process!

## Prerequisites

Make sure you have all needed [build prerequisites](./install.md#build-prerequisites).

## Building the node

### 1. Clone the `nimbus-eth2` repository

```sh
git clone https://github.com/status-im/nimbus-eth2
cd nimbus-eth2
```

### 2. Run the beacon node build process

To build the Nimbus beacon node and its dependencies, run:

```sh
make -j4 nimbus_beacon_node
```

!!! tip
    Omit `-j4` on systems with 4GB of memory or less.
