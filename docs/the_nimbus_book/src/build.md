# Build the beacon node

## Prerequisites

Before building and running the application, make sure you've installed the [required dependencies](./install.md).

## Building the node

### 1. Clone the `nimbus-eth2` repository

```sh
git clone https://github.com/status-im/nimbus-eth2
cd nimbus-eth2
```

### 2. Run the beacon node build process

To build the Nimbus beacon node and it's dependencies, run:

```sh
make -j4 nimbus_beacon_node
```

> 🛈 Omit `-j4` on systems with 4GB of memory or less.
