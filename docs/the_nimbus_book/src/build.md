# Build the beacon node

The beacon node connects to the eth2 network, manages the blockchain, and provides API's to interact with the beacon chain.

Importantly, you need to have built the beacon node in order to be able to import your keys.

*Todo: explain relationship between beacon node and validator client*

## Prerequisites

Before building and running the application, make sure you've gone through the [installed the required dependencies](./install.md).

## Building the node

### 1. Clone the nim beacon chain repository

```
git clone https://github.com/status-im/nimbus-eth2
cd nimbus-eth2
```

### 2. Run the beacon node build process

To build the Nimbus beacon node and it's dependencies, run:

```
make nimbus_beacon_node
```

## Updating the node

Make sure you stay on the lookout for any critical updates to Nimbus and [keep your node updated](./keep-updated.md).

