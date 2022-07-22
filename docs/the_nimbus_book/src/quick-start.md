# Run the beacon node

This page takes you through the steps of getting a standard setup the Nimbus beacon node up and running.

The quickstart setup involves running two nodes: an [execution client](./eth1.md) and a beacon node - both are needed to run a full Ethereum setup.

The beacon node connects to the beacon chain network, syncs historical data and provides [API's](./rest-api.md) to monitor and interact with the beacon chain.

Running a beacon node is a [worthwhile endeavor](https://vitalik.ca/general/2021/05/23/scaling.html#its-crucial-for-blockchain-decentralization-for-regular-users-to-be-able-to-run-a-node) even if your are not planning on validating yourself!

The guide assumes [Ubuntu Linux](https://ubuntu.com/download/server) is being used, and therefore some familiarity with [the linux command line](https://ubuntu.com/tutorials/command-line-for-beginners) is needed.

!!! note
    To become a validator, you will first need to be running a beacon node.


!!! tip
    You can practice running the node safely on the [Prater testnet](./prater.md) - throughout, we'll provide instructions for both Prater and Mainnet.


## 1. Prepare

Prepare your machine by installing [Nimbus' dependencies](./install.md). In particular, this step will show how to set up an [execution client](./eth1.md).

## 2. Install

Next, download the [latest release](./binaries.md) and install it by unpacking the archive. Using a command line terminal:

```sh
# Create a directory that can hold the beacon chain data and applications - this should be a fast SSD
mkdir -p nimbus-eth2

# Download the latest release - replace the link with the latest release on the download page!
wget https://github.com/status-im/nimbus-eth2/releases/download/v22.6.1/nimbus-eth2_Linux_amd64_22.6.1_2444e994.tar.gz

# Unpack the archive into the `nimbus-eth2` directory you just created
tar xvf nimbus-eth2_Linux_amd64_22.6.1_2444e994.tar.gz --strip-components 1 -C nimbus-eth2
```

!!! tip
    Advanced users looking to take advantage of hardware-specific features and optimization may wish to [build from source](./build.md) instead!


## 3. Start the node

Once you've installed the binaries, you can [start the node](./start-syncing.md) which will initiate the sync process.

```sh
cd nimbus-eth2
```

=== "Mainnet"

    ```sh
    # Start a mainnet node
    ./run-mainnet-beacon-node.sh
    ```

=== "Prater"

    ```sh
    # Start a prater testnet node
    ./run-prater-beacon-node.sh
    ```

Once the beacon node starts, you'll see it logging information to the console, like so:

```sh
INF 2022-07-19 15:42:58.145+02:00 Launching beacon node                      topics="beacnde" version=v22.6.1-2444e9-stateofus ...
```

Congratulations! Your beacon node is up and running, and syncing the network!

## Where to go from here

* If you will be running the node on a regular basis, it is recommended you set up a [systemd service](./beacon-node-systemd.md) that automatically restarts your node if the computer reboots.
* If you wish to stake, continue your journey by following the [validator quick start](./run-a-validator.md).
* The [monitoring](./health.md) page contains information about how to keep your node healthy
