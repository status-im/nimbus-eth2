# Beacon node

This page takes you through the steps of getting a standard installation of the Nimbus beacon node running.

The quickstart setup involves running two nodes: an [execution client](./eth1.md) and a beacon node.
Both are needed to run a full Ethereum setup.

To become a validator, you first need to set up a beacon node.
The beacon node connects to the beacon chain network, syncs historical data, and provides [API's](./rest-api.md) to monitor and interact with the beacon chain.
Running a beacon node is a [worthwhile endeavor](https://vitalik.eth.limo/general/2021/05/23/scaling.html#its-crucial-for-blockchain-decentralization-for-regular-users-to-be-able-to-run-a-node) even if you are not planning on validating yourself!

The guide assumes [Ubuntu Linux](https://ubuntu.com/download/server) is being used, and therefore some familiarity with [the Linux command line](https://ubuntu.com/tutorials/command-line-for-beginners) is needed.

!!! tip
    You can practice running the node safely on the [Holesky testnet](./holesky.md).
    Throughout, we'll provide instructions for both Holesky and Mainnet.


## Steps

### 1. Prepare

Prepare your machine by installing [Nimbus' dependencies](./install.md).

### 2. Set up an execution client

To run a beacon node, you need to have access to an execution client exposing the web3 API.
Throughout, we'll assume an execution client is running on the same machine as the beacon node, but this is not required.

See the [execution client guide](./eth1.md) for instructions on how to pick and install an execution client.

### 3. Install Nimbus

=== "Download binaries"

    Binary releases are available from [GitHub](https://github.com/status-im/nimbus-eth2/releases/latest) and our [APT repository](https://apt.status.im/) (Debian/Ubuntu).

    We currently have binaries available for Linux `AMD64`, `ARM` and `ARM64`, Windows `AMD64` and macOS (`AMD64` and `ARM64`).

    See the [binaries guide](./binaries.md) on how to install them.


=== "Build from source"

    Building Nimbus from source is simple and fully automated.
    Follow the [build guide](./build.md).


### 4. Sync from a trusted node

While this step is not mandatory, since Nimbus will automatically start syncing process on the first start, we recommend doing it as it will allow you to get started in **minutes** instead of hours or even days.

Follow our [trusted node sync guide](./trusted-node-sync.md).


### 5. Start the node

Once you've completed previous steps, it is time to start the beacon node.

If you have skipped the syncing from a trusted node step, starting the node will initiate the [syncing process](./start-syncing.md).

```sh
cd nimbus-eth2
```

=== "Mainnet"

    ```sh
    # Start a mainnet node
    ./run-mainnet-beacon-node.sh --web3-url=http://127.0.0.1:8551 --jwt-secret=/tmp/jwtsecret
    ```

=== "Holesky"

    ```sh
    # Start a holesky testnet node
    ./run-holesky-beacon-node.sh --web3-url=http://127.0.0.1:8551 --jwt-secret=/tmp/jwtsecret
    ```

Once the beacon node starts, you'll see it logging information to the console, like so:

```sh
INF 2022-07-19 15:42:58.145+02:00 Launching beacon node                      topics="beacnde" version=v22.10.1-97a1cdc4-stateofus ...
```

Congratulations!
Your beacon node is up and running!

!!! success "What next?"

    * If you will be running the node on a regular basis, it is recommended that you [set up a systemd service](./beacon-node-systemd.md) that automatically restarts your node if the computer reboots.
    * If you wish to stake, continue your journey by following the [validator quick start](./run-a-validator.md).
    * The [monitoring](./health.md) page contains information about how to keep your node healthy.
