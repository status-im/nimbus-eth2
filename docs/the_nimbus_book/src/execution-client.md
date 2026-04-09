# Execution client

!!! warning "Pre-release software"
    The Nimbus execution client is currently available as a proof of concept - all aspects of it, including resource requirements, command line interface and in particular the database format will change!

    Have fun with it and let us know how it goes while keeping the above in mind.

    If you're looking for information about setting up an execution client for validator duties or any other production usage, see the [execution clients guide](./eth1.md).

The Nimbus execution client is a light-weight implementation of the Ethereum execution protocol.

It provides access to the Ethereum blockchain for dapps and users alike via the standard [Web3 API](https://ethereum.github.io/execution-apis/api-documentation/).

This document describes how to pair the execution client with an external beacon node.

The execution client can also run as part of the [unified node](https://github.com/status-im/nimbus-eth1/pull/3646), without a separate beacon node process.

## Building from source

The Nimbus execution client is currently only provided as a source code distribution.

### Clone the `nimbus-eth1` repository

```sh
git clone https://github.com/status-im/nimbus-eth1
cd nimbus-eth1
```

### Run the build process

To build the Nimbus execution client and its dependencies, make sure you have [all prerequisites](./install.md) and then run:

```sh
make -j8 nimbus
```

This may take a few minutes.

When the process finishes, the `nimbus` executable can be found in the `build` subdirectory.

## Syncing using era files

Syncing Nimbus requires a set of `era1` and `era` files. These can be generated from a `geth` and `nimbus` consensus client respectively or downloaded from a third-party repository.

In addition to the era files themselves, you will need at least 200GB of free space on a fast SSD in your data directory, as set by the `--data-dir` command line option.

When using Nimbus for both execution client and beacon node, the nodes can share the same data directory.

!!! info "`era` file downloading"
    `era` and `era1` files for testing purposes could at the time of writing be found here - these sources may or may not be available:

    === "Mainnet"
        * https://mainnet.era.nimbus.team/
        * https://mainnet.era1.nimbus.team/

    === "Hoodi"
        * https://hoodi.era.nimbus.team/

        The Hoodi network does not have `era1` files since it never operated as a proof-of-work chain

    === "Sepolia"
        * https://sepolia.era.nimbus.team/
        * https://sepolia.era1.nimbus.team/

    A wider community maintained list of `era` and `era1` files can be found eth-clients github [history-endpoints](https://eth-clients.github.io/history-endpoints/)

    Downloading these files can take a long time, specially if you are downloading sequentially.
    For easier and fast download, please use the `era_downloader.sh` script provided in the `nimbus-eth1` repository.
    #### You'll need:
    - [`aria2`](https://aria2.github.io/) installed:
        - **macOS**: `brew install aria2`
        - **Ubuntu/Debian**: `sudo apt install aria2`
    - Standard Unix tools: `bash`, `awk`, `find`, `grep`, `curl`

    === "Mainnet"
        ```sh
        cd nimbus-eth1
        chmod +x scripts/era_downloader.sh
        ./scripts/era_downloader.sh https://mainnet.era1.nimbus.team/ ../build/era1
        ./scripts/era_downloader.sh https://mainnet.era.nimbus.team/ ../build/era
        ```

    === "Hoodi"
        ```sh
        cd nimbus-eth1
        chmod +x scripts/era_downloader.sh
        ./scripts/era_downloader.sh https://hoodi.era.nimbus.team/ ../build/era
        ```

    === "Sepolia"
        ```sh
        cd nimbus-eth1
        chmod +x scripts/era_downloader.sh
        ./scripts/era_downloader.sh https://sepolia.era1.nimbus.team/ ../build/era1
        ./scripts/era_downloader.sh https://sepolia.era.nimbus.team/ ../build/era
        ```

It is recommended that you place the era files in the data directory under `era1` and `era` respectively. Era files can be shared between multiple nodes and can reside on a slow drive - use the `--era1-dir` and `--era-dir` options if they are located outside of the data directory.

See the [era file guide](./era-store.md) for more information.

!!! tip ""
    Future versions of Nimbus will support other methods of syncing, such as snap sync.

=== "Mainnet"
    !!! note ""
        Performing a full sync of mainnet from era files takes several days - its speed varies greatly depending on hardware. Use one of the testnets to get started more quickly!

    ```sh
    build/nimbus executionClient --data-dir=build/mainnet import
    ```

=== "Hoodi"
    ```sh
    build/nimbus executionClient --network=hoodi --data-dir=build/hoodi import
    ```

=== "Sepolia"
    ```sh
    build/nimbus executionClient --network=sepolia --data-dir=build/sepolia import
    ```

## Launch the client

In order for the execution client to operate, you need to connect a consensus node. This can be the [Nimbus beacon node](./quick-start.md), a [supported consensus client](https://ethereum.org/en/developers/docs/nodes-and-clients/#consensus-clients) or a [consensus light client](./consensus-light-client.md).

The consensus node connects to the execution client via the Engine API which is enabled using `--engine-api` and by default runs on port `8551`.

During startup, a `jwt.hex` file will be placed in the data directory containing authentication information that the consensus node uses to connect - make sure to use the same `jwt.hex` file on both consensus and execution node.

=== "Mainnet"
    ```sh
    build/nimbus executionClient --data-dir=build/mainnet --engine-api
    ```

=== "Hoodi"
    ```sh
    build/nimbus executionClient --network=hoodi --data-dir=build/hoodi --engine-api
    ```

=== "Sepolia"
    ```sh
    build/nimbus executionClient --network=sepolia --data-dir=build/sepolia --engine-api
    ```

!!! tip "Unified node"
    Nimbus also supports running Ethereum as a single process, in the [unified node](https://github.com/status-im/nimbus-eth1/pull/3646)

## Optionally quickstart with a pre-synced database

!!! warning "Unverified pre-synced database"
    The pre-synced database is provided by the Nimbus team which contained the state, but using this database is trusting the team to have provided a valid database. This gives you a headstart on syncing, but if you don't trust the provider, you should do a full sync instead, either from era files or from the p2p network.
    The pre-synced database is not available for all networks, and is only available for mainnet

If you want to skip the era file import and start with a pre-synced database, you can download a pre-synced database from the Nimbus team. This database is for now only available for the mainnet.

```sh
# Download the pre-synced database
wget https://eth1-db.nimbus.team/mainnet-latest.tar.gz

# Extract the database into the data directory
tar -xzf mainnet-latest.tar.gz
```

This will extract the pre-synced database into the current directory, which you can then use as your data directory.

## Using the consensus node to sync

While era files cover the majority of chain history. In most cases, Nimbus will automatically sync recent blocks via peer-to-peer networking.
However, if your node is stuck, has no peers, or you're on a weak network connection, you can optionally use nrpc to sync recent blocks directly from a connected consensus node using the Engine API.

This method of syncing loads blocks from the consensus node and passes them to the execution client via the Engine API.

=== "Mainnet"
    ```sh
    ./build/nrpc sync --beacon-api=http://localhost:5052 --el-engine-api=http://localhost:8550 --jwt-secret=build/mainnet/jwt.hex
    ```

=== "Hoodi"
    ```sh
    ./build/nrpc sync --network=hoodi --beacon-api=http://localhost:5052 --el-engine-api=http://localhost:8550 --jwt-secret=build/hoodi/jwt.hex
    ```

=== "Sepolia"
    ```sh
    ./build/nrpc sync --network=sepolia --beacon-api=http://localhost:5052 --el-engine-api=http://localhost:8550 --jwt-secret=build/sepolia/jwt.hex
    ```

!!! tip ""
    Future versions of Nimbus will support snap sync.
