# Execution client

!!! warning "Pre-release software"
    The Nimbus execution client is currently available as a proof of concept - all aspects of it, including resource requirements, command line interface and in particular the database format will change!

    Have fun with it and let us know how it goes while keeping the above in mind.

    If you're looking for information about setting up an execution client for validator duties or any other production usage, see the [execution clients guide](./eth1.md).

The Nimbus execution client is a light-weight implementation of the Ethereum execution protocol. Paired with a [beacon node](./quick-start.md) or [light client](./el-light-client.md), it provides access to Ethereum blockchain for dapps and users alike via the standard [Web3 API](https://ethereum.github.io/execution-apis/api-documentation/).

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
make -j4 nimbus_execution_client nrpc
```

This may take a few minutes.

When the process finishes, the `nimbus_execution_client` and `nrpc` executables can be found in the `build` subdirectory.

## Import era files

Syncing Nimbus requires a set of `era1` and `era` files. These can be generated from a `geth` and `nimbus` consensus client respectively or downloaded from a third-party repository.

In addition to the era files themselves, you will need at least 200GB of free space on a fast SSD in your data directory, as set by the `--data-dir` command line option.

!!! info "`era` file download locations"
    `era` and `era1` files for testing purposes could at the time of writing be found here - these sources may or may not be available:

    === "Mainnet"
        * https://mainnet.era.nimbus.team/
        * https://mainnet.era1.nimbus.team/

    === "Holesky"
        * https://holesky.era.nimbus.team/

        The Holesky network does not have `era1` files since it never operated as a proof-of-work chain

    === "Sepolia"
        * https://sepolia.era.nimbus.team/
        * https://sepolia.era1.nimbus.team/

It is recommended that you place the era files in the data directory under `era1` and `era` respectively. Era files can be shared between multiple nodes and can reside on a slow drive - use the `--era1-dir` and `--era-dir` options if they are located outside of the data directory.

See the [era file guide](./era-store.md) for more information.

!!! tip ""
    Future versions of Nimbus will support other methods of syncing

=== "Mainnet"
    !!! note ""
        Performing a full sync of mainnet from era files takes several days - its speed varies greatly depending on hardware. Use one of the testnets to get started more quickly!

    ```sh
    build/nimbus_execution_client --data-dir=build/mainnet import
    ```


=== "Holesky"
    ```sh
    build/nimbus_execution_client --network=holesky --data-dir=build/holesky import
    ```

=== "Sepolia"
    ```sh
    build/nimbus_execution_client --network=sepolia --data-dir=build/sepolia import
    ```

## Launch the client

In order for the execution client to operate, you need to connect a consensus node. This can be the [Nimbus beacon node](./quick-start.md), a [supported consensus client](https://ethereum.org/en/developers/docs/nodes-and-clients/#consensus-clients) or a [light client](./el-light-client.md).

The consensus node connects to the execution client via the Engine API which is enabled using `--engine-api` and by default runs on port `8551`.

During startup, a `jwt.hex` file will be placed in the data directory containing authentication information that the consensus node uses to connect - make sure to use the same `jwt.hex` file on both consensus and execution node.

=== "Mainnet"
    ```sh
    build/nimbus_execution_client --data-dir=build/mainnet --engine-api
    ```

=== "Holesky"
    ```sh
    build/nimbus_execution_client --network=holesky --data-dir=build/holesky --engine-api
    ```

=== "Sepolia"
    ```sh
    build/nimbus_execution_client --network=sepolia --data-dir=build/sepolia --engine-api
    ```

## Top up blocks from the consensus node

While era files cover the majority of chain history, Nimbus currenty relies on the consensus node to sync the most recent blocks using the `nrpc` helper.

This method of syncing loads blocks from the consensus node and passes them to the execution client via the Engine API.

=== "Mainnet"
    ```sh
    # Start `nrpc` every 2 seconds in case there is a fork or the execution client goes out of sync
    while true; do build/nrpc sync --beacon-api=http://localhost:5052 --el-engine-api=http://localhost:8550 --jwt-secret=build/mainnet/jwt.hex; sleep 2; done
    ```

=== "Holesky"
    ```sh
    # Start `nrpc` every 2 seconds in case there is a fork or the execution client goes out of sync
    while true; do build/nrpc sync --network=holesky --beacon-api=http://localhost:5052 --el-engine-api=http://localhost:8550 --jwt-secret=build/holesky/jwt.hex; sleep 2; done
    ```

=== "Sepolia"
    ```sh
    # Start `nrpc` every 2 seconds in case there is a fork or the execution client goes out of sync
    while true; do build/nrpc sync --network=sepolia --beacon-api=http://localhost:5052 --el-engine-api=http://localhost:8550 --jwt-secret=build/sepolia/jwt.hex; sleep 2; done
    ```

!!! tip ""
    Future versions of Nimbus will support other methods of syncing
