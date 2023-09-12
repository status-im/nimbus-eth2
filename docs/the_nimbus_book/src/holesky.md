# Holešky testnet

`holesky` will be launched on 15h of September to succeed Prater as the main long-running Ethereum testnet.

It provides an opportunity to verify your setup works as expected through the proof-of-stake transition and in a post-merge context as well as to safely practice node operations such as adding and removing validators, migrating between clients, and performing upgrades and backups.
If you come across any issues, please [report them here](https://github.com/status-im/nimbus-eth2/issues).

## General Preparation

1. Generate the JWT secret with `openssl rand -hex 32 | tr -d "\n" > "/opt/jwtsecret"`. This file needs to be passed to both the execution client and the consensus client.

2. Choose an Ethereum address to receive transaction fees.
   This ETH will be immediately available, not part of the staking contract.

3. Download the [latest release](./binaries.md) and install it by unpacking the archive.

4. Choose one of Nethermind, Besu, Erigon, or Geth as an execution client.
   Download, install, and [run it](https://notes.ethereum.org/@launchpad/goerli#Run-an-Execution-Layer-Client).

    === "Nethermind"

        ```sh
        cd nethermind/src/Nethermind/Nethermind.Runner
        dotnet run -c Release -- --config holesky \
          --JsonRpc.Host=0.0.0.0 \
          --JsonRpc.JwtSecretFile=/opt/jwtsecret
        ```

    === "Erigon"

        ```sh
        ./build/bin/erigon --chain=holesky \
          --datadir holesky-testnet \
          --authrpc.jwtsecret=/opt/jwtsecret \
          --http --http.api=engine,net,eth
        ```

    === "Besu"

        ```sh
        build/install/besu/bin/besu     \
          --network=holesky             \
          --rpc-http-enabled=true       \
          --rpc-http-host="0.0.0.0"     \
          --rpc-http-cors-origins="*"   \
          --sync-mode="X_SNAP"          \
          --data-storage-format="BONSAI"\
          --Xmerge-support=true         \
          --rpc-ws-host="0.0.0.0"       \
          --host-allowlist="*"          \
          --engine-rpc-enabled=true     \
          --engine-host-allowlist="*"   \
          --engine-jwt-enabled=true     \
          --engine-jwt-secret=/opt/jwtsecret
        ```





    ## Sync the beacon node and execution client

5. [Start syncing](./start-syncing.md) the node consisting of Nimbus and chosen execution client, for example by running:
    ```sh
    nimbus-eth2/build/nimbus_beacon_node \
        --network=holesky \
        --web3-url=http://127.0.0.1:8551 \
        --rest \
        --metrics \
        --jwt-secret="/opt/jwtsecret" \
        --suggested-fee-recipient=<Enter-eth-address-here>
    ```

    !!! tip
        If you want the syncing process to complete much faster, you can [sync from a trusted node](./trusted-node-sync.md).

    One might consider here to [set up a systemd service](./beacon-node-systemd.md) to ensure this runs automatically, including after restarts.





    ## Obtaining genesis file (optional)

    By default, Nimbus will automatically download the genesis state of Holešky from Github through the HTTPS protocol.
    If something prevents you from using this method, you may be able to work-around the issue by either instructing Nimbus to use a different URL by specifying the `--genesis-state-url` command-line parameter (for example, you can point it to the `/eth/v2/debug/beacon/states/genesis` endpoint of a trusted beacon node or a checkpoint provider) or by downloading the `genesis.ssz` file of the network through some other means and then supplying its path through the `--genesis-state` command-line parameter.





    ## Begin validating

6. Once this Holešky node is [completely synced](./keep-an-eye.md#keep-track-of-your-syncing-progress), use the [Holesky launchpad](https://holesky.launchpad.ethereum.org/en/) to obtain Holesky validators.
It might require some time before these enter and are activated on the beacon chain.
If one does this before the node which will attest and propose using those validators has synced, one might miss attestations and block proposals.

7. Follow our validating guide from [step 2 (import the validator keys) onward](./run-a-validator.md#2-import-your-validator-keys).







## Useful resources

- Holesky [landing page](https://holesky.ethpandaops.io): view block explorers, request funds from the faucet, and connect to a JSON RPC endpoint.

- Holesky [EF launchpad notes](https://notes.ethereum.org/@launchpad/holesky): how to run a node; contains instructions for how to build Nimbus from source for this purpose

- Holesky consensus layer [beacon chain explorer](https://holesky.beaconcha.in/)

- Holesky execution layer [transaction explorer](https://holesky.etherscan.io/)
