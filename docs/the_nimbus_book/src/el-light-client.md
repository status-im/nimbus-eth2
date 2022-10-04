# Run the light client

!!! warning
    The light client is currently in BETA and details around running it may change.

The Nimbus Light Client is a light-weight alternative to running a full beacon node, when setting up an Ethereum execution client for read-only use cases after the merge.

Execution layer (EL) clients provide the [web3 API](https://ethereum.github.io/execution-apis/api-documentation/) to expose information stored on the Ethereum blockchain. Post-merge, EL clients can no longer run standalone and require an external component to determine the latest state to sync to.

## Comparison

Compared to a full beacon node, a light client has several advantages and disadvantages.

| Feature | Light Client | Beacon Node |
| -- | -- | -- |
| Disk usage | **<1MB** | ~70GB |
| Bandwidth | **TBD (low)** | *TBD* |
| Sync time | **Seconds** | Days |
| Head delay | 4/3 slot (15 s) | **None** |
| Security | Light | **Full** |

Light clients delegate full validation to other network participants and operate under a honest supermajority (> 2/3) assumption among elected participants. Due to this delegation, light clients are typically behind by ~4/3 slots (~15 seconds on Ethereum mainnet).

!!! note
    If you are validating, you must run a full beacon node. To use Nimbus, follow the [installation instructions](./install.md).

## Building from source

The Nimbus light client is currently not bundled as part of the Docker images and needs to be built from source.

### 1. Clone the `nimbus-eth2` repository

```sh
git clone https://github.com/status-im/nimbus-eth2
cd nimbus-eth2
```

### 2. Run the build process

To build the Nimbus light client and its dependencies, run:

```sh
make -j4 nimbus_light_client
```

!!! tip
    Omit `-j4` on systems with 4GB of memory or less.

This may take a few minutes. When the process finishes, the `nimbus_light_client` executable can be found in the `build` subdirectory.

## Pairing with the EL client

To ensure that only the light client can control the EL client, a file with random content (JWT secret) must be created. The format is 64 hexadecimal (0-9, a-f) characters. To create one, the following command may be used:

```sh
openssl rand -hex 32 | tr -d "\n" > "$HOME/jwtsecret"
```

!!! tip
    To adjust where the file is created, adjust the `$HOME/jwtsecret` portion in the command above. Also adjust other commands in this guide accordingly.

The JWT secret must be passed to both the EL client and the light client to complete the pairing.

## Running the EL client

In addition to the [regular instructions](./eth1.md) to run an EL client, the JWT secret must be configured. The following sections explain how to do this for certain EL clients.

=== "Geth"

    === "Mainnet"
        ```sh
        geth --ws --authrpc.jwtsecret="$HOME/jwtsecret"
        ```

    === "Goerli"
        ```sh
        geth --goerli --ws --authrpc.jwtsecret="$HOME/jwtsecret"
        ```

=== "Nethermind"

    === "Mainnet"
        ```sh
        nethermind --JsonRpc.JwtSecretFile="$HOME/jwtsecret"
        ```

    === "Goerli"
        ```sh
        nethermind --config goerli --JsonRpc.JwtSecretFile="$HOME/jwtsecret"
        ```

=== "Others"

    Please consult your EL client's documentation for instructions on how to configure the JWT secret and running the EL client.

## Running the light client

The light client starts syncing from a trusted block. This trusted block should be somewhat recent ([~1-2 weeks](https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/weak-subjectivity.md)) and needs to be configured each time when starting the light client.

1. Obtaining a trusted block root

A block root may be obtained from another trusted beacon node, or from a trusted provider.

=== "Trusted beacon node"
    The REST interface must be enabled on the trusted beacon node (`--rest --rest-port=5052` for Nimbus).

    ```sh
    curl -s "http://localhost:5052/eth/v1/beacon/headers/finalized" | \
        jq -r '.data.root'
    ```

=== "Beaconcha.in"
    On the [beaconcha.in](https://beaconcha.in) website ([Goerli](https://prater.beaconcha.in)), navigate to the `Epochs` section and select a recent `Finalized` epoch. Then, scroll down to the bottom of the page. If the bottom-most slot has a `Proposed` status, copy its `Root Hash`. Otherwise, for example if the bottom-most slot was `Missed`, go back and pick a different epoch.

!!! warning
    Selecting a block root from an untrusted source or using an outdated block root may lead to the light client syncing to an unexpected state. If that happens, stop the light client and restart it with a new trusted block root. Depending on the EL client, its database must be deleted and sync restarted from scratch.

2. Starting the light client

To start the light client, run the following commands (inserting your own trusted block root):

=== "Mainnet"
    ```sh
    TRUSTED_BLOCK_ROOT=0x1234567890123456789012345678901234567890123456789012345678901234
    build/nimbus_light_client \
        --web3-url=ws://127.0.0.1:8551 --jwt-secret="$HOME/jwtsecret" \
        --trusted-block-root=$TRUSTED_BLOCK_ROOT
    ```

=== "Goerli"
    ```sh
    TRUSTED_BLOCK_ROOT=0x1234567890123456789012345678901234567890123456789012345678901234
    build/nimbus_light_client --network=goerli \
        --web3-url=ws://127.0.0.1:8551 --jwt-secret="$HOME/jwtsecret" \
        --trusted-block-root=$TRUSTED_BLOCK_ROOT
    ```

!!! tip
    The light client can be left running in the background. Note that a new trusted block root is required when restarting.

## Observing the sync process

After a while, the light client will pick up beacon block headers from the Ethereum network and start informing the EL client about the latest data. You should see logs similar to the following:

### Nimbus

```
NOT 2022-08-20 14:56:58.063+02:00 Starting light client                      topics="lightcl" trusted_block_root=Some(e734eae428acd2e5ab3fb9a6db04926e5cc597a6f3d3b94835b051859539adfa)
...
INF 2022-08-20 15:04:07.674+02:00 New LC optimistic header                   optimistic_header="(slot: 1600, proposer_index: 158, parent_root: \"5692b969\", state_root: \"06befac2\")"
INF 2022-08-20 15:04:07.674+02:00 New LC finalized header                    finalized_header="(slot: 1600, proposer_index: 158, parent_root: \"5692b969\", state_root: \"06befac2\")"
INF 2022-08-20 15:04:08.041+02:00 New LC optimistic header                   optimistic_header="(slot: 3119, proposer_index: 1408, parent_root: \"f42c6c38\", state_root: \"b7cd7a87\")"
INF 2022-08-20 15:04:08.041+02:00 New LC finalized header                    finalized_header="(slot: 3040, proposer_index: 263, parent_root: \"5df53d22\", state_root: \"bed3164c\")"
...
INF 2022-08-20 15:04:08.207+02:00 New LC optimistic header                   optimistic_header="(slot: 432829, proposer_index: 1003, parent_root: \"2f847459\", state_root: \"5d9bbf00\")"
INF 2022-08-20 15:04:08.207+02:00 New LC finalized header                    finalized_header="(slot: 432736, proposer_index: 579, parent_root: \"23dd3358\", state_root: \"7273da0b\")"
WRN 2022-08-20 15:04:08.356+02:00 Peer count low, no new peers discovered    topics="networking" discovered_nodes=0 new_peers=@[] current_peers=15 wanted_peers=160
INF 2022-08-20 15:04:15.984+02:00 New LC optimistic header                   optimistic_header="(slot: 438920, proposer_index: 1776, parent_root: \"81e3f439\", state_root: \"94298e8c\")"
WRN 2022-08-20 15:04:35.212+02:00 Peer count low, no new peers discovered    topics="networking" discovered_nodes=0 new_peers=@[] current_peers=16 wanted_peers=160
INF 2022-08-20 15:04:39.979+02:00 New LC optimistic header                   optimistic_header="(slot: 438921, proposer_index: 163, parent_root: \"9fc27396\", state_root: \"3ff1d624\")"
INF 2022-08-20 15:04:51.982+02:00 New LC optimistic header                   optimistic_header="(slot: 438923, proposer_index: 706, parent_root: \"8112e2f5\", state_root: \"a0628d4a\")"
WRN 2022-08-20 15:04:54.156+02:00 Peer count low, no new peers discovered    topics="networking" discovered_nodes=0 new_peers=@[] current_peers=16 wanted_peers=160
WRN 2022-08-20 15:05:03.161+02:00 Peer count low, no new peers discovered    topics="networking" discovered_nodes=1 new_peers=@[] current_peers=16 wanted_peers=160
INF 2022-08-20 15:05:03.987+02:00 New LC optimistic header                   optimistic_header="(slot: 438924, proposer_index: 1522, parent_root: \"3ff23c0c\", state_root: \"2de6d378\")"
NOT 2022-08-20 15:05:03.987+02:00 New LC optimistic block                    opt=69449681:438924 wallSlot=438925
WRN 2022-08-20 15:05:08.668+02:00 Peer count low, no new peers discovered    topics="networking" discovered_nodes=0 new_peers=@[] current_peers=16 wanted_peers=160
WRN 2022-08-20 15:05:24.971+02:00 Peer count low, no new peers discovered    topics="networking" discovered_nodes=0 new_peers=@[] current_peers=17 wanted_peers=160
WRN 2022-08-20 15:05:30.264+02:00 Peer count low, no new peers discovered    topics="networking" discovered_nodes=0 new_peers=@[] current_peers=17 wanted_peers=160
INF 2022-08-20 15:05:39.982+02:00 New LC optimistic header                   optimistic_header="(slot: 438925, proposer_index: 1275, parent_root: \"69449681\", state_root: \"b1a6c3d6\")"
NOT 2022-08-20 15:05:39.983+02:00 New LC optimistic block                    opt=935c35e8:438925 wallSlot=438928
WRN 2022-08-20 15:05:42.601+02:00 Peer count low, no new peers discovered    topics="networking" discovered_nodes=0 new_peers=@[] current_peers=18 wanted_peers=160
INF 2022-08-20 15:05:51.982+02:00 New LC optimistic header                   optimistic_header="(slot: 438928, proposer_index: 1356, parent_root: \"935c35e8\", state_root: \"331dda33\")"
NOT 2022-08-20 15:05:51.982+02:00 New LC optimistic block                    opt=5dbb26df:438928 wallSlot=438929
```

!!! note
    The [light client protocol](https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md) depends on consensus layer (CL) full nodes to serve additional data. As this is a new protocol, not all implementations are supporting it yet. Therefore, it may take several minutes to discover supporting peers, during which no log messages may be produced.

=== "Geth"

    ```
    WARN [07-24|22:19:16.777] Ignoring payload with missing parent     number=12,658,012 hash=306fad..bdfd44 parent=a22dc7..093bea
    INFO [07-24|22:19:16.778] Forkchoice requested sync to new head    number=12,658,012 hash=306fad..bdfd44
    INFO [07-24|22:19:17.232] Syncing beacon headers                   downloaded=7168 left=12,650,843 eta=13m21.441s
    INFO [07-24|22:19:21.626] Syncing beacon headers                   downloaded=75201 left=0          eta=0s
    INFO [07-24|22:19:21.627] Block synchronisation started
    ```

=== "Nethermind"

    ```
    2022-07-24 22:09:05.0853|Received a new payload: 12657968 (0xa5eedb4e4e4b0f84238464d563b82d7dddadfc68f21cfa2bfcbbbcdb944c4b63)
    2022-07-24 22:09:05.1018|Insert block into cache without parent 12657968 (0xa5eedb...4c4b63)
    2022-07-24 22:09:05.1141|Received: ForkchoiceState: (HeadBlockHash: 0xa5eedb4e4e4b0f84238464d563b82d7dddadfc68f21cfa2bfcbbbcdb944c4b63, SafeBlockHash: 0xa5eedb4e4e4b0f84238464d563b82d7dddadfc68f21cfa2bfcbbbcdb944c4b63, FinalizedBlockHash: 0x0000000000000000000000000000000000000000000000000000000000000000) .
    2022-07-24 22:09:05.1141|Syncing... Block 0xa5eedb4e4e4b0f84238464d563b82d7dddadfc68f21cfa2bfcbbbcdb944c4b63 not found.
    ```
