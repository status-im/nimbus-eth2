# Run the light client

!!! warning
    The light client is currently in BETA and details around running it may change.

The Nimbus Light Client is a light-weight alternative to running a full beacon node, when setting up an Ethereum execution client for read-only use cases after the merge.

Execution layer (EL) clients provide the [web3 API](https://ethereum.github.io/execution-apis/api-documentation/) to expose information stored on the Ethereum blockchain. With [the merge 🐼](./merge.md), EL clients can no longer run standalone and require an external component to determine the latest state to sync to.

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
NOT 2022-07-24 21:57:57.537+02:00 Starting light client                      topics="lightcl" trusted_block_root=Some(f013a6f35bdfcffbf9cf8919c48bc0afb7720fb9c61f62a3659d7359f52386c4)
...
INF 2022-07-24 22:07:59.892+02:00 New LC optimistic header                   optimistic_header="(slot: 396960, proposer_index: 90824, parent_root: \"77d30de6\", state_root: \"9c7343a0\")"
INF 2022-07-24 22:07:59.892+02:00 New LC finalized header                    finalized_header="(slot: 396960, proposer_index: 90824, parent_root: \"77d30de6\", state_root: \"9c7343a0\")"
INF 2022-07-24 22:08:03.962+02:00 New LC optimistic header                   optimistic_header="(slot: 397539, proposer_index: 97474, parent_root: \"063c998d\", state_root: \"0f790eaf\")"
WRN 2022-07-24 22:08:09.217+02:00 Peer count low, no new peers discovered    topics="networking" discovered_nodes=2 new_peers=@[] current_peers=11 wanted_peers=160
INF 2022-07-24 22:08:15.961+02:00 New LC optimistic header                   optimistic_header="(slot: 397540, proposer_index: 56720, parent_root: \"812d4790\", state_root: \"b846e95e\")"
INF 2022-07-24 22:08:27.961+02:00 New LC optimistic header                   optimistic_header="(slot: 397541, proposer_index: 65758, parent_root: \"725e435d\", state_root: \"559fd631\")"
INF 2022-07-24 22:08:39.960+02:00 New LC optimistic header                   optimistic_header="(slot: 397542, proposer_index: 90389, parent_root: \"903645d6\", state_root: \"873c9904\")"
WRN 2022-07-24 22:08:49.503+02:00 Peer count low, no new peers discovered    topics="networking" discovered_nodes=1 new_peers=@[] current_peers=11 wanted_peers=160
INF 2022-07-24 22:08:51.960+02:00 New LC optimistic header                   optimistic_header="(slot: 397543, proposer_index: 73061, parent_root: \"1abdfcd1\", state_root: \"c8ee813c\")"
WRN 2022-07-24 22:08:55.097+02:00 Peer count low, no new peers discovered    topics="networking" discovered_nodes=0 new_peers=@[] current_peers=11 wanted_peers=160
INF 2022-07-24 22:09:03.961+02:00 New LC optimistic header                   optimistic_header="(slot: 397544, proposer_index: 62086, parent_root: \"4797507d\", state_root: \"60815f6a\")"
NOT 2022-07-24 22:09:05.069+02:00 New LC optimistic block                    opt=c6cf8526:397409 wallSlot=397545
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
