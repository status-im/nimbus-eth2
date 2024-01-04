# Light client

!!! warning
    The light client is currently in BETA and details around running it may change.

The Nimbus Light Client is a light-weight alternative to running a full beacon node, when you're not planning on becoming a validator but still want to run an Ethereum execution layer client.

Execution layer (EL) clients provide the [Web3 API](https://ethereum.github.io/execution-apis/api-documentation/) to expose information stored on the Ethereum blockchain.
Since the merge 🐼, execution clients can no longer run standalone.

## Comparison

Compared to a full beacon node, a light client has several advantages and disadvantages.

| Feature | Beacon Node | Light Client |
| -- | -- | -- |
| Disk usage | ~70GB | **<1MB** |
| Bandwidth | *TBD* | **TBD (low)** |
| Sync time | Hours | **Seconds** |
| Head delay | **None** | 4/3 slot (15 s) |
| Security | **Full** | Light |

Light clients delegate full validation to other network participants and operate under a honest supermajority (> 2/3) assumption among elected participants.
Due to this delegation, light clients are typically behind by ~4/3 slots (~15 seconds on Ethereum mainnet).

!!! note
    If you are validating, you must run a full beacon node.
    To use Nimbus, follow the [installation instructions](./install.md).

## Building from source

The Nimbus light client is currently not bundled as part of the Docker images and needs to be built from source.

### 1. Clone the `nimbus-eth2` repository

```sh
git clone https://github.com/status-im/nimbus-eth2
cd nimbus-eth2
```

### 2. Run the build process

To build the Nimbus light client and its dependencies, make sure you have [all prerequisites](./install.md) and then run:

```sh
make -j4 nimbus_light_client
```

!!! tip
    Omit `-j4` on systems with 4GB of memory or less.

This may take a few minutes.
When the process finishes, the `nimbus_light_client` executable can be found in the `build` subdirectory.

## Pairing with the EL client

To ensure that only the light client can control the EL client, a file with random content (JWT secret) must be created.
The format is 64 hexadecimal (0-9, a-f) characters.
To create one, the following command may be used:

```sh
openssl rand -hex 32 | tr -d "\n" > "$HOME/jwtsecret"
```

!!! tip
    To adjust where the file is created, adjust the `$HOME/jwtsecret` portion in the command above.
    Also adjust other commands in this guide accordingly.

The JWT secret must be passed to both the EL client and the light client to complete the pairing.

## Running the EL client

In addition to the [regular instructions](./eth1.md) to run an EL client, the JWT secret must be configured.
The following sections explain how to do this for certain EL clients.

=== "Geth"

    === "Mainnet"
        ```sh
        geth --authrpc.jwtsecret="$HOME/jwtsecret"
        ```

    === "Holesky"
        ```sh
        geth --holesky --authrpc.jwtsecret="$HOME/jwtsecret"
        ```

=== "Nethermind"

    === "Mainnet"
        ```sh
        nethermind --JsonRpc.JwtSecretFile="$HOME/jwtsecret"
        ```

    === "Holesky"
        ```sh
        nethermind --config holesky --JsonRpc.JwtSecretFile="$HOME/jwtsecret"
        ```

=== "Others"

    Please consult your EL client's documentation for instructions on how to configure the JWT secret and running the EL client.

## Running the light client

The light client starts syncing from a trusted block.
This trusted block should be somewhat recent ([~1-2 weeks](https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/weak-subjectivity.md)) and needs to be configured each time when starting the light client.

### 1. Obtaining a trusted block root

A block root may be obtained from another trusted beacon node, or from a trusted provider.

=== "Trusted beacon node"
    The REST interface must be enabled on the trusted beacon node (`--rest --rest-port=5052` for Nimbus).

    ```sh
    curl -s "http://localhost:5052/eth/v1/beacon/headers/finalized" | \
        jq -r '.data.root'
    ```

=== "Beaconcha.in"
    On the [beaconcha.in](https://beaconcha.in) website ([Holesky](https://holesky.beaconcha.in)), navigate to the `Epochs` section and select a recent `Finalized` epoch.
    Then, scroll down to the bottom of the page.
    If the bottom-most slot has a `Proposed` status, copy its `Root Hash`.
    Otherwise, for example if the bottom-most slot was `Missed`, go back and pick a different epoch.

!!! warning
    Selecting a block root from an untrusted source or using an outdated block root may lead to the light client syncing to an unexpected state.
    If that happens, stop the light client and restart it with a new trusted block root.
    Depending on the EL client, its database must be deleted and sync restarted from scratch.

### 2. Starting the light client

To start the light client, run the following commands (inserting your own trusted block root):

=== "Mainnet"
    ```sh
    TRUSTED_BLOCK_ROOT=0x1234567890123456789012345678901234567890123456789012345678901234
    build/nimbus_light_client \
        --web3-url=http://127.0.0.1:8551 --jwt-secret="$HOME/jwtsecret" \
        --trusted-block-root=$TRUSTED_BLOCK_ROOT
    ```

=== "Holesky"
    ```sh
    TRUSTED_BLOCK_ROOT=0x1234567890123456789012345678901234567890123456789012345678901234
    build/nimbus_light_client --network=holesky \
        --web3-url=http://127.0.0.1:8551 --jwt-secret="$HOME/jwtsecret" \
        --trusted-block-root=$TRUSTED_BLOCK_ROOT
    ```

!!! tip
    The light client can be left running in the background.
    Note that a new trusted block root is required when restarting.

## Observing the sync process

After a while, the light client will pick up beacon block headers from the Ethereum network and start informing the EL client about the latest data.
You should see logs similar to the following:

### Nimbus

```
NTC 2022-11-21 18:00:23.666+01:00 Starting light client                      topics="lightcl" trusted_block_root=some(c092a1d110a1c8d630ac2c3fa2565813d43087f42c986855a2cd985b995a328c)
...
INF 2022-11-21 18:01:24.001+01:00 Slot start                                 slot=1109707 epoch=34678 sync=bootstrapping(c092a1d110a1c8d630ac2c3fa2565813d43087f42c986855a2cd985b995a328c) peers=5 head=fb9b64fe:0 finalized=fb9b64fe:0 delay=1ms495us
INF 2022-11-21 18:01:24.734+01:00 Exchanged engine configuration             topics="eth1" terminalTotalDifficulty=17000000000000000 terminalBlockHash=0x0000000000000000000000000000000000000000000000000000000000000000 terminalBlockNumber=0
...
INF 2022-11-21 18:02:48.001+01:00 Slot start                                 slot=1109714 epoch=34678 sync=bootstrapping(c092a1d110a1c8d630ac2c3fa2565813d43087f42c986855a2cd985b995a328c) peers=6 head=fb9b64fe:0 finalized=fb9b64fe:0 delay=1ms161us
WRN 2022-11-21 18:02:53.603+01:00 Peer count low, no new peers discovered    topics="networking" discovered_nodes=1 new_peers=@[] current_peers=6 wanted_peers=160
INF 2022-11-21 18:03:00.001+01:00 Slot start                                 slot=1109715 epoch=34678 sync=bootstrapping(c092a1d110a1c8d630ac2c3fa2565813d43087f42c986855a2cd985b995a328c) peers=5 head=fb9b64fe:0 finalized=fb9b64fe:0 delay=1ms154us
INF 2022-11-21 18:03:09.989+01:00 New LC optimistic header                   optimistic_header="(beacon: (slot: 1109216, proposer_index: 1813, parent_root: \"0871af30\", state_root: \"5c0afc98\"))"
INF 2022-11-21 18:03:09.989+01:00 New LC finalized header                    finalized_header="(beacon: (slot: 1109216, proposer_index: 1813, parent_root: \"0871af30\", state_root: \"5c0afc98\"))"
INF 2022-11-21 18:03:12.001+01:00 Slot start                                 slot=1109716 epoch=34678 sync=syncing peers=6 head=c092a1d1:1109216 finalized=c092a1d1:1109216 delay=1ms159us
INF 2022-11-21 18:03:16.047+01:00 New LC optimistic header                   optimistic_header="(beacon: (slot: 1109715, proposer_index: 262, parent_root: \"676f4fe4\", state_root: \"2d13aa42\"))"
INF 2022-11-21 18:03:24.001+01:00 Slot start                                 slot=1109717 epoch=34678 sync=synced peers=7 head=58cae92a:1109715 finalized=c092a1d1:1109216 delay=1ms120us
INF 2022-11-21 18:03:27.984+01:00 New LC optimistic header                   optimistic_header="(beacon: (slot: 1109716, proposer_index: 1281, parent_root: \"58cae92a\", state_root: \"de464f71\"))"
WRN 2022-11-21 18:03:31.419+01:00 Peer count low, no new peers discovered    topics="networking" discovered_nodes=0 new_peers=@[] current_peers=7 wanted_peers=160
INF 2022-11-21 18:03:36.001+01:00 Slot start                                 slot=1109718 epoch=34678 sync=synced peers=7 head=c5464508:1109716 finalized=c092a1d1:1109216 delay=1ms98us
INF 2022-11-21 18:03:40.012+01:00 New LC optimistic header                   optimistic_header="(beacon: (slot: 1109717, proposer_index: 835, parent_root: \"c5464508\", state_root: \"13f823f8\"))"
NTC 2022-11-21 18:03:40.012+01:00 New LC optimistic block                    opt=99ab28aa:1109717 wallSlot=1109718
WRN 2022-11-21 18:03:40.422+01:00 Peer count low, no new peers discovered    topics="networking" discovered_nodes=1 new_peers=@[] current_peers=7 wanted_peers=160
INF 2022-11-21 18:03:48.001+01:00 Slot start                                 slot=1109719 epoch=34678 sync=synced peers=7 head=99ab28aa:1109717 finalized=c092a1d1:1109216 delay=1ms53us
WRN 2022-11-21 18:03:50.205+01:00 Peer count low, no new peers discovered    topics="networking" discovered_nodes=0 new_peers=@[] current_peers=7 wanted_peers=160
INF 2022-11-21 18:04:00.001+01:00 Slot start                                 slot=1109720 epoch=34678 sync=synced peers=7 head=99ab28aa:1109717 finalized=c092a1d1:1109216 delay=1ms145us
INF 2022-11-21 18:04:03.982+01:00 New LC optimistic header                   optimistic_header="(beacon: (slot: 1109718, proposer_index: 1202, parent_root: \"99ab28aa\", state_root: \"7f7f88d2\"))"
NTC 2022-11-21 18:04:03.982+01:00 New LC optimistic block                    opt=ab007266:1109718 wallSlot=1109720
```

!!! note
    The [light client protocol](https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md) depends on consensus layer (CL) full nodes to serve additional data.
    As this is a new protocol, not all implementations are supporting it yet.
    Therefore, it may take several minutes to discover supporting peers, during which no log messages may be produced.

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
