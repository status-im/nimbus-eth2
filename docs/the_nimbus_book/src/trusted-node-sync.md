# Sync from a trusted node

!!! note ""
    This feature is available from `v1.7.0` onwards

When you [start the beacon node](./quick-start.md) for the first time, it will connect to the beacon chain network and start syncing automatically - a process that can take several days.

Trusted node sync allows you to get started more quickly by fetching a recent checkpoint from a trusted node - you can get started in minutes instead of days.

To use trusted node sync, you must have access to a node that you trust that exposes the [Beacon API](./rest-api.md) (for example a locally running backup node).

Should this node, or your connection to it, be compromised, your node will not be able to detect whether or not it is being served false information.

It is possibly to use trusted node sync with a third-party API provider -- see [here](trusted-node-sync.md#verify-you-synced-the-correct-chain) for how to verify that the chain you are given corresponds to the canonical chain at the time.

!!! tip
    A list of community-operated checkpoint sync nodes can be found [here](https://eth-clients.github.io/checkpoint-sync-endpoints/) - always verify after after a checkpoint sync that the right chain was provided by the node.

## Perform a trusted node sync

!!! tip
    Make sure to replace `http://localhost:5052` in the commands below with the appropriate endpoint of the trusted beacon node. `http://localhost:5052` is the default endpoint exposed by Nimbus, but this is not consistent across all clients.

    For example, if your trusted node is a [Prysm node](https://docs.prylabs.network/docs/how-prysm-works/ethereum-public-api#performing-requests-against-a-local-prysm-node), it exposes `127.0.0.1:3500` by default. Which means you would run the commands below with `--trusted-node-url=http://127.0.0.1:3500`

!!! note
    The path specified for `--data-dir` must be an empty directory as trusted node sync needs to be started from a fresh database.

To start trusted node sync, run:

=== "Mainnet"
    ```sh
    build/nimbus_beacon_node trustedNodeSync \
      --network:mainnet \
      --data-dir=build/data/shared_mainnet_0 \
      --trusted-node-url=http://localhost:5052
    ```

=== "Prater"
    ```sh
    build/nimbus_beacon_node trustedNodeSync --network:prater \
    --data-dir=build/data/shared_prater_0  \
    --trusted-node-url=http://localhost:5052
    ```

If the command was executed succesfully, following log lines will be visible:

```
Writing checkpoint state
Writing checkpoint block
```
And eventually:
```
Done, your beacon node is ready to serve you! Don't forget to check that you're on the canonical chain by comparing the checkpoint root with other online sources. See https://nimbus.guide/trusted-node-sync.html for more information.
```

After this the application will terminate and you can now [start the `nimbus_beacon_node`](./quick-start.md) with your usual command.

!!! note
    Because trusted node sync by default copies all blocks via REST, you may hit API limits if you are using a third-party provider. If this happens to you, you may need to use the `--backfill` option to [delay the backfill of the block history](./trusted-node-sync.md#delay-block-history-backfill).


## Verify you synced the correct chain

When performing a trusted node sync, you can manually verify that the correct chain was synced by comparing the head hash with other sources (e.g. your friends, forums, chats and web sites). If you're syncing using your own backup node you can retrieve the current head from the node using:

```sh
# Make sure to enable the `--rest` option when running your node:

curl http://localhost:5052/eth/v1/beacon/blocks/head/root
```

The `head` root is also printed in the log output at regular intervals.

!!! note
    The same [Beacon API](./rest-api.md) request works with any API provider.

    For example, to compare it out with our mainnet [testing server](rest-api.md#test-your-tooling-against-our-servers), you can run:
    `curl -X GET http://testing.mainnet.beacon-api.nimbus.team/eth/v1/beacon/blocks/head/root`

## Advanced

### Delay block history backfill

By default, both the state and the full block history will be downloaded from the trusted node.

It is possible to get started more quickly by delaying the backfill of the block history using the `--backfill=false` parameter. In this case, the beacon node will first sync to the current head so that it can start performing its duties, then backfill the blocks from the network.

You can also resume the trusted node backfill at any time by simply running the trusted node sync command again.

!!! note
    While backfilling blocks, your node will not be able to answer historical requests or sync requests. This might lead to you being de-scored, and eventually disconnected, by your peers.

### Modify sync point

By default, the node will sync up to the latest finalized checkpoint of the node that you're syncing with. While you can choose a different sync point using a state hash or a slot number, this state must fall on an epoch boundary:

```sh
build/nimbus_beacon_node trustedNodeSync \
  --network:mainnet \
  --data-dir=build/data/shared_mainnet_0 \
  --state-id:1024
```

### Sync from checkpoint files

If you have a state file available, you can start the node using the `--finalized-checkpoint-state`:

```sh
# Obtain a state and a block from a Beacon API - these must be in SSZ format:
curl -o state.32000.ssz \
  -H 'Accept: application/octet-stream' \
  http://localhost:5052/eth/v2/debug/beacon/states/32000

# Start the beacon node using the downloaded state as starting point
./run-mainnet-beacon-node.sh \
  --finalized-checkpoint-state=state.32000.ssz
```

## Recreate historical state access indices

When performing checkpoint sync, the historical state data from the time before the checkpoint is not available. To recreate the indices and caches necessary for historical state access, run trusted node sync with the `--reindex` flag - this can be done on an already-synced node as well, in which case the process will simply resume where it left off:

```sh
build/nimbus_beacon_node trustedNodeSync \
  --network:mainnet \
  --data-dir=build/data/shared_mainnet_0 \
  --reindex=true
```
