# Historical data

!!! note ""
    This feature is available from Nimbus `v23.1.0` onwards.

Ethereum consensus nodes are required to keep a minimum of 5 months of historical block data ensuring the health of the network.

Nimbus can be configured to either retain or remove historical data past that point using the `--history` option. By default, Nimbus prunes historical data.

## History modes

The history mode controls how far back Nimbus supports answering historical queries in the [REST API](./rest-api.md).
It does not affect the ability to perform validator duties.

In `prune` mode, blocks and states past that point are removed from the database continuously and the freed space is reused for more recent data.

!!! tip "Database size"
    Although blocks and states are pruned, the database will not shrink in size: instead, the freed space is reused for new data.

In `archive` mode, queries can be as far back as the state that the database was created with — the checkpoint state in the case of trusted node sync or genesis.

## Switching between modes

It is possible to switch between `prune` and `archive` modes.

When switching to `prune` mode, deep history will be removed from the database and the prune point will be updated continuously as usual.

As noted above, the database will not shrink in size.
To reclaim space, perform a [trusted node sync](./trusted-node-sync.md) using a fresh database.

When switching to `archive` mode, the node will start keeping history from the most recent prune point, but will not recreate deep history.

In order to recreate deep history in a pruned node, download the [era archive of deep history](./era-store.md) and [reindex the database](./trusted-node-sync.md#recreate-historical-state-access-indices) — this operation may take several hours.

## Command line

=== "Mainnet"
    ```sh
    ./run-mainnet-beacon-node.sh --history=prune ...
    ```

=== "Holesky"
    ```sh
    ./run-holesky-beacon-node.sh --history=prune ...
    ```
