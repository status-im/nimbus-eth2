# Historical data

!!! note ""
    This feature is available from `v23.1.0` onwards

In order for the network to remain healthy, each node must keep a minimum of 5 months of historical block data.

Nimbus can be configured to either retain or remove historical data past that point using the `--history` option.

!!! note "Default mode"
    Nimbus currently retains full history by default - after the `Capella` hard fork, this will change to pruning.

## History modes

The history mode controls how far back Nimbus supports answering historical queries in the [REST API](./rest-api.md) - it does not affect the ability to perform validator duties.

In `prune` mode, blocks and states past that point are removed from the database continuously and the freed space is reused for more recent data.

!!! info
    Although blocks and states are pruned, the database will not shrink in size - instead, the freed space is reused for new data

In `archive` mode, queries can be as far back as the state that the database was created with - the checkpoint state in the case of trusted node sync or genesis.

## Switching between modes

It is possible to switch between `prune` and `archive` modes.

When switching to `prune` mode, deep history will be removed from the database and the prune point will be updated continuously as usual. As noted above, the database will not shrink in size - to reclaim space, perform a [trusted node sync](./trusted-node-sync.md) on a fresh database instead.

!!! warning "Backwards compatiblity"
    Versions prior to v23.1.0 do not fully support pruned databases - to downgrade, you may need to perform a [trusted node sync](./trusted-node-sync.md).

When switching to `archive` mode, the node will start keeping history from the most recent prune point, but will not recreate deep history.

In order to recreate deep history in a pruned node, downloading the [era archive of deep history](./era-store.md) and reindexing the database using [trusted node sync](./trusted-node-sync.md) with the `--reindex` option is necessary - this is a lengthy operation.

## Command line

=== "Mainnet"
    ```sh
    ./run-mainnet-beacon-node.sh --history=prune ...
    ```

=== "Prater"
    ```sh
    ./run-prater-beacon-node.sh --history=prune ...
    ```
