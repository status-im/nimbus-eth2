# Era store

!!! warning
    This feature is currently in BETA - nodes using era files may need to be resynced as the data format is not yet considered stable.

Era files are a long-term archival format for Ethereum data. They are used to provide an easy interchange medium that clients interested in deep ethereum history can use to recreate past state.

!!! tip
    For more information about era files, see [this post](https://ethresear.ch/t/era-archival-files-for-block-and-consensus-data/13526).

Each era file contains the blocks of 8192 slots (~27 hours). Blocks in era files are considered finalized - since the history no longer is subject to change, the files are suitable to be archived for long-term storage, history recreation and other uses and can be shared using traditional mediums such as `http` and `bittorrent`.

Nimbus can both create and use era files as a starting point to regenerate past history as well as to serve blocks.

## Generating era files

To generate era files, you need to first [build](./build.md) Nimbus from source, and [sync](./start-syncing.md) the node using either full sync or a trusted node sync with [`--backfill`](./trusted-node-sync.md#delay-block-history-backfill) and [`--reindex`](./trusted-node-sync.md#recreate-historical-state-access-indices) enabled.

After that, build the additional `ncli_db` tool:

```sh
make ncli_db
```

The era export tool works by reading an existing Nimbus database and creating an era store. Every time the tool is run, it will check the existing store and export any new data to it.

```sh
# Go to the data directory of nimbus (the directory passed to --data-dir)
cd build/data/shared_mainnet_0/

# Create a directory for the era store
mkdir -p era
cd era

# Launch the era export
../../../ncli_db exportEra --db:../db
```

The first time the export is run, full history is exported which make take some time. Subsequent runs will top up the era store with new blocks.

It is recommended to set up a cron job or a timer, and run the export command every hour - doing so will ensure that era files are created on a timely basis.

!!! tip
    You do not need to stop Nimbus to generate era files - it is however not recommended to run era file generation on a node that is also serving validators.


## Sharing era files

Era files can be shared directly from the `era` folder using a web server, or simply by copying them to a new location.

## Importing era files

Nimbus supports reading era files directly, replacing the backfill of a trusted node sync. To use era files instead of backfill, copy the `era` folder to the data directory, then perform a [trusted node sync](./trusted-node-sync.md) with `--backfill=false`.

```sh
# Go to the nimbus directory
cd build/data/shared_mainnet_0

# Create era directory
mkdir -p era

# Download era store from era provider
wget --no-parent  -A '*.era' -q --show-progress -nd -r -c https://provider/era
```

## Options

You can pass a custom era store location to Nimbus using `--era-dir` - multiple Nimbus instances can share the same era store.

```sh
nimbus_beacon_node --era-dir:/path/to/era
```

!!! tip
    Multiple nimbus beacon node instances can share the same era store
