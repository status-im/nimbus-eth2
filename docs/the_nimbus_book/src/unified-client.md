# Unified client

!!! warning "Pre-release software"
    The Nimbus unified client is currently available as a preview - all aspects of it, including resource requirements, command line interface and in particular the database format will change!

    Have fun with it and let us know how it goes while keeping the above in mind.

The Nimbus unified client runs a full Ethereum node in a single process - no need to run separate consensus and execution clients!

* **Easy to set up and run** - one binary, one process, no JWT secret files, no cross-client communication or timing issues
* **Small database** - the beacon node and execution client share a single data directory
* **Runs without the legacy devp2p network** - as long as you're reasonably synced, the execution chain can be kept up to date from the consensus network (see [CL-driven sync](#cl-driven-sync))
* **Full node** - the node can be used both for [validators](./run-a-validator.md) and as a web3 provider for wallets and dapps

## Quick start

This section takes you from a fresh machine to a fully synced mainnet node.

### Download the client

Binary releases  are available from [github](https://github.com/status-im/nimbus-eth1/releases).

### Checkpoint-sync the consensus chain

Checkpoint-syncing downloads the current list of validators from a trusted source. See [trusted node sync](./trusted-node-sync.md) for more information.

!!! note
    The path specified for `--data-dir` must be an empty directory, as trusted node sync needs to be started from a fresh database.

```sh
# Grab a recent consensus checkpoint
build/nimbus trustedNodeSync \
  --data-dir=build/mainnet \
  --trusted-node-url=http://testing.mainnet.beacon-api.nimbus.team/ \
  --backfill=false
```

With the `--backfill=false` option, historical blocks will be downloaded from the P2P network - omit it to fetch them from the trusted node instead.

### Download the latest execution state snapshot

The [state snapshot](https://eth1-db.nimbus.team/) contains the Ethereum execution state and is used to bootstrap the client more quickly. See the full guide below for alternatives.

!!! note "Glamserdam"
    The unified client relies on the `snap/2` protocol for syncing the Ethereum state, which is not yet available on `mainnet`. With the Glamsterdam upgrade, this step
    will no longer be needed.

!!! warning "Untrusted snapshot"
    Using this snapshot is trusting the Nimbus team to have provided a valid database.
    This gives you a headstart on syncing, but if you don't trust the provider, you should do a full sync instead, either from [era files](./execution-client.md#syncing-using-era-files) or via full sync.

```sh
# Download the latest execution state snapshot
wget https://eth1-db.nimbus.team/mainnet-latest.tar.gz

# Extract the snapshot into the data directory
tar -xzf mainnet-latest.tar.gz -C build/mainnet
```

Together with the checkpoint sync from the previous step, you'll have a fully synced node!

### Run the node

```sh
build/nimbus --data-dir=build/mainnet
```

That's it! The consensus chain starts from the checkpoint while the execution chain is synced via P2P.

You need about **500GB** of space in total, but if you're buying a drive today, get 2 or 4 TB anyway.

To run a node that is immediately useful as a web3 provider and for validators, turn on the APIs:

```sh
build/nimbus --data-dir=build/mainnet --rpc --rest
```

* `--rpc` enables the [web3 API](./execution-client.md) (default port `8545`) which allows connecting wallets
* `--rest` enables the [Beacon API](./rest-api.md) (default port `5052`) that validator clients use

### Testnets

Testnets like `hoodi` can reasonably be synced from P2P all the way, without the checkpoint sync or a state snapshot:

```sh
build/nimbus --network=hoodi --data-dir=build/hoodi
```

This takes a few days at the time of writing.

## Unified binary, split processes

In a single process binary, the beacon node and the execution client each run
together in a single, sharing the data directory and common services - similar
to running the two pieces separately with the same data directory.

The unified binary also provides the option top run the execution client and
beacon node as stand-alone processes. This mode can be also be used to run
Nimbus with other consensus and execution clients.

| Command | Description |
|---------|-------------|
| `nimbus` | Run the unified node (default) |
| `nimbus beaconNode` | Run the consensus beacon node in stand-alone mode |
| `nimbus executionClient` | Run the execution client in stand-alone mode |
| `nimbus lightClient` | Run the consensus light client in stand-alone mode |
| `nimbus import` | Import execution blocks from era or era1 files |
| `nimbus trustedNodeSync` | Checkpoint-sync the beacon node database from a trusted node |

Subcommand options can also be used with the main node - see `nimbus beaconNode --help`, `nimbus executionClient --help` and `nimbus lightClient --help` for the full list.

## CL-driven sync

By default, the unified node has `--el-sync` enabled, which turns on consensus layer (CL)-driven sync of the execution layer (EL): recent execution blocks are sourced from the consensus network instead of the legacy devp2p network.

This means the node can run without the devp2p network as long as you're reasonably synced - for example, after a checkpoint sync and state snapshot as in the [quick start](#quick-start).

There are two consequences of this:

* **No local block production** - the beacon node has no access to the transaction mempool, so it has to rely on external builders to produce blocks
* **Limited execution history** - up to about 5 months of execution block history are sourced from the consensus network

Use `--el-sync=false` to disable CL-driven sync and sync the execution chain via the devp2p network instead.

## Light mode

The `--light` option runs a light node: it pairs the execution client with the [consensus light client](./consensus-light-client.md) instead of a full beacon node, significantly reducing resource requirements.

It requires a `--trusted-block-root` to start from.

## Data directory

Use `--data-dir` to tell Nimbus where to store data:

* if you were already running `nimbus-eth1` or `nimbus-eth2`, you can reuse your existing data directory
* if you had both an eth1 and an eth2 data directory, just merge their contents

## Importing era files

The execution chain can also be imported from [era files](./era-store.md), downloading the history from https://mainnet.era.nimbus.team/ and https://mainnet.era1.nimbus.team/ and placing them in `era` and `era1` in the data directory as the [execution client guide](./execution-client.md#syncing-using-era-files) suggests, then running:

```sh
build/nimbus import
```

This takes a few days on mainnet.

## Running validators

You can run your validators [in the node](./run-a-validator.md#2-import-your-validator-keys) as well - with `--rest` enabled, the node exposes the Beacon API that validator clients use.

## Notes

The unified client is a preview and there are known limitations:

* cross-thread communication between the beacon node and execution client is done using a local instance of web3 / JSON
* the thread pools of the two components are not shared
* discovery is not shared - each of the execution and consensus layer runs its own discovery protocol and consequently the node has two "identities"
* there are efficiency opportunities to exploit, in particular on the memory usage front
* in future versions, the state snapshot will be replaced by snap sync or an equivalent state sync mechanism
