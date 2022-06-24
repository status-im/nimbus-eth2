# Run a separate validator client

> ⚠️ This feature is currently in BETA - we are still testing it and implementation details may change in response to community feedback. **We strongly advise against using it on mainnet** - your validators may get slashed

By default, Nimbus loads validator keys into the main beacon node process, which is a simple, safe and efficient way to run a validator.

Advanced users may wish to run validators in a separate process, allowing more flexible deployment strategies. The Nimbus beacon node supports both it's own and third-party validator clients via the built-in [REST API](./rest-api.md).

> ⚠️ So far, all slashings with known causes have been linked to overly complex setups involving separation between beacon node and validator client! Only use this setup if you've taken steps to mitigate the increased risk.

## Build

The validator client is currently only available when built from source. To build the validator client, [build the beacon node](./build.md), then issue:

```sh
make -j4 nimbus_validator_client
```

When upgrading, don't forget to upgrade the validator client also, with the same command as above!

## Setup

To run a separate validator client, you must first make sure that your beacon node has its REST API enabled - start it with the `--rest` option.

Next, choose a data directory for the validator client and import the keys there:

```sh
build/nimbus_beacon_node deposits import \
  --data-dir:build/data/vc_shared_prater_0 "<YOUR VALIDATOR KEYS DIRECTORY>"
```

> ⚠️ Do not use the same data directory for beacon node and validator client - they will both try to load the same keys which may result in slashing!

> ⚠️ If you are migrating your keys from the beacon node to the validator client, simply move the `secrets` and `validators` folders in the beacon node data directory to the data directory of the validator client

With the keys imported, you are ready to start validator client:

```sh
build/nimbus_validator_client \
  --network:prater \
  --data-dir:build/data/vc_shared_prater_0
```

## Options

`nimbus_validator_client` supports command line options similar to the beacon node:
```sh
# See help
build/nimbus_validator_client --help
```

The client will by defualt connect to a beacon node on the same machine as the validator client. Pick a different node with `--beacon-node`:

```sh
build/nimbus_validator_client \
  --network:prater \
  --data-dir:build/data/vc_shared_prater_0 \
  --beacon-node:http://host:port/
```
