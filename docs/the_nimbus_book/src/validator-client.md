# Run a separate validator client

!!! warning
    Some features of the validator client, such as the metrics server, are currently in BETA and details may change in response to community feedback.
    Please consult the `--help` screen for more details.

By default, Nimbus integrates the validator client into the main beacon node process — this is a simple, safe and efficient way to run a validator.

Advanced users may wish to run validators in a separate process, allowing more flexible deployment strategies.
The Nimbus beacon node supports both its own and third-party validator clients via the built-in [REST API](./rest-api.md).

!!! warning
    So far, all slashings with known causes have been linked to overly complex setups involving separation between beacon node and validator client!
    Only use this setup if you've taken steps to mitigate the increased risk.

## Setup

To run a separate validator client, you must first make sure that your beacon node has its REST API enabled: start it with the `--rest` option.

Next, choose a data directory for the validator client and import the keys there:

```sh
build/nimbus_beacon_node deposits import \
  --data-dir:build/data/vc_shared_prater_0 "<YOUR VALIDATOR KEYS DIRECTORY>"
```

!!! warning
    Do not use the same data directory for beacon node and validator client!
    They will both try to load the same keys which may result in slashing!

!!! warning
    If you are migrating your keys from the beacon node to the validator client, simply move the `secrets` and `validators` folders in the beacon node data directory to the data directory of the validator client

With the keys imported, you are ready to start validator client:

```sh
build/nimbus_validator_client \
  --data-dir:build/data/vc_shared_prater_0
```

# Options

See the [validator client options](./validator-client-options.md) page for more information about beacon node roles, redundant setups and sentry nodes!
