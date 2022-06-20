# Perform a voluntary exit

Voluntary exits allow validators to permanently stop performing their duties, and eventually recover the deposit.

Exits are subject to a wait period that depends on the length of the exit queue. While a validator is exiting, it still must perform its duties in order not to lose funds to inactivity penalities.

> ⚠️ Voluntary exits are **irreversible**. You won't be able to validate again with the same key. And you won't be able to withdraw your stake until the Eth1 and Eth2 merge. *Note that voluntary exits won't be processed if the chain isn't finalising.*

To perform a voluntary exit, make sure your beacon node is running with the `--rest`option enabled (e.g. `./run-mainnet-beacon-node.sh --rest`), then run:

**Prater**

```
build/nimbus_beacon_node deposits exit \
 --validator=<VALIDATOR_PUBLIC_KEY> \
 --data-dir=build/data/shared_prater_0
```


**Mainnet**

```
build/nimbus_beacon_node deposits exit \
 --validator=<VALIDATOR_PUBLIC_KEY> \
 --data-dir=build/data/shared_mainnet_0
```

> **Note:** Make sure your `<VALIDATOR_PUBLIC_KEY>` is prefixed with `0x`. In other words the public key should look like `0x95e3...`

## `rest-url` parameter

> **Note:** This feature is available from `v1.7.0` onwards - earlier versions relied on the now removed [JSON-RPC API](./api.md).

The `--rest-url` parameter can be used to point the exit command to a specific node for publishing the request, as long as it's compatible with the [REST API](./rest-api.md).
