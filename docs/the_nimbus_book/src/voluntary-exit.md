# Perform a voluntary exit

```admonish title=''
This feature is available from `v1.7.0` onwards - earlier versions relied on the now removed [JSON-RPC API](./api.md).
```

Voluntary exits allow validators to permanently stop performing their duties, and eventually recover the deposit.

Exits are subject to a wait period that depends on the length of the exit queue. While a validator is exiting, it still must perform its duties in order not to lose funds to inactivity penalities.

```admonish warning
Voluntary exits are **irreversible**. You won't be able to validate again with the same key.

You will also not be able to withdraw your funds until a future hard fork that enables withdrawals.*
```

```admonish note
Voluntary exits won't be processed if the chain isn't finalising.
```

To perform a voluntary exit, make sure your beacon node is running with the `--rest`option enabled (e.g. `./run-mainnet-beacon-node.sh --rest`), then run:


**Mainnet**
```
build/nimbus_beacon_node deposits exit \
  --data-dir=build/data/shared_mainnet_0 \
  --validator=<VALIDATOR_PUBLIC_KEY>
```

**Prater**
```
build/nimbus_beacon_node deposits exit \
  --data-dir=build/data/shared_prater_0 \
  --validator=<VALIDATOR_PUBLIC_KEY>
```

```admonish note
Make sure your `<VALIDATOR_PUBLIC_KEY>` is prefixed with `0x`. In other words the public key should look like `0x95e3...`
```

## `rest-url` parameter

The `--rest-url` parameter can be used to point the exit command to a specific node for publishing the request, as long as it's compatible with the [REST API](./rest-api.md).
