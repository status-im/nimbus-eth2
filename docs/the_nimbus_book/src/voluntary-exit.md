# Perform a voluntary exit

!!! note ""
    This feature is available from `v1.7.0` onwards - earlier versions relied on the now removed [JSON-RPC API](./api.md).

Voluntary exits allow validators to permanently stop performing their duties, and eventually recover the deposit.

Exits are subject to a wait period that depends on the length of the exit queue. While a validator is exiting, it still must perform its duties in order not to lose funds to inactivity penalities.

!!! warning
    Voluntary exits are **irreversible**. You won't be able to validate again with the same key.

    You will also not be able to withdraw your funds until a future hard fork that enables withdrawals.*

!!! note
    Voluntary exits won't be processed if the chain isn't finalising.

To perform a voluntary exit, make sure your beacon node is running with the `--rest` option enabled (e.g. `./run-mainnet-beacon-node.sh --rest`), then run:

=== "Mainnet"
    ```
    build/nimbus_beacon_node deposits exit \
      --data-dir=build/data/shared_mainnet_0 \
      --validator=<VALIDATOR_KEYSTORE_PATH>
    ```

=== "Prater"
    ```
    build/nimbus_beacon_node deposits exit \
      --data-dir=build/data/shared_prater_0 \
      --validator=<VALIDATOR_KEYSTORE_PATH>
    ```

!!! note
    In the command above, you must replace `<VALIDATOR_KEYSTORE_PATH>` with the file-system path of an Ethereum [ERC-2335 Keystore](https://eips.ethereum.org/EIPS/eip-2335) created by a tool such as [staking-deposit-cli](https://github.com/ethereum/staking-deposit-cli) or [ethdo](https://github.com/wealdtech/ethdo).

## `rest-url` parameter

The `--rest-url` parameter can be used to point the exit command to a specific node for publishing the request, as long as it's compatible with the [REST API](./rest-api.md).
