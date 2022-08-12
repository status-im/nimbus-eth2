# Set up suggested fee recipient

A suggested fee recipient offers an execution client, in a merged Ethereum network, a coinbase it might use, based on the validator that is proposing the block.

!!! warning
    The execution client is not required to follow the suggestion and may instead send the fees to a different address - only use execution clients you trust!

Nimbus offers two ways to a suggested fee recipient, the `--suggested-fee-recipient` option and a per-validator recipient set using the [keymanager API](./keymanager-api.md). Any validator without a per-validator recipient set will fall back to a `--suggested-fee-recipient` if configured. In order, it selects from the first available, for each validator, of:

1. the keymanager API per-validator suggested fee recipient
2. `--suggested-fee-recipient`

For example, `nimbus_beacon_node --suggested-fee-recipient=0x70E47C843E0F6ab0991A3189c28F2957eb6d3842` suggests to the execution client that `0x70E47C843E0F6ab0991A3189c28F2957eb6d3842` might be the coinbase. If this Nimbus node has two validators, one of which has its own suggested fee recipient via the keymanager API and the other does not, the former would use its own per-validator suggested fee cipient while the latter would fall back to `0x70E47C843E0F6ab0991A3189c28F2957eb6d3842`.

## Command line option

=== "Mainnet"
    ```sh
    ./run-mainnet-beacon-node.sh --suggested-fee-recipient=0x70E47C843E0F6ab0991A3189c28F2957eb6d3842
    ```

=== "Prater"
    ```sh
    ./run-mainnet-beacon-node.sh --suggested-fee-recipient=0x70E47C843E0F6ab0991A3189c28F2957eb6d3842
    ```
