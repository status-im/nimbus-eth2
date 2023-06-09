# Set up block builders / MEV

Nimbus supports outsourcing block production to an external block builder, thus presenting the opportunity to capture [Maximal Extractable Value](https://ethereum.org/en/developers/docs/mev/) (MEV).

When external block building is enabled, the beacon node connects to a service using the [builder API](https://ethereum.github.io/builder-specs/) with the execution client acting as a fallback.

Setting up external block building typically involves running an additional service on your server which is configured to choose the best block from one or more relays and having the beacon node connect to this service.

!!! warning
    External block builders introduce additional risk to the block building process which may cause loss of rewards.

    In particular, once Nimbus has signed the block header proposed by the external builder, the execution client can no longer be used as fallback, and the external builder is trusted to complete the building process.

!!! note
    By default, [priority and maximum gas fees](https://eips.ethereum.org/EIPS/eip-1559#abstract) determine transaction inclusion in blocks.

    External block builders may use other strategies for transaction selection, including regulatory constraints and extracted value.
    For further information, check the documentation of the block builder.

## Command line

External block building is must be enabled on both beacon node and [validator client](./validator-client.md) using the `--payload-builder=true` flag.

You can use the `--local-block-value-boost` option to give preference to the best block provided by an execution client, as long as its value is within the specified percentage of the value advertised by the best external builder.

!!! tip
    Setting this flag to a non-zero value is recommended due to the additional risk introduced by the usage of an external block builder.

Additionally, the URL of the service exposing the [builder API](https://ethereum.github.io/builder-specs/) must be provided to the beacon node:

=== "Mainnet Beacon Node"
    ```sh
    ./run-mainnet-beacon-node.sh --payload-builder=true --payload-builder-url=https://${HOST}:${PORT}/
    ```

=== "Prater Beacon Node"
    ```sh
    ./run-prater-beacon-node.sh --payload-builder=true --payload-builder-url=https://${HOST}:${PORT}/
    ```

=== "Validator Client"
    ```sh
    build/nimbus_validator_client --payload-builder=true
    ```

## Useful resources

- [EthStaker MEV setup guide](https://github.com/eth-educators/ethstaker-guides/blob/main/prepare-for-the-merge.md#choosing-and-configuring-an-mev-solution)

- [EthStaker MEV relay list](https://ethstaker.cc/mev-relay-list/)

- [Mainnet Relay Overview](https://beaconcha.in/relays)

- [Goerli Relay Overview](https://goerli.beaconcha.in/relays)
