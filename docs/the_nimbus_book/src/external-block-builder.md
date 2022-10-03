# Set up block builders

[Maximal extractable value](https://ethereum.org/en/developers/docs/mev/) involves consensus clients contacting an external block builder which might maximize profit or some other defined metric in ways hindered for a purely local consensus and execution client setup. This external builder network uses the [builder API](https://ethereum.github.io/builder-specs/) which consensus clients use to access external block builder bundles found by searchers. In exchange, such searchers and builders might choose to retain some of the profit gained from such bundles. A builder API relay provides access to multiple searchers via a single URL.

Nimbus supports this API to access these external block builders. If one is configured, the block production flow becomes modified:

1. attempt to use the specified external block builder relay or builder to create an execution payload
2. if the external block builder builder or relay doesn't function, and Nimbus has not signed a blinded beacon block, then fall back to existing local execution client to produce a block

There exists a failure mode, intrinsic to the builder API, wherein the consensus client has signed a blinded proposal and therefore even if the external block builder relay or builder doesn't provide a full block, a consensus client such as Nimbus cannot safely proceed with step 2 and fall back on its local execution client.

!!! note
    By default, [priority and maximum gas fees](https://eips.ethereum.org/EIPS/eip-1559#abstract) determine transaction inclusion in blocks, but external block builders may use other strategies for transaction selection, which might involve regulatory constraints and extracted value. For further information, check the documentation of the block builder.

## Command line option

=== "Mainnet"
    ```sh
    ./run-mainnet-beacon-node.sh --payload-builder=true --payload-builder-url=https://${HOST}:${PORT}/
    ```

=== "Prater"
    ```sh
    ./run-prater-beacon-node.sh --payload-builder=true --payload-builder-url=https://${HOST}:${PORT}/
    ```

## Useful resources

- [MEV relay list](https://github.com/remyroy/ethstaker/blob/main/MEV-relay-list.md)

- [Prater Relay Overview](https://prater.beaconcha.in/relays)
