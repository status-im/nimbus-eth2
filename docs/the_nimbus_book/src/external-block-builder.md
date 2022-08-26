# Set up block builders

[Maximal extractable value](https://ethereum.org/en/developers/docs/mev/) involves consensus clients contacting an external execution payload builder which might maximize profit or some other defined metric in ways hindered for a purely local consensus and execution client setup. This external builder network uses the [builder API](https://ethereum.github.io/builder-specs/) which consensus clients use to access MEV bundles found by searchers. In exchange, such searchers and builders might choose to retain some of the profit gained from such bundles. A builder API relay provides access to multiple searchers via a single URL.

Nimbus supports this builder API to access these MEV builders. If one is configured, the block production flow becomes modified:
1. attempt to use the specified MEV relay or builder to create an execution payload
2. if the MEV builder or relay doesn't function, then fall back to existing local execution client

There does exist a failure mode, intrinsic to the builder API, wherein the consensus client has signed a blinded proposal and therefore even if the MEV relay or builder doesn't provide a full block, a consensus client such as Nimbus cannot safely proceed with step 2 and fall back on its local execution client.

## Command line option

=== "Mainnet"
    ```sh
    ./run-mainnet-beacon-node.sh --payload-builder=true --payload-builder-url=https://${HOST}:${PORT}/
    ```

=== "Prater"
    ```sh
    ./run-prater-beacon-node.sh --payload-builder=true --payload-builder-url=https://${HOST}:${PORT}/
    ```
