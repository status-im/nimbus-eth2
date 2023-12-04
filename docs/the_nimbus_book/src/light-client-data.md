# Light client data

Nimbus is configured by default to serve data that allows light clients to stay in sync with the Ethereum network.
Light client data is imported incrementally and does not affect validator performance.
Information about the light client sync protocol can be found in the [Ethereum consensus specs](https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md).

!!! note
    Nimbus also implements a [standalone light client](./el-light-client.md) that may be used to sync an execution layer (EL) client.

## Configuration

The following [configuration options](./options.md) adjust the import and serving of light client data:

| Option                                         | Description |
|------------------------------------------------|-------------|
| <nobr>`--light-client-data-serve`</nobr>       | <ul><li>`false`: Disable light client data serving</li><li>`true` (default): Provide imported light client data to others</li></ul> |
| <nobr>`--light-client-data-import-mode`</nobr> | <ul><li>`none`: Do not import new light client data</li><li>`only-new` (default): Incrementally import new light client data</li><li>`full`: Import historic light client data (slow startup)</li><li>`on-demand`: Like `full`, but import on demand instead of on start</li></ul> |
| <nobr>`--light-client-data-max-periods`</nobr> | <ul><li>Controls the maximum number of sync committee periods to retain light client data</li><li>When unspecified (default), light client data is never pruned</li></ul> |

!!! warning
    Setting `--light-client-data-import-mode` to `full` or `on-demand` imports historic light client data which is computationally expensive.
    While importing historic light client data, validator duties may be missed.
