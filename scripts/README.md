_Work in progress. Things may and probably will break for the foreseeable future. Do not rely on this for anything._

## Connecting to Testnet

To connect to a short-lived testnet we may or may not have running at the moment, use the `connect_to_testnet` script like so:

```bash
scripts/connect_to_testnet.sh testnet0
```

## Running your own testnet

The `beacon_node` binary has a `createTestnet` command.

```bash
  nim c -r beacon_chain/beacon_node \
    --data-dir=$NETWORK_DIR/data \
    createTestnet \
    --validators-dir=$NETWORK_DIR \
    --total-validators=$VALIDATOR_COUNT \
    --last-user-validator=$LAST_USER_VALIDATOR \
    --output-genesis=$NETWORK_DIR/genesis.ssz \
    --output-bootstrap-file=$NETWORK_DIR/bootstrap_nodes.txt \
    --bootstrap-address=$PUBLIC_IP \
    --genesis-offset=600 # Delay in seconds
```

Replace ENV vars with values that make sense to you.

Full tutorial coming soon.

## Maintaining the Status testnets

For detailed instructions, please see https://github.com/status-im/nimbus-private/blob/master/testnets-maintenance.md

