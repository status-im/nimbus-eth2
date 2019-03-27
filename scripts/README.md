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
    --network=$NETWORK_NAME \
    --dataDir=$DATA_DIR/node-0 \
    createTestnet \
    --networkId=$NETWORK_ID \
    --validatorsDir=$NETWORK_DIR \
    --totalValidators=$VALIDATOR_COUNT \
    --lastUserValidator=$LAST_USER_VALIDATOR \
    --outputGenesis=$NETWORK_DIR/genesis.json \
    --outputNetwork=$NETWORK_DIR/$NETWORK_FLAVOUR-network.json \
    --bootstrapAddress=$PUBLIC_IP \
    --genesisOffset=600 # Delay in seconds
```

Replace ENV vars with values that make sense to you.

Full tutorial coming soon.
