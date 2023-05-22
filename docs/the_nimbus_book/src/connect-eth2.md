# Start validating

Once your keys have been [imported](./keys.md), it is time to configure a [fee recipient](./suggested-fee-recipient.md) and restart the beacon node to start validating.

## Steps

### 1. Choose a fee recipient

The [fee recipient](./suggested-fee-recipient.md) is an Ethereum address that receives transaction fees from the blocks that your validators produce.
You can set up a separate address or reuse the address from which you funded your deposits.

### 2. (Re)start the node

Press `Ctrl-c` to stop the beacon node if it's running, then use the same command as before to run it again, this time adding the `--suggested-fee-recipient` option in addition to `--web3-url`:

=== "Mainnet"
    ```sh
    ./run-mainnet-beacon-node.sh --web3-url=http://127.0.0.1:8551 --suggested-fee-recipient=0x...
    ```

=== "Prater"
    ```sh
    ./run-prater-beacon-node.sh --web3-url=http://127.0.0.1:8551 --suggested-fee-recipient=0x...
    ```

### 3. Check the logs

Your beacon node will launch and connect your validator to the beacon chain network.
To check that keys were imported correctly, look for `Local validator attached` in the logs:

```
INF 2020-11-18 11:20:00.181+01:00 Launching beacon node
...
NOT 2020-11-18 11:20:02.091+01:00 Local validator attached
```

Congratulations!
Your node is now ready to perform validator duties.
Depending on when the deposit was made, it may take a while before the first attestation is sent — this is normal.
