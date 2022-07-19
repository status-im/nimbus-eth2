# Start performing validator duties

Once your keys have been [imported](./keys.md), it is time to restart the beacon node and start validating!

```admonish note
Unlike other beacon chain clients, Nimbus does not require setting up a separate validator client process - instead, it is the beacon node itself that performs validator duties. This is a simple, safe and efficient way to get started.

Advanced users may want to use a separate [validator client](./validator-client.md) process instead.
```

## (Re)start the node

Press `Ctrl-c` to stop the beacon node if it's running, then use the same command as before to run it again:

**Mainnet**

```sh
./run-mainnet-beacon-node.sh
```

**Prater**

```sh
 ./run-prater-beacon-node.sh
```

## Check the logs

Your beacon node will launch and connect your validator to the beacon chain network. To check that keys were imported correctly, look for `Local validator attached` in the logs:

```
INF 2020-11-18 11:20:00.181+01:00 Launching beacon node
...
NOT 2020-11-18 11:20:02.091+01:00 Local validator attached
```

Congratulations! Your node is now ready to perform validator duties. Depending on when the deposit was made, it may take a while before the first attestation is sent - this is normal.
