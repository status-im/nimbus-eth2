# Start performing validator duties

Once your keys have been [imported](./keys.md), it is time to restart the beacon node and start validating!

## (Re)start the node

Press `ctrl-c` to stop the beacon node if it's running, then use the same command as before to run it again:

**Prater**

```
 ./run-prater-beacon-node.sh
```

**Mainnet**

```
./run-mainnet-beacon-node.sh
```

## Check the logs

Your beacon node will launch and connect your validator to the beacon chain network. To check that keys were imported correctly, look for `Local validator attached` in the logs:

```
INF 2020-11-18 11:20:00.181+01:00 Launching beacon node
...
NOT 2020-11-18 11:20:02.091+01:00 Local validator attached
```
