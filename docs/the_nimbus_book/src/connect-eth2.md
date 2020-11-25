# Connect your validator to eth2

**Pyrmont**

To connect your validator to the Pyrmont testnet, from the `nimbus-eth2` repository run:

```
 ./run-pyrmont-beacon-node.sh
```

**Mainnet**

To connect your validator to mainnet, from the `nimbus-eth2` repository run:

```
./run-mainnet-beacon-node.sh
```



In both cases, you'll be asked to enter your [Web3 provider URL](./start-syncing.md#web3-provider-url) again.

> **Note:** If your beacon node is already running, you'll need to shut it down gracefully (`Ctrl+c`) and re-run the above command.

Your beacon node will launch and connect your validator the eth2 network. To check that this has happened correctly, check your logs for the following:

```
INF 2020-11-18 11:20:00.181+01:00 Launching beacon node 
...
NOT 2020-11-18 11:20:02.091+01:00 Local validator attached
```

