# Connect your validator to eth2

> ⚠️  This page concerns the **Pyrmont** testnet only. If you have made a mainnet deposit, you do not need to connect your validator to eth2 quite yet. Mainnet [Genesis](https://hackmd.io/@benjaminion/genesis) date has been set to [December 1st](https://blog.ethereum.org/2020/11/04/eth2-quick-update-no-19/). This page will be updated nearer the time.

To connect your validator to the Pyrmont testnet, from the `nimbus-eth2` repository run:

```
 ./run-pyrmont-beacon-node.sh
```

You'll be asked to enter your [Web3 provider URL](./start-syncing.md#web3-provider-url) again.

> **Note:** If your beacon node is already running, you'll need to shut it down gracefully (`Ctrl+c`) and re-run the above command.

This will build Nimbus and its dependencies, and connect your validator the eth2 network.
You should see that the beacon node has launched with your validator attached:

```
INF 2020-11-18 11:20:00.181+01:00 Launching beacon node 
...
NOT 2020-11-18 11:20:02.091+01:00 Local validator attached
```

