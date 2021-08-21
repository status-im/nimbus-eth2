# Connect your validator to eth2

**Prater**

To connect your validator to the Prater testnet, from the `nimbus-eth2` repository run:

```
 ./run-prater-beacon-node.sh
```

**Mainnet**

To connect your validator to mainnet, from the `nimbus-eth2` repository run:

```
./run-mainnet-beacon-node.sh
```

In both cases, you'll be asked to enter your [Web3 provider URL](./start-syncing.md#web3-provider-url) again.

> **Note:** If your beacon node is already running, you'll need to shut it down gracefully (`Ctrl+c`) and re-run the above command.

To ensure your Validator is correctly monitoring the eth1 chain, it's important you enter a valid web3 provider.

Your beacon node will launch and connect your validator to the eth2 network. To check that this has happened correctly, check your logs for the following:

```
INF 2020-11-18 11:20:00.181+01:00 Launching beacon node 
...
NOT 2020-11-18 11:20:02.091+01:00 Local validator attached
```

