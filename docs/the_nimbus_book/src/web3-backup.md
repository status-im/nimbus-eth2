# Add a backup web3 provider

It's a good idea to add a backup web3 provider in case your main one goes down. You can do this by simply repeating the `--web3-url` parameter on launch.

For example, if your primary eth1 node is a [local Geth](./eth1.md), but you want to use [Infura](./infura-guide.md) as a backup you would run:

```
./run-mainnet-beacon-node.sh  --web3-url="ws://127.0.0.1:8546" --web3-url="wss://mainnet.infura.io/ws/v3/..."
```


> **Note:** that as it stands, when you run this command, you'll be prompted once again for  a web3url again -- **please enter your primary one**. This is a UX bug and [we've pushed a fix](https://github.com/status-im/nimbus-eth2/pull/2501) that will be integrated into our next release.
