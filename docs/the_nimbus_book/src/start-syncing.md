
# Start syncing

If you're joining a network that has already launched, you need to ensure that your beacon node is [completely synced](./keep-an-eye.md#keep-track-of-your-syncing-progress) before submitting your deposit.

This is particularly important if you are joining a network that's been running for a while.

### Testnet

To start syncing the `medalla` testnet , from the `nimbus-eth2` repository, run:

```
 ./run-medalla-beacon-node.sh
```

### Mainnet

> **Note:** Mainnet won't launch before December 1st.


To start monitoring the eth1 mainnet chain for deposits, from the `nimbus-eth2` repository, run:

```
 ./run-mainnet-beacon-node.sh
```

### Web3 provider URL
You should see the following prompt:

```
To monitor the Eth1 validator deposit contract, you'll need to pair
the Nimbus beacon node with a Web3 provider capable of serving Eth1
event logs. This could be a locally running Eth1 client such as Geth
or a cloud service such as Infura. For more information please see
our setup guide:

https://status-im.github.io/nimbus-eth2/eth1.html

Please enter a Web3 provider URL:
```

If you're running a local geth instance, geth accepts connections from the loopback interface (`127.0.0.1`), with default WebSocket port `8546`. This means that your default Web3 provider URL should be: 
```
ws://127.0.0.1:8546
```
Enter it, you should see the following output:

```
INF 2020-11-07 13:59:31.199+01:00 Generating a random Peer ID to protect your privacy                   topics="networking" tid=18382613 file=eth2_network.nim:1229 network_public_key=08021221020ee5c1cfbf731405d14f2f382bc4037fbbee2b6ac5511dd51f1d9e28abb1aa62
INF 2020-11-07 13:59:31.336+01:00 Starting Eth1 deposit contract monitoring  tid=18382613 file=mainchain_monitor.nim:783 contract=0x1234567890123456789012345678901234567890 url=web3(ws://127.0.0.1:8546)
...
```

