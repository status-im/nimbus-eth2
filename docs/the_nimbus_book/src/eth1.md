# Run an eth1 node

In order to process incoming validator deposits from the eth1 chain, you'll need to run an eth1 client in parallel to your eth2 client. 

Validators are responsible for including new deposits when they propose blocks. And an eth1 client is needed to ensure your validator performs this task correctly.

On this page we provide instructions for using Geth (however, any reputable eth1 client should do the trick).

> **Note:** If you have a > 500GB SSD, and your [hardware](./hardware.md) can handle it, we strongly recommend running your own eth1 client. This will help ensure the network stays as decentralised as possible. If you can't however, the next best option is to set up a 3rd part provider like [infura](./infura-guide.md).

## Nimbus
In parallel to `nimbus-eth2` we are working hard on our [our exectution client](https://github.com/status-im/nimbus-eth1). While this is  very much a project in development (i.e. not yet ready for public consumption), we welcome you to experiment with it.

## Nethermind
*TBC*

## Geth

### 1. Install Geth
If you're running MacOS, follow the instructions [listed here](https://github.com/ethereum/go-ethereum/wiki/Installation-Instructions-for-Mac) to install geth. Otherwise [see here](https://github.com/ethereum/go-ethereum/wiki/Installing-Geth).

### 2. Start Geth

Once you have geth installed, use the following command to start your eth1 node:

**Testnet**
```
geth --goerli --ws
```

**Mainnet**
```
geth --ws
```

>**Note:** The `--ws` flag is needed to enable the websocket RPC API. This allows Nimbus to query the eth1 chain using Web3 API calls.


### 3. Leave Geth running

Let it sync - Geth uses a fast sync mode by default. It may take anywhere between a few hours and a couple of days.

>**N.B.** It is safe to run Nimbus and start validating even if Geth hasn't fully synced yet

You'll know Geth has finished syncing, when you start seeing logs that look like the following:

```
INFO [05-29|01:14:53] Imported new chain segment               blocks=1 txs=2   mgas=0.043  elapsed=6.573ms   mgasps=6.606   number=3785437 hash=f72595…c13f23
INFO [05-29|01:15:08] Imported new chain segment               blocks=1 txs=3   mgas=0.067  elapsed=7.639ms   mgasps=8.731   number=3785441 hash=be7e55…a8c1c7
INFO [05-29|01:15:25] Imported new chain segment               blocks=1 txs=21  mgas=1.084  elapsed=33.610ms  mgasps=32.264  number=3785442 hash=fd54be…79b047
INFO [05-29|01:15:42] Imported new chain segment               blocks=1 txs=26  mgas=0.900  elapsed=26.209ms  mgasps=34.335  number=3785443 hash=2504ff…119622
INFO [05-29|01:15:59] Imported new chain segment               blocks=1 txs=12  mgas=1.228  elapsed=22.693ms  mgasps=54.122  number=3785444 hash=951dfe…a2a083
INFO [05-29|01:16:05] Imported new chain segment               blocks=1 txs=3   mgas=0.065  elapsed=5.885ms   mgasps=11.038  number=3785445 hash=553d9e…fc4547
INFO [05-29|01:16:10] Imported new chain segment               blocks=1 txs=0   mgas=0.000  elapsed=5.447ms   mgasps=0.000   number=3785446 hash=5e3e7d…bd4afd
INFO [05-29|01:16:10] Imported new chain segment               blocks=1 txs=1   mgas=0.021  elapsed=7.382ms   mgasps=2.845   number=3785447 hash=39986c…dd2a01
INFO [05-29|01:16:14] Imported new chain segment               blocks=1 txs=11  mgas=1.135  elapsed=22.281ms  mgasps=50.943  number=3785444 hash=277bb9…623d8c
```


Geth accepts connections from the loopback interface (`127.0.0.1`), with default WebSocket port `8546`. This means that your default Web3 provider URL should be: `ws://127.0.0.1:8546`





