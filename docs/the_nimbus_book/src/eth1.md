## Run an eth1 node

In order to process incoming validator deposits from the eth1 chain, you'll need to run an eth1 client in parallel to your eth2 client. While it is possible to use a third-party service like [Infura](./infura-guide.md), we recommend running your own client in order to ensure the network stays as decentralised as possible.

In a sentence, validators are responsible for including new deposits when they propose blocks. An eth1 client is needed to ensure your validator performs this task correctly.

On this page we provide instructions for using Geth (however, any reputable eth1 client should do the trick).

### Install Geth
If you're running MacOS, follow the instructions [listed here](https://github.com/ethereum/go-ethereum/wiki/Installation-Instructions-for-Mac) to install geth. Otherwise [see here](https://github.com/ethereum/go-ethereum/wiki/Installing-Geth).

### Start Geth

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


### Leave Geth running

Let it sync - Geth uses a fast sync mode by default. It shouldn't take longer than a few hours.


