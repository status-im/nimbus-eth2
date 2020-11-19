## Run an eth1 node

In order to process incoming validator deposits from the eth1 chain, you'll need to run an eth1 client in parallel to your eth2 client. 

Validators are responsible for including new deposits when they propose blocks. And an eth1 client is needed to ensure your validator performs this task correctly.

On this page we provide instructions for using Geth (however, any reputable eth1 client should do the trick).

> **Note:** If you're running on a resource-restricted device like a [Raspberry Pi](./pi-guide.md), we recommend [setting up a personal Infura endpoint](./infura-guide.md) instead as a stop-gap solution.
> As it stands it may be a little complicated to run a full Geth node on a Pi (and light mode doesn't give you the deposit data you need).
>
>In the medium term (3-6 months), we expect someone (perhaps us) will build a thin layer on top of plain Eth1 header-syncing light clients to address this issue. Specifically, what's missing is a gossip network broadcasting deposit proofs (i.e. deposits and corresponding Merkle proofs rooted in Eth1 headers). When that happens, you should be able to swap out Infura.
>
> However, if you have a > 500GB SSD, and your hardware can handle it, we strongly recommend running your own eth1 client. This will help ensure the network stays as decentralised as possible.

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

>**Note:** It is safe to run Nimbus and start validating even if Geth hasn't fully synced yet.




