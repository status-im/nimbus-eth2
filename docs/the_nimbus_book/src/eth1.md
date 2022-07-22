# Run an execution client

In order to be able to produce blocks and process incoming validator deposits, you'll need to run an execution client in together with the beacon node.

Nimbus has been tested all major execution clients - see the [execution client comparison](https://ethereum.org/en/developers/docs/nodes-and-clients/#execution-clients) for more information.

The `--web3-url` option informs the beacon node how to connect to the execution client - both `http://` and `ws://` URL:s are supported.

You can pass one or more `--web3-url` parameters to the node. Any additional web3 url:s will be used for backup, should the first client become unavailable:

```sh
./run-mainnet-beacon-node.sh --web3-url=ws://127.0.0.1:8546 --web3-url=http://other:8545
```

```admonish warn
You need to run your own execution client after [the merge](./merge.md) - relying on third-party services such as Infura, Alchemy and Pocket will not be possible.
```

```admonish note
Syncing an execution client may take hours or even days, depending on your hardware!
```

## Nimbus

In parallel to `nimbus-eth2`, we are working hard on the [Nimbus execution client](https://github.com/status-im/nimbus-eth1). While this is very much a project in development (i.e. not yet ready for public consumption), we welcome you to experiment with it.

## Geth

### 1. Install Geth

See the [Installing Geth](https://geth.ethereum.org/docs/install-and-build/installing-geth) for instructions on installing Geth.

### 2. Start Geth

Once you have geth installed, make sure to enable the JSON-RPC WebSocket interface when running geth:

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

Let it sync - Geth uses snap sync by default. It may take anywhere between a few hours and a couple of days.

>**N.B.** It is safe to run Nimbus and start validating even if Geth hasn't fully synced yet

You'll know Geth has finished syncing, when you start seeing logs that look like the following:

```
INFO [05-29|01:16:05] Imported new chain segment               blocks=1 txs=3   mgas=0.065  elapsed=5.885ms   mgasps=11.038  number=3785445 hash=553d9e…fc4547
INFO [05-29|01:16:10] Imported new chain segment               blocks=1 txs=0   mgas=0.000  elapsed=5.447ms   mgasps=0.000   number=3785446 hash=5e3e7d…bd4afd
INFO [05-29|01:16:10] Imported new chain segment               blocks=1 txs=1   mgas=0.021  elapsed=7.382ms   mgasps=2.845   number=3785447 hash=39986c…dd2a01
INFO [05-29|01:16:14] Imported new chain segment               blocks=1 txs=11  mgas=1.135  elapsed=22.281ms  mgasps=50.943  number=3785444 hash=277bb9…623d8c
```

Geth accepts connections from the loopback interface (`127.0.0.1`), with default WebSocket port `8546`. This means that your default Web3 provider URL should be: `ws://127.0.0.1:8546`

## Nethermind

See the [Getting started](https://docs.nethermind.io/nethermind/first-steps-with-nethermind/getting-started) guide to set up Nethermind.

Make sure to enable the [JSON-RPC](https://docs.nethermind.io/nethermind/first-steps-with-nethermind/running-nethermind-post-merge#jsonrpc-configuration-module) interface over WebSockets.

## Besu

See the [Besu documentation](https://besu.hyperledger.org/en/stable/) for instructions on setting up Besu.

Make sure to enable the [JSON-RPC](https://besu.hyperledger.org/en/stable/HowTo/Interact/APIs/Using-JSON-RPC-API/) WebSocket interface.

## Erigon

See the [Erigon README](https://github.com/ledgerwatch/erigon#getting-started=) for instructions on setting up Erigon.

Make sure to enable the [JSON-RPC](https://github.com/ledgerwatch/erigon#beacon-chain=) WebSocket interface.
