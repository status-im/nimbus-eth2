# The beacon node

The beacon node application connects to the eth2 network, manages the blockchain, and provides API's to interact with the beacon chain.

You can run the beacon node without being a validator - doing so allows you to sync the network and access its latest state.

## Prerequisites

Before compiling and running the application, make sure you've gone through the [installation guidelines](./install.md).

## Running the node

When running the beacon node, you connect to a specific ethereum 2 network - this may be a private network or a public testnet like [Medalla](https://github.com/goerli/medalla/).

When running the node for the first time, you need to specify network parameters, boot nodes and genesis information. This information can typically be found in the [eth2 testnets](https://github.com/eth2-clients/eth2-testnets) repository. This information is automatically downloaded when using the simplified startup.

Once the beacon node is running, it will first connect to the boot nodes in the network, look for more peers and start syncing the chain. Once the sync is complete, it will keep following the head of the chain (you can interact with it through the [API](./api.md).

Before running the beacon node, it's important that your computer is set to the correct time - preferably using a trusted time source (this can be an NTP server you trust, GPS time or another precise source of time) -- however don't worry if you're unsure of how to do this, it isn't essential for testnet purposes.

### Syncing

To start syncing the `medalla` network:


#### 1. Clone the nim beacon chain repository

```
git clone https://github.com/status-im/nim-beacon-chain
cd nim-beacon-chain
```

#### 2. Run the build process

```
make medalla

# Build output...

```

This will build Nimbus and its dependencies, and connect you to Medalla.
You should see that the beacon node has launched and started syncing.

```
INF 2020-07-03 15:28:15+02:00 Starting beacon node                       topics="beacnde" tid=176865 file=beacon_node.nim:866 SECONDS_PER_SLOT=12 SLOTS_PER_EPOCH=32 SPEC_VERSION=0.12.1 cat=init dataDir=/home/arnetheduck/status/nim-beacon-chain/build/data/shared_medalla_0 finalizedRoot=72e7b21c finalizedSlot=20064 headRoot=f92bf720 headSlot=20142 nim="Nim Compiler Version 1.2.2 [Linux: amd64] (be34b5ab)" pcs=start_beacon_node timeSinceFinalization=-108322 version="0.5.0 (c64737e)"


 peers: 7 ❯ finalized: 3a806c9f:634 ❯ head: b364f8e9:636:29 ❯ time: 909:7 (29095)              ETH: 0.0
```

### Status bar

The status bar shows important health information about your node:

* peers - The number of peers you're connected to
* finalized - The block root and epoch of the latest finalized checkpoint - when the network is healthy, this value will stay at 2-3 epochs from the wall clock
* head - The block root and time of the head block - as blocks are produced and processed, this will be updated to the latest head block as chosen by the consensus algorithm.
* time - The current wall time according to your computer - when the node is synced, the head block will closely follow this time.
* ETH: the total ETH validators attached to the node have accumulated. When there are no validators attached, this number will be 0.

Time is shown as `epoch:subslot`, starting from the block chain genesis time - one epoch is typically 32 slots but this may vary between networks.

The status bar content may be updated using command line flags.

### Metrics
Nimbus includes metrics support using the Prometheus format. To enable it, you need to enable insecure feature when compiling the application. The http server that exports Prometheus metrics should not be exposed to external parties.

```
# Compile with insecure features enabled
make NIMFLAGS="-d:insecure" medalla
```

## Help
To see a list of command line options with descriptions, navigate to the `build` directory and run:

```
./beacon_node --help
```

You should see the following output:

```
Usage:

beacon_node [OPTIONS]... command

The following options are available:

     --log-level               Sets the log level.
     --eth1-network            The Eth1 network tracked by the beacon node.
 -d, --data-dir                The directory where nimbus will store all blockchain data.
     --web3-url                URL of the Web3 server to observe Eth1.
     --deposit-contract        Address of the deposit contract.
     --deposit-contract-block  The Eth1 block hash where the deposit contract has been deployed.
     --non-interactive         Do not display interative prompts. Quit on missing configuration.
 -b, --bootstrap-node          Specifies one or more bootstrap nodes to use when connecting to the network.
     --bootstrap-file          Specifies a line-delimited file of bootstrap Ethereum network addresses.
     --listen-address          Listening address for the Ethereum LibP2P traffic.
     --tcp-port                Listening TCP port for Ethereum LibP2P traffic.
     --udp-port                Listening UDP port for node discovery.
     --max-peers               The maximum number of peers to connect to.
     --nat                     Specify method to use for determining public address. Must be one of: any, none,
                               upnp, pmp, extip:<IP>.
 -v, --validator               Path to a validator keystore.
     --validators-dir          A directory containing validator keystores.
     --secrets-dir             A directory containing validator keystore passwords.
     --wallets-dir             A directory containing wallet files.
 -s, --state-snapshot          Json file specifying a recent state snapshot.
     --node-name               A name for this node that will appear in the logs. If you set this to 'auto', a
                               persistent automatically generated ID will be selected for each --data-dir
                               folder.
     --verify-finalization     Specify whether to verify finalization occurs on schedule, for testing.
     --stop-at-epoch           A positive epoch selects the epoch at which to stop.
     --metrics                 Enable the metrics server.
     --metrics-address         Listening address of the metrics server.
     --metrics-port            Listening HTTP port of the metrics server.
     --status-bar              Display a status bar at the bottom of the terminal screen.
     --status-bar-contents     Textual template for the contents of the status bar.
     --rpc                     Enable the JSON-RPC server.
     --rpc-port                HTTP port for the JSON-RPC service.
     --rpc-address             Listening address of the RPC server.
     --dump                    Write SSZ dumps of blocks, attestations and states to data dir.

Available sub-commands:

beacon_node_shared_medalla_0 createTestnet [OPTIONS]...

The following options are available:

     --validators-dir          Directory containing validator keystores.
     --total-validators        The number of validator deposits in the newly created chain.
     --first-validator         Index of first validator to add to validator list.
     --last-user-validator     The last validator index that will free for taking from a testnet participant.
     --bootstrap-address       The public IP address that will be advertised as a bootstrap node for the
                               testnet.
     --bootstrap-port          The TCP/UDP port that will be used by the bootstrap node.
     --genesis-offset          Seconds from now to add to genesis time.
     --output-genesis          Output file where to write the initial state snapshot.
     --with-genesis-root       Include a genesis root in 'network.json'.
     --output-bootstrap-file   Output file with list of bootstrap nodes for the network.

beacon_node_shared_medalla_0 deposits [OPTIONS]... command

The following options are available:

     --deposit-private-key     Private key of the controlling (sending) account.

Available sub-commands:

beacon_node_shared_medalla_0 deposits create [OPTIONS]...

Creates validator keystores and deposits.

The following options are available:

     --count                   Number of deposits to generate.
     --wallet                  An existing wallet ID. If not specified, a new wallet will be created.
     --out-validatorss-dir     Output folder for validator keystores and deposits.
     --out-secrets-dir         Output folder for randomly generated keystore passphrases.
     --dont-send               By default, all created deposits are also immediately sent to the validator
                               deposit contract. You can use this option to prevent this behavior. Use the
                               `deposits send` command to send the deposit transactions at your convenience
                               later.

beacon_node_shared_medalla_0 deposits send [OPTIONS]...

Sends prepared deposits to the validator deposit contract.

The following options are available:

     --validators-dir          A folder with validator metadata created by the `deposits create` command.
     --min-delay               Minimum possible delay between making two deposits (in seconds).
     --max-delay               Maximum possible delay between making two deposits (in seconds).

beacon_node_shared_medalla_0 deposits status

Displays status information about all deposits.

beacon_node_shared_medalla_0 wallets command

Available sub-commands:

beacon_node_shared_medalla_0 wallets create [OPTIONS]...

Creates a new EIP-2386 wallet.

The following options are available:

     --name                    An easy-to-remember name for the wallet of your choice.
     --next-account            Initial value for the 'nextaccount' property of the wallet.
     --out                     Output wallet file.

beacon_node_shared_medalla_0 wallets restore [OPTIONS]...

Restores a wallet from cold storage.

The following options are available:

     --name                    An easy-to-remember name for the wallet of your choice.
     --deposits                Expected number of deposits to recover. If not specified, Nimbus will try to
                               guess the number by inspecting the latest beacon state.
     --out                     Output wallet file.

beacon_node_shared_medalla_0 wallets list

Lists details about all wallets.
```

## Next steps

Once you're synced, you can move on to become a [validator](./validator.md).
