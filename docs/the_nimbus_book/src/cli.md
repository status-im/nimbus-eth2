# Command-line Options

You can run your customized beacon node using the `beacon_node` executable. The available options are shown below - you can also run `beacon_node --help` for a reminder.

## Prerequisites

Specifying a genesis file is mandatory to run this executable. You can either get it from the official eth2 repository [here](https://github.com/eth2-clients/eth2-testnets/blob/master/shared/witti/genesis.ssz) or generate your own like [this](https://github.com/status-im/nim-beacon-chain/blob/db92c2f2549a339be60896c3907cefdb394b5e11/scripts/launch_local_testnet.sh#L154) when starting a local testnet. You can also specify the path of your genesis file like [this](https://github.com/status-im/nim-beacon-chain/blob/db92c2f2549a339be60896c3907cefdb394b5e11/scripts/launch_local_testnet.sh#L229).

For example, download a genesis file and then run the following command to start the node:

<img src="./img/beacon_node_example.PNG" alt="" style="margin: 0 40 0 40"/>

## Usage

```
$ ./beacon_node --help
Nimbus beacon node v0.3.0 (877a358)

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

beacon_node_shared_altona_0 createTestnet [OPTIONS]...

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

beacon_node_shared_altona_0 deposits [OPTIONS]... command

The following options are available:

     --deposit-private-key     Private key of the controlling (sending) account.

Available sub-commands:

beacon_node_shared_altona_0 deposits create [OPTIONS]...

Creates validator keystores and deposits.

The following options are available:

     --count                   Number of deposits to generate.
     --wallet                  An existing wallet ID. If not specified, a new wallet will be created.
     --out-deposits-dir        Output folder for validator keystores and deposits.
     --out-secrets-dir         Output folder for randomly generated keystore passphrases.
     --dont-send               By default, all created deposits are also immediately sent to the validator
                               deposit contract. You can use this option to prevent this behavior. Use the
                               `deposits send` command to send the deposit transactions at your convenience
                               later.

beacon_node_shared_altona_0 deposits send [OPTIONS]...

Sends prepared deposits to the validator deposit contract.

The following options are available:

     --deposits-dir            A folder with validator metadata created by the `deposits create` command.
     --min-delay               Minimum possible delay between making two deposits (in seconds).
     --max-delay               Maximum possible delay between making two deposits (in seconds).

beacon_node_shared_altona_0 deposits status

Displays status information about all deposits.

beacon_node_shared_altona_0 wallets command

Available sub-commands:

beacon_node_shared_altona_0 wallets create [OPTIONS]...

Creates a new EIP-2386 wallet.

The following options are available:

     --name                    An easy-to-remember name for the wallet of your choice.
     --next-account            Initial value for the 'nextaccount' property of the wallet.
     --out                     Output wallet file.

beacon_node_shared_altona_0 wallets restore [OPTIONS]...

Restores a wallet from cold storage.

The following options are available:

     --name                    An easy-to-remember name for the wallet of your choice.
     --deposits                Expected number of deposits to recover. If not specified, Nimbus will try to
                               guess the number by inspecting the latest beacon state.
     --out                     Output wallet file.

beacon_node_shared_altona_0 wallets list

Lists details about all wallets.
```
