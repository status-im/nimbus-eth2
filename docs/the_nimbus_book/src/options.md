# Command line options

You can pass any `nimbus_beacon_node` options to the `pyrmont` and `mainnet` scripts. For example, if you wanted to launch Nimbus on mainnet with a different base port, say `9100`, you would run:

```
./run-mainnet-beacon-node.sh --tcp-port=9100 --udp-port=9100
```

To see a list of the command line options availabe to you, with descriptions, navigate to the `build` directory and run:

```
./nimbus_beacon_node --help
```

You should see the following output:

```
Usage: 

nimbus_beacon_node [OPTIONS]... command

The following options are available:

     --log-level               Sets the log level.
     --log-file                Specifies a path for the written Json log file.
     --network                 The Eth2 network to join.
 -d, --data-dir                The directory where nimbus will store all blockchain data.
     --validators-dir          A directory containing validator keystores.
     --secrets-dir             A directory containing validator keystore passwords.
     --wallets-dir             A directory containing wallet files.
     --web3-url                URL of the Web3 server to observe Eth1.
     --deposit-contract        Address of the deposit contract.
     --deposit-contract-block  The Eth1 block number or hash where the deposit contract has
                               been deployed.
     --non-interactive         Do not display interative prompts. Quit on missing
                               configuration.
     --netkey-file             Source of network (secp256k1) private key file
                               (random|<path>) (default: random).
     --insecure-netkey-password  Use pre-generated INSECURE password for network private key
                               file (default: false).
 -b, --bootstrap-node          Specifies one or more bootstrap nodes to use when connecting
                               to the network.
     --bootstrap-file          Specifies a line-delimited file of bootstrap Ethereum network
                               addresses.
     --listen-address          Listening address for the Ethereum LibP2P and Discovery v5
                               traffic.
     --tcp-port                Listening TCP port for Ethereum LibP2P traffic.
     --udp-port                Listening UDP port for node discovery.
     --max-peers               The maximum number of peers to connect to.
     --nat                     Specify method to use for determining public address. Must be
                               one of: any, none, upnp, pmp, extip:<IP>.
     --weak-subjectivity-checkpoint  Weak subjectivity checkpoint in the format
                               block_root:epoch_number.
     --finalized-checkpoint-state  SSZ file specifying a recent finalized state.
     --finalized-checkpoint-block  SSZ file specifying a recent finalized block.
     --node-name               A name for this node that will appear in the logs. If you set
                               this to 'auto', a persistent automatically generated ID will
                               be selected for each --data-dir folder.
     --graffiti                The graffiti value that will appear in proposed blocks. You
                               can use a 0x-prefixed hex encoded string to specify raw
                               bytes.
     --verify-finalization     Specify whether to verify finalization occurs on schedule,
                               for testing.
     --stop-at-epoch           A positive epoch selects the epoch at which to stop.
     --metrics                 Enable the metrics server.
     --metrics-address         Listening address of the metrics server.
     --metrics-port            Listening HTTP port of the metrics server.
     --status-bar              Display a status bar at the bottom of the terminal screen.
     --status-bar-contents     Textual template for the contents of the status bar.
     --rpc                     Enable the JSON-RPC server.
     --rpc-port                HTTP port for the JSON-RPC service.
     --rpc-address             Listening address of the RPC server.
     --in-process-validators   Disable the push model (the beacon node tells a signing
                               process with the private keys of the validators what to sign
                               and when) and load the validators in the beacon node itself.
     --discv5                  Enable Discovery v5.
     --dump                    Write SSZ dumps of blocks, attestations and states to data
                               dir.
							   ```
							   
