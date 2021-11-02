# Command line options

You can pass any `nimbus_beacon_node` options to the `prater` and `mainnet` scripts. For example, if you want to launch Nimbus on mainnet with different base ports than the default `9000/udp` and `9000/tcp`, say `9100/udp` and `9100/tcp`, run:

```
./run-mainnet-beacon-node.sh --tcp-port=9100 --udp-port=9100
```

To see a list of the command line options availabe to you, with descriptions, run:

```
build/./nimbus_beacon_node --help
```

You should see the following output:

```
Usage:

nimbus_beacon_node [OPTIONS]... command

The following options are available:

     --log-level               Sets the log level for process and topics (e.g. "DEBUG;
                               TRACE:discv5,libp2p; REQUIRED:none; DISABLED:none") [=INFO].
     --log-stdout              Specifies what kind of logs should be written to stdout
                               (auto, colors, nocolors, json) [=auto].
     --log-file                Specifies a path for the written Json log file.
     --network                 The Eth2 network to join [=mainnet].
 -d, --data-dir                The directory where nimbus will store all blockchain data.
     --validators-dir          A directory containing validator keystores.
     --secrets-dir             A directory containing validator keystore passwords.
     --wallets-dir             A directory containing wallet files.
     --web3-url                One or more Web3 provider URLs used for obtaining deposit
                               contract data.
     --non-interactive         Do not display interative prompts. Quit on missing
                               configuration.
     --netkey-file             Source of network (secp256k1) private key file
                               (random|<path>) [=random].
     --insecure-netkey-password  Use pre-generated INSECURE password for network private key
                               file [=false].
     --agent-string            Node agent string which is used as identifier in network
                               [=nimbus].
     --subscribe-all-subnets   Subscribe to all attestation subnet topics when gossiping
                               [=false].
     --num-threads             Number of worker threads (set this to 0 to use as many
                               threads as there are CPU cores available) [=1].
 -b, --bootstrap-node          Specifies one or more bootstrap nodes to use when connecting
                               to the network.
     --bootstrap-file          Specifies a line-delimited file of bootstrap Ethereum network
                               addresses.
     --listen-address          Listening address for the Ethereum LibP2P and Discovery v5
                               traffic [=0.0.0.0].
     --tcp-port                Listening TCP port for Ethereum LibP2P traffic [=9000].
     --udp-port                Listening UDP port for node discovery [=9000].
     --max-peers               The maximum number of peers to connect to [=160].
     --nat                     Specify method to use for determining public address. Must be
                               one of: any, none, upnp, pmp, extip:<IP> [=any].
     --enr-auto-update         Discovery can automatically update its ENR with the IP
                               address and UDP port as seen by other nodes it communicates
                               with. This option allows to enable/disable this functionality
                               [=false].
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
                               for testing [=false].
     --stop-at-epoch           A positive epoch selects the epoch at which to stop [=0].
     --metrics                 Enable the metrics server [=false].
     --metrics-address         Listening address of the metrics server [=127.0.0.1].
     --metrics-port            Listening HTTP port of the metrics server [=8008].
     --status-bar              Display a status bar at the bottom of the terminal screen
                               [=true].
     --status-bar-contents     Textual template for the contents of the status bar.
     --rpc                     Enable the JSON-RPC server [=false].
     --rpc-port                HTTP port for the JSON-RPC service [=9190].
     --rpc-address             Listening address of the RPC server [=127.0.0.1].
     --rest                    Enable the REST server [=false].
     --rest-port               Port for the REST server [=5052].
     --rest-address            Listening address of the REST server [=127.0.0.1].
     --validator-api           Enable the REST (BETA version) validator keystore management
                               API [=false].
     --in-process-validators   Disable the push model (the beacon node tells a signing
                               process with the private keys of the validators what to sign
                               and when) and load the validators in the beacon node itself
                               [=true].
     --discv5                  Enable Discovery v5 [=true].
     --dump                    Write SSZ dumps of blocks, attestations and states to data
                               dir [=false].
     --direct-peer             The list of priviledged, secure and known peers to connect
                               and maintain the connection to, this requires a not random
                               netkey-file. In the complete multiaddress format like:
                               /ip4/<address>/tcp/<port>/p2p/<peerId-public-key>. Peering
                               agreements are established out of band and must be
                               reciprocal..
     --doppelganger-detection  If enabled, the beacon node prudently listens for 2 epochs
                               for attestations from a validator with the same index (a
                               doppelganger), before sending an attestation itself. This
                               protects against slashing (due to double-voting) but means
                               you will miss two attestations when restarting. [=true].


...
```
