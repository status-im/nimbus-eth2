# Command line

Command line options allow you to customize the way your beacon node operates.

You pass options to the beacon node by adding them to the command line.
For example, if you want to launch Nimbus on mainnet with different base ports than the default `9000/udp` and `9000/tcp`, say `9100/udp` and `9100/tcp`, run:

```sh
./run-mainnet-beacon-node.sh --tcp-port=9100 --udp-port=9100
```

## Available options

To see the full list of command line options available to you, with descriptions, run:

```sh
build/nimbus_beacon_node --help
```

You should see the following output:

```
Usage:

nimbus_beacon_node [OPTIONS]... command

The following options are available:

     --config-file             Loads the configuration from a TOML file.
     --log-level               Sets the log level for process and topics (e.g. "DEBUG; TRACE:discv5,libp2p;
                               REQUIRED:none; DISABLED:none") [=INFO].
     --log-file                Specifies a path for the written JSON log file (deprecated).
     --network                 The Eth2 network to join [=mainnet].
 -d, --data-dir                The directory where nimbus will store all blockchain data.
     --validators-dir          A directory containing validator keystores.
     --verifying-web3-signer-url  Remote Web3Signer URL that will be used as a source of validators.
     --proven-block-property   The field path of a block property that will be sent for verification to the
                               verifying Web3Signer (for example ".execution_payload.fee_recipient").
     --web3-signer-url         Remote Web3Signer URL that will be used as a source of validators.
     --web3-signer-update-interval  Number of seconds between validator list updates [=3600].
     --secrets-dir             A directory containing validator keystore passwords.
     --wallets-dir             A directory containing wallet files.
     --web3-url                One or more execution layer Engine API URLs.
     --el                      One or more execution layer Engine API URLs.
     --no-el                   Don't use an EL. The node will remain optimistically synced and won't be able to
                               perform validator duties [=false].
     --non-interactive         Do not display interactive prompts. Quit on missing configuration.
     --netkey-file             Source of network (secp256k1) private key file (random|<path>) [=random].
     --insecure-netkey-password  Use pre-generated INSECURE password for network private key file [=false].
     --agent-string            Node agent string which is used as identifier in network [=nimbus].
     --subscribe-all-subnets   Subscribe to all subnet topics when gossiping [=false].
     --num-threads             Number of worker threads ("0" = use as many threads as there are CPU cores
                               available) [=0].
     --jwt-secret              A file containing the hex-encoded 256 bit secret key to be used for
                               verifying/generating JWT tokens.
 -b, --bootstrap-node          Specifies one or more bootstrap nodes to use when connecting to the network.
     --bootstrap-file          Specifies a line-delimited file of bootstrap Ethereum network addresses.
     --listen-address          Listening address for the Ethereum LibP2P and Discovery v5 traffic [=0.0.0.0].
     --tcp-port                Listening TCP port for Ethereum LibP2P traffic [=9000].
     --udp-port                Listening UDP port for node discovery [=9000].
     --max-peers               The target number of peers to connect to [=160].
     --hard-max-peers          The maximum number of peers to connect to. Defaults to maxPeers * 1.5.
     --nat                     Specify method to use for determining public address. Must be one of: any, none,
                               upnp, pmp, extip:<IP> [=any].
     --enr-auto-update         Discovery can automatically update its ENR with the IP address and UDP port as
                               seen by other nodes it communicates with. This option allows to enable/disable
                               this functionality [=false].
     --weak-subjectivity-checkpoint  Weak subjectivity checkpoint in the format block_root:epoch_number.
     --external-beacon-api-url  External beacon API to use for syncing (on empty database).
     --sync-light-client       Accelerate sync using light client [=true].
     --trusted-block-root      Recent trusted finalized block root to sync from external beacon API (with
                               `--external-beacon-api-url`). Uses the light client sync protocol to obtain the
                               latest finalized checkpoint (LC is initialized from trusted block root).
     --trusted-state-root      Recent trusted finalized state root to sync from external beacon API (with
                               `--external-beacon-api-url`).
     --finalized-checkpoint-state  SSZ file specifying a recent finalized state.
     --genesis-state           SSZ file specifying the genesis state of the network (for networks without a
                               built-in genesis state).
     --genesis-state-url       URL for obtaining the genesis state of the network (for networks without a
                               built-in genesis state).
     --finalized-deposit-tree-snapshot  SSZ file specifying a recent finalized EIP-4881 deposit tree snapshot.
     --node-name               A name for this node that will appear in the logs. If you set this to 'auto', a
                               persistent automatically generated ID will be selected for each --data-dir
                               folder.
     --graffiti                The graffiti value that will appear in proposed blocks. You can use a
                               0x-prefixed hex encoded string to specify raw bytes.
     --metrics                 Enable the metrics server [=false].
     --metrics-address         Listening address of the metrics server [=127.0.0.1].
     --metrics-port            Listening HTTP port of the metrics server [=8008].
     --status-bar              Display a status bar at the bottom of the terminal screen [=true].
     --status-bar-contents     Textual template for the contents of the status bar.
     --rest                    Enable the REST server [=false].
     --rest-port               Port for the REST server [=5052].
     --rest-address            Listening address of the REST server [=127.0.0.1].
     --rest-allow-origin       Limit the access to the REST API to a particular hostname (for CORS-enabled
                               clients such as browsers).
     --rest-statecache-size    The maximum number of recently accessed states that are kept in memory. Speeds
                               up requests obtaining information for consecutive slots or epochs. [=3].
     --rest-statecache-ttl     The number of seconds to keep recently accessed states in memory [=60].
     --rest-request-timeout    The number of seconds to wait until complete REST request will be received
                               [=infinite].
     --rest-max-body-size      Maximum size of REST request body (kilobytes) [=16384].
     --rest-max-headers-size   Maximum size of REST request headers (kilobytes) [=128].
     --keymanager              Enable the REST keymanager API [=false].
     --keymanager-port         Listening port for the REST keymanager API [=5052].
     --keymanager-address      Listening port for the REST keymanager API [=127.0.0.1].
     --keymanager-allow-origin  Limit the access to the Keymanager API to a particular hostname (for
                               CORS-enabled clients such as browsers).
     --keymanager-token-file   A file specifying the authorization token required for accessing the keymanager
                               API.
     --light-client-data-serve  Serve data for enabling light clients to stay in sync with the network [=true].
     --light-client-data-import-mode  Which classes of light client data to import. Must be one of: none, only-new,
                               full (slow startup), on-demand (may miss validator duties) [=only-new].
     --light-client-data-max-periods  Maximum number of sync committee periods to retain light client data.
     --in-process-validators   Disable the push model (the beacon node tells a signing process with the private
                               keys of the validators what to sign and when) and load the validators in the
                               beacon node itself [=true].
     --discv5                  Enable Discovery v5 [=true].
     --dump                    Write SSZ dumps of blocks, attestations and states to data dir [=false].
     --direct-peer             The list of privileged, secure and known peers to connect and maintain the
                               connection to. This requires a not random netkey-file. In the multiaddress
                               format like: /ip4/<address>/tcp/<port>/p2p/<peerId-public-key>, or enr format
                               (enr:-xx). Peering agreements are established out of band and must be
                               reciprocal.
     --doppelganger-detection  If enabled, the beacon node prudently listens for 2 epochs for attestations from
                               a validator with the same index (a doppelganger), before sending an attestation
                               itself. This protects against slashing (due to double-voting) but means you will
                               miss two attestations when restarting. [=true].
     --validator-monitor-auto  Monitor validator activity automatically for validators active on this beacon
                               node [=true].
     --validator-monitor-pubkey  One or more validators to monitor - works best when --subscribe-all-subnets is
                               enabled.
     --validator-monitor-details  Publish detailed metrics for each validator individually - may incur significant
                               overhead with large numbers of validators [=false].
     --suggested-fee-recipient  Suggested fee recipient.
     --suggested-gas-limit     Suggested gas limit [=defaultGasLimit].
     --payload-builder         Enable external payload builder [=false].
     --payload-builder-url     Payload builder URL.
     --local-block-value-boost  Increase execution layer block values for builder bid comparison by a percentage
                               [=0].
     --history                 Retention strategy for historical data (archive/prune) [=HistoryMode.Prune].

...
```

Any `debug`-prefixed flags are considered ephemeral and subject to removal without notice.

## Configuration files

All command line options can also be provided in a [TOML](https://toml.io/en/)
config file specified through the `--config-file` flag.
Within the config file, you need to use the long names of all options.
Please note that certain options
such as `web3-url`, `bootstrap-node`, `direct-peer`, and `validator-monitor-pubkey`
can be supplied more than once on the command line: in the TOML file, you need
to supply them as arrays.

There are also some minor differences in the parsing
of certain option values in the TOML files in order to conform more closely to
existing TOML standards.
For example, you can freely use keywords such as `on`,
`off`, `yes` and `no` on the command-line as synonyms for the canonical values
`true` and `false` which are mandatory to use in TOML. Options affecting Nimbus
sub-commands should appear in a section of the file matching the sub-command name.

Here is an example config file illustrating all of the above:

!!! example "nimbus-eth2.toml"
    ```toml
    # Comments look like this
    doppelganger-detection = true
    web3-url = ["http://127.0.0.1:8551"]
    num-threads = 0

    [trustedNodeSync]
    trusted-node-url = "http://192.168.1.20:5052"
    ```

## Exit Codes

| Exit code | Description                                                           |
|-----------|-----------------------------------------------------------------------|
| 0         | Successful exit                                                       |
| 1         | Generic failure or unspecified error                                  |
| 129       | Doppelganger detection; one might prefer not to restart automatically |
