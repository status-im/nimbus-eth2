# Connect your validator to eth2

> ⚠️  This page concerns the Medalla testnet only. If you have made a mainnet deposit, you do not need to connect your validator to eth2 quite yet. Mainnet [Genesis](https://hackmd.io/@benjaminion/genesis) date has been set to [December 1st](https://blog.ethereum.org/2020/11/04/eth2-quick-update-no-19/). This page will be updated nearer the time.

To connect your validator to the Medalla testnet, from the `nimbus-eth2` repository run:

```
 ./run-medalla-beacon-node.sh
```

You'll be asked to enter your [Web3 provider URL](./start-syncing.md#web3-provider-url) again.

> **Note:** If your beacon node is already running, you'll need to shut it down gracefully (`Ctrl+c`) and re-run the above command.

This will build Nimbus and its dependencies, and connect your validator the eth2 network.
You should see that the beacon node has launched with your validator attached:

```
INF 2020-11-07 16:36:44.968+01:00 Generating a random Peer ID to protect your privacy topics="networking" tid=18434834 file=eth2_network.nim:1271 network_public_key=08021221024de664bd393499b1e852ea82c22068b95ffbf1b64dc40f31cafb5b0eac87c730
INF 2020-11-07 16:36:45.797+01:00 Block dag initialized                      topics="beacnde" tid=18434834 file=chain_dag.nim:423 head=ebe49843:0 finalizedHead=ebe49843:0 tail=ebe49843:0 totalBlocks=1
INF 2020-11-07 16:36:47.248+01:00 Starting Eth1 deposit contract monitoring  tid=18434834 file=eth1_monitor.nim:690 contract=0x07b39f4fde4a38bace212b546dac87c58dfe3fdc url=wss://goerli.infura.io/ws/v3/ae0e57122a1e49af8e835e82a5e35e60
INF 2020-11-07 16:36:47.248+01:00 Waiting for new Eth1 block headers         tid=18434834 file=eth1_monitor.nim:303
INF 2020-11-07 16:36:48.940+01:00 Initializing networking                    topics="networking" tid=18434834 file=eth2_network.nim:1395 hostAddress=/ip4/0.0.0.0/tcp/9000 network_public_key=38131421024de776bd393503b1e852ea82c22068b95ffbf1b64dc40f31cafb5b0eac87d669 announcedAddresses=@[/ip4/192.175.15.54/tcp/9000]
INF 2020-11-07 16:36:49.084+01:00 Initializing fork choice from block database topics="beacnde" tid=18434834 file=attestation_pool.nim:55 unfinalized_blocks=0
INF 2020-11-07 16:36:49.085+01:00 Fork choice initialized                    topics="beacnde" tid=18434834 file=attestation_pool.nim:81 justified_epoch=0 finalized_epoch=0 finalized_root=ebe49843
NOT 2020-11-07 16:36:49.091+01:00 Local validators attached                  topics="beacval" tid=18434834 file=validator_duties.nim:65 count=0
```

