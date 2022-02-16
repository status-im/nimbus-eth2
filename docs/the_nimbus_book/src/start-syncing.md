# Sync from scratch

To minimize the amount of downtime, you should ensure that your beacon node is [completely synced](./keep-an-eye.md#keep-track-of-your-syncing-progress) before submitting your deposit.  If it's not fully synced you will miss attestations and proposals until it has finished syncing.

This is particularly important if you are joining a network that's been running for a while since the sync could take some time.

> ⚠️ If you want to sync faster and attest immediately, you should take a look at [trusted node sync](./trusted-node-sync.md)

> **N.B.** In order to process incoming validator deposits from the eth1 chain, you'll need to run an eth1 client (**web3 provider**) in parallel to your eth2 client. See [here](./eth1.md) for instructions on how to do so.

### Testnet

To start syncing the `prater` testnet , from the `nimbus-eth2` repository, run:

```
 ./run-prater-beacon-node.sh --web3-url="<YOUR_WEB3_PROVIDER_URL>"
```

### Mainnet


To start syncing the eth2 mainnet, run:

```
 ./run-mainnet-beacon-node.sh --web3-url="<YOUR_WEB3_PROVIDER_URL>"
```

You should see the following output:

```
INF 2020-12-01 11:25:33.487+01:00 Launching beacon node
...
INF 2020-12-01 11:25:34.556+01:00 Loading block dag from database            topics="beacnde" tid=19985314 file=nimbus_beacon_node.nim:198 path=build/data/shared_prater_0/db
INF 2020-12-01 11:25:35.921+01:00 Block dag initialized
INF 2020-12-01 11:25:37.073+01:00 Generating new networking key
...
NOT 2020-12-01 11:25:59.512+00:00 Eth1 sync progress                         topics="eth1" tid=21914 file=eth1_monitor.nim:705 blockNumber=3836397 depositsProcessed=106147
NOT 2020-12-01 11:26:02.574+00:00 Eth1 sync progress                         topics="eth1" tid=21914 file=eth1_monitor.nim:705 blockNumber=3841412 depositsProcessed=106391
...
INF 2020-12-01 11:26:31.000+00:00 Slot start                                 topics="beacnde" tid=21815 file=nimbus_beacon_node.nim:505 lastSlot=96566 scheduledSlot=96567 beaconTime=1w6d9h53m24s944us774ns peers=7 head=b54486c4:96563 headEpoch=3017 finalized=2f5d12e4:96479 finalizedEpoch=3014
INF 2020-12-01 11:26:36.285+00:00 Slot end                                   topics="beacnde" tid=21815 file=nimbus_beacon_node.nim:593 slot=96567 nextSlot=96568 head=b54486c4:96563 headEpoch=3017 finalizedHead=2f5d12e4:96479 finalizedEpoch=3014
...
```
> If you want to put the database somewhere else, (e.g. an external ssd) pass the `--data-dir=/your/path`. ⚠️ If you do this, remember to pass this flag to **all** your nimbus calls.

### Command line options

You can pass any `nimbus_beacon_node` options to the `prater` and `mainnet` scripts. For example, if you wanted to launch Nimbus on `prater` with a different base port, say `9100`, you would run:

```
./run-prater-beacon-node.sh --tcp-port=9100 --udp-port=9100
```

To see a list of the command line options availabe to you, with descriptions, navigate to the `build` directory and run:

```
./nimbus_beacon_node --help
```
### Keep track of your sync progress

See [here](./keep-an-eye.html#keep-track-of-your-syncing-progress) for how to keep track of your sync progress.
