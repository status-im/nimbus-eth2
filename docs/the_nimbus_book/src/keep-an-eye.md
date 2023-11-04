# Keep an eye on your validator

Once your validator has been activated, you can set up [validator monitoring](./validator-monitor.md) together with a [dashboard](./metrics-pretty-pictures.md) to keep track of its performance.

Another way of keeping track is using an online service such as beaconcha.in: [Mainnet](https://beaconcha.in/) or [Holesky](https://holesky.beaconcha.in).

Both online services and dashboards allow setting up alerts for when the validator is offline.

## Troubleshooting

### Make sure your validator is attached

On startup, you should see a log message that reads `Local validator attached`.
This has a `pubkey` field which should be the public key of your validator.

### Keep track of your syncing progress

To keep track of your sync progress, pay attention to the `Slot start` messages in your logs:

```
INF 2022-06-16 13:23:11.008+02:00 Slot start
  topics="beacnde"
  slot=4046214
  epoch=126444
  sync="00h37m (99.38%) 11.0476slots/s (DDQQDDDPDD:4021215)"
  peers=55
  head=5d59aba3:4021234
  finalized=125661:82616f78
  delay=8ms245us608ns
```

Where:

- `slot` is the current time on the beacon chain, measured in "slots"
- `epoch` shows the current epoch: each epoch has 32 slots, and each validator performs one attestation per epoch
- `peers` tells you how many peers you're currently connected to: depending on the number of attached validators, you may need anywhere from 10 to 60 peers connected
- `sync` tells you if your client is synced and can perform duties, or how long it will take to get there
  - `/opt` means that the node is [optimistically synced](./optimistic-sync.md): it is waiting for the execution client to finish syncing
  - in the case of [trusted node sync](./trusted-node-sync.md) it may also show `backfill` in which case duties are being performed but more bandwidth than usual is being used to download historical blocks
- `head` tells you the most recent block you've synced to so far (`5d59aba3` is the first part of the block hash, `4021234` is the slot number)
- `finalized` tells you the most recent finalized epoch you've synced to so far (`125661` is the epoch, `82616f78` is the checkpoint hash)

The string of letters -- what we call the `sync worker map` (in the above case represented by `DDQQDDDPDD`) represents the peers you are syncing from, where:

```
    s - sleeping (idle),
    w - waiting for a peer from PeerPool,
    R - requesting blocks from peer
    D - downloading blocks from peer
    Q - queued/waiting for ancestor blocks
    P - processing/verifying blocks
    U - updating peer's status information
```

!!! tip
    You can also use you calls outlined in the [REST API page](./rest-api.md) to retrieve similar information.
