# Keep an eye on your validator
 
 
The best way to keep track of your validator's status is using the `beaconcha.in` explorer (click on the orange magnifying glass at the very top and paste in your validator's public key):
 
 - **Testnet:** [prater.beaconcha.in](https:/prater.beaconcha.in) 
 - **Mainnet:** [beaconcha.in](https://beaconcha.in/)
 
If you deposit after the [genesis](https://hackmd.io/@benjaminion/genesis) state was decided, your validator(s) will be put in a queue based on deposit time, and will slowly be inducted into the validator set after genesis. Getting through the queue may take a few hours or a day or so.

 
You can even create an account ([testnet link](https://prater.beaconcha.in/register), [mainnet link](https://beaconcha.in/register)) to add alerts and keep track of your validator's performance ([testnet link](https://prater.beaconcha.in/dashboard), [mainnet link](https://beaconcha.in/dashboard)).

-------------------------------

## Make sure your validator is attached

On startup, you should see a log message that reads `Local validator attached`. This has a `pubkey` field which should the public key of your validator.

## Check your IP address

Check that Nimbus has recognised your external IP properly. To do this, look at the end of the first log line:

```
Starting discovery node","topics":"discv5","tid":2665484,"file":"protocol.nim:802","node":"b9*ee2235:<IP address>:9000"
```

`<IP address>` should match your external IP (the IP by which you can be reached from the internet).

Note that the port number is displayed directly after the IP -- in the above case `9000`. This is the port that should be opened and mapped.

## Keep track of your syncing progress

To keep track of your sync progress, pay attention to the `Slot start` messages in your logs:

```
INF 2021-05-24 14:53:59.067+02:00 Slot start                                 
topics="beacnde" tid=3485464 file=nimbus_beacon_node.nim:968 lastSlot=1253067 wallSlot=1253068 delay=67ms515us0ns
peers=22
head=eb994064:90753 
headEpoch=2836 
finalized=031b9591:90688 
finalizedEpoch=2834 
sync="PPPPPDDDDP:10:15.4923:7.7398:01d17h43m (90724)"
```

Where:
- `peers` tells you how many peers you're currently connected to (in the above case, 35 peers)
- `finalized` tells you the most recent finalized epoch you've synced to so far (the 8765th epoch)
- `head` tells you the most recent slot you've synced to so far (the 2nd slot of the 8767th epoch)
- `sync` tells you how fast you're syncing right now (`15.4923` blocks per second), your average sync speed since you stared (`7.7398` blocks per second), the time left until you're fully synced (`01d17h43m`) how many blocks you've synced so far (`90724`), along with information about 10 sync workers linked to the 10 most performant peers you are currently connected to (represented by a string of letters and a number).

The string of letters -- what we call the `sync worker map` (in the above case represented by `wPwwwwwDwwDPwPPPwwww`) represents the status of the sync workers mentioned above, where:

```
    s - sleeping (idle),
    w - waiting for a peer from PeerPool,
    R - requesting blocks from peer
    D - downloading blocks from peer
    P - processing/verifying blocks
    U - updating peer's status information
```

The number following it (in the above case represented by `10`) represents the number of workers that are currently active (i.e not sleeping or waiting for a peer).

> **Note:** You can also use you the RPC calls outlined in the [API page](./api.md) to retrieve similar information.


