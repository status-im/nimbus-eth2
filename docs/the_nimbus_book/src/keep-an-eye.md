# Keep an eye on your validator
 
 
The best way to keep track of your validator's status is using the `beaconcha.in` explorer (click on the orange magnifying glass at the very top and paste in your validator's public key):
 
 - **Testnet:** [pyrmont.beaconcha.in](https:/pyrmont.beaconcha.in) 
 - **Mainnet:** [beaconcha.in](https://beaconcha.in/)
 
If you deposit after the [genesis](https://hackmd.io/@benjaminion/genesis) state was decided, your validator(s) will be put in a queue based on deposit time, and will slowly be inducted into the validator set after genesis. Getting through the queue may take a few hours or a day or so.

 
You can even create an account ([testnet link](https://pyrmont.beaconcha.in/register), [mainnet link](https://beaconcha.in/register)) to add alerts and keep track of your validator's performance ([testnet link](https://pyrmont.beaconcha.in/dashboard), [mainnet link](https://beaconcha.in/dashboard)).

-------------------------------

## Make sure your validator is attached

On startup, you should see a log message that reads `Local validator attached`. This has a `pubKey` field which should the public key of your validator.

## Check your IP address

Check that Nimbus has recognised your external IP properly. To do this, look at the end of the first log line:

```
Starting discovery node","topics":"discv5","tid":2665484,"file":"protocol.nim:802","node":"b9*ee2235:<IP address>:9000"
```

`<IP address>` should match your external IP (the IP by which you can be reached from the internet).

Note that the port number is displayed directly after the IP -- in the above case `9000`. This is the port that should be opened and mapped.

## Keep track of your syncing progress

To keep track of your syncing progress, have a look at the output at the very bottom of the terminal window in which your validator is running. You should see something like:

```
peers: 35 ❯ finalized: ada7228a:8765 ❯ head: b2fe11cd:8767:2 ❯ time: 9900:7 (316807) ❯ sync: wPwwwwwDwwDPwPPPwwww:7:4.2313:4.0627:03h01m(280512)
```

Where:
- `peers` tells you how many peers you're currently connected to (in the above case, 35 peers)
- `finalized` tells you the most recent finalized epoch you've synced to so far (the 8765th epoch)
- `head` tells you the most recent slot you've synced to so far (the 2nd slot of the 8767th epoch)
- `time` tells you the current time since Genesis (the 7th slot of the 9900th epoch -- or equivalently, the 316,807th slot)
- `sync` tells you how fast you're syncing right now (4.2313 blocks per second), your average sync speed since you stared (4.0627 blocks per second), the time left until you're fully synced (3 hours and 1 min) how many blocks you've synced so far (280,512), along with information about 20 sync workers linked to the 20 most performant peers you are currently connected to (represented by a string of letters and a number).

The string of letters -- what we call the `sync worker map` (in the above case represented by `wPwwwwwDwwDPwPPPwwww`) represents the status of the sync workers mentioned above, where:

```
    s - sleeping (idle),
    w - waiting for a peer from PeerPool,
    R - requesting blocks from peer
    D - downloading blocks from peer
    P - processing/verifying blocks
    U - updating peer's status information
```

The number following it (in the above case represented by `7`) represents the number of workers that are currently active (i.e not sleeping or waiting for a peer).

> **Note:** If you're running Nimbus as a service, the above status bar won't be visible to you. You can use you the RPC calls outlined in the [API page](./api.md) to retrieve similar information.


