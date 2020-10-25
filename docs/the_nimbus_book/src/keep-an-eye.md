# Keep an eye on your validator
 
 If you deposit after the [genesis](https://hackmd.io/@benjaminion/genesis) state was decided, your validator(s) will be put in a queue based on deposit time, and will slowly be inducted into the validator set after genesis. Getting through the queue may take a few hours or a day or so.
 
 The best way to keep track of your validator's status is [medalla.beaconcha.in](https:/medalla.beaconcha.in) (click on the orange magnifying glass at the very top and paste in your validator's public key).
 
You can even [create an account](https://medalla.beaconcha.in/register) to add alerts and keep track of your validator's [performance](https://medalla.beaconcha.in/dashboard).

## Syncing progress
To keep track of your syncing progress, have a look at the output at the very bottom of the terminal window in which your validator is running. You should see something like:

```
peers: 35 ❯ finalized: ada7228a:8765 ❯ head: b2fe11cd:8767:2 ❯ time: 9900:7 (316807) ❯ sync: wPwwwwwDwwDPwPPPwwww:7:4.0627 (280512)
```

Where:
- `peers` tells you how many peers you're currently connected to (in the above case, 35 peers)
- `finalized` tells you the most recent finalized epoch you've synced to so far (the 8765th epoch)
- `head` tells you the most recent slot you've synced to so far (the 2nd slot of the 8767th epoch)
- `time` tells you the current time since Genesis (the 7th slot of the 9900th epoch -- or equivalently, the 316,807th slot)
- `sync` tells you how fast you're syncing (4.0627 blocks per second), how many blocks you've synced so far (280,512), along with information about 20 sync workers linked to the 20 most performant peers you are currently connected to (represented by a string of letters and a number).

To dig into `sync` a little:
```
sync: <sync worker map>:<number of active workers>:<current syncing speed in blocks/second>
```

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
