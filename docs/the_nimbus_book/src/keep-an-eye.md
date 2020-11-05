# Keep an eye on your validator
 
 
The best way to keep track of your validator's status is using the `beaconcha.in` explorer (click on the orange magnifying glass at the very top and paste in your validator's public key):
 
 - **Testnet:** [medalla.beaconcha.in](https:/medalla.beaconcha.in) 
 - **Mainnet:** [beaconcha.in](https://beaconcha.in/)
 
If you deposit after the [genesis](https://hackmd.io/@benjaminion/genesis) state was decided, your validator(s) will be put in a queue based on deposit time, and will slowly be inducted into the validator set after genesis. Getting through the queue may take a few hours or a day or so.

 
You can even create an account ([testnet link](https://medalla.beaconcha.in/register), [mainnet link](https://beaconcha.in/register)) to add alerts and keep track of your validator's performance ([testnet link](https://medalla.beaconcha.in/dashboard), [mainnet link](https://beaconcha.in/dashboard)).

-------------------------------

> ⚠️  The rest of this page concerns the Medalla testnet only. If you have made a mainnet deposit, you do not need to run Nimbus quite yet. Mainnet [Genesis](https://hackmd.io/@benjaminion/genesis) date has been set to [December 1st](https://blog.ethereum.org/2020/11/04/eth2-quick-update-no-19/). This page will be updated nearer the time.

## Make sure your validator is attached

On startup, you should see a log message that reads `Local validators attached`. This has a `count` field which should correctly reflect the number of validators you wish to run.

```
{"lvl":"NOT","ts":"2020-10-26 10:16:51.365+00:00","msg":"Local validators attached ","topics":"beacval","tid":12291,"file":"validator_duties.nim:65","count":1}
```
*In the above case, the `count` field reads `1`, which means 1 validator has successfully attached to the beacon node.*

## Keep track of your syncing progress

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

## eth2stats
<blockquote class="twitter-tweet"><p lang="en" dir="ltr">Zinken eth2stats is up!<a href="https://t.co/3LsvmN3NXN">https://t.co/3LsvmN3NXN</a><br><br>One good pre-genesis check is to query your local node&#39;s API to see if you have peers (you should!)<br><br>If you hook up to eth2stats, you can easily monitor this metric from anywhere 👀</p>&mdash; dannyryan (@dannyryan) <a href="https://twitter.com/dannyryan/status/1314280942651858945?ref_src=twsrc%5Etfw">October 8, 2020</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

*Todo*
