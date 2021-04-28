# Troubleshooting

> ⚠️  The commands on this page refer to the Pyrmont testnet. If you're running mainnet, replace `pyrmont` with `mainnet` in the commands below.


As it stands, we are continuously making improvements to both stability and memory usage. So please make sure you keep your client up to date! This means restarting your node and updating your software regularly from the `master` branch. If you can't find a solution to your problem here, feel free to hit us up on our [discord](https://discord.com/invite/XRxWahP)!

> **Note:** While the `stable` branch of the `nimbus-eth2` repository is more stable, the latest updates happen in the `unstable` branch which is (usually) merged into master every week on Tuesday. If you choose to run Nimbus directly from the `unstable` branch, be prepared for instabilities!

To update and restart, run `git pull`, `make update`, followed by `make nimbus_beacon_node`:

```
cd nimbus-eth2
git pull
make update # Update dependencies
make nimbus_beacon_node # Rebuild beacon node
./run-pyrmont-beacon-node.sh # Restart using same keys as last run
```

If you find that `make update` causes the console to hang for too long, try running `make update V=1` or `make update V=2` instead (these will print a more verbose output to the console which may make it easier to diagnose the problem).

>**Note:** rest assured that when you restart the beacon node, the software will resume from where it left off, using the validator keys you have already imported.

### Starting over
The directory that stores the blockchain data of the testnet is `build/data/pyrmont_shared_0` (if you're connecting to another testnet, replace `pyrmont` with that testnet's name). If you've imported the wrong keys, and wish to start over, delete this repository.

### Syncing
If you’re experiencing sync problems,  we recommend running `make clean-pyrmont` to delete the database and restart your sync (make sure you’ve updated to the latest `master` first though).

> **Warning**: `make clean-pyrmont` will erase all of your syncing progress so far, so it should only be used as a last resort -- if your client gets stuck for a long time (because it's unable to find the right chain and/or stay with the same head value) and a normal restart doesn't improve things.

### Pruning the database
If you're running out of storage, you can [prune](https://blog.ethereum.org/2015/06/26/state-tree-pruning/) the database of unnecessary blocks and states by running:

```
make ncli_db
build/ncli_db pruneDatabase --db=build/data/shared_pyrmont_0/db --verbose=true
```

This will create `nbc_pruned.sqlite3` files in `build/data/shared_pyrmont_0/db`, which you can use in place of the orginal `nbc.sqlite3` files. We recommend you hold onto the originals until you've verified that your validator is behaving as expected with the pruned files.

Options:
- `--keepOldStates` (boolean):  Keep pre-finalisation states; defaults to `true`.
- `--verbose` (boolean): Print a more verbose output to the console; defaults to `false`.

### Low peer counts

If you're experiencing a low peer count, you may be behind a firewall. Try restarting your client and passing `--nat:extip:$EXT_IP_ADDRESS` as an option to `./run-pyrmont-beacon-node.sh`, where `$EXT_IP_ADDRESS` is your real IP. For example, if your real IP address is `35.124.65.104`, you'd run:

```
./run-pyrmont-beacon-node.sh --nat:extip:35.124.65.104
```

### Address already in use error

If you're seeing an error that looks like:

```
Error: unhandled exception: (98) Address already in use [TransportOsError]
```

It's probably because you're running multiple validators -- and the default base port `9000` is already in use.

To change the base port, run:

```
./run-pyrmont-beacon-node.sh --tcp-port=9100 --udp-port=9100
```

(You can replace `9100` with a port of your choosing)

###  Catching up on validator duties

If you're being flooded with `Catching up on validator duties` messages, then your CPU is probably too slow to run Nimbus. Please check that your setup matches our [system requirements](./hardware.md).

### Local timer is broken error

If you cannot start your validator because you are seeing logs that look like the following:

```
WRN 2021-01-08 06:32:46.975+00:00 Local timer is broken or peer's status information is invalid topics="beacnde" tid=120491 file=sync_manager.nim:752 wall_clock_slot=271961 remote_head_slot=271962 local_head_slot=269254 peer=16U*mELUgu index=0 tolerance_value=0 peer_speed=2795.0 peer_score=200
```

This is likely due to the fact that your local clock is off. To compare your local time with a internet time, run:

```
cat </dev/tcp/time.nist.gov/13 ; date -u 
```

The first line in the output will give you internet time. And the second line will give you the time according to your machine. These shouldn't be more than a second apart.

### Eth1 chain monitor failure

*todo*


