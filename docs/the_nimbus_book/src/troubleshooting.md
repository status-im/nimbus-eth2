# Troubleshooting

> ⚠️  The commands on this page refer to the Prater testnet. If you're running mainnet, replace `prater` with `mainnet` in the commands below.


As it stands, we are continuously making improvements to both stability and memory usage. So please make sure you keep your client up to date! This means restarting your node and updating your software regularly from the `stable` branch. If you can't find a solution to your problem here, feel free to get in touch with us on our [discord](https://discord.com/invite/XRxWahP)!

> **Note:** While the `stable` branch of the `nimbus-eth2` repository is more stable, the latest updates happen in the `unstable` branch which is (usually) merged into master every week on Tuesday. If you choose to run Nimbus directly from the `unstable` branch, be prepared for instabilities!


## Networking

> For more complete advice on fine-tuning your networking setup see [here](./networking.md)

### Low peer count

If you see a message that looks like the following in your logs:

```
Peer count low, no new peers discovered...
```

Your node is finding it hard to find peers. It's possible that you  may be behind a firewall. Try restarting your client and passing `--nat:extip:$EXT_IP_ADDRESS` as an option to `./run-prater-beacon-node.sh`, where `$EXT_IP_ADDRESS` is your real IP. For example, if your real IP address is `1.2.3.4`, you'd run:

```
./run-prater-beacon-node.sh --nat:extip:1.2.3.4
```

If this doesn't improve things, you may need to [set enr-auto-update](./networking.md#set-enr-auto-update) and/or [set up port forwarding](./networking.md#set-up-port-forwarding).

### No peers for topic

If you see a message that looks like the following in your logs:

```
No peers for topic, skipping publish...
```

This means you've missed an attestation because either your peer count is too low, or the quality of your peers is lacking.

There can be several reasons behind why this is the case. The first thing to check is that your max peer count (`--max-peers`) hasn't been set too low. In order to ensure your attestations are published correctly, we recommend setting `--max-peers` to 60, at the *very least*.

> Note that Nimbus manages peers slightly differently to other clients (we automatically connect to more peers than we actually use, in order not to have to do costly reconnects). As such, `--max-peers` is set to 160 by default.

If this doesn't fix the problem, please double check your node is able to [receive incoming connections](./networking.md#check-for-incoming-connections).

## Misc
### Console hanging for too long on update

To update and restart, run `git pull`, `make update`, followed by `make nimbus_beacon_node`:

```
cd nimbus-eth2
git pull
make update # Update dependencies
make nimbus_beacon_node # Rebuild beacon node
./run-prater-beacon-node.sh # Restart using same keys as last run
```

If you find that `make update` causes the console to hang for too long, try running `make update V=1` or `make update V=2` instead (these will print a more verbose output to the console which may make it easier to diagnose the problem).

>**Note:** rest assured that when you restart the beacon node, the software will resume from where it left off, using the validator keys you have already imported.

### Starting over after importing wrong keys
The directory that stores the blockchain data of the testnet is `build/data/prater_shared_0` (if you're connecting to another testnet, replace `prater` with that testnet's name). If you've imported the wrong keys, and wish to start over, delete this repository.

### Sync problems
If you’re experiencing sync problems,  we recommend running `make clean-prater` to delete the database and restart your sync (make sure you’ve updated to the latest `master` first though).

> **Warning**: `make clean-prater` will erase all of your syncing progress so far, so it should only be used as a last resort -- if your client gets stuck for a long time (because it's unable to find the right chain and/or stay with the same head value) and a normal restart doesn't improve things.

### Running out of storage
If you're running out of storage, you can [prune](https://blog.ethereum.org/2015/06/26/state-tree-pruning/) the database of unnecessary blocks and states by running:

```
make ncli_db
build/ncli_db pruneDatabase --db=build/data/shared_prater_0/db --verbose=true
```

This will create `nbc_pruned.sqlite3` files in `build/data/shared_prater_0/db`, which you can use in place of the orginal `nbc.sqlite3` files. We recommend you hold onto the originals until you've verified that your validator is behaving as expected with the pruned files.

Options:
- `--keepOldStates` (boolean):  Keep pre-finalisation states; defaults to `true`.
- `--verbose` (boolean): Print a more verbose output to the console; defaults to `false`.



### noCommand does not accept arguments

If, on start,  you see `The command 'noCommand' does not accept arguments`

Double check to see if your command line flags are in the correct format, i.e. `--foo=bar`, `--baz`, or `--foo-bar=qux`.

### Address already in use error

If you're seeing an error that looks like:

```
Error: unhandled exception: (98) Address already in use [TransportOsError]
```

It's probably because you're running multiple validators -- and the default base port `9000` is already in use.

To change the base port, run:

```
./run-prater-beacon-node.sh --tcp-port=9100 --udp-port=9100
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


If you see an error that looks like the following:

```
{"lvl":"ERR","ts":"2021-05-11 09:05:53.547+00:00","msg":"Eth1 chain monitoring failure, restarting","topics":"eth1","tid":1,"file":"eth1_monitor.nim:1158","err":"Trying to access value with err: Failed to setup web3 connection"}
```

It's because your node can't connect to the web3 provider you have specified. Please double check that you've correctly specified your provider. If you haven't done so already, we recommend [adding a backup](web3-backup.md).

### Discovered new external address warning log

```console
WRN 2021-03-11 13:26:25.943-08:00
Discovered new external address but ENR auto update is off
topics="discv5" tid=77655 file=protocol.nim:940 majority=Some("myIPaddressHere":9000) previous=None[Address]
```

This message is displayed regularly when Nimbus canot detect your correct IP address. It may be a sign that you have a dynamic IP address that keeps changing. Or that Nimbus is unable to get your IP from the [UPnP](https://en.wikipedia.org/wiki/Universal_Plug_and_Play).

The first step is to try relaunching the beacon node with the `--enr-auto-update` option.

If that doesn't fix the problem, double check that your [ports are open](https://www.yougetsignal.com/tools/open-ports/) and that you have [port forwarding](https://www.computerhope.com/issues/ch001201.htm) enabled on your gateway (assuming that you are behind a [NAT](https://en.wikipedia.org/wiki/Network_address_translation)).

See our page on [monitoring the health of your node](./health.md) for more.



## Raspberry Pi

### Trouble transferring data to/from USB3.0 SSDs

We have seen reports of extremely degraded performance when using several types of USB3.0 to SSD adapter or when using native USB3.0 disk drives. [This post](https://www.raspberrypi.org/forums/viewtopic.php?t=245931#p1501426) details why there is a difference in behaviour from models prior to Pi 4 and the recommended workaround.

