# Troubleshooting

!!! note
    The commands on this page refer to mainnet.
    If you're running on `holesky` or another testnet, replace `mainnet` accordingly.

We are continuously making improvements to both stability and resource usage.
If you run into any problem with Nimbus and are not running the latest version, chances are they have already been fixed.
See the [update guide](./keep-updated.md) for instructions of how to upgrade.

If you can't find a solution to your problem here, get in touch with us on our [discord](https://discord.com/invite/XRxWahP).

!!! note
    When installing Nimbus, you will typically be using the latest `stable` release.

    However, the latest changes happen in the `unstable` branch.
    If you're looking to test the changes coming to the _next_ Nimbus release, consider building Nimbus from [source](./keep-updated.md#build-from-source) using the `unstable` branch.

## Networking

A correctly configured network is key to getting good performance: the [networking guide](./networking.md) details everything you need to know!

### Low peer count

If you see a message that looks like the following in your logs:

```
Peer count low, no new peers discovered...
```

Your node is finding it hard to find peers.
It's possible that you  may be behind a firewall.
Try restarting your client and passing `--nat:extip:$EXT_IP_ADDRESS` as an option to `./run-mainnet-beacon-node.sh`, where `$EXT_IP_ADDRESS` is your real IP. For example, if your real IP address is `1.2.3.4`, you'd run:

```
./run-mainnet-beacon-node.sh --nat:extip:1.2.3.4
```

If this doesn't improve things, you may need to [set enr-auto-update](./networking.md#set-enr-auto-update) and/or [set up port forwarding](./networking.md#set-up-port-forwarding).

### No peers for topic

If you see a message that looks like the following in your logs:

```
No peers for topic, skipping publish...
```

This means you've missed an attestation because either your peer count is too low, or the quality of your peers is lacking.

There can be several reasons behind why this is the case.
The first thing to check is that your max peer count (`--max-peers`) hasn't been set too low.
In order to ensure your attestations are published correctly, `--max-peers` should be set to 70, at the *very least*.

!!! note
    Nimbus manages peers slightly differently to other clients (we automatically connect to more peers than we actually use, in order not to have to do costly reconnects).
    As such, `--max-peers` is set to 160 by default.

If this doesn't fix the problem, please double check your node is able to [receive incoming connections](./networking.md#check-for-incoming-connections).

## Misc

### Console hanging for too long on update

To update and restart, run `git pull`, `make update`, followed by `make nimbus_beacon_node`:

```
cd nimbus-eth2
git pull
make update # Update dependencies
make nimbus_beacon_node # Rebuild beacon node
./run-mainnet-beacon-node.sh # Restart using same keys as last run
```

If you find that `make update` causes the console to hang for too long, try running `make update V=1` or `make update V=2` instead (these will print a more verbose output to the console which may make it easier to diagnose the problem).

!!! note
    Rest assured that when you restart the beacon node, the software will resume from where it left off, using the validator keys you have already imported.

### Starting over after importing wrong keys

Your keys and secrets are stored in the [data directory](./data-dir.md) (usually `build/data/shared_mainnet_0`).
If you imported the wrong keys, simply remove them from `validators` and `secrets` found in the data directory.

### Sync problems

If you’re experiencing sync problems, make sure that your network is healthy and that you have a recent version installed.

In rare cases, such as after an unclean shutdown, it may happen that the database has been corrupted and you need to restart the sync.
To do so, remove the `db` folder from the [data directory](./data-dir.md) and restart the node.
You can get re-synced faster using [trusted node sync](./trusted-node-sync.md).

### noCommand does not accept arguments

If, on start,  you see `The command 'noCommand' does not accept arguments`.

Double check to see if your command line flags are in the correct format, e.g. `--foo=bar`, `--baz`, or `--foo-bar=qux`.

!!! tip
    All options accepting values need a `=` between the option name and the value!

### Address already in use error

If you're seeing an error that looks like:

```
Error: unhandled exception: (98) Address already in use [TransportOsError]
```

It means that you're running another node that is using the same port as the one you're trying to start or that you're trying to start a second instance of the same node.

To change the base port, run:

```
./run-mainnet-beacon-node.sh --tcp-port=9100 --udp-port=9100
```

You can replace `9100` with a port of your choosing.

###  Catching up on validator duties

If you're being flooded with `Catching up on validator duties` messages, your CPU is probably too slow to run Nimbus.
Please check that your setup matches our [system requirements](./hardware.md).

### Eth1 chain monitor failure

<!-- TODO: This error message has changed -->

If you see an error that looks like the following:

```
{"lvl":"ERR","ts":"2021-05-11 09:05:53.547+00:00","msg":"Eth1 chain monitoring failure, restarting","topics":"eth1","tid":1,"err":"Trying to access value with err: Failed to setup web3 connection"}
```

It is because your node can't connect to the web3 provider you have specified.
Please double check that you've correctly specified your provider.

If you haven't done so already, we recommend [allowing multiple execution clients](./eth1.md#running-multiple-execution-clients).

### Discovered new external address warning log

```
WRN 2021-03-11 13:26:25.943-08:00
Discovered new external address but ENR auto update is off
topics="discv5" tid=77655 file=protocol.nim:940 majority=Some("myIPaddressHere":9000) previous=None[Address]
```

This message is displayed regularly when Nimbus cannot detect your correct IP address.
It may be a sign that you have a dynamic IP address that keeps changing.
Or that Nimbus is unable to get your IP from the [UPnP](https://en.wikipedia.org/wiki/Universal_Plug_and_Play).

The first step is to try relaunching the beacon node with the `--enr-auto-update` option.

If that doesn't fix the problem, double check that your [ports are open](https://www.yougetsignal.com/tools/open-ports/) and that you have [port forwarding](https://www.computerhope.com/issues/ch001201.htm) enabled on your gateway (assuming that you are behind a [NAT](https://en.wikipedia.org/wiki/Network_address_translation)).

See our page on [monitoring the health of your node](./health.md) for more.


## Raspberry Pi

### Trouble transferring data to/from USB3.0 SSDs

We have seen reports of degraded performance when using several types of USB3.0 to SSD adapters or when using native USB3.0 disk drives.
[This post on RPi forums](https://forums.raspberrypi.com/viewtopic.php?t=245931#p1501426 ) details why there is a difference in behaviour from models prior to Pi 4 and the recommended workaround.

