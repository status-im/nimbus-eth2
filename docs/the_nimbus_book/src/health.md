# Monitor the health of your node

The most important thing for the the health, performance and stablity of your node and the overall network is the strength of your node's network connectivity / peer count.

### Verify your IP

```console
WRN 2021-03-11 13:26:25.943-08:00
Discovered new external address but ENR auto update is off
topics="discv5" tid=77655 file=protocol.nim:940 majority=Some("myIPaddressHere":9000) previous=None[Address]
```

This message is displayed regularly when Nimbus canot detect your correct IP address. It may be a sign that you have a dynamic IP address that keeps changing. Or that Nimbus is unable to get your IP from the [UPnP](https://en.wikipedia.org/wiki/Universal_Plug_and_Play).

The first step is to try relaunching the beacon node with the `--enr-auto-update` option.

If that doesn't fix the problem, double check that your [ports are open](https://www.yougetsignal.com/tools/open-ports/) and that you have [port forwarding](https://www.computerhope.com/issues/ch001201.htm) enabled on your gateway (assuming that you are behind a [NAT](https://en.wikipedia.org/wiki/Network_address_translation)). 

To determine your public IP address, visit [http://v4.ident.me/](http://v4.ident.me/) or run this command:

```
curl v4.ident.me
```

To determine your private IP address, or run the appropriate command for your OS:

**GNU/Linux:**

```
ip addr show | grep "inet " | grep -v 127.0.0.1
```

**Windows:**
```
ipconfig | findstr /i "IPv4 Address"
```

**macOS:**
```
ifconfig | grep "inet " | grep -v 127.0.0.1
```

### Monitor your Peer count

```
WRN 2021-05-08 12:59:26.669+00:00 Peer count low, no new peers discovered    topics="networking" tid=1914 file=eth2_network.nim:963 discovered_nodes=9 new_peers=0 current_peers=1 wanted_peers=160
```

If you see such a warning it means you're probably not reachable from the outside. This means you won't be able to make any incoming peer connections.

If you don't have UPnP or NAT-PMP enabled in your router, you may need to [manually open and forward ports](https://www.computerhope.com/issues/ch001201.htm).

Use [this tool](https://www.yougetsignal.com/tools/open-ports/) to check your external IP address and detect open ports on your connection.

> Note that Nimbus TCP and UDP ports are both set to `9000` by default, and both need to be forwarded.

For more on enabling incoming connections, see Prysm's wonderful guide on [improving peer-to-peer connectivity](https://docs.prylabs.network/docs/prysm-usage/p2p-host-ip/).



### Monitor your system's network I/O usage

If you're a Linux user and want to track how much network I/O your system uses over time, you can install a nice utility called [`vnstat`](https://humdi.net/vnstat/).

To install, run:

```
sudo apt install vnstat
```

To run it:

*TBC*

See [here](https://github.com/jclapis/rp-pi-guide/blob/main/Native.md#monitoring-your-pis-performance) for more.
