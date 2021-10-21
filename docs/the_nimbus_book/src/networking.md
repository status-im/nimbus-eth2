# Network setup


A collection of tips and tricks to help improve your network connectivity.

## Monitor your Peer count

If your Peer count is low (less than `15`) and/or you repeatedly see the following warning:
```
WRN 2021-05-08 12:59:26.669+00:00 Peer count low, no new peers discovered    topics="networking" tid=1914 file=eth2_network.nim:963 discovered_nodes=9 new_peers=0 current_peers=1 wanted_peers=160
```

It probably means that your computer is not reachable from the outside. This means you won't be able to accept any incoming peer connections.

If you're on a home network, the fix here is to set up port forwarding.

## Check for incoming connections

To check if you have incoming connections set, run:

```
curl -s http://localhost:8008/metrics | grep libp2p_open_streams 
```

> **N.B** you need to run the client with the `--metrics` option enabled in order for this to work


## Set up port forwarding

If you're running on a home network and want to ensure you are able to receive incoming connections you may need to set up port forwarding (though some routers automagically set this up for you).


> **Note:** If you are running your node on a virtual public cloud (VPC) instance, you can safely ignore this section.

While the specific steps required vary based on your router, they can be summarised as follows:


1. Determine your [public IP address](./health.md#public-ip-address)
2. Determine your [private IP address](./health.html#private-ip-address)
3. Browse to the management website for your home router (typically [http://192.168.1.1)](http://192.168.1.1)
4. Log in as admin / root
5. Find the section to configure port forwarding
6. Configure a port forwarding rule with the following values:
- External port: `9000`
- Internal port: `9000`
- Protocol: `TCP`
- IP Address: Private IP address of the computer running Nimbus
7. Configure a second port forwarding rule with the following values:
- External port: `9000`
- Internal port: `9000`
- Protocol: `UDP`
- IP Address: Private IP address of the computer running Nimbus

### Determine your public IP address

To determine your public IP address, visit [http://v4.ident.me/](http://v4.ident.me/) or run this command:

```
curl v4.ident.me
```

### Determine your private IP address

To determine your private IP address, run the appropriate command for your OS:

**Linux:**

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

### Check open ports on your connection
Use [this tool](https://www.yougetsignal.com/tools/open-ports/) to check your external (public) IP address and detect open ports on your connection (Nimbus TCP and UDP ports are both set to `9000` by default).


## Pass the extip option

If you're still experiencing a low peer count, you may be behind a firewall. Try restarting your client and passing `--nat:extip:$EXT_IP_ADDRESS` as an option to the client,  where `$EXT_IP_ADDRESS` is your real IP. For example, if your real IP address is `35.124.65.104`, you'd run:

```
./run-prater-beacon-node.sh --nat:extip:35.124.65.104
```

## ENR auto update = true

Additionally you can turn on `--enr-auto-update` to allow discovery to keep your external IP address up to date based on information received from peers.

In practice this means relaunching the beacon node with `--enr-auto-update:true` (pass it as an option in the command line).

## Reading the logs

`No external IP provided for the ENR...`

This message basically means that the software did not manage to find a public IP address (by either looking at your routed interface IP address, and/or by attempting to get it from your gateway through UPnP or NAT-PMP).

`Discovered new external address but ENR auto update is off...` 

It's possible that your ISP has changed your IP address without you knowing. The first thing to do it to try relaunching the beacon node with with `--enr-auto-update:true` (pass it as an option in the command line).

If this doesn't fix the problem, the next thing to do is to check your external (public) IP address and detect open ports on your connection - you can use [this site](https://www.yougetsignal.com/tools/open-ports/ ).  Note that Nimbus `TCP` and `UDP` ports are both set to `9000` by default. See above for how to set up port forwarding.


