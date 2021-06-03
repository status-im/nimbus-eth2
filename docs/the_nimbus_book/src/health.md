# Monitor the health of your node

The most important thing for the the health, performance and stablity of your node and the overall network is the strength of your node's network connectivity / peer count.

## Monitor your Peer count

If your Peer count is low (less than `20`) and/or you repeatedly see the following warning:
```
WRN 2021-05-08 12:59:26.669+00:00 Peer count low, no new peers discovered    topics="networking" tid=1914 file=eth2_network.nim:963 discovered_nodes=9 new_peers=0 current_peers=1 wanted_peers=160
```

It probably means that your computer is not reachable from the outside. This means you won't be able to accept any incoming peer connections.

If you're on a home network, the fix here is to set up port forwarding.

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

## Keep track of your attestation effectiveness

Attestation effectiveness is a metric that directly affects your validator rewards. In simple terms, an attestation is more valuable the sooner it is put into a block and included in the chain. 

This interval is called the *inclusion distance* of an attestation. The smaller it is, the more profitable your validator will be. For a deeper understanding we highly recommend reading [Attestant's wonderful blog post](https://www.attestant.io/posts/defining-attestation-effectiveness/#:~:text=Stakers%20looking%20to%20maximize%20their,provide%20clear%20metrics%20for%20performance.) on the matter.

You can verify your validator's effectiveness on the [beaconcha.in](https://beaconcha.in/) website.

![](https://i.imgur.com/u80Ub2j.png)

Ideally you want to see a value above 80%.

While attestation effectiveness depends on a variety of factors - attestation network propagation, your network connectivity, and the peers you are connected to - your network connectivity is likely the most important factors you can control to improve this metric. Apart from the tips outlined on this guide, you could also experiment with [subscribing to all subnets](./profits.md#subscribe-to-all-subnets).

## Monitor your system's network I/O usage

If you're a Linux user and want to track how much network I/O your system uses over time, you can install a nice utility called [`vnstat`](https://humdi.net/vnstat/).

To install, run:

```
sudo apt install vnstat
```

To run it:

*TBC -See [here](https://github.com/jclapis/rp-pi-guide/blob/main/Native.md#monitoring-your-pis-performance) for more*

