# Networking

Nimbus will automatically connect to peers based on the health and quality of peers that it's already connected to.
Depending on the network and the number of validators attached to the node, Nimbus may need anywhere from 10 to 60 peers connected to operate well.

In addition to making outgoing connections, the beacon node node works best when others can connect to it — this speeds up the process of finding good peers.

To allow incoming connections, the node must be reachable via a public IP address.
It must also be aware of this address, so that it can advertise it to its peers.

## UPnP

By default, Nimbus uses [UPnP](https://en.wikipedia.org/wiki/Universal_Plug_and_Play) to set up port forwarding and detect your external IP address.
If you do not have UPnP enabled, you may need to pass additional command-line options to the node, as explained in the subsequent sections.

Enabling UPnP is usually as simple as checking a box in your router's configuration.

## Monitor your Peer count

!!! note
    The `--max-peers` setting should not be set below 70.
    Lowering `max-peers` does not significantly improve bandwidth usage, but does increase the risk of missed attestations.

If your Peer count is low (less than `15`) and/or you repeatedly see either of the following warnings:

`Peer count low, no new peers discovered...`

or

`No peers for topic, skipping publish...`

It means that Nimbus is unable to find a sufficient number of peers to guarantee stable operation, and you may miss attestations and blocks as a result.

Most commonly, this happens when your computer is not reachable from the outside and therefore won't be able to accept any incoming peer connections.

If you're on a home network, the fix here is to [set up port forwarding](./networking.md#set-up-port-forwarding) (this may require you to [pass the extip option](./networking.md#pass-the-extip-option) and [set enr-auto-update](./networking.md#set-enr-auto-update)).

The first step however, is to check for incoming connections.

## Check for incoming connections

To check if you have incoming connections set, run:

<!-- TODO: It would be very sweet if we can create some kind of CI tests that verify that these instructions work -->

```
curl -s http://localhost:8008/metrics | grep libp2p_open_streams
```

In the output, look for a line that looks like:

```
libp2p_open_streams{type="ChronosStream",dir="in"}
```

If there are no `dir=in` ChronosStreams, incoming connections are not working.

!!! note
    You need to run the client with the `--metrics` option enabled in order for this to work

## Set an explicit external IP

If you have a static public IP address, use the `--nat:extip:$EXT_IP_ADDRESS` option to pass it to the client,  where `$EXT_IP_ADDRESS` is your public IP.
See [here](./networking.md#determine-your-public-ip-address) for how to determine your public IP address.

!!! note
    If you have a dynamic IP, you can use `extip` the initial setting, but should also enable `--enr-auto-update` to keep it up-to-date.

## Set ENR auto update

The `--enr-auto-update` feature keeps your external IP address up to date based on information received from other peers on the network.
This option is useful with ISPs that assign IP addresses dynamically.

In practice this means relaunching the beacon node with `--enr-auto-update:true` (pass it as an option in the command line).

## Set up port forwarding

If you're running on a home network and want to ensure you are able to receive incoming connections you may need to set up port forwarding (though some routers automagically set this up for you).

!!! note
    If you are running your node on a virtual public server (VPS) instance, you can safely ignore this section.

While the specific steps required vary based on your router, they can be summarised as follows:

1. Determine your [public IP address](./networking.md#determine-your-public-ip-address)
2. Determine your [private IP address](./networking.md#determine-your-private-ip-address)
3. Browse to the management website for your home router ([http://192.168.1.1](http://192.168.1.1) for most routers)
4. Log in as admin
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

=== "Linux"
    ```sh
    ip addr show | grep "inet " | grep -v 127.0.0.1
    ```

=== "Windows"
    ```sh
    ipconfig | findstr /i "IPv4 Address"
    ```

=== "macOS"
    ```sh
    ifconfig | grep "inet " | grep -v 127.0.0.1
    ```

## Check open ports on your connection

Use the [open ports tool](https://www.yougetsignal.com/tools/open-ports/) to check your external (public) IP address and detect open ports on your connection (Nimbus TCP and UDP ports are both set to `9000` by default).

## Reading the logs

- `No peers for topic, skipping publish...`

    This is printed when the client lacks quality peers to publish attestations to - this is the most important indication that the node is having trouble keeping up.
    If you see this, you are missing attestations.

- `Peer count low, no new peers discovered...`

    This is a sign that you may be missing attestations.

- `No external IP provided for the ENR...`

    This message basically means that the software did not manage to find a public IP address (by either looking at your routed interface IP address, and/or by attempting to get it from your gateway through UPnP or NAT-PMP).

- `Discovered new external address but ENR auto update is off...`

    It's possible that your ISP has changed your IP address without you knowing.
    The first thing to do it to try relaunching the beacon node with with `--enr-auto-update:true` (pass it as an option in the command line).

    If this doesn't fix the problem, the next thing to do is to check your external (public) IP address and detect open ports on your connection - you can use [this site](https://www.yougetsignal.com/tools/open-ports/ ).
    Note that Nimbus `TCP` and `UDP` ports are both set to `9000` by default.
    See above for how to set up port forwarding.

