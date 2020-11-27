# Validating with a Raspberry Pi

<blockquote class="twitter-tweet"><p lang="en" dir="ltr">I expect the new Raspberry Pi 4 (4GB RAM option, external SSD) to handle an Eth2 validator node without breaking a sweat. That&#39;s $100 of hardware running at 10 Watts to support a 32 ETH node (currently ~$10K stake).</p>&mdash; Justin Ðrake (@drakefjustin) <a href="https://twitter.com/drakefjustin/status/1143091047058366465?ref_src=twsrc%5Etfw">June 24, 2019</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

## Introduction
This page will take you through how to use your laptop to program your Raspberry Pi, get Nimbus running, and connect to the **Pyrmont testnet** (if this is not something you plan on doing, feel free to [skip ahead](./keep-an-eye.md)).

One of the most important aspects of the Raspberry Pi experience is trying to make it as easy as possible to get started. As such, we try our best to explain things from first-principles.

## Prerequisites
- Raspberry Pi 4 (4GB RAM option)
- 64GB microSD Card
- microSD USB adapter
- 5V 3A USB-C charger
- Reliable Wifi connection
- Laptop
- Basic understanding of the [command line](https://www.learnenough.com/command-line-tutorial/basics)
- 160GB SSD

> ⚠️  You will need an SSD to run the Nimbus (without an SSD drive you have absolutely no chance of syncing the Ethereum blockchain). You have two options:
>
> 1. Use an USB portable SSD disk such as the Samsung T5 Portable SSD.
>
> 2. Use an USB 3.0 External Hard Drive Case with a SSD Disk. For example, [Ethereum on Arm](https://twitter.com/EthereumOnARM) use an Inateck 2.5 Hard Drive Enclosure FE2011. Make sure to buy a case with an UASP compliant chip, particularly, one of these: JMicron (JMS567 or JMS578) or ASMedia (ASM1153E).
>
> In both cases, avoid low quality SSD disks (the SSD is a key component of your node and can drastically affect both the performance and sync time). Keep in mind that you need to plug the disk to an USB 3.0 port (the blue port).

### 1. Download Raspberry Pi Imager

[Raspberry Pi Imager](https://www.raspberrypi.org/blog/raspberry-pi-imager-imaging-utility/) is a new imaging utility that makes it simple to manage your microSD card with Raspbian (the free Pi operating system based on Debian).

You can find the [download](https://www.learnenough.com/command-line-tutorial/basics) link for your operating system here: [Windows](https://downloads.raspberrypi.org/imager/imager_1.4.exe), [macOS](https://downloads.raspberrypi.org/imager/imager_1.4.dmg), [Ubuntu](https://downloads.raspberrypi.org/imager/imager_1.4_amd64.deb).

### 2. Download Raspian 64-bit OS (Beta)
You can find the latest version, [here](https://downloads.raspberrypi.org/raspios_arm64/images/).

### 3. Plug in SD card
Use your microSD to USB adapter to plug the SD card into your computer.


### 4. Download Raspberry Pi OS

Open Raspberry Pi Imager and click on **CHOOSE OS**

![](https://storage.googleapis.com/ethereum-hackmd/upload_7b8cfa54f877218b6d971f09fa8d62ff.png)

Scroll down and click on **Use custom**

![](https://i.imgur.com/ar88MTt.png)

Find the OS you downloaded in step 2

![](https://i.imgur.com/NeOT8pf.png)

### 4b. Write to SD card


Click on **CHOOSE SD CARD**. You should see a menu pop-up with your SD card listed -- Select it

![](https://storage.googleapis.com/ethereum-hackmd/upload_f90713c1ef782a94b5fce9eb8249c206.png)

Click on **WRITE**

![](https://storage.googleapis.com/ethereum-hackmd/upload_0e02be31057745c6b9834a925c54b9d3.png)

Click **YES**

![](https://storage.googleapis.com/ethereum-hackmd/upload_160208a5bc983165c2a1eb9bffed01c2.png)

Make a cup of coffee :)

### 5. Set up wireless LAN

Since you have loaded Raspberry Pi OS onto a blank SD card, you will have two partitions. The first one, which is the smaller one, is the `boot` partition.

Create a `wpa_supplicant` configuration file in the `boot` partition with the following content:

```
# wpa_supplicant.conf

ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=<Insert 2 letter ISO 3166-1 country code here>

network={
    ssid="<Insert your Wifi network's name here>"
    psk="<Insert your Wifi network's password here>"
}
```


 > **Note:** Don't forget to replace the placeholder `country`, `ssid`, and `psk` values. See [Wikipedia](https://en.wikipedia.org/wiki/ISO_3166-1) for a list of 2 letter `ISO 3166-1` country codes.



### 6. Enable SSH (using Linux or macOS)

You can [access the command line](https://www.raspberrypi.org/documentation/remote-access/ssh/) of a Raspberry Pi remotely from another computer or device on the same network using [SSH](https://en.wikipedia.org/wiki/Ssh_(Secure_Shell)).

While SSH is not enabled by default, you can enable it by placing a file named `ssh`, without any extension, onto the boot partition of the SD card.

When the Pi boots, it will look for the `ssh` file. If it is found, SSH is enabled and the file is deleted. The content of the file does not matter; it can contain text, or nothing at all.

To create an empty `ssh` file, from the home directory of the `boot` partition file, run:

```
touch ssh
```

### 7. Find your Pi's IP address

Since Raspberry Pi OS supports [Multicast_DNS](https://en.wikipedia.org/wiki/Multicast_DNS) out of the box, you can reach your Raspberry Pi by using its hostname and the `.local` suffix.

The default hostname on a fresh Raspberry Pi OS install is `raspberrypi`, so any Raspberry Pi running Raspberry Pi OS should respond to:


```
ping raspberrypi.local
```

The output should look more or less as follows:

```
PING raspberrypi.local (195.177.101.93): 56 data bytes
64 bytes from 195.177.101.93: icmp_seq=0 ttl=64 time=13.272 ms
64 bytes from 195.177.101.93: icmp_seq=1 ttl=64 time=16.773 ms
64 bytes from 195.177.101.93: icmp_seq=2 ttl=64 time=10.828 ms
...
```

Keep note of your Pi's IP address. In the above case, that's `195.177.101.93`


### 8. SSH (using Linux or macOS)

Connect to your Pi by running:

```
ssh pi@195.177.101.93
```

You'll be prompted to enter a password:
```
pi@195.177.101.93's password:
```

Enter the Pi's default password: `raspberry`

You should see a message that looks like the following:
```
Linux raspberrypi 5.4.51-v8+ #1333 SMP PREEMPT Mon Aug 10 16:58:35 BST 2020 aarch64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Aug 20 12:59:01 2020

SSH is enabled and the default password for the 'pi' user has not been changed.
This is a security risk - please login as the 'pi' user and type 'passwd' to set a new password.
```

Followed by a command-line prompt indicating a successful connection:

```
pi@raspberrypi:~ $
```

### 9. Increase swap size to 2GB

The first step is to increase the [swap size](https://itsfoss.com/swap-size/) to 2GB (2048MB).

> **Note:** Swap acts as a breather to your system when the RAM is exhausted. When the RAM is exhausted, your Linux system uses part of the hard disk memory and allocates it to the running application.

Use the Pi's built-in text editor [nano](https://www.nano-editor.org/dist/latest/cheatsheet.html) to open up the swap file:

```
sudo nano /etc/dphys-swapfile
```



Change the value assigned to `CONF_SWAPSIZE` from `100` to `2048`:

```
...

# set size to absolute value, leaving empty (default) then uses computed value
#   you most likely don't want this, unless you have an special disk situation
CONF_SWAPSIZE=2048

...

```

Save (`Ctrl+S`) and exit (`Ctrl+X`).


### 10. Reboot
Reboot your Pi to have the above changes take effect:

```
sudo reboot
```

This will cause your connection to close. So you'll need to `ssh` into your Pi again:

```
ssh pi@195.177.101.93
```

> **Note:** Remember to replace `195.177.101.93` with the IP address of your Pi.

### 10b. Boot from external SSD

Follow [this guide](https://www.tomshardware.com/how-to/boot-raspberry-pi-4-usb) to copy the contents of your SD card over to your SSD, and boot your Pi from your SSD.

> **Tip:** the USB 3 port is the blue port.

Once you're done, `ssh` back into your Pi.


### 11. Install Nimbus dependencies

You'll need to install some packages (`git`) in order for Nimbus to run correctly.

To do so, run:
```
sudo apt-get install git

```
### 12. Install Screen

`screen` is a tool that lets you safely detach from the SSH session without exiting the remote job. In other words `screen` allows the commands you run on your Pi from your laptop to keep running after you've logged out.

Run the following command to install `screen`:
```
sudo apt-get install screen
```

### 13. Clone the Nimbus repository

Run the following command to clone the [nimbus-eth2 repository](https://github.com/status-im/nimbus-eth2):

```
git clone https://github.com/status-im/nimbus-eth2
```

### 14. Build the beacon node

Change into the directory and build the beacon node.
```
cd nimbus-eth2
make nimbus_beacon_node
```

*Patience... this may take a few minutes.*

### 15. Copy signing key over to Pi

>**Note:** If you haven't generated your validator key(s) and/or made your deposit yet, follow the instructions on [this page](./deposit.md) before carrying on.

We'll use the `scp` command to send files over SSH. It allows you to copy files between computers, say from your Raspberry Pi to your desktop/laptop, or vice-versa.

Copy the folder containing your validator key(s) from your computer to your `pi`'s homefolder by opening up a new terminal window and running the following command:

```
scp -r <VALIDATOR_KEYS_DIRECTORY> pi@195.177.101.93:
```

> **Note:** Don't forget the colon (:) at the end of the command!

As usual, replace `195.177.101.93` with your Pi's IP address, and `<VALIDATOR_KEYS_DIRECTORY>` with the full pathname of your `validator_keys` directory (if you used the Launchpad [command line app](https://github.com/ethereum/eth2.0-deposit-cli/releases/) this would have been created for you when you generated your keys).


 > **Tip:** run `pwd` in your `validator_keys` directory to print the full pathname to the console.


### 16. Import signing key into Nimbus

To import your signing key into Nimbus, from the `nimbus-eth2` directory run:

```
build/nimbus_beacon_node deposits import  --data-dir=build/data/shared_pyrmont_0 ../validator_keys
```

 You'll be asked to enter the password you created to encrypt your keystore(s). Don't worry, this is entirely normal. Your validator client needs both your signing keystore(s) and the password encrypting it to import your [key](https://blog.ethereum.org/2020/05/21/keys/) (since it needs to decrypt the keystore in order to be able to use it to sign on your behalf).

### 17. Run Screen

From the `nimbus-eth2` directory, run:
```
screen
```

You should see output that looks like the following:
```
GNU Screen version 4.06.02 (GNU) 23-Oct-17

Copyright (c) 2015-2017 Juergen Weigert, Alexander Naumov, Amadeusz Slawinski
Copyright (c) 2010-2014 Juergen Weigert, Sadrul Habib Chowdhury
Copyright (c) 2008-2009 Juergen Weigert, Michael Schroeder, Micah Cowan, Sadrul Habib Chowdhury
Copyright (c) 1993-2007 Juergen Weigert, Michael Schroeder
Copyright (c) 1987 Oliver Laumann

This program is free software; you can redistribute it and/or modify it under the terms of the GNU
General Public License as published by the Free Software Foundation; either version 3, or (at your
option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even
the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
License for more details.

You should have received a copy of the GNU General Public License along with this program (see the file
COPYING); if not, see http://www.gnu.org/licenses/, or contact Free Software Foundation, Inc., 51
Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA.

Send bugreports, fixes, enhancements, t-shirts, money, beer & pizza to screen-devel@gnu.org


Capabilities:
+copy +remote-detach +power-detach +multi-attach +multi-user +font +color-256 +utf8 +rxvt
+builtin-telnet
```

Press `Enter` or `Space`.

### 18. Connect to Pyrmont

We're finally ready to connect to Pyrmont!

>**Note:** If you haven't already, we recommend registering for, and running, your own Infura endpoint to connect to eth1. For instruction on how to do so, see [this page](./infura-guide.md).

To connect to pyrmont, run:
```
./run-pyrmont-beacon-node.sh
```

You'll be prompted to enter a web3-provider url:

```
To monitor the Eth1 validator deposit contract, you'll need to pair
the Nimbus beacon node with a Web3 provider capable of serving Eth1
event logs. This could be a locally running Eth1 client such as Geth
or a cloud service such as Infura. For more information please see
our setup guide:

https://status-im.github.io/nimbus-eth2/eth1.html

Please enter a Web3 provider URL:
```

Enter your own secure websocket (`wss`) [Infura endpoint](./infura-guide.md).

### 19. Check for successful connection

If you look near the top of the logs printed to your console, you should see confirmation that your beacon node has started, with your local validator attached:

```
INF 2020-10-07 17:04:09.213+02:00 Initializing networking                    topics="networking" tid=11688398 file=eth2_network.nim:1335 hostAddress=/ip4/0.0.0.0/tcp/9000 network_public_key=0802122102defb020c8e47dd8f5da89f51ed6c3998aaa0dd59eeb2784e29d47fdbdab69235 announcedAddresses=@[/ip4/195.177.101.93/tcp/9000]
WRN 2020-10-07 17:04:09.215+02:00 Ignoring invalid bootstrap address         tid=11688398 file=eth2_discovery.nim:45 bootstrapAddr= reason="an empty string is not a valid bootstrap node"
NOT 2020-10-07 17:04:09.231+02:00 Local validators attached                  topics="beacval" tid=11688398 file=validator_duties.nim:65 count=0
NOT 2020-10-07 17:04:09.231+02:00 Starting beacon node                       topics="beacnde" tid=11688398 file=nimbus_beacon_node.nim:923 version="0.5.0 (1dec860b)" nim="Nim Compiler Version 1.2.6 [MacOSX: amd64] (bf320ed1)" timeSinceFinalization=0ns head=0814b036:0 finalizedHead=0814b036:0 SLOTS_PER_EPOCH=32 SECONDS_PER_SLOT=12 SPEC_VERSION=0.12.3 dataDir=build/data/shared_pyrmont_0
```

To keep track of your syncing progress, have a look at the output at the very bottom of the terminal window in which your validator is running. You should see something like:

```
peers: 35 ❯ finalized: ada7228a:8765 ❯ head: b2fe11cd:8767:2 ❯ time: 9900:7 (316807) ❯ sync: wPwwwwwDwwDPwPPPwwww:7:4.0627 (280512)
```

Keep an eye on the number of peers your currently connected to (in the above case that's `35`), as well as your [sync progress](./keep-an-eye.md#syncing-progress).

### 20. End ssh session and logout

To detach your `screen` session but leave your processes running, press `Ctrl-A` followed by `Ctrl-D`. You can now exit your `ssh` session (`Ctrl-C`) and switch off your laptop.

Verifying your progress is as simple as `ssh`ing back into your Pi and typing `screen -r`. This will resume your screen session (and you will be able to see your node's entire output since you logged out).

