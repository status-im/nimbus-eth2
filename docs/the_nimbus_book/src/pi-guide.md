# Validating with a Raspberry Pi: Guide

<blockquote class="twitter-tweet"><p lang="en" dir="ltr">I expect the new Raspberry Pi 4 (4GB RAM option, external SSD) to handle an Eth2 validator node without breaking a sweat. That&#39;s $100 of hardware running at 10 Watts to support a 32 ETH node (currently ~$10K stake).</p>&mdash; Justin Ðrake (@drakefjustin) <a href="https://twitter.com/drakefjustin/status/1143091047058366465?ref_src=twsrc%5Etfw">June 24, 2019</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

## Introduction
This page will take you through how to use your laptop to program your Raspberry Pi, get Nimbus running, and connect to the **Pyrmont testnet**.



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

![](https://i.imgur.com/NeOT8pf.png)

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

> **Tips:**
>
> Make sure you connect your SSD the Pi's USB 3 port (the blue port).
>
> If your Pi is headless (no monitor attached) you can use the [`rpi-clone`](https://github.com/billw2/rpi-clone) repository to copy the contents of the SD over to the SSD; in a nutshell, replace steps 14 and 15 of the above guide with the following commands (which you should run from the Pi's `home` directory):
> ```bash
> git clone https://github.com/billw2/rpi-clone.git 
> cd rpi-clone
> sudo cp rpi-clone rpi-clone-setup /usr/local/sbin
> sudo rpi-clone-setup -t testhostname
> rpi-clone sda
> ```
>
>For more on `raspi-config`, see [here](https://www.raspberrypi.org/documentation/configuration/raspi-config.md).
>
> To shutdown your Pi safely, run `sudo shutdown -h now`


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

Enter your own secure websocket (`wss`) [endpoint](eth1.md).

### 19. Check for successful connection

If you look near the top of the logs printed to your console, you should see confirmation that your beacon node has started, with your local validator attached:

```
INF 2020-12-01 11:25:33.487+01:00 Launching beacon node
...
INF 2020-12-01 11:25:34.556+01:00 Loading block dag from database            topics="beacnde" tid=19985314 file=nimbus_beacon_node.nim:198 path=build/data/shared_pyrmont_0/db
INF 2020-12-01 11:25:35.921+01:00 Block dag initialized
INF 2020-12-01 11:25:37.073+01:00 Generating new networking key
...
NOT 2020-12-01 11:25:45.267+00:00 Local validator attached                   tid=22009 file=validator_pool.nim:33 pubKey=95e3cbe88c71ab2d0e3053b7b12ead329a37e9fb8358bdb4e56251993ab68e46b9f9fa61035fe4cf2abf4c07dfad6c45 validator=95e3cbe8
...
NOT 2020-12-01 11:25:59.512+00:00 Eth1 sync progress                         topics="eth1" tid=21914 file=eth1_monitor.nim:705 blockNumber=3836397 depositsProcessed=106147
NOT 2020-12-01 11:26:02.574+00:00 Eth1 sync progress                         topics="eth1" tid=21914 file=eth1_monitor.nim:705 blockNumber=3841412 depositsProcessed=106391
...
INF 2020-12-01 11:26:31.000+00:00 Slot start                                 topics="beacnde" tid=21815 file=nimbus_beacon_node.nim:505 lastSlot=96566 scheduledSlot=96567 beaconTime=1w6d9h53m24s944us774ns peers=7 head=b54486c4:96563 headEpoch=3017 finalized=2f5d12e4:96479 finalizedEpoch=3014
INF 2020-12-01 11:26:36.285+00:00 Slot end                                   topics="beacnde" tid=21815 file=nimbus_beacon_node.nim:593 slot=96567 nextSlot=96568 head=b54486c4:96563 headEpoch=3017 finalizedHead=2f5d12e4:96479 finalizedEpoch=3014
```

To keep track of your syncing progress, have a look at the output at the very bottom of the terminal window in which your validator is running. You should see something like:

```
peers: 15 ❯ finalized: ada7228a:8765 ❯ head: b2fe11cd:8767:2 ❯ time: 9900:7 (316807) ❯ sync: wPwwwwwDwwDPwPPPwwww:7:1.2313:1.0627:12h01m(280512)
```

Keep an eye on the number of peers your currently connected to (in the above case that's `15`), as well as your [sync progress](./keep-an-eye.md#syncing-progress).

> **Note:** 15 - 20 peers and an average sync speed of **0.5 - 1.0** blocks per second is normal on `Pyrmont` with a Pi. If you're sync speed is much slower than this, the root of the problem may be your USB3.0 to SSD adapter. See [this post](https://www.raspberrypi.org/forums/viewtopic.php?f=28&t=245931) for a recommended workaround.

### 20. End ssh session and logout

To detach your `screen` session but leave your processes running, press `Ctrl-A` followed by `Ctrl-D`. You can now exit your `ssh` session (`Ctrl-C`) and switch off your laptop.

Verifying your progress is as simple as `ssh`ing back into your Pi and typing `screen -r`. This will resume your screen session (and you will be able to see your node's entire output since you logged out).

### Professional setup advice

While `screen` is a nice tool for testing, it's not really a good idea to rely on it for serious use. For a more professional setup, we recommend [setting up a systemd service](https://www.raspberrypi.org/documentation/linux/usage/systemd.md) with an autorestart on boot (should you experience an unexpected power outage, this will ensure your validator restarts correctly). 

For the details on how to do this, see [this page](./beacon-node-systemd.md).

