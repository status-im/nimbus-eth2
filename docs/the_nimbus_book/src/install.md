# Install dependencies

The Nimbus beacon chain can run on Linux, macOS, Windows, and Android. At the moment, Nimbus has to be built from source, which means you'll need to install some dependencies.

## Time

The beacon chain relies on your computer having the correct time set (plus or minus 0.5 seconds).

We recommended you run a high quality time service on your computer such as:

* GPS
* NTS (network time security, [IETF draft](https://tools.ietf.org/html/draft-ietf-ntp-using-nts-for-ntp-19))
* [Roughtime](https://roughtime.googlesource.com/roughtime) (google)

At a minimum, you should run an NTP client on the server.

> **Note:** Most operating systems (including macOS') automatically sync with NTP by default.

If the above sounds like latin to you, don't worry. You should be fine as long as you haven't messed around with the time and date settings on your computer (they should be set automatically).

## External Dependencies

- Developer tools (C compiler, Make, Bash, Git)

Nimbus will build its own local copy of Nim, so Nim is not an external dependency,

## Linux

On common Linux distributions the dependencies can be installed with

```sh
# Debian and Ubuntu
sudo apt-get install build-essential git

# Fedora
dnf install @development-tools

# Archlinux, using an AUR manager
yourAURmanager -S base-devel
```

### macOS

Assuming you use [Homebrew](https://brew.sh/) to manage packages

```sh
brew install cmake
```
# Quick start

This page takes you through how to run just the beacon node without a validator attached.

Running just a beacon node can help improve the anonymity properties of the network as a whole.

### 1. Install dependencies

You'll need to install some packages (`git`) in order for Nimbus to run correctly.

To do so, run:
```
sudo apt-get install git

```

### 2. Clone the Nimbus repository

Run the following command to clone the [nimbus-eth2 repository](https://github.com/status-im/nimbus-eth2):

```
git clone https://github.com/status-im/nimbus-eth2
```

### 3. Build the beacon node

Change into the directory and build the beacon node.
```
cd nimbus-eth2
make nimbus_beacon_node
```

*Patience... this may take a few minutes.*

### 4. Connect to mainnet

To connect to mainnet, run:
```
./run-mainnet-beacon-node.sh
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

Press enter to skip (this is only important when you're running a validator).


### Windows

You can install the developer tools by following the instruction in our [Windows dev environment section](./advanced.md#windows-dev-environment).

### Android

- Install the [Termux](https://termux.com) app from FDroid or the Google Play store
- Install a [PRoot](https://wiki.termux.com/wiki/PRoot) of your choice following the instructions for your preferred distribution.
  Note, the Ubuntu PRoot is known to contain all Nimbus prerequisites compiled on Arm64 architecture (the most common architecture for Android devices).

Assuming you  use Ubuntu PRoot

```sh
apt install build-essential git
```

