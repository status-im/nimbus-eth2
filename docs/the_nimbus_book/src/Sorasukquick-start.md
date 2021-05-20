# Run just the beacon node (quickstart)

This page takes you through how to run just the beacon node **without a validator attached.**

Running a beacon node without a validator attached can help improve the anonymity properties of the network as a whole. 

It's also a necessary step to running a validator (since an active validator requires a synced beacon node).

## 1. Install dependencies

You'll need to install some packages in order for Nimbus to run correctly.

**Linux**

On common Linux distributions the dependencies can be installed with

```sh
# Debian and Ubuntu
sudo apt-get install build-essential git

# Fedora
dnf install @development-tools

# Archlinux, using an AUR manager
yourAURmanager -S base-devel
```

**macOS**

Assuming you use [Homebrew](https://brew.sh/) to manage packages:

```sh
brew install cmake
```


## 2. Clone the Nimbus repository

Run the following command to clone the [nimbus-eth2 repository](https://github.com/status-im/nimbus-eth2):

```
git clone https://github.com/status-im/nimbus-eth2
```

## 3. Build the beacon node

Change into the directory and build the beacon node.
```
cd nimbus-eth2
make nimbus_beacon_node
```

*Patience... this may take a few minutes.*

## 4. Connect to mainnet

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

