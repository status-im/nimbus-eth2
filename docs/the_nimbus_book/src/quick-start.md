# Run the beacon node

This page takes you through how to run just the beacon node **without a validator attached.**

The beacon node connects to the eth2 network, manages the blockchain, and provides API's to interact with the beacon chain.

Running a beacon node without a validator attached is a [worthwhile endeavor](https://vitalik.ca/general/2021/05/23/scaling.html#its-crucial-for-blockchain-decentralization-for-regular-users-to-be-able-to-run-a-node).

It's also a necessary step to running a validator (since an active validator requires a synced beacon node).

## 1. Install

[Install Nimbus' dependencies](./install.html#external-dependencies) 



## 2. Build

[Build the beacon node](./build.md) or install a precompiled release from the [Nimbus eth2 releases page](https://github.com/status-im/nimbus-eth2/releases/latest).



## 3. Sync

[Sync the chain](./start-syncing.md)
