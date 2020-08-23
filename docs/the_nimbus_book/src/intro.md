# The Nimbus beacon chain book

The Nimbus beacon chain is a research implementation of the Beacon Chain – the core system level chain at the heart of Ethereum 2.0.


- Open sourced at [github.com/status-im/nim-beacon-chain](https://github.com/status-im/nim-beacon-chain/tree/master)

- Specification described at [ethereum/eth2.0-specs](https://github.com/ethereum/eth2.0-specs/tree/v0.12.2#phase-0)


### Helpful resources
- [Ben Edgington's annotated spec](https://benjaminion.xyz/eth2-annotated-spec/phase0/beacon-chain/) 

- [Vitalik's annotated spec](https://github.com/ethereum/annotated-spec/blob/master/phase0/beacon-chain.md)
- [Danny Ryan's annotated spec](https://notes.ethereum.org/@djrtwo/Bkn3zpwxB)


## Overview

In this book, we will cover:

1. An introduction to the [beacon chain](./faq.md#whats-the-beacon-chain) and [Nimbus](./faq.md#what-is-nimbus) to equip you with some basic knowledge
2. [Installation steps](./install.md) outlining the prerequisites to get started
3. How to [become a Medalla validator](./medalla.md)
4. How to [run the beacon node](./beacon_node.md) software to sync the beacon chain
5. The [API](./api.md) for monitoring your node
6. [Advanced usage](./advanced.md) for developers
7. How to [setup up a systemd service](./beacon_node_systemd.md)
8. How to [use Nimbus to generate your validator keys](./create_wallet_and_deposit.md)
7. Common [questions and answers](./faq.md) to satisfy your curiosity
8. How to [contribute](./contribute.md) to this book


## Introduction

### What's the Beacon Chain?

You can find a complete introduction to the beacon chain in our [Ethereum 2.0 blog series](https://our.status.im/two-point-oh-the-beacon-chain/).

In short, the beacon chain is the brain underpinning eth2 -- the next generation of Ethereum. It contains all of the machinery behind eth2's consensus.


### Why eth2?

Eth2 is a multi-year plan to improve the scalability, security, and programmability of Ethereum, without compromising on decentralisation.

In contrast to the Ethereum chain, as it currently stands, eth2 uses proof-of-stake (PoS) to secure its network. And while Ethereum as you know and love it will continue to exist as its own independent proof-of-work chain for a little while to come, the transition towards PoS starts now.

In traditional PoW, block proposers are called **_miners_**, whereas in PoS, they are called **_validators_**. In essence, _miners_ rely on actual hardware (such as some specifically manufactured mining machines), while _validators_ rely on software (such as Nimbus) and a good network connection.

### Why Nimbus?

In a sentence, Nimbus aims to be an ethereum client for resource-restricted devices. You can use Nimbus to run a validator on eth2.

It is open sourced at [github.com/status-im/nimbus](github.com/status-im/nimbus). Development progress and updates can be viewed on the [Nimbus blog](https://our.status.im/tag/nimbus/).


## Get in touch

Need help with anything? Join us on [Status](https://join.status.im/nimbus-general) or [Discord](https://discord.gg/9dWwPnG)!


## Disclaimer

This documentation assumes Nimbus is in its ideal state. The project is still under active development. Please submit a [Github issue](https://github.com/status-im/nim-beacon-chain/issues) if you come across a problem.

<!-- > > > TODO:

1. fill up the gitbook content
2. write questions in the faq.md page -->
