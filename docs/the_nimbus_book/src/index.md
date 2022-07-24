# The Nimbus Guide

!!! note ""
    If you're eager to get started, check out our [quickstart guide](./quick-start.md). Coming from a different client? Check out the [migration guide](./migration.md).

Nimbus is a client for the Ethereum `consensus layer` (eth2) and `execution layer` (eth1) that is [lightweight](https://our.status.im/ethereum-is-green/), [secure](./audit.md) and [easy to use](./run-a-validator.md).

This book describes the consensus layer client, `nimbus-eth2`, in particular.

Its efficiency and low resource consumption allows it to perform well on all kinds of systems, ranging from Raspberry Pi's and mobile devices where it contributes to low power consumption and security -- to powerful servers where it leaves resources free to perform other tasks, such as running an [execution node](./eth1.md).

</br>

<blockquote class="twitter-tweet"><p lang="en" dir="ltr">&quot;just because it [Nimbus] is optimized to be minimally resource intensive, doesn&#39;t mean you can&#39;t run it on a server. It means that when you do run it on a server, it is consuming a lot less resources.&quot; <a href="https://t.co/F2sdZouBtD">https://t.co/F2sdZouBtD</a></p>&mdash; Nimbus (@ethnimbus) <a href="https://twitter.com/ethnimbus/status/1376836270245154817?ref_src=twsrc%5Etfw">March 30, 2021</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

</br>

This book explains the ways in which you can use Nimbus to either monitor the beacon chain or become a fully-fledged validator.

!!! tip
    [The Merge 🐼](https://ethereum.org/en/upgrades/merge/) is happening soon! Bookmark our [merge readiness](./merge.md) page to stay on top of how you need to prepare.

!!! note
    Staking and becoming a validator on Ethereum requires 32 ETH, a stable high-speed internet connection and an always-on server. Before staking, make sure that you understand the requirements and practice setting up a validator on a testnet. [Pooled staking](https://ethereum.org/en/staking/pools/) and [Staking as a service](https://ethereum.org/en/staking/saas/) are alternative ways to stake in the network. You can also run a Nimbus node without staking.

## Helpful resources

- [Ethereum consensus spec](https://github.com/ethereum/consensus-specs/)
- [Ben Edgington's annotated spec](https://benjaminion.xyz/eth2-annotated-spec/phase0/beacon-chain/)
- [Vitalik's annotated spec](https://github.com/ethereum/annotated-spec/blob/master/phase0/beacon-chain.md)
- [Danny Ryan's annotated spec](https://notes.ethereum.org/@djrtwo/Bkn3zpwxB)

### Get in touch

Need help with anything? Join us on [Status](https://join.status.im/nimbus-general) and [Discord](https://discord.gg/9dWwPnG).

### Donate

If you'd like to contribute to Nimbus development:

* Our donation address is [`0x70E47C843E0F6ab0991A3189c28F2957eb6d3842`](https://etherscan.io/address/0x70E47C843E0F6ab0991A3189c28F2957eb6d3842)
* We're also listed on [GitCoin](https://gitcoin.co/grants/137/nimbus-2)

### Stay updated

Subscribe to our newsletter [here](https://subscribe.nimbus.guide/).

### Disclaimer

This documentation assumes Nimbus is in its ideal state. The project is still under active development. Please submit a [Github issue](https://github.com/status-im/nimbus-eth2/issues) if you come across a problem.
