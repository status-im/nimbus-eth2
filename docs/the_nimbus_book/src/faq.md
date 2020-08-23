# Frequently Asked Questions

## What's the Beacon Chain?

You can find a complete introduction to the beacon chain in our [Ethereum 2.0 blog series](https://our.status.im/two-point-oh-the-beacon-chain/).

In short, the beacon chain is the brain underpinning eth2 -- the next generation of Ethereum. It contains all of the machinery behind eth2's consensus.


## Why eth2?

Eth2 is a multi-year plan to improve the scalability, security, and programmability of Ethereum, without compromising on decentralisation.

In contrast to the Ethereum chain, as it currently stands, eth2 uses proof-of-stake (PoS) to secure its network. And while Ethereum as you know and love it will continue to exist as its own independent proof-of-work chain for a little while to come, the transition towards PoS starts now.

In traditional PoW, block proposers are called **_miners_**, whereas in PoS, they are called **_validators_**. In essence, _miners_ rely on actual hardware (such as some specifically manufactured mining machines), while _validators_ rely on software (such as Nimbus) and a good network connection.

## What's it like being a validator?

In contrast to being a miner, you don't need any dedicated hardware or a great deal of computing power to become a validator. In sum:

1. A special smart contract named **_deposit contract_** is deployed on the original Ethereum blockchain. Note that in this case, the new beacon chain and the original blockchain co-exist.
2. To "register" as a validator, you have to first deposit **_32 Ether_** from your account to this smart contract.
3. Run the beacon node and wait for the network to sync before your validator is activated.
4. That's all! Remember to stay connected to the network, or you may lose some of your deposit, as punishment, depending on how long you're offline. :P

## Why Nimbus?

In a sentence, Nimbus aims to be an ethereum client for resource-restricted devices. You can use Nimbus to run a validator on eth2.

It is open sourced at [github.com/status-im/nimbus](github.com/status-im/nimbus). Development progress and updates can be viewed on the [Nimbus blog](https://our.status.im/tag/nimbus/).

## Why are metrics not working?

Metrics are currently implemented using a HTTP server that hasn't been hardened sufficiently (which means it can't be exposed as a public endpoint). It must therefore be enabled specifically during build:

```
make NIMFLAGS="-d:insecure" beacon_node --metrics ...
```
