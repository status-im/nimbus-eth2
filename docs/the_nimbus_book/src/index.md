# The Nimbus Guide

Nimbus is a client for the Ethereum network that is [lightweight](https://our.status.im/ethereum-is-green/), [secure](./audit.md) and [easy to use](./run-a-validator.md).

Its efficiency and low resource consumption allows it to perform well on all kinds of systems: ranging from Raspberry Pi and mobile devices — where it contributes to low power consumption and security — to powerful servers where it leaves resources free to perform other tasks, such as running an [execution node](./eth1.md).

This book describes the consensus layer client, [`nimbus-eth2`](https://github.com/status-im/nimbus-eth2).
An execution client, [nimbus-eth1](https://github.com/status-im/nimbus-eth1), is also under development.


## Feature highlights

* [Beacon node](./quick-start.md) with integrated validator client, slashing protection and doppelganger detection
* Stand-alone [validator client](./validator-client.md) with [sentry node](./validator-client.md#sentry-node-setup) support
* Fast [Beacon](./rest-api.md) and [KeyManager](./keymanager-api.md) APIs with extensions
* [Web3Signer](https://docs.web3signer.consensys.net/en/latest/) remote signing
* [Validator monitoring](./validator-monitor.md) and [performance analysis](./attestation-performance.md) tooling
* [External block builder](./external-block-builder.md) (PBS / mev-boost) support with execution client fallback
* [Light consensus client](./el-light-client.md) for running an execution client without a full beacon node


## Design goals

One of our most important design goals is an application architecture that makes it **simple to embed Nimbus into other software.**

Another goal is to **minimize reliance on third-party software.**

A third one is for the application binary to be as **lightweight as possible in terms of resources used.**

### Integration with Status

<blockquote class="twitter-tweet"><p lang="en" dir="ltr">I can&#39;t wait to run Nimbus straight from Status Desktop <a href="https://twitter.com/hashtag/hyped?src=hash&amp;ref_src=twsrc%5Etfw">#hyped</a></p>&mdash; JARRAÐ HOPΞ (@jarradhope) <a href="https://twitter.com/jarradhope/status/1293473249347555334?ref_src=twsrc%5Etfw">August 12, 2020</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

As part of our first design goal, our primary objective here is for Nimbus to be tightly integrated into the [Status messaging app](https://status.im/).

Our dream is for you to be able to run and monitor your validator straight from Status desktop.


## Book contents

You can read this book from start to finish, or you might want to read just specific topics you're interested in:

* If you're eager to get started, the [quickstart guide](./quick-start.md) is for you.
* Coming from a different client? Check out the [migration guide](./migration.md).
* Visualize the important metrics with [Grafana and Prometheus](./metrics-pretty-pictures.md).
* Interested in becoming a validator? Follow the [validator guide](./run-a-validator.md).
* If you're not planning on becoming a validator, you can run the [light client](./el-light-client.md).



## Get in touch

Need help with anything?
Join us on [Status](https://join.status.im/nimbus-general) and [Discord](https://discord.gg/9dWwPnG).

## Donate

If you'd like to contribute to Nimbus development:

* Our donation address is [`0xDeb4A0e8d9a8dB30a9f53AF2dCc9Eb27060c6557`](https://etherscan.io/address/0xDeb4A0e8d9a8dB30a9f53AF2dCc9Eb27060c6557)
* We're also listed on [GitCoin](https://gitcoin.co/grants/137/nimbus-2)

## Stay updated

Subscribe to our newsletter [here](https://subscribe.nimbus.guide/).

## Disclaimer

This documentation assumes Nimbus is in its ideal state.
The project is still under active development.
Please submit a [Github issue](https://github.com/status-im/nimbus-eth2/issues) if you come across a problem.
