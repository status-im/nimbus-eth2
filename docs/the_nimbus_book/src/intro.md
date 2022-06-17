# The Nimbus book

*This book focuses on our consensus layer client. If you're eager to get started, check out our [quickstart guide](./quick-start.md).*

Nimbus is a client implementation for both the `consensus layer` (eth2) and `execution layer` (eth1) that strives to be as [lightweight as possible](https://our.status.im/ethereum-is-green/) in terms of resources used. This allows it to perform well on embedded systems, resource-restricted devices -- including Raspberry Pis and mobile devices.

However, resource-restricted hardware is not the only thing Nimbus is good for. Its low resource consumption makes it an excellent choice to pair with an [execution client](./eth1) and makes it easy to run together with other workloads on your server, lowering the total cost.

</br>

<blockquote class="twitter-tweet"><p lang="en" dir="ltr">&quot;just because it [Nimbus] is optimized to be minimally resource intensive, doesn&#39;t mean you can&#39;t run it on a server. It means that when you do run it on a server, it is consuming a lot less resources.&quot; <a href="https://t.co/F2sdZouBtD">https://t.co/F2sdZouBtD</a></p>&mdash; Nimbus (@ethnimbus) <a href="https://twitter.com/ethnimbus/status/1376836270245154817?ref_src=twsrc%5Etfw">March 30, 2021</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

</br>

This book explains the ways in which you can use Nimbus to either monitor the beacon chain or become a fully-fledged validator.

> **N.B.** The reality is that we are very early in the eth2 validating life cycle. Validating is not for everyone yet, and it comes with both risks and responsibilities. It isn't a particularly easy way to make money. You'll need to put effort into updating your software, researching hard-forks, having a robust setup... . As such, you should only stake if you are genuinely interested in securing the protocol.

> ⚠ The Merge is happening soon! Bookmark our [merge readiness](./merge.md) page to stay on top of how you need to prepare.


## Helpful resources

- [nimbus-eth2 repository](https://github.com/status-im/nimbus-eth2)
- [eth2 specification](https://github.com/ethereum/consensus-specs/tree/v1.2.0-rc.1#phase-0)
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

<!-- > > > TODO:

1. fill up the gitbook content
2. write questions in the faq.md page -->
