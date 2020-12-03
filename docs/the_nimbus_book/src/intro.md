# The Nimbus book

Nimbus is an Ethereum 2.0 client focused on offering the best user experience possible for low-resource devices.

This book explains the ways in which you can use Nimbus to either monitor the eth2 chain or become a fully-fledged validator.

> The reality is that we are very early in the eth2 validating life cycle. Validating is not for everyone yet, and it comes with both risks and responsibilities. It isn't a particularly easy way to make money. You'll need to put effort into updating your software, researching hard-forks, having a robust setup... . As such, you should only stake if you are genuinely interested in securing the protocol.

### Helpful resources

- [nimbus-eth2 repository](github.com/status-im/nimbus-eth2)
- [eth2 specification](https://github.com/ethereum/eth2.0-specs/tree/v1.0.0#phase-0)
- [Ben Edgington's annotated spec](https://benjaminion.xyz/eth2-annotated-spec/phase0/beacon-chain/) 

- [Vitalik's annotated spec](https://github.com/ethereum/annotated-spec/blob/master/phase0/beacon-chain.md)

- [Danny Ryan's annotated spec](https://notes.ethereum.org/@djrtwo/Bkn3zpwxB)


### Why eth2?

Eth2 is a multi-year plan to improve the scalability, security, and programmability of Ethereum, without compromising on decentralisation.

In contrast to the Ethereum chain, as it currently stands, eth2 uses proof-of-stake (PoS) to secure its network. And while Ethereum as you know and love it will continue to exist as its own independent proof-of-work chain for a little while to come, the transition towards PoS starts now.

In traditional PoW, block proposers are called **_miners_**, whereas in PoS, they are called **_validators_**. In essence, _miners_ rely on actual hardware (such as some specifically manufactured mining machines), while _validators_ rely on software (such as Nimbus) and a good network connection.

### Why Nimbus?

In a sentence, Nimbus aims to be an ethereum client for resource-restricted devices. 

Because we believe that the largest deployment of Ethereum will be on embedded systems, Nimbus is being designed to perform well on IoT and personal mobile devices, including older smartphones with resource-restriced hardware.

Although Nimbus will support full and archival nodes, its main implementation will be as a light client, with a focus on Proof of Stake and sharding.

All our code is open source; we encourage you to keep track of our activity on [GitHub](https://github.com/status-im/nimbus). You can also keep up to date with our progress through the [Nimbus blog](https://our.status.im/tag/nimbus/).


### Get in touch

Need help with anything? Join us on [Status](https://join.status.im/nimbus-general) and [Discord](https://discord.gg/9dWwPnG).


### Disclaimer

This documentation assumes Nimbus is in its ideal state. The project is still under active development. Please submit a [Github issue](https://github.com/status-im/nimbus-eth2/issues) if you come across a problem.

<!-- > > > TODO:

1. fill up the gitbook content
2. write questions in the faq.md page -->
