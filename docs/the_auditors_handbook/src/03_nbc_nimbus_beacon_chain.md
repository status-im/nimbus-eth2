# Nimbus Beacon Chain

!!! warning
    This auditors' handbook is frozen and obsolete; the [Nim language manual](https://nim-lang.org/docs/manual.html) alongside [other Nim documentation](https://nim-lang.org/documentation.html), [Status Nim style guide](https://status-im.github.io/nim-style-guide/), [Chronos guides](https://github.com/status-im/nim-chronos/blob/master/docs/src/SUMMARY.md), and [Nim by Example](https://nim-by-example.github.io/getting_started/) supercede it.

[https://github.com/status-im/nimbus-eth2](https://github.com/status-im/nimbus-eth2)

Nimbus Beacon Chain (NBC) is an implementation of an Ethereum 2 client.

## Audit scope

### Network Core (leveraging the libp2p framework)

| Sub-topic                              |
| -------------------------------------- |
| Discovery Protocol (discv5)            |
| Publish/Subscribe protocol             |
| Eth2 Request/Response protocol         |
| SSZ - (De)serialization & tree hashing |
| Wire encryption                        |

### ETH2 Specification core

| Sub-topic                             |
| ------------------------------------- |
| State transition logic                |
| Signature verification                |
| Epoch finalisation and justification  |
| Reward processing                     |
| Eth1 data processing                  |
| Fork choice logic                     |
| Block processing and production       |
| Attestation processing and production |
| Block synchronization                 |
| Peer pool management                  |

### Validator core and user experience

| Sub-topic                         |
| --------------------------------- |
| Block/attestation signing         |
| Slash-prevention mechanisms       |
| RPC API                           |
| Accounts management & key storage |
| Command Line Interface (CLI)      |

## High-level view of the stack

[https://miro.com/app/board/o9J_kvfytDI=/](https://miro.com/app/board/o9J_kvfytDI=/)

## Diagram

TODO

## Specifications

We target v1.0.1 phase0 of [https://github.com/ethereum/consensus-specs](https://github.com/ethereum/consensus-specs)
- [https://github.com/ethereum/consensus-specs/tree/v1.0.1/specs/phase0](https://github.com/ethereum/consensus-specs/tree/v1.0.1/specs/phase0)

The p2p-interface specs in particular describe the subset of libp2p spec that
are used to implement Ethereum 2

## Resources

Ethereum 2.0 Ask Me Anything:
- [https://docs.ethhub.io/other/ethereum-2.0-ama/](https://docs.ethhub.io/other/ethereum-2.0-ama/)
