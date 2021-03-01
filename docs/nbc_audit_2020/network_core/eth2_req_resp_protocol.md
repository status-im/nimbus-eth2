---
title: "Ethereum 2 Request/Response protocol"
code_owner: "Zahary Karadjov (zah)"
round: "Audit round 1"
category: "Network Core Audit"
repositories: "nim-beacon-chain, nim-faststreams, nim-serialization"
---

The Eth2 Requests/Response protocols are specified here:
https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/p2p-interface.md

Within nim-beacon-chain, we have a single module implementing the spec:
https://github.com/status-im/nim-beacon-chain/blob/devel/beacon_chain/eth2_network.nim

The implementation sits on top of our LibP2P library:
https://github.com/status-im/nim-libp2p

At the moment, Ethereum 2 defines a single high-level protocol based on the spec (the Beacon chain syncing protocol). Our implementation of this protocol can be found here:
https://github.com/status-im/nim-beacon-chain/blob/devel/beacon_chain/sync_protocol.nim
https://github.com/status-im/nim-beacon-chain/blob/devel/beacon_chain/sync_manager.nim

Certain parts of the protocol implementation are procedurally generated through Nim's compile-time code generation features (i.e. macros). This is similar to using a RPC framework such as Apache Thrift or gRPC and the primary motivation is avoiding the manual writing of tedious and error-prone message serialization code. As a convenience, the build system provides an always up-to-date snapshot of the generated code here:
https://github.com/status-im/nim-beacon-chain/blob/devel/beacon_chain/sync_protocol.nim.generated.nim

The generated code should be easy to read and I recommend focusing the review on it, but if studying the generator is also of interest, it can be found here:
https://github.com/status-im/nim-eth/blob/master/eth/p2p/p2p_protocol_dsl.nim

Further explanations and more detailed rationale can be found here:
https://github.com/status-im/nim-beacon-chain/wiki/The-macro-skeptics-guide-to-the-p2pProtocol-macro

Network flow outline: https://github.com/status-im/nim-beacon-chain/wiki/networking-flow
