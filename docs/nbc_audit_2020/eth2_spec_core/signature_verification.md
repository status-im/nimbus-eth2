---
title: "Signature verification"
code_owner: "Mamy André-Ratsimbazafy (mratsim)"
round: "Audit round 2"
category: "ETH2 Specification Core Audit"
repositories: "nim-beacon-chain, nim-blscurve"
---

# Description

Verify that cryptographic primitives (Miracl and BLST) are properly used at a high-level.
We assume that they are correctly implemented in the backend.

Specs:
- [https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/beacon-chain.md#bls-signatures](https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/beacon-chain.md#bls-signatures)

For information, evaluation of backends: [https://notes.status.im/nim-bls-curve-backends](https://notes.status.im/nim-bls-curve-backends)

# Links

Links to the repositories and more information

- [https://github.com/status-im/nim-blscurve](https://github.com/status-im/nim-blscurve) (low-level wrapper over crypto primitives, 2 backends)
- [https://github.com/status-im/nim-beacon-chain/blob/master/beacon_chain/spec/crypto.nim](https://github.com/status-im/nim-beacon-chain/blob/master/beacon_chain/spec/crypto.nim) (high-level BLS signature types and serialization)
- [https://github.com/status-im/nim-beacon-chain/blob/devel/beacon_chain/spec/signatures.nim](https://github.com/status-im/nim-beacon-chain/blob/devel/beacon_chain/spec/signatures.nim) (abstraction over signing and verification of consensus objects)
