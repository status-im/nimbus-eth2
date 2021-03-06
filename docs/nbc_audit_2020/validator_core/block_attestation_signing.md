---
title: "Block/attestation signing"
code_owner: "Mamy André-Ratsimbazafy (mratsim)"
round: "Audit round 2"
category: "Validator Core Audit"
repositories: "nim-beacon-chain"
---

# Description

Verify that cryptographic primitives (Miracl and BLST) are properly used at a high-level.
We assume that they are correctly implemented in the backend. Note, for this phase 2 we are concerned about the proper usage internal to nim-beacon-chain. Phase 3 will be about the end-user API (keystores and secret management).

Specs:
- [https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/beacon-chain.md#bls-signatures](https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/beacon-chain.md#bls-signatures)

For information, evaluation of backends: [https://notes.status.im/nim-bls-curve-backends](https://notes.status.im/nim-bls-curve-backends)

(phase 3) ETH2 has 2 kinds of keys
- a signing key which is used by validators to sign attestations or blocks.
The signing key is needed on a permanent basis by the validator client (audit phase 3).
Leaking this key puts the owner at risk of slashing (double-voting)
- a withdrawal key which is used by validators to retrieve their stake (~32 ETH).
The withdrawal key should be generated offline and stored offline.
Doc: [https://blog.ethereum.org/2020/05/21/keys/](https://blog.ethereum.org/2020/05/21/keys/)

# Links

Links to the repositories and more information

- [https://github.com/status-im/nim-blscurve](https://github.com/status-im/nim-blscurve) (low-level wrapper over crypto primitives, 2 backends)
- [https://github.com/status-im/nim-beacon-chain/blob/master/beacon_chain/spec/crypto.nim](https://github.com/status-im/nim-beacon-chain/blob/master/beacon_chain/spec/crypto.nim) (high-level BLS signature types and serialization)
- [https://github.com/status-im/nim-beacon-chain/blob/devel/beacon_chain/spec/signatures.nim](https://github.com/status-im/nim-beacon-chain/blob/devel/beacon_chain/spec/signatures.nim) (abstraction over signing and verification of consensus objects)
- [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_pool.nim](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_pool.nim) (Pool of validators, currently includes secret keys in process)
    - For information (not merged, not to be audited), PR to separate the key in another process: [https://github.com/status-im/nim-beacon-chain/pull/1522](https://github.com/status-im/nim-beacon-chain/pull/1522)
- High-level callers of signing primitives (for round 3 "validators"):
    - [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_duties.nim](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_duties.nim)
    - [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_client.nim](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_client.nim)
