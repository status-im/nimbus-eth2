---
title: "Slash Prevention Mechanisms"
code_owner: "Mamy André-Ratsimbazafy (mratsim)"
round: "Audit round 3"
category: "Validator Core Audit"
repositories: "nim-beacon-chain"
---
Note: Slashing Protection is a very new feature and not merged/enabled by default yet in the codebase.

For the moment it leaves in the PR: [https://github.com/status-im/nim-beacon-chain/pull/1643](https://github.com/status-im/nim-beacon-chain/pull/1643)

----------------------

## Resources

### Overview of slashing and how it ties in with the rest of Eth2.0

Phase 0 for humans - Validator responsibilities:

- https://notes.ethereum.org/@djrtwo/Bkn3zpwxB#Validator-responsibilities

Phase 0 spec - Honest Validator - how to avoid slashing

- https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#how-to-avoid-slashing

### In-depth reading on slashing conditions

- Detecting slashing conditions https://hackmd.io/@n0ble/By897a5sH
- Open issue on writing a slashing detector https://github.com/ethereum/eth2.0-pm/issues/63
- Casper the Friendly Finality Gadget, Vitalik Buterin and Virgil Griffith
https://arxiv.org/pdf/1710.09437.pdf
Figure 2
An individual validator ν MUST NOT publish two distinct votes,〈ν,s1,t1,h(s1),h(t1) AND〈ν,s2,t2,h(s2),h(t2),
such that either:
I. h(t1) = h(t2). Equivalently, a validator MUST NOT publish two distinct votes for the same target height.

     OR
     II. h(s1) < h(s2) < h(t2) < h(t1).
     Equivalently, a validator MUST NOT vote within the span of its other votes.

- Vitalik's annotated spec: https://github.com/ethereum/annotated-spec/blob/d8c51af84f9f309d91c37379c1fcb0810bc5f10a/phase0/beacon-chain.md#proposerslashing
1. A proposer can get slashed for signing two distinct headers at the same slot.
2. An attester can get slashed for signing
two attestations that together violate the Casper FFG slashing conditions.
- https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#ffg-vote
- The "source" is the current_justified_epoch
- The "target" is the current_epoch

### Reading on weak subjectivity

- https://notes.ethereum.org/@adiasg/weak-subjectvity-eth2
- https://www.symphonious.net/2019/11/27/exploring-ethereum-2-weak-subjectivity-period/
- https://ethresear.ch/t/weak-subjectivity-under-the-exit-queue-model/5187

### Reading of interop serialization format

- Import/export format: https://hackmd.io/@sproul/Bk0Y0qdGD
- Tests: https://github.com/eth2-clients/slashing-protection-interchange-tests

## Implementation

In `validator_slashing_protection.nim` (TODO merge PR and tag an audit branch)
and used in `validator_duties.nim`  (no VC/BN split) or `validator_clients.nim` (with Validator Client/Beacon Node split)

For slashing protection (in contrast to slashing detection) we only care about our own validators. We also assume that before signing a block or an attestation, the node is "synced" to the chain, i.e. it knows last finalized epoch of the whole blockchain.

The `isSynced` function has a naive heuristic for now and will be changed in the future to properly handle weak subjectivity period.

[https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_duties.nim#L87-L111](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_duties.nim#L87-L111)
