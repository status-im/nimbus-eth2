---
title: "Attestation Processing & production"
code_owner: "(tersec) and Mamy André-Ratsimbazafy (mratsim)"
round: "Audit round 3"
category: "Validator Core Audit"
repositories: "nim-beacon-chain"
---

Related readings:

- Honest validator spec: [https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md](https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md)
- Deposit contract spec: [https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/deposit-contract.md](https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/deposit-contract.md)

## 0. Clarification of Scope

There is a slight overlap between Trail of Bits tasks and NCC tasks in this round

Trail of Bits will be in charge of the high-level attestation/block processing and production.

This relies on BLS signatures and so secret keys which are under NCC scope.

Concretely:
- NCC scope [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_pool.nim](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_pool.nim)
- Trail of Bits scope:

  - [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_duties.nim](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_duties.nim)

  - [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_client.nim](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_client.nim)

## 1. State after round 2

- Crypto.nim and nim-blscurve dependencies were audited by NCC in phase 1:

[https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/spec/crypto.nim](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/spec/crypto.nim)

- signatures.nim and dependencies which handles signature and verification were audited as well

[https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/spec/signatures.nim](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/spec/signatures.nim)

## 2. Explanation of the application flow

The main application is the **beacon_node**, it has 2 mode of operations regarding accounts. With accounts managed in an integrated manner or managed in a split manner, something we call the VC/BN split (Validator Client / Beacon Node split).

In both case, there is a need of a keystore to hold the validators' **signing keys.**

### 2.1 Reminder on Ethereum secret keys

As a reminder, the best explanation for the 2 kinds of secret keys (signing keys and **withdrawal keys**) used in Ethereum 2.0 is at [https://blog.ethereum.org/2020/05/21/keys/](https://blog.ethereum.org/2020/05/21/keys/).

#### Risks

A Beacon Node only requires the signing key which presents the following risks: someone who get holds of a signing keys can sign blocks and attestations, leading to double-signing and slashing. The slashing penalty is about 1 ETH (from the initial 32 ETH) but you are ejected when you reach below 16 ETH. An attacker cannot get your funds

### 2.2 Validation in Nimbus

2.2.1 ***Case: No Validator Client split***

**#### This part will be audited by Trail of Bits**

Every start of a slot (every 12 seconds), "onSlotStart" will be scheduled: [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/beacon_node.nim#L986-L987](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/beacon_node.nim#L986-L987)

This will call "[handleValidator](https://github.com/status-im/nim-beacon-chain/blob/a84a8ba192e2f4c7bae22470b44b2db12f95ab0f/beacon_chain/beacon_node.nim#L516)Duties": [https://github.com/status-im/nim-beacon-chain/blob/a84a8ba192e2f4c7bae22470b44b2db12f95ab0f/beacon_chain/beacon_node.nim#L516](https://github.com/status-im/nim-beacon-chain/blob/a84a8ba192e2f4c7bae22470b44b2db12f95ab0f/beacon_chain/beacon_node.nim#L516)

Then we get in the validator_duties.nim file which is the main consumer of the keystore: [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_duties.nim#L439-L440](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_duties.nim#L439-L440)

In particular when signing attestations:

- [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_duties.nim#L146](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_duties.nim#L146)

and blocks:

- [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_duties.nim#L295](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_duties.nim#L295)

**#### This part will be audited by NCC**

The block and attestation signing functions need access to the secret keys and they are isolated in validator_pool.nim [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_pool.nim](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_pool.nim)

The AttachedValidator type is an abstraction over having the secret key in-memory or in a separate process:

- [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/beacon_node_types.nim#L73-L94](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/beacon_node_types.nim#L73-L94)

2.2.2 ***Case: With Validator Client split*

A nbc-audit-2020-2 will be tagged with the** **validator client split.
****

**#### This part will be audited by Trail of Bits**

When there is a VC/BN split, the Validator Client logic mirrors the main BeaconNode with an onSlotStart [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_client.nim#L102](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_client.nim#L102)

Note: validator_client.nim is a stand-alone application

**#### This part will be audited by NCC (in validator_pool.nim)**

And signing block and attestations calls the same function as the no-split case:

- [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_client.nim#L168](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_client.nim#L168)
- [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_client.nim#L144](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_client.nim#L144)

with implementation in [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_pool.nim](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_pool.nim)
