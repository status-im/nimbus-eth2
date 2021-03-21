---
title: "Account Management & Key storage"
code_owner: "Zahary Karadjov (zah) & Mamy André-Ratsimbazafy (mratsim)"
round: "Audit round 3"
category: "Validator Core Audit"
repositories: "nim-beacon-chain"
---


Related readings:

- Honest validator spec: [https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md](https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md)
- Deposit contract spec: [https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/deposit-contract.md](https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/deposit-contract.md)
- Explanation of signing and withdrawal keys: [https://blog.ethereum.org/2020/05/21/keys/](https://blog.ethereum.org/2020/05/21/keys/)
- Keystore EIP2386: [https://github.com/ethereum/EIPs/blob/4494da0966afa7318ec0157948821b19c4248805/EIPS/eip-2386.md](https://github.com/ethereum/EIPs/blob/4494da0966afa7318ec0157948821b19c4248805/EIPS/eip-2386.md)
- Key Derivation EIP2333: [https://eips.ethereum.org/EIPS/eip-2333](https://eips.ethereum.org/EIPS/eip-2333)

A validator will do a deposit of 32 ETH to participate in proof of stake. Each secret key control 32 ETH, a single beacon node can handle hundreds to thousands of validators and so the same amount of secret keys.

## 0. Scope clarification

Beyond the signing and withdrawal keys, another type of keys is used in the application called "Network private keys". Those are application instance specific not user-specific and are used for P2P identity (secp256k1 secret keys), they do not secure money.

They were reviewed as part of [https://github.com/status-im/nim-beacon-chain/issues/1320](https://github.com/status-im/nim-beacon-chain/issues/1320)

and so are out of scope. See [https://github.com/status-im/nim-beacon-chain/pull/1533/files#diff-f64593cb13697c7f93a225b3b01a5921](https://github.com/status-im/nim-beacon-chain/pull/1533/files#diff-f64593cb13697c7f93a225b3b01a5921) to have an idea of where they are used

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

2.2.3 ***Side-note on hardening***

We plan to make signing in a separate process ([https://github.com/status-im/nim-beacon-chain/issues/545](https://github.com/status-im/nim-beacon-chain/issues/545)) whether the Beacon Node and Validator Client are split or integrated.

This was introduced in [https://github.com/status-im/nim-beacon-chain/pull/1522/files](https://github.com/status-im/nim-beacon-chain/pull/1522/files)
which adds a signing_process.nim file - it is a separate binary and for now the BN (or potentially the VC) talks to it through stdin/stdout to give it roots to sign and it echoes back the signed result.

a nbc-audit-2020-2 branch which will have this PR will be tagged before the start of the audit

Further hardening may consist of:

- a hardened memory allocator [https://github.com/status-im/nim-beacon-chain/issues/563](https://github.com/status-im/nim-beacon-chain/issues/563)
- non-dumpable memory and encrypted memory: [https://github.com/status-im/nim-beacon-chain/issues/545](https://github.com/status-im/nim-beacon-chain/issues/545)

## 3. Deposits creation

Besides validation, deposits creation also involves keys, keystore and wallets.

This is done in a dedicated binary `deposit_contract.nim`
which in particular asks for user private keys [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/deposit_contract.nim](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/deposit_contract.nim)

and creates the directory for each validator and their wallet and mnemonic private keys

[https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/deposit_contract.nim#L173](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/deposit_contract.nim#L173)

The reference implementation is [https://github.com/ethereum/eth2.0-deposit-cli](https://github.com/ethereum/eth2.0-deposit-cli)

User instructions are at: [https://status-im.github.io/nim-beacon-chain/create_wallet_and_deposit.html](https://status-im.github.io/nim-beacon-chain/create_wallet_and_deposit.html)

#### Related audits

Trail of Bits audit of the Ethereum Foundation deposit contract [https://github.com/ethereum/eth2.0-deposit-cli/issues?q=is%3Aissue+is%3Aopen+ToB+Audit](https://github.com/ethereum/eth2.0-deposit-cli/issues?q=is%3Aissue+is%3Aopen+ToB+Audit)

## 3. Key management

### 3.1 Loading the keys

Keys are loaded in-memory by everything that calls `addLocalValidator` and `addLocalValidators` [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_duties.nim#L44-L61](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_duties.nim#L44-L61)

Namely, on BeaconNode init: [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/beacon_node.nim#L291](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/beacon_node.nim#L291)
Note: the out of process signing will be tagged later, see devel code: [https://github.com/status-im/nim-beacon-chain/blob/697bd23c/beacon_chain/beacon_node.nim#L280-L286](https://github.com/status-im/nim-beacon-chain/blob/697bd23c9bbdc76470d6ed1a01260c34617f60bd/beacon_chain/beacon_node.nim#L280-L286)

The `validatorKeys` iterator which returns the validators secret signing keys is defined in `keystore_management.nim` [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/keystore_management.nim#L71-L93](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/keystore_management.nim#L71-L93)

### 3.2 Saving keys

The keys are saved in the following situations:

- After the deposits process we provide: [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/deposit_contract.nim#L179-L185](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/deposit_contract.nim#L179-L185)
- When someone stakes through the official Ethereum 2 launchpad: [https://medalla.launchpad.ethereum.org/](https://medalla.launchpad.ethereum.org/)
- When someone uses a third-party that happen to use Nimbus in the backend, typically a stacking pool or an exchange
- When keys are migrated from one client to the next, on both import or export.

The `saveValidatorKey` procedure is a leftover of refactoring [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_duties.nim#L37-L42](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_duties.nim#L37-L42)

### 3.3 Keystore & Wallet implementation

EIP2386 [https://github.com/ethereum/EIPs/blob/4494da0966afa7318ec0157948821b19c4248805/EIPS/eip-2386.md](https://github.com/ethereum/EIPs/blob/4494da0966afa7318ec0157948821b19c4248805/EIPS/eip-2386.md) is implemented in [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/spec/keystore.nim](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/spec/keystore.nim)

EIP2333 for key derivation [https://eips.ethereum.org/EIPS/eip-2333](https://eips.ethereum.org/EIPS/eip-2333) is implemented in [https://github.com/status-im/nim-blscurve/blob/master/blscurve/eth2_keygen/eth2_keygen.nim](https://github.com/status-im/nim-blscurve/blob/master/blscurve/eth2_keygen/eth2_keygen.nim)

The `keystore.nim` has references to related spec EIP2334 and BIP39

UUID generation implementation is in [https://github.com/status-im/nim-eth/blob/master/eth/keyfile/uuid.nim](https://github.com/status-im/nim-eth/blob/master/eth/keyfile/uuid.nim) (already audited?)

Importing keystores and keymanagement as explained to users:

- import keystore link
- [https://status-im.github.io/nim-beacon-chain/medalla.html#key-management](https://status-im.github.io/nim-beacon-chain/medalla.html#key-management)

## 4. Configuring Secrets

Secrets are configured in `conf.nim` [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/conf.nim](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/conf.nim)

In particular:

- validatorsDirFlag: "A directory containing validator keystores"
- secretsDirFlag: "A directory containing validator keystore passwords"
- walletsDirFlag: "A directory containing wallet files"
- validators: "Path to a validator keystore"
- inProcessValidators: "Disable the push model (the beacon node tells a signing process with the private keys of the validators what to sign and when) and load the validators in the beacon node itself". Actually the keys are currently loaded in-process by default (and not in the signing_process binary) but that should change in the future and then this switch will make sense.

Everything related to wallets and generating/signing validator deposits:

[https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/conf.nim#L259-L324](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/conf.nim#L259-L324)

Also impacting secrets is the nonInteractive flag as it will be used by people handling more than a couple of keys.

CLI audit is in Consensys Diligence scope.

### 5. Testing the APIs that handle secrets

TODO, scripts to easily try the following scenarios
1. Launch a testnet
2. Join with an extra validator by passing credentials via

- wallets
- commandline
- keystores

3. Import 100 new validators

4. Export 100 validators to use in another client

 And/or use the Medalla testnet:

- provide ETH1 secret keys to go through the deposit process
- provide ETH2 keystore.json and/or mnemonic to go through their importing in Nimbus

      This is to avoid waiting a day due to ETH1_FOLLOW_DISTANCE to become a ETH2 validator

User instructions to import a keystore:

- [https://status-im.github.io/nim-beacon-chain/medalla.html#3-import-keystores](https://status-im.github.io/nim-beacon-chain/medalla.html#3-import-keystores)
- [https://status-im.github.io/nim-beacon-chain/medalla.html#key-management](https://status-im.github.io/nim-beacon-chain/medalla.html#key-management)
- Base files: [https://github.com/status-im/nim-beacon-chain/tree/nbc-audit-2020-1/docs/the_nimbus_book/src](https://github.com/status-im/nim-beacon-chain/tree/nbc-audit-2020-1/docs/the_nimbus_book/src)

For now (for Nimbus to implement the script)

- modifying the launch local testnet script [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/conf.nim#L259-L324](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/conf.nim#L259-L324)
    - deposits: [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/scripts/launch_local_testnet.sh#L182-L188](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/scripts/launch_local_testnet.sh#L182-L188)
    - launching a node with its validators and their secret: [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/scripts/launch_local_testnet.sh#L311-L316](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/scripts/launch_local_testnet.sh#L311-L316)
