---
title: "ETH1 data processing"
code_owner: ""
round: "Audit round 2"
category: "ETH2 Specification Core Audit"
repositories: "nim-beacon-chain, nim-web3"
---

ETH2 validators are added by locking ETH on a designated ETH1 contract.

Monitoring the ETH1 deposit contract is done via the mainchain_monitor service
which connects to a ETH1 Web3 provider (Geth or Infura):
- [https://github.com/status-im/nim-beacon-chain/blob/master/beacon_chain/mainchain_monitor.nim](https://github.com/status-im/nim-beacon-chain/blob/master/beacon_chain/mainchain_monitor.nim)
- Spec of the deposit contract (for reference): [https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/deposit-contract.md](https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/deposit-contract.md)

nim-web3 scope is significantly larger (and unimplemented) that the audit of nim-beacon-chain. The subset in scope is the one used by mainchain_monitor namely:

- The types Web3, Sender, Subscription

- The procedures

  - eth_getBlockByHash, eth_getBlockByNumber

Processing the new entrants is done in the following state_transition function:
- [https://github.com/status-im/nim-beacon-chain/blob/master/beacon_chain/spec/state_transition_block.nim#L125-L130](https://github.com/status-im/nim-beacon-chain/blob/master/beacon_chain/spec/state_transition_block.nim#L125-L130)
- Specced at [https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#eth1-data](https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#eth1-data)
