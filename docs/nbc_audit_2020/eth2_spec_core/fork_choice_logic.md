---
title: "Fork choice logic"
code_owner: "Mamy André-Ratsimbazafy (mratsim)"
round: "Audit round 2"
category: "ETH2 Specification Core Audit"
repositories: "nim-beacon-chain"
---

Fork choice backend:
- [https://github.com/status-im/nim-beacon-chain/tree/unstable/beacon_chain/fork_choice](https://github.com/status-im/nim-beacon-chain/tree/unstable/beacon_chain/fork_choice)

Fork choice is provided by the "attestation_pool" when "select_head" is called

- [https://github.com/status-im/nim-beacon-chain/blob/unstable/beacon_chain/consensus_object_pools/attestation_pool.nim](https://github.com/status-im/nim-beacon-chain/blob/unstable/beacon_chain/consensus_object_pools/attestation_pool.nim)

Tests:
- [https://github.com/status-im/nim-beacon-chain/tree/master/tests/fork_choice](https://github.com/status-im/nim-beacon-chain/tree/master/tests/fork_choice)

- [https://github.com/status-im/nim-beacon-chain/blob/master/tests/test_attestation_pool.nim](https://github.com/status-im/nim-beacon-chain/blob/master/tests/test_attestation_pool.nim)

Specs:
- [https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/fork-choice.md](https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/fork-choice.md)

- Explainer from Prysmatic: [https://hackmd.io/bABJiht3Q9SyV3Ga4FT9lQ?view](https://hackmd.io/bABJiht3Q9SyV3Ga4FT9lQ?view)

Paper:
- Combining GHOST and Casper
  Vitalik Buterin, Diego Hernandez, Thor Kamphefner, Khiem Pham, Zhi Qiao, Danny Ryan, Juhyeok Sin, Ying Wang, Yan X Zhang
  [https://arxiv.org/abs/2003.03052](https://arxiv.org/abs/2003.03052)

(Short) Implementations

- [https://github.com/ethereum/research/blob/master/ghost/ghost.py](https://github.com/ethereum/research/blob/master/ghost/ghost.py)
- Original Proto-array (in Go): [https://github.com/protolambda/lmd-ghost/blob/master/eth2/fork_choice/choices/proto_array/proto_array.go](https://github.com/protolambda/lmd-ghost/blob/master/eth2/fork_choice/choices/proto_array/proto_array.go)
- Proto-array incorporating Lighthouse updates: [https://github.com/protolambda/eth2-py-hacks/blob/master/proto_array.py](https://github.com/protolambda/eth2-py-hacks/blob/master/proto_array.py)
