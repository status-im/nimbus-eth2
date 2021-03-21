---
title: "Block synchronization"
code_owner: "Eugene Kabanov (cheatfate)"
round: "Audit round 2"
category: "ETH2 Specification Core Audit"
repositories: "nim-beacon-chain"
---

**Note:** Currently there is an issue where ingoing block sync is slow on Medalla testnet and being investigated. There are many changes being made.

Spec: TODO

# Ingoing Sync algorithms

*syncing from remote peers*

We have 2 kinds of ingoing sync, forward sync and backward sync

forward sync:

[https://github.com/status-im/nim-beacon-chain/blob/devel/beacon_chain/sync_manager.nim](https://github.com/status-im/nim-beacon-chain/blob/devel/beacon_chain/sync_protocol.nim)

backward sync:

[https://github.com/status-im/nim-beacon-chain/blob/devel/beacon_chain/request_manager.nim](https://github.com/status-im/nim-beacon-chain/blob/devel/beacon_chain/request_manager.nim)

# Outgoing Sync algorithms

*remote peers sync from us*

[https://github.com/status-im/nim-beacon-chain/blob/devel/beacon_chain/sync_protocol.nim](https://github.com/status-im/nim-beacon-chain/blob/devel/beacon_chain/sync_protocol.nim)
