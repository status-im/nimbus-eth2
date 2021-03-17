---
title: "Discovery Protocol (discv5)"
code_owner: ""
round: "Audit round 1"
category: "Network Core Audit"
repositories: "nim-eth"
---

## Discovery “discv5”

- Protocol specification: [https://github.com/ethereum/devp2p/tree/master/discv5](https://github.com/ethereum/devp2p/tree/master/discv5)
- Note: the wire format might change ([https://github.com/ethereum/devp2p/issues/152](https://github.com/ethereum/devp2p/issues/152))
- Part of `nim-eth` repository that holds the discovery v5 code: [https://github.com/status-im/nim-eth/tree/master/eth/p2p/discoveryv5](https://github.com/status-im/nim-eth/tree/master/eth/p2p/discoveryv5)
- In scope:
    - All of `discoveryv5` directory
    - All other modules in the `nim-eth` repository that the discoveryv5 code depends on, namely: `keys`, `rlp`, `async_utils`. It currently is also depending on and `trie/db` but as this is to be replaced, it can be considered out-of-scope.
- For additional information see also the [readme](https://github.com/status-im/nim-eth/blob/master/doc/discv5.md).
- [Open issues](https://github.com/status-im/nim-eth/issues?q=is%3Aissue+is%3Aopen+label%3Adiscoveryv5) and those that are likely to have [security implications](https://github.com/status-im/nim-eth/issues?q=is%3Aissue+is%3Aopen+label%3Adiscoveryv5+label%3Asecurity).
