---
title: "RPC API"
code_owner: ""
round: "Audit round 3"
category: "Validator Core Audit"
repositories: "nim-beacon-chain, nim-json_rpc"
---

RPC resources:

- Official mandatory APIs: [https://ethereum.github.io/eth2.0-APIs/](https://ethereum.github.io/eth2.0-APIs/)
* OpenAPI description: [https://ethereum.github.io/eth2.0-APIs/beacon-node-oapi.yaml](https://ethereum.github.io/eth2.0-APIs/beacon-node-oapi.yaml)

Code:

- RpcServer in [https://github.com/status-im/nim-json-rpc](https://github.com/status-im/nim-json-rpc)
- Validator API handlers: [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_api.nim#L177](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/validator_api.nim#L177)
- init: [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/beacon_node.nim#L259-L262](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/beacon_node.nim#L259-L262)
- Beacon Node API handlers: [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/beacon_node.nim#L715-L833](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/beacon_node.nim#L715-L833)

----------------------------------------------------------------

https://github.com/status-im/nim-json-rpc/issues/81

https://github.com/status-im/nim-beacon-chain/issues/1653
https://github.com/status-im/nim-beacon-chain/issues/1652
https://github.com/status-im/nim-beacon-chain/issues/1651
https://github.com/status-im/nim-beacon-chain/issues/1650

recommendations/observations: [https://github.com/status-im/nim-beacon-chain/issues/1665](https://github.com/status-im/nim-beacon-chain/issues/1665)
