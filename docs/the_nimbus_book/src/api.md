# APIs

`nimbus-eth2`  exposes a collection of APIs for querying the state of the application at runtime.

> **Note:** Where applicable, these APIs mimic the [eth2 APIs](https://github.com/ethereum/eth2.0-APIs) with the exception that JSON-RPC is used instead of http rest (the method names, parameters and results are all the same except for the encoding / access method).

## Introduction

The `nimbus-eth2` API is implemented using JSON-RPC 2.0. To query it, you can use a JSON-RPC library in the language of your choice, or a tool like `curl` to access it from the command line. A tool like [jq](https://stedolan.github.io/jq/) is helpful to pretty-print the responses.

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"peers","params":[] }' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Before you can access the API, make sure it's enabled using the RPC flag (`nimbus_beacon_node --rpc`):

```
     --rpc                     Enable the JSON-RPC server.
     --rpc-port                HTTP port for the JSON-RPC service.
     --rpc-address             Listening address of the RPC server.
```

One difference is that currently endpoints that correspond to specific ones from the [spec](https://ethereum.github.io/eth2.0-APIs/) are named weirdly - for example an endpoint such as [`getGenesis`](https://ethereum.github.io/eth2.0-APIs/#/Beacon/getGenesis) is currently named `get_v1_beacon_genesis` which would map 1:1 to the actual REST path in the future - verbose but unambiguous.


## Beacon chain API

### [`get_v1_beacon_genesis`](https://ethereum.github.io/eth2.0-APIs/#/Beacon/getGenesis)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_genesis","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_beacon_states_root`](https://ethereum.github.io/eth2.0-APIs/#/Beacon/getStateRoot)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_states_root","params":["finalized"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_beacon_states_fork`](https://ethereum.github.io/eth2.0-APIs/#/Beacon/getStateFork)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_states_fork","params":["finalized"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_beacon_states_finality_checkpoints`](https://ethereum.github.io/eth2.0-APIs/#/Beacon/getStateFinalityCheckpoints)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_states_finality_checkpoints","params":["finalized"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_beacon_states_stateId_validators`](https://ethereum.github.io/eth2.0-APIs/#/Beacon/getStateValidators)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_states_stateId_validators","params":["finalized"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_beacon_states_stateId_validators_validatorId`](https://ethereum.github.io/eth2.0-APIs/#/Beacon/getStateValidator)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_states_stateId_validators_validatorId","params":["finalized", "100167"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_beacon_states_stateId_validator_balances`](https://ethereum.github.io/eth2.0-APIs/#/Beacon/getStateValidatorBalances)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_states_stateId_validator_balances","params":["finalized"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_beacon_states_stateId_committees_epoch`](https://ethereum.github.io/eth2.0-APIs/#/Beacon/getEpochCommittees)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_states_stateId_committees_epoch","params":["finalized"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_beacon_headers`](https://ethereum.github.io/eth2.0-APIs/#/Beacon/getBlockHeaders)

### [`get_v1_beacon_headers_blockId`](https://ethereum.github.io/eth2.0-APIs/#/Beacon/getBlockHeader)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_headers_blockId","params":["finalized"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`post_v1_beacon_blocks`](https://ethereum.github.io/eth2.0-APIs/#/Beacon/publishBlock)

```
curl -d '{"jsonrpc":"2.0","method":"post_v1_beacon_blocks","params":[{"message":{"slot":"1","proposer_index":"1","parent_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","state_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","body":{"randao_reveal":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","eth1_data":{"deposit_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","deposit_count":"1","block_hash":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"graffiti":"string","proposer_slashings":[{"signed_header_1":{"message":{"slot":"1","proposer_index":"1","parent_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","state_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","body_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"},"signed_header_2":{"message":{"slot":"1","proposer_index":"1","parent_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","state_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","body_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}}],"attester_slashings":[{"attestation_1":{"attesting_indices":["1"],"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}},"attestation_2":{"attesting_indices":["1"],"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}}}],"attestations":[{"aggregation_bits":"0x01","signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}}],"deposits":[{"proof":["0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"],"data":{"pubkey":"0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a","withdrawal_credentials":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","amount":"1","signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}}],"voluntary_exits":[{"message":{"epoch":"1","validator_index":"1"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}]}},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_beacon_blocks_blockId`](https://ethereum.github.io/eth2.0-APIs/#/Beacon/getBlock)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_blocks_blockId","params":["finalized"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_beacon_blocks_blockId_root`](https://ethereum.github.io/eth2.0-APIs/#/Beacon/getBlockRoot)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_blocks_blockId_root","params":["finalized"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_beacon_blocks_blockId_attestations`](https://ethereum.github.io/eth2.0-APIs/#/Beacon/getBlockAttestations)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_blocks_blockId_attestations","params":["finalized"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`post_v1_beacon_pool_attestations`](https://ethereum.github.io/eth2.0-APIs/#/Beacon/submitPoolAttestations)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_blocks_blockId_attestations","params":[{"aggregation_bits":"0x01","signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}}],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_beacon_pool_attester_slashings`](https://ethereum.github.io/eth2.0-APIs/#/Beacon/getPoolAttesterSlashings)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_pool_attester_slashings","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`post_v1_beacon_pool_attester_slashings`](https://ethereum.github.io/eth2.0-APIs/#/Beacon/submitPoolAttesterSlashings)

```
curl -d '{"jsonrpc":"2.0","method":"post_v1_beacon_pool_attester_slashings","params":[{"attestation_1":{"attesting_indices":["1"],"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}},"attestation_2":{"attesting_indices":["1"],"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}}}],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_beacon_pool_proposer_slashings`](https://ethereum.github.io/eth2.0-APIs/#/Beacon/getPoolProposerSlashings)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_pool_proposer_slashings","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`post_v1_beacon_pool_proposer_slashings`](https://ethereum.github.io/eth2.0-APIs/#/Beacon/submitPoolProposerSlashings)

```
curl -d '{"jsonrpc":"2.0","method":"post_v1_beacon_pool_proposer_slashings","params":[{"signed_header_1":{"message":{"slot":"1","proposer_index":"1","parent_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","state_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","body_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"},"signed_header_2":{"message":{"slot":"1","proposer_index":"1","parent_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","state_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","body_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}}],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_beacon_pool_voluntary_exits`](https://ethereum.github.io/eth2.0-APIs/#/Beacon/getPoolVoluntaryExits)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_pool_voluntary_exits","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`post_v1_beacon_pool_voluntary_exits`](https://ethereum.github.io/eth2.0-APIs/#/Beacon/submitPoolVoluntaryExit)

```
curl -d '{"jsonrpc":"2.0","method":"post_v1_beacon_pool_voluntary_exits","params":[{"message":{"epoch":"1","validator_index":"1"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

## Beacon Node API

### [`get_v1_node_identity`](https://ethereum.github.io/eth2.0-APIs/#/Node/getNetworkIdentity)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_node_identity","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_node_peers`](https://ethereum.github.io/eth2.0-APIs/#/Node/getPeers)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_node_peers","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_node_peers_peerId`](https://ethereum.github.io/eth2.0-APIs/#/Node/getPeer)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_node_peers_peerId","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_node_peer_count`](https://ethereum.github.io/eth2.0-APIs/#/Node/getPeerCount)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_node_peer_count","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_node_version`](https://ethereum.github.io/eth2.0-APIs/#/Node/getNodeVersion)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_node_version","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_node_syncing`](https://ethereum.github.io/eth2.0-APIs/#/Node/getSyncingStatus)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_node_syncing","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_node_health`](https://ethereum.github.io/eth2.0-APIs/#/Node/getHealth)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_node_health","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

## Valdiator API

### [`get_v1_validator_duties_attester`](https://ethereum.github.io/eth2.0-APIs/#/ValidatorRequiredApi/getAttesterDuties)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_validator_duties_attester","params":[1,["a7a0502eae26043d1ac39a39457a6cdf68fae2055d89c7dc59092c25911e4ee55c4e7a31ade61c39480110a393be28e8","a1826dd94cd96c48a81102d316a2af4960d19ca0b574ae5695f2d39a88685a43997cef9a5c26ad911847674d20c46b75"]],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_validator_duties_proposer`](https://ethereum.github.io/eth2.0-APIs/#/ValidatorRequiredApi/getProposerDuties)

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"get_v1_validator_duties_proposer","params":[1] }' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_validator_block`](https://ethereum.github.io/eth2.0-APIs/#/ValidatorRequiredApi/produceBlock)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_validator_block","params":["1","0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","0x4e696d6275732f76312e302e322d64333032633164382d73746174656f667573"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_validator_attestation_data`](https://ethereum.github.io/eth2.0-APIs/#/Validator/produceAttestationData)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_validator_attestation_data","params":[1, 1],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_validator_aggregate_attestation`](https://ethereum.github.io/eth2.0-APIs/#/Validator/getAggregatedAttestation)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_validator_aggregate_attestation","params":[1, "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`post_v1_validator_aggregate_and_proofs`](https://ethereum.github.io/eth2.0-APIs/#/Validator/publishAggregateAndProofs)

```
curl -d '{"jsonrpc":"2.0","method":"post_v1_validator_aggregate_and_proofs","params":[{"message":{"aggregator_index":"1","aggregate":{"aggregation_bits":"0x01","signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}},"selection_proof":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`post_v1_validator_beacon_committee_subscriptions`](https://ethereum.github.io/eth2.0-APIs/#/Validator/prepareBeaconCommitteeSubnet)

## Config API

### [`get_v1_config_fork_schedule`](https://ethereum.github.io/eth2.0-APIs/#/Config/getForkSchedule)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_config_fork_schedule","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_config_spec`](https://ethereum.github.io/eth2.0-APIs/#/Config/getSpec)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_config_spec","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_config_deposit_contract`](https://ethereum.github.io/eth2.0-APIs/#/Config/getDepositContract)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_config_deposit_contract","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

## Administrative / Debug API

### [`get_v1_debug_beacon_states_stateId`](https://ethereum.github.io/eth2.0-APIs/#/Debug/getState)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_debug_beacon_states_stateId","params":["head"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### [`get_v1_debug_beacon_heads`](https://ethereum.github.io/eth2.0-APIs/#/Debug/getDebugChainHeads)

## Nimbus extensions

### getBeaconHead

The latest head slot, as chosen by the latest fork choice.

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"getBeaconHead","params":[] }' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### getChainHead

Show chain head information, including head, justified and finalized checkpoints.

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"getChainHead","params":[] }' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### getNodeVersion

```
 curl -d '{"jsonrpc":"2.0","method":"getNodeVersion","params":[],"id":1}' -H 'Content-Type: application/json' localhost:7001 -s | jq
```

### getSpecPreset

```
 curl -d '{"jsonrpc":"2.0","method":"getSpecPreset","params":[],"id":1}' -H 'Content-Type: application/json' localhost:7001 -s | jq
```

### peers

Show a list of peers in PeerPool.

```
 curl -d '{"jsonrpc":"2.0","method":"peers","params":[],"id":1}' -H 'Content-Type: application/json' localhost:7001 -s | jq
```

### getSyncing

Shows current state of forward syncing manager.

```
 curl -d '{"jsonrpc":"2.0","method":"getSyncing","params":[],"id":1}' -H 'Content-Type: application/json' localhost:7001 -s | jq
```

### getNetworkPeerId

Shows current node's libp2p peer identifier (PeerID).

```
 curl -d '{"jsonrpc":"2.0","method":"getNetworkPeerId","params":[],"id":1}' -H 'Content-Type: application/json' localhost:7001 -s | jq
```

### getNetworkPeers

Shows list of available PeerIDs in PeerPool.

```
 curl -d '{"jsonrpc":"2.0","method":"getNetworkPeers","params":[],"id":1}' -H 'Content-Type: application/json' localhost:7001 -s | jq
```

### getNetworkEnr

### setLogLevel

Set the current logging level dynamically: TRACE, DEBUG, INFO, NOTICE, WARN, ERROR or FATAL

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"setLogLevel","params":["DEBUG; TRACE:discv5,libp2p; REQUIRED:none; DISABLED:none"] }' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### setGraffiti

Set the graffiti bytes that will be included in proposed blocks. The graffiti bytes can be
specified as an UTF-8 encoded string or as an 0x-prefixed hex string specifying raw bytes.

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"setGraffiti","params":["Mr F was here"] }' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### getEth1Chain

Get the list of Eth1 blocks that the beacon node is currently storing in memory.

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"getEth1Chain","params":[] }' -H 'Content-Type: application/json' localhost:9190 -s | jq '.result'
```

### getEth1ProposalData

Inspect the eth1 data that the beacon node would produce if it was tasked to produce a block for the current slot.

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"getEth1ProposalData","params":[] }' -H 'Content-Type: application/json' localhost:9190 -s | jq '.result'
```

### getChronosFutures

Get the current list of live async futures in the process - compile with `-d:chronosFutureTracking` to enable.

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"getChronosFutures","params":[] }' -H 'Content-Type: application/json' localhost:9190 -s | jq '.result | (.[0] | keys_unsorted) as $keys | $keys, map([.[ $keys[] ]])[] | @csv'
```

### getGossipSubPeers

Get the current list of live async futures in the process - compile with `-d:chronosFutureTracking` to enable.

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"getGossipSubPeers","params":[] }' -H 'Content-Type: application/json' localhost:9190 -s | jq '.result'
```
