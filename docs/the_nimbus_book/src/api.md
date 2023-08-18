# JSON-RPC API (deprecated)

!!! warning
    As of v22.6.0, the Nimbus JSON-RPC interface has been **removed** following an extended deprecation period. 
    You are encouraged to migrate your applications to the [REST API](./rest-api.md).

The JSON-RPC API pre-dated the REST API and was based on early designs of the beacon chain.

This guide is kept for historical reference, as well as to aid migration.

## Beacon chain API

### [`get_v1_beacon_genesis`](https://ethereum.github.io/beacon-APIs/#/Beacon/getGenesis)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_genesis","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/beacon/genesis -s | jq
```

### [`get_v1_beacon_states_root`](https://ethereum.github.io/beacon-APIs/#/Beacon/getStateRoot)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_states_root","params":["finalized"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/beacon/states/finalized/root -s | jq
```

### [`get_v1_beacon_states_fork`](https://ethereum.github.io/beacon-APIs/#/Beacon/getStateFork)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_states_fork","params":["finalized"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/beacon/states/finalized/fork -s | jq
```

### [`get_v1_beacon_states_finality_checkpoints`](https://ethereum.github.io/beacon-APIs/#/Beacon/getStateFinalityCheckpoints)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_states_finality_checkpoints","params":["finalized"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/beacon/states/finalized/finality_checkpoints -s | jq
```

### [`get_v1_beacon_states_stateId_validators`](https://ethereum.github.io/beacon-APIs/#/Beacon/getStateValidators)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_states_stateId_validators","params":["finalized"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/beacon/states/finalized/validators -s | jq
```

### [`get_v1_beacon_states_stateId_validators_validatorId`](https://ethereum.github.io/beacon-APIs/#/Beacon/getStateValidator)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_states_stateId_validators_validatorId","params":["finalized", "100167"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/beacon/states/finalized/validators/100167 -s | jq
```

### [`get_v1_beacon_states_stateId_validator_balances`](https://ethereum.github.io/beacon-APIs/#/Beacon/getStateValidatorBalances)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_states_stateId_validator_balances","params":["finalized"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/beacon/states/finalized/validator_balances -s | jq
```

### [`get_v1_beacon_states_stateId_committees_epoch`](https://ethereum.github.io/beacon-APIs/#/Beacon/getEpochCommittees)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_states_stateId_committees_epoch","params":["finalized"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/beacon/states/finalized/committees -s | jq
```

### [`get_v1_beacon_headers`](https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockHeaders)

### [`get_v1_beacon_headers_blockId`](https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockHeader)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_headers_blockId","params":["finalized"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/beacon/headers/finalized -s | jq
```

### [`post_v1_beacon_blocks`](https://ethereum.github.io/beacon-APIs/#/Beacon/publishBlock)

```
curl -d '{"jsonrpc":"2.0","method":"post_v1_beacon_blocks","params":[{"message":{"slot":"1","proposer_index":"1","parent_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","state_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","body":{"randao_reveal":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","eth1_data":{"deposit_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","deposit_count":"1","block_hash":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"graffiti":"string","proposer_slashings":[{"signed_header_1":{"message":{"slot":"1","proposer_index":"1","parent_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","state_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","body_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"},"signed_header_2":{"message":{"slot":"1","proposer_index":"1","parent_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","state_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","body_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}}],"attester_slashings":[{"attestation_1":{"attesting_indices":["1"],"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}},"attestation_2":{"attesting_indices":["1"],"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}}}],"attestations":[{"aggregation_bits":"0x01","signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}}],"deposits":[{"proof":["0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"],"data":{"pubkey":"0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a","withdrawal_credentials":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","amount":"1","signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}}],"voluntary_exits":[{"message":{"epoch":"1","validator_index":"1"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}]}},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl -X POST -d '{"message":{"slot":"1","proposer_index":"1","parent_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","state_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","body":{"randao_reveal":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","eth1_data":{"deposit_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","deposit_count":"1","block_hash":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"graffiti":"string","proposer_slashings":[{"signed_header_1":{"message":{"slot":"1","proposer_index":"1","parent_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","state_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","body_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"},"signed_header_2":{"message":{"slot":"1","proposer_index":"1","parent_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","state_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","body_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}}],"attester_slashings":[{"attestation_1":{"attesting_indices":["1"],"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}},"attestation_2":{"attesting_indices":["1"],"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}}}],"attestations":[{"aggregation_bits":"0x01","signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}}],"deposits":[{"proof":["0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"],"data":{"pubkey":"0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a","withdrawal_credentials":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","amount":"1","signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}}],"voluntary_exits":[{"message":{"epoch":"1","validator_index":"1"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}]}},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}' -H 'Content-Type: application/json' http://localhost:5052/eth/v1/beacon/blocks -s | jq
```

### [`get_v1_beacon_blocks_blockId`](https://ethereum.github.io/beacon-APIs/#/Beacon/getBlock)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_blocks_blockId","params":["finalized"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v2/beacon/blocks/finalized -s | jq
```

### [`get_v1_beacon_blocks_blockId_root`](https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockRoot)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_blocks_blockId_root","params":["finalized"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/beacon/blocks/finalized/root -s | jq
```

### [`get_v1_beacon_blocks_blockId_attestations`](https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockAttestations)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_blocks_blockId_attestations","params":["finalized"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/beacon/blocks/finalized/attestations -s | jq
```

### [`post_v1_beacon_pool_attestations`](https://ethereum.github.io/beacon-APIs/#/Beacon/submitPoolAttestations)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_blocks_blockId_attestations","params":[{"aggregation_bits":"0x01","signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}}],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl -X POST -d '[{"aggregation_bits":"0x01","signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}}]'  -H 'Content-Type: application/json' http://localhost:5052/eth/v1/beacon/pool/attestations -s | jq
```

### [`get_v1_beacon_pool_attester_slashings`](https://ethereum.github.io/beacon-APIs/#/Beacon/getPoolAttesterSlashings)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_pool_attester_slashings","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/beacon/pool/attester_slashings -s | jq
```

### [`post_v1_beacon_pool_attester_slashings`](https://ethereum.github.io/beacon-APIs/#/Beacon/submitPoolAttesterSlashings)

```
curl -d '{"jsonrpc":"2.0","method":"post_v1_beacon_pool_attester_slashings","params":[{"attestation_1":{"attesting_indices":["1"],"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}},"attestation_2":{"attesting_indices":["1"],"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}}}],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl -X POST -d '{"attestation_1":{"attesting_indices":["1"],"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}},"attestation_2":{"attesting_indices":["1"],"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}}}' -H 'Content-Type: application/json' http://localhost:5052/eth/v1/beacon/pool/attester_slashings -s | jq
```

### [`get_v1_beacon_pool_proposer_slashings`](https://ethereum.github.io/beacon-APIs/#/Beacon/getPoolProposerSlashings)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_pool_proposer_slashings","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/beacon/pool/proposer_slashings -s | jq
```

### [`post_v1_beacon_pool_proposer_slashings`](https://ethereum.github.io/beacon-APIs/#/Beacon/submitPoolProposerSlashings)

```
curl -d '{"jsonrpc":"2.0","method":"post_v1_beacon_pool_proposer_slashings","params":[{"signed_header_1":{"message":{"slot":"1","proposer_index":"1","parent_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","state_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","body_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"},"signed_header_2":{"message":{"slot":"1","proposer_index":"1","parent_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","state_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","body_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}}],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl -X POST -d '{"signed_header_1":{"message":{"slot":"1","proposer_index":"1","parent_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","state_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","body_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"},"signed_header_2":{"message":{"slot":"1","proposer_index":"1","parent_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","state_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","body_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}}' -H 'Content-Type: application/json' http://localhost:5052/eth/v1/beacon/pool/proposer_slashings -s | jq
```

### [`get_v1_beacon_pool_voluntary_exits`](https://ethereum.github.io/beacon-APIs/#/Beacon/getPoolVoluntaryExits)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_beacon_pool_voluntary_exits","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/beacon/pool/voluntary_exits -s | jq
```

### [`post_v1_beacon_pool_voluntary_exits`](https://ethereum.github.io/beacon-APIs/#/Beacon/submitPoolVoluntaryExit)

```
curl -d '{"jsonrpc":"2.0","method":"post_v1_beacon_pool_voluntary_exits","params":[{"message":{"epoch":"1","validator_index":"1"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl -X POST -d '{"message":{"epoch":"1","validator_index":"1"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}' -H 'Content-Type: application/json' http://localhost:5052/eth/v1/beacon/pool/voluntary_exits -s | jq
```

## Beacon Node API

### [`get_v1_node_identity`](https://ethereum.github.io/beacon-APIs/#/Node/getNetworkIdentity)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_node_identity","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/node/identity -s | jq
```

### [`get_v1_node_peers`](https://ethereum.github.io/beacon-APIs/#/Node/getPeers)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_node_peers","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/node/peers -s | jq
```

### [`get_v1_node_peers_peerId`](https://ethereum.github.io/beacon-APIs/#/Node/getPeer)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_node_peers_peerId","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/node/peer/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N -s | jq
```

### [`get_v1_node_peer_count`](https://ethereum.github.io/beacon-APIs/#/Node/getPeerCount)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_node_peer_count","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/node/peer_count -s | jq
```

### [`get_v1_node_version`](https://ethereum.github.io/beacon-APIs/#/Node/getNodeVersion)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_node_version","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/node/version -s | jq
```

### [`get_v1_node_syncing`](https://ethereum.github.io/beacon-APIs/#/Node/getSyncingStatus)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_node_syncing","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/node/syncing -s | jq
```

### [`get_v1_node_health`](https://ethereum.github.io/beacon-APIs/#/Node/getHealth)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_node_health","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/node/health -s -w "%{http_code}"
```

## Validator API

### [`get_v1_validator_duties_attester`](https://ethereum.github.io/beacon-APIs/#/ValidatorRequiredApi/getAttesterDuties)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_validator_duties_attester","params":[1,["a7a0502eae26043d1ac39a39457a6cdf68fae2055d89c7dc59092c25911e4ee55c4e7a31ade61c39480110a393be28e8","a1826dd94cd96c48a81102d316a2af4960d19ca0b574ae5695f2d39a88685a43997cef9a5c26ad911847674d20c46b75"]],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl -X POST http://localhost:5052/eth/v1/validator/duties/attester/1 -H 'Content-Type: application/json' -d '["a7a0502eae26043d1ac39a39457a6cdf68fae2055d89c7dc59092c25911e4ee55c4e7a31ade61c39480110a393be28e8"]' -s | jq
```

### [`get_v1_validator_duties_proposer`](https://ethereum.github.io/beacon-APIs/#/ValidatorRequiredApi/getProposerDuties)

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"get_v1_validator_duties_proposer","params":[1] }' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/validator/duties/proposer/1 -s | jq
```

### [`get_v1_validator_block`](https://ethereum.github.io/beacon-APIs/#/Validator/produceBlockV2)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_validator_block","params":[1,"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","0x4e696d6275732f76312e302e322d64333032633164382d73746174656f667573"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v2/validator/blocks/1?randao_reveal=0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505&graffiti=0x4e696d6275732f76312e302e322d64333032633164382d73746174656f667573 -s | jq
```

### [`get_v1_validator_attestation_data`](https://ethereum.github.io/beacon-APIs/#/Validator/produceAttestationData)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_validator_attestation_data","params":[1, 1],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/validator/attestation_data?slot=1&committee_index=1 -s | jq
```

### [`get_v1_validator_aggregate_attestation`](https://ethereum.github.io/beacon-APIs/#/Validator/getAggregatedAttestation)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_validator_aggregate_attestation","params":[1, "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/validator/aggregate_attestation?slot=1&attestation_data_root=0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2 -s | jq
```

### [`post_v1_validator_aggregate_and_proofs`](https://ethereum.github.io/beacon-APIs/#/Validator/publishAggregateAndProofs)

```
curl -d '{"jsonrpc":"2.0","method":"post_v1_validator_aggregate_and_proofs","params":[{"message":{"aggregator_index":"1","aggregate":{"aggregation_bits":"0x01","signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}},"selection_proof":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl -X POST http://localhost:5052/eth/v1/validator/aggregate_and_proofs -H 'Content-Type: application/json' -d '[{"message":{"aggregator_index":"1","aggregate":{"aggregation_bits":"0x01","signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505","data":{"slot":"1","index":"1","beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2","source":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"},"target":{"epoch":"1","root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}},"selection_proof":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"},"signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"}]' -s | jq
```

### [`post_v1_validator_beacon_committee_subscriptions`](https://ethereum.github.io/beacon-APIs/#/Validator/prepareBeaconCommitteeSubnet)

## Config API

### [`get_v1_config_fork_schedule`](https://ethereum.github.io/beacon-APIs/#/Config/getForkSchedule)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_config_fork_schedule","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/config/fork_schedule -s | jq
```

### [`get_v1_config_spec`](https://ethereum.github.io/beacon-APIs/#/Config/getSpec)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_config_spec","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/config/spec -s | jq
```

### [`get_v1_config_deposit_contract`](https://ethereum.github.io/beacon-APIs/#/Config/getDepositContract)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_config_deposit_contract","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v1/config/deposit_contract -s | jq
```

## Administrative / Debug API

### [`get_v1_debug_beacon_states_stateId`](https://ethereum.github.io/beacon-APIs/#/Debug/getStateV2)

```
curl -d '{"jsonrpc":"2.0","method":"get_v1_debug_beacon_states_stateId","params":["head"],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v2/debug/beacon/states/head -s | jq
```

### [`get_v2_debug_beacon_heads`](https://ethereum.github.io/beacon-APIs/#/Debug/getDebugChainHeadsV2)

Equivalent call in the official REST API:

```
curl http://localhost:5052/eth/v2/debug/beacon/heads -s | jq
```

## Nimbus extensions

### getBeaconHead

The latest head slot, as chosen by the latest fork choice.

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"getBeaconHead","params":[] }' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/nimbus/v1/beacon/head -s | jq
```

### getChainHead

Show chain head information, including head, justified and finalized checkpoints.

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"getChainHead","params":[] }' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/nimbus/v1/chain/head -s | jq
```

### getNodeVersion

```
curl -d '{"jsonrpc":"2.0","method":"getNodeVersion","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/nimbus/v1/node/version -s | jq
```

### peers

Show a list of peers in PeerPool.

```
curl -d '{"jsonrpc":"2.0","method":"peers","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/nimbus/v1/network/peers -s | jq
```

### getSyncing

Shows current state of forward syncing manager.

```
curl -d '{"jsonrpc":"2.0","method":"getSyncing","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/nimbus/v1/syncmanager/status -s | jq
```

### getNetworkPeerId

Shows current node's libp2p peer identifier (PeerID).

```
curl -d '{"jsonrpc":"2.0","method":"getNetworkPeerId","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

### getNetworkPeers

Shows list of available PeerIDs in PeerPool.

```
curl -d '{"jsonrpc":"2.0","method":"getNetworkPeers","params":[],"id":1}' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/nimbus/v1/network/peers -s | jq
```

### getNetworkEnr

### setLogLevel

Set the current logging level dynamically: TRACE, DEBUG, INFO, NOTICE, WARN, ERROR or FATAL

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"setLogLevel","params":["DEBUG; TRACE:discv5,libp2p; REQUIRED:none; DISABLED:none"] }' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl -X POST http://localhost:5052/nimbus/v1/chronicles/settings -d "DEBUG; TRACE:discv5,libp2p; REQUIRED:none; DISABLED:none" -s | jq
```

### setGraffiti

Set the graffiti bytes that will be included in proposed blocks.
The graffiti bytes can be specified as an UTF-8 encoded string or as an 0x-prefixed hex string specifying raw bytes.

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"setGraffiti","params":["Mr F was here"] }' -H 'Content-Type: application/json' localhost:9190 -s | jq
```

Equivalent call in the official REST API:

```
curl -X POST http://localhost:5052/nimbus/v1/graffiti -d "Mr F was here" -s | jq
```

### getEth1Chain

Get the list of Eth1 blocks that the beacon node is currently storing in memory.

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"getEth1Chain","params":[] }' -H 'Content-Type: application/json' localhost:9190 -s | jq '.result'
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/nimbus/v1/eth1/chain -s | jq
```

### getEth1ProposalData

Inspect the eth1 data that the beacon node would produce if it was tasked to produce a block for the current slot.

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"getEth1ProposalData","params":[] }' -H 'Content-Type: application/json' localhost:9190 -s | jq '.result'
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/nimbus/v1/eth1/proposal_data -s | jq
```

### debug_getChronosFutures

Get the current list of live async futures in the process - compile with `-d:chronosFutureTracking` to enable.

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"debug_getChronosFutures","params":[] }' -H 'Content-Type: application/json' localhost:9190 -s | jq '.result | (.[0] | keys_unsorted) as $keys | $keys, map([.[ $keys[] ]])[] | @csv'
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/nimbus/v1/debug/chronos/futures -s | jq
```

### debug_getGossipSubPeers

Get the current list of live async futures in the process - compile with `-d:chronosFutureTracking` to enable.

```
curl -d '{"jsonrpc":"2.0","id":"id","method":"debug_getGossipSubPeers","params":[] }' -H 'Content-Type: application/json' localhost:9190 -s | jq '.result'
```

Equivalent call in the official REST API:

```
curl http://localhost:5052/nimbus/v1/debug/gossip/peers -s | jq
```
