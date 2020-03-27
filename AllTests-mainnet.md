AllTests-mainnet
===
## Beacon chain DB [Preset: mainnet]
```diff
+ empty database [Preset: mainnet]                                                           OK
+ find ancestors [Preset: mainnet]                                                           OK
+ sanity check blocks [Preset: mainnet]                                                      OK
+ sanity check genesis roundtrip [Preset: mainnet]                                           OK
+ sanity check states [Preset: mainnet]                                                      OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## Beacon node
```diff
+ Compile                                                                                    OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Beacon state [Preset: mainnet]
```diff
+ Smoke test initialize_beacon_state_from_eth1 [Preset: mainnet]                             OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Block processing [Preset: mainnet]
```diff
+ Attestation gets processed at epoch [Preset: mainnet]                                      OK
+ Passes from genesis state, empty block [Preset: mainnet]                                   OK
+ Passes from genesis state, no block [Preset: mainnet]                                      OK
+ Passes through epoch update, empty block [Preset: mainnet]                                 OK
+ Passes through epoch update, no block [Preset: mainnet]                                    OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## BlockRef and helpers [Preset: mainnet]
```diff
+ getAncestorAt sanity [Preset: mainnet]                                                     OK
+ isAncestorOf sanity [Preset: mainnet]                                                      OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## BlockSlot and helpers [Preset: mainnet]
```diff
+ atSlot sanity [Preset: mainnet]                                                            OK
+ parent sanity [Preset: mainnet]                                                            OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## Discovery v5 utilities
```diff
+ ENR to ENode                                                                               OK
+ Multiaddress to ENode                                                                      OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## Honest validator
```diff
+ Attestation topics                                                                         OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Official - 0.11.1 - constants & config  [Preset: mainnet]
```diff
+ BASE_REWARD_FACTOR                                64                   [Preset: mainnet]   OK
+ BLS_WITHDRAWAL_PREFIX                             "0x00"               [Preset: mainnet]   OK
+ CHURN_LIMIT_QUOTIENT                              65536                [Preset: mainnet]   OK
+ CUSTODY_PERIOD_TO_RANDAO_PADDING                  2048                 [Preset: mainnet]   OK
- DEPOSIT_CONTRACT_ADDRESS                          "0x1234567890123456789012345678901234567 Fail
+ DOMAIN_AGGREGATE_AND_PROOF                        "0x06000000"         [Preset: mainnet]   OK
+ DOMAIN_BEACON_ATTESTER                            "0x01000000"         [Preset: mainnet]   OK
+ DOMAIN_BEACON_PROPOSER                            "0x00000000"         [Preset: mainnet]   OK
+ DOMAIN_CUSTODY_BIT_SLASHING                       "0x83000000"         [Preset: mainnet]   OK
+ DOMAIN_DEPOSIT                                    "0x03000000"         [Preset: mainnet]   OK
+ DOMAIN_LIGHT_CLIENT                               "0x82000000"         [Preset: mainnet]   OK
+ DOMAIN_RANDAO                                     "0x02000000"         [Preset: mainnet]   OK
+ DOMAIN_SELECTION_PROOF                            "0x05000000"         [Preset: mainnet]   OK
+ DOMAIN_SHARD_COMMITTEE                            "0x81000000"         [Preset: mainnet]   OK
+ DOMAIN_SHARD_PROPOSAL                             "0x80000000"         [Preset: mainnet]   OK
+ DOMAIN_VOLUNTARY_EXIT                             "0x04000000"         [Preset: mainnet]   OK
+ EARLY_DERIVED_SECRET_PENALTY_MAX_FUTURE_EPOCHS    16384                [Preset: mainnet]   OK
+ EARLY_DERIVED_SECRET_REVEAL_SLOT_REWARD_MULTIPLE  2                    [Preset: mainnet]   OK
+ EFFECTIVE_BALANCE_INCREMENT                       1000000000           [Preset: mainnet]   OK
+ EJECTION_BALANCE                                  16000000000          [Preset: mainnet]   OK
+ EPOCHS_PER_CUSTODY_PERIOD                         2048                 [Preset: mainnet]   OK
+ EPOCHS_PER_ETH1_VOTING_PERIOD                     32                   [Preset: mainnet]   OK
+ EPOCHS_PER_HISTORICAL_VECTOR                      65536                [Preset: mainnet]   OK
+ EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION             256                  [Preset: mainnet]   OK
+ EPOCHS_PER_SLASHINGS_VECTOR                       8192                 [Preset: mainnet]   OK
+ ETH1_FOLLOW_DISTANCE                              1024                 [Preset: mainnet]   OK
+ GASPRICE_ADJUSTMENT_COEFFICIENT                   8                    [Preset: mainnet]   OK
+ GENESIS_FORK_VERSION                              "0x00000000"         [Preset: mainnet]   OK
+ HISTORICAL_ROOTS_LIMIT                            16777216             [Preset: mainnet]   OK
+ HYSTERESIS_DOWNWARD_MULTIPLIER                    1                    [Preset: mainnet]   OK
+ HYSTERESIS_QUOTIENT                               4                    [Preset: mainnet]   OK
+ HYSTERESIS_UPWARD_MULTIPLIER                      5                    [Preset: mainnet]   OK
+ INACTIVITY_PENALTY_QUOTIENT                       33554432             [Preset: mainnet]   OK
+ INITIAL_ACTIVE_SHARDS                             64                   [Preset: mainnet]   OK
+ INITIAL_GASPRICE                                  10                   [Preset: mainnet]   OK
+ LIGHT_CLIENT_COMMITTEE_PERIOD                     256                  [Preset: mainnet]   OK
+ LIGHT_CLIENT_COMMITTEE_SIZE                       128                  [Preset: mainnet]   OK
+ MAX_ATTESTATIONS                                  128                  [Preset: mainnet]   OK
+ MAX_ATTESTER_SLASHINGS                            1                    [Preset: mainnet]   OK
+ MAX_COMMITTEES_PER_SLOT                           64                   [Preset: mainnet]   OK
+ MAX_CUSTODY_KEY_REVEALS                           256                  [Preset: mainnet]   OK
+ MAX_CUSTODY_SLASHINGS                             1                    [Preset: mainnet]   OK
+ MAX_DEPOSITS                                      16                   [Preset: mainnet]   OK
+ MAX_EARLY_DERIVED_SECRET_REVEALS                  1                    [Preset: mainnet]   OK
+ MAX_EFFECTIVE_BALANCE                             32000000000          [Preset: mainnet]   OK
+ MAX_EPOCHS_PER_CROSSLINK                          64                   [Preset: mainnet]   OK
+ MAX_GASPRICE                                      16384                [Preset: mainnet]   OK
+ MAX_PROPOSER_SLASHINGS                            16                   [Preset: mainnet]   OK
+ MAX_REVEAL_LATENESS_DECREMENT                     128                  [Preset: mainnet]   OK
+ MAX_SEED_LOOKAHEAD                                4                    [Preset: mainnet]   OK
+ MAX_SHARDS                                        1024                 [Preset: mainnet]   OK
+ MAX_SHARD_BLOCKS_PER_ATTESTATION                  12                   [Preset: mainnet]   OK
+ MAX_SHARD_BLOCK_CHUNKS                            4                    [Preset: mainnet]   OK
+ MAX_VALIDATORS_PER_COMMITTEE                      2048                 [Preset: mainnet]   OK
+ MAX_VOLUNTARY_EXITS                               16                   [Preset: mainnet]   OK
+ MINOR_REWARD_QUOTIENT                             256                  [Preset: mainnet]   OK
+ MIN_ATTESTATION_INCLUSION_DELAY                   1                    [Preset: mainnet]   OK
+ MIN_DEPOSIT_AMOUNT                                1000000000           [Preset: mainnet]   OK
+ MIN_EPOCHS_TO_INACTIVITY_PENALTY                  4                    [Preset: mainnet]   OK
+ MIN_GASPRICE                                      32                   [Preset: mainnet]   OK
+ MIN_GENESIS_ACTIVE_VALIDATOR_COUNT                16384                [Preset: mainnet]   OK
+ MIN_GENESIS_DELAY                                 86400                [Preset: mainnet]   OK
+ MIN_GENESIS_TIME                                  1578009600           [Preset: mainnet]   OK
+ MIN_PER_EPOCH_CHURN_LIMIT                         4                    [Preset: mainnet]   OK
+ MIN_SEED_LOOKAHEAD                                1                    [Preset: mainnet]   OK
+ MIN_SLASHING_PENALTY_QUOTIENT                     32                   [Preset: mainnet]   OK
+ MIN_VALIDATOR_WITHDRAWABILITY_DELAY               256                  [Preset: mainnet]   OK
+ ONLINE_PERIOD                                     8                    [Preset: mainnet]   OK
+ PERSISTENT_COMMITTEE_PERIOD                       2048                 [Preset: mainnet]   OK
+ PHASE_1_FORK_VERSION                              "0x01000000"         [Preset: mainnet]   OK
+ PROPOSER_REWARD_QUOTIENT                          8                    [Preset: mainnet]   OK
+ RANDAO_PENALTY_EPOCHS                             2                    [Preset: mainnet]   OK
+ RANDOM_SUBNETS_PER_VALIDATOR                      1                    [Preset: mainnet]   OK
+ SAFE_SLOTS_TO_UPDATE_JUSTIFIED                    8                    [Preset: mainnet]   OK
+ SECONDS_PER_ETH1_BLOCK                            14                   [Preset: mainnet]   OK
+ SECONDS_PER_SLOT                                  12                   [Preset: mainnet]   OK
+ SHARD_BLOCK_CHUNK_SIZE                            262144               [Preset: mainnet]   OK
- SHARD_BLOCK_OFFSETS                               [1,2,3,5,8,13,21,34,55,89,144,233] [Pres Fail
+ SHARD_COMMITTEE_PERIOD                            256                  [Preset: mainnet]   OK
+ SHUFFLE_ROUND_COUNT                               90                   [Preset: mainnet]   OK
+ SLOTS_PER_EPOCH                                   32                   [Preset: mainnet]   OK
+ SLOTS_PER_HISTORICAL_ROOT                         8192                 [Preset: mainnet]   OK
+ TARGET_AGGREGATORS_PER_COMMITTEE                  16                   [Preset: mainnet]   OK
+ TARGET_COMMITTEE_SIZE                             128                  [Preset: mainnet]   OK
+ TARGET_SHARD_BLOCK_SIZE                           196608               [Preset: mainnet]   OK
+ VALIDATOR_REGISTRY_LIMIT                          1099511627776        [Preset: mainnet]   OK
+ WHISTLEBLOWER_REWARD_QUOTIENT                     512                  [Preset: mainnet]   OK
```
OK: 85/87 Fail: 2/87 Skip: 0/87
## PeerPool testing suite
```diff
+ Access peers by key test                                                                   OK
+ Acquire from empty pool                                                                    OK
+ Acquire/Sorting and consistency test                                                       OK
+ Iterators test                                                                             OK
+ Peer lifetime test                                                                         OK
+ Safe/Clear test                                                                            OK
+ addPeer() test                                                                             OK
+ addPeerNoWait() test                                                                       OK
+ deletePeer() test                                                                          OK
```
OK: 9/9 Fail: 0/9 Skip: 0/9
## SSZ dynamic navigator
```diff
+ navigating fields                                                                          OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## SSZ navigator
```diff
+ lists with max size                                                                        OK
+ simple object fields                                                                       OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## Spec helpers
```diff
+ integer_squareroot                                                                         OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Sync protocol
```diff
+ Compile                                                                                    OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## SyncManager test suite
```diff
+ PeerGroup tests                                                                            OK
+ PeerSlot tests                                                                             OK
+ SyncManager failure test                                                                   OK
+ SyncManager group-recovery test                                                            OK
+ SyncManager one-peer test                                                                  OK
+ SyncManager one-peer-group test                                                            OK
+ SyncManager one-peer-slot test                                                             OK
+ SyncQueue async tests                                                                      OK
+ SyncQueue non-async tests                                                                  OK
```
OK: 9/9 Fail: 0/9 Skip: 0/9
## Zero signature sanity checks
```diff
+ SSZ serialization roundtrip of SignedBeaconBlockHeader                                     OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## [Unit - Spec - Block processing] Attestations  [Preset: mainnet]
```diff
+ Valid attestation                                                                          OK
+ Valid attestation from previous epoch                                                      OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## [Unit - Spec - Block processing] Deposits  [Preset: mainnet]
```diff
+ Deposit at MAX_EFFECTIVE_BALANCE balance (32 ETH)                                          OK
+ Deposit over MAX_EFFECTIVE_BALANCE balance (32 ETH)                                        OK
+ Deposit under MAX_EFFECTIVE_BALANCE balance (32 ETH)                                       OK
+ Validator top-up                                                                           OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
## [Unit - Spec - Epoch processing] Justification and Finalization  [Preset: mainnet]
```diff
+  Rule I - 234 finalization with enough support                                             OK
+  Rule I - 234 finalization without support                                                 OK
+  Rule II - 23 finalization with enough support                                             OK
+  Rule II - 23 finalization without support                                                 OK
+  Rule III - 123 finalization with enough support                                           OK
+  Rule III - 123 finalization without support                                               OK
+  Rule IV - 12 finalization with enough support                                             OK
+  Rule IV - 12 finalization without support                                                 OK
```
OK: 8/8 Fail: 0/8 Skip: 0/8

---TOTAL---
OK: 142/144 Fail: 2/144 Skip: 0/144
