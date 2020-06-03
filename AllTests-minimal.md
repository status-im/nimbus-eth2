AllTests-minimal
===
## Attestation pool processing [Preset: minimal]
```diff
+ Attestations may arrive in any order [Preset: minimal]                                     OK
+ Attestations may overlap, bigger first [Preset: minimal]                                   OK
+ Attestations may overlap, smaller first [Preset: minimal]                                  OK
+ Attestations should be combined [Preset: minimal]                                          OK
+ Can add and retrieve simple attestation [Preset: minimal]                                  OK
+ Fork choice returns block with attestation                                                 OK
+ Fork choice returns latest block with no attestations                                      OK
```
OK: 7/7 Fail: 0/7 Skip: 0/7
## Beacon chain DB [Preset: minimal]
```diff
+ empty database [Preset: minimal]                                                           OK
+ find ancestors [Preset: minimal]                                                           OK
+ sanity check blocks [Preset: minimal]                                                      OK
+ sanity check genesis roundtrip [Preset: minimal]                                           OK
+ sanity check states [Preset: minimal]                                                      OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## Beacon node
```diff
+ Compile                                                                                    OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Beacon state [Preset: minimal]
```diff
+ Smoke test initialize_beacon_state_from_eth1 [Preset: minimal]                             OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Block pool processing [Preset: minimal]
```diff
+ Can add same block twice [Preset: minimal]                                                 OK
+ Reverse order block add & get [Preset: minimal]                                            OK
+ Simple block add&get [Preset: minimal]                                                     OK
+ getRef returns nil for missing blocks                                                      OK
+ loadTailState gets genesis block on first load [Preset: minimal]                           OK
+ updateHead updates head and headState [Preset: minimal]                                    OK
+ updateStateData sanity [Preset: minimal]                                                   OK
```
OK: 7/7 Fail: 0/7 Skip: 0/7
## Block processing [Preset: minimal]
```diff
+ Attestation gets processed at epoch [Preset: minimal]                                      OK
+ Passes from genesis state, empty block [Preset: minimal]                                   OK
+ Passes from genesis state, no block [Preset: minimal]                                      OK
+ Passes through epoch update, empty block [Preset: minimal]                                 OK
+ Passes through epoch update, no block [Preset: minimal]                                    OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## BlockPool finalization tests [Preset: minimal]
```diff
+ init with gaps [Preset: minimal]                                                           OK
+ prune heads on finalization [Preset: minimal]                                              OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## BlockRef and helpers [Preset: minimal]
```diff
+ getAncestorAt sanity [Preset: minimal]                                                     OK
+ isAncestorOf sanity [Preset: minimal]                                                      OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## BlockSlot and helpers [Preset: minimal]
```diff
+ atSlot sanity [Preset: minimal]                                                            OK
+ parent sanity [Preset: minimal]                                                            OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## Fork Choice + Finality  [Preset: minimal]
```diff
+ fork_choice - testing finality #01                                                         OK
+ fork_choice - testing finality #02                                                         OK
+ fork_choice - testing no votes                                                             OK
+ fork_choice - testing with votes                                                           OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
## Honest validator
```diff
+ General pubsub topics:                                                                     OK
+ Mainnet attestation topics                                                                 OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## Interop
```diff
+ Interop genesis                                                                            OK
+ Interop signatures                                                                         OK
+ Mocked start private key                                                                   OK
```
OK: 3/3 Fail: 0/3 Skip: 0/3
## Keystore
```diff
+ Pbkdf2 decryption                                                                          OK
+ Pbkdf2 encryption                                                                          OK
+ Pbkdf2 errors                                                                              OK
```
OK: 3/3 Fail: 0/3 Skip: 0/3
## Mocking utilities
```diff
+ merkle_minimal                                                                             OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Official - 0.11.3 - constants & config  [Preset: minimal]
```diff
+ BASE_REWARD_FACTOR                                64                   [Preset: minimal]   OK
+ BLS_WITHDRAWAL_PREFIX                             "0x00"               [Preset: minimal]   OK
+ CHURN_LIMIT_QUOTIENT                              65536                [Preset: minimal]   OK
+ CUSTODY_PERIOD_TO_RANDAO_PADDING                  2048                 [Preset: minimal]   OK
  DEPOSIT_CONTRACT_ADDRESS                          "0x1234567890123456789012345678901234567 Skip
+ DOMAIN_AGGREGATE_AND_PROOF                        "0x06000000"         [Preset: minimal]   OK
+ DOMAIN_BEACON_ATTESTER                            "0x01000000"         [Preset: minimal]   OK
+ DOMAIN_BEACON_PROPOSER                            "0x00000000"         [Preset: minimal]   OK
+ DOMAIN_CUSTODY_BIT_SLASHING                       "0x83000000"         [Preset: minimal]   OK
+ DOMAIN_DEPOSIT                                    "0x03000000"         [Preset: minimal]   OK
+ DOMAIN_LIGHT_CLIENT                               "0x82000000"         [Preset: minimal]   OK
+ DOMAIN_RANDAO                                     "0x02000000"         [Preset: minimal]   OK
+ DOMAIN_SELECTION_PROOF                            "0x05000000"         [Preset: minimal]   OK
+ DOMAIN_SHARD_COMMITTEE                            "0x81000000"         [Preset: minimal]   OK
+ DOMAIN_SHARD_PROPOSAL                             "0x80000000"         [Preset: minimal]   OK
+ DOMAIN_VOLUNTARY_EXIT                             "0x04000000"         [Preset: minimal]   OK
+ EARLY_DERIVED_SECRET_PENALTY_MAX_FUTURE_EPOCHS    4096                 [Preset: minimal]   OK
+ EARLY_DERIVED_SECRET_REVEAL_SLOT_REWARD_MULTIPLE  2                    [Preset: minimal]   OK
+ EFFECTIVE_BALANCE_INCREMENT                       1000000000           [Preset: minimal]   OK
+ EJECTION_BALANCE                                  16000000000          [Preset: minimal]   OK
+ EPOCHS_PER_CUSTODY_PERIOD                         2048                 [Preset: minimal]   OK
+ EPOCHS_PER_ETH1_VOTING_PERIOD                     2                    [Preset: minimal]   OK
+ EPOCHS_PER_HISTORICAL_VECTOR                      64                   [Preset: minimal]   OK
+ EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION             256                  [Preset: minimal]   OK
+ EPOCHS_PER_SLASHINGS_VECTOR                       64                   [Preset: minimal]   OK
+ ETH1_FOLLOW_DISTANCE                              16                   [Preset: minimal]   OK
+ GASPRICE_ADJUSTMENT_COEFFICIENT                   8                    [Preset: minimal]   OK
  GENESIS_FORK_VERSION                              "0x00000001"         [Preset: minimal]   Skip
+ HISTORICAL_ROOTS_LIMIT                            16777216             [Preset: minimal]   OK
+ HYSTERESIS_DOWNWARD_MULTIPLIER                    1                    [Preset: minimal]   OK
+ HYSTERESIS_QUOTIENT                               4                    [Preset: minimal]   OK
+ HYSTERESIS_UPWARD_MULTIPLIER                      5                    [Preset: minimal]   OK
+ INACTIVITY_PENALTY_QUOTIENT                       33554432             [Preset: minimal]   OK
+ INITIAL_ACTIVE_SHARDS                             4                    [Preset: minimal]   OK
+ LIGHT_CLIENT_COMMITTEE_PERIOD                     256                  [Preset: minimal]   OK
+ LIGHT_CLIENT_COMMITTEE_SIZE                       128                  [Preset: minimal]   OK
+ MAX_ATTESTATIONS                                  128                  [Preset: minimal]   OK
+ MAX_ATTESTER_SLASHINGS                            1                    [Preset: minimal]   OK
+ MAX_COMMITTEES_PER_SLOT                           4                    [Preset: minimal]   OK
+ MAX_CUSTODY_KEY_REVEALS                           256                  [Preset: minimal]   OK
+ MAX_CUSTODY_SLASHINGS                             1                    [Preset: minimal]   OK
+ MAX_DEPOSITS                                      16                   [Preset: minimal]   OK
+ MAX_EARLY_DERIVED_SECRET_REVEALS                  1                    [Preset: minimal]   OK
+ MAX_EFFECTIVE_BALANCE                             32000000000          [Preset: minimal]   OK
+ MAX_EPOCHS_PER_CROSSLINK                          4                    [Preset: minimal]   OK
+ MAX_GASPRICE                                      16384                [Preset: minimal]   OK
+ MAX_PROPOSER_SLASHINGS                            16                   [Preset: minimal]   OK
+ MAX_REVEAL_LATENESS_DECREMENT                     128                  [Preset: minimal]   OK
+ MAX_SEED_LOOKAHEAD                                4                    [Preset: minimal]   OK
+ MAX_SHARDS                                        8                    [Preset: minimal]   OK
+ MAX_SHARD_BLOCKS_PER_ATTESTATION                  12                   [Preset: minimal]   OK
+ MAX_SHARD_BLOCK_CHUNKS                            4                    [Preset: minimal]   OK
+ MAX_VALIDATORS_PER_COMMITTEE                      2048                 [Preset: minimal]   OK
+ MAX_VOLUNTARY_EXITS                               16                   [Preset: minimal]   OK
+ MINOR_REWARD_QUOTIENT                             256                  [Preset: minimal]   OK
+ MIN_ATTESTATION_INCLUSION_DELAY                   1                    [Preset: minimal]   OK
+ MIN_DEPOSIT_AMOUNT                                1000000000           [Preset: minimal]   OK
+ MIN_EPOCHS_TO_INACTIVITY_PENALTY                  4                    [Preset: minimal]   OK
+ MIN_GASPRICE                                      8                    [Preset: minimal]   OK
+ MIN_GENESIS_ACTIVE_VALIDATOR_COUNT                64                   [Preset: minimal]   OK
+ MIN_GENESIS_DELAY                                 300                  [Preset: minimal]   OK
+ MIN_GENESIS_TIME                                  1578009600           [Preset: minimal]   OK
+ MIN_PER_EPOCH_CHURN_LIMIT                         4                    [Preset: minimal]   OK
+ MIN_SEED_LOOKAHEAD                                1                    [Preset: minimal]   OK
+ MIN_SLASHING_PENALTY_QUOTIENT                     32                   [Preset: minimal]   OK
+ MIN_VALIDATOR_WITHDRAWABILITY_DELAY               256                  [Preset: minimal]   OK
+ ONLINE_PERIOD                                     8                    [Preset: minimal]   OK
+ PERSISTENT_COMMITTEE_PERIOD                       128                  [Preset: minimal]   OK
+ PHASE_1_FORK_VERSION                              "0x01000001"         [Preset: minimal]   OK
+ PROPOSER_REWARD_QUOTIENT                          8                    [Preset: minimal]   OK
+ RANDAO_PENALTY_EPOCHS                             2                    [Preset: minimal]   OK
+ RANDOM_SUBNETS_PER_VALIDATOR                      1                    [Preset: minimal]   OK
+ SAFE_SLOTS_TO_UPDATE_JUSTIFIED                    2                    [Preset: minimal]   OK
+ SECONDS_PER_ETH1_BLOCK                            14                   [Preset: minimal]   OK
+ SECONDS_PER_SLOT                                  6                    [Preset: minimal]   OK
+ SHARD_BLOCK_CHUNK_SIZE                            262144               [Preset: minimal]   OK
  SHARD_BLOCK_OFFSETS                               [1,2,3,5,8,13,21,34,55,89,144,233] [Pres Skip
+ SHARD_COMMITTEE_PERIOD                            256                  [Preset: minimal]   OK
+ SHUFFLE_ROUND_COUNT                               10                   [Preset: minimal]   OK
+ SLOTS_PER_EPOCH                                   8                    [Preset: minimal]   OK
+ SLOTS_PER_HISTORICAL_ROOT                         64                   [Preset: minimal]   OK
+ TARGET_AGGREGATORS_PER_COMMITTEE                  16                   [Preset: minimal]   OK
+ TARGET_COMMITTEE_SIZE                             4                    [Preset: minimal]   OK
+ TARGET_SHARD_BLOCK_SIZE                           196608               [Preset: minimal]   OK
+ VALIDATOR_REGISTRY_LIMIT                          1099511627776        [Preset: minimal]   OK
+ WHISTLEBLOWER_REWARD_QUOTIENT                     512                  [Preset: minimal]   OK
```
OK: 83/86 Fail: 0/86 Skip: 3/86
## PeerPool testing suite
```diff
+ Access peers by key test                                                                   OK
+ Acquire from empty pool                                                                    OK
+ Acquire/Sorting and consistency test                                                       OK
+ Iterators test                                                                             OK
+ Peer lifetime test                                                                         OK
+ Safe/Clear test                                                                            OK
+ Score check test                                                                           OK
+ addPeer() test                                                                             OK
+ addPeerNoWait() test                                                                       OK
+ deletePeer() test                                                                          OK
```
OK: 10/10 Fail: 0/10 Skip: 0/10
## SSZ dynamic navigator
```diff
+ navigating fields                                                                          OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## SSZ navigator
```diff
+ basictype                                                                                  OK
+ lists with max size                                                                        OK
+ simple object fields                                                                       OK
```
OK: 3/3 Fail: 0/3 Skip: 0/3
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
## Zero signature sanity checks
```diff
+ SSZ serialization roundtrip of SignedBeaconBlockHeader                                     OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## [Unit - Spec - Block processing] Attestations  [Preset: minimal]
```diff
+ Valid attestation                                                                          OK
+ Valid attestation from previous epoch                                                      OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## [Unit - Spec - Block processing] Deposits  [Preset: minimal]
```diff
+ Deposit at MAX_EFFECTIVE_BALANCE balance (32 ETH)                                          OK
+ Deposit over MAX_EFFECTIVE_BALANCE balance (32 ETH)                                        OK
+ Deposit under MAX_EFFECTIVE_BALANCE balance (32 ETH)                                       OK
+ Validator top-up                                                                           OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
## [Unit - Spec - Epoch processing] Justification and Finalization  [Preset: minimal]
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
## hash
```diff
+ HashArray                                                                                  OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1

---TOTAL---
OK: 160/163 Fail: 0/163 Skip: 3/163
