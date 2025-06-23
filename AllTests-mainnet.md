AllTests-mainnet
===
## Ancestry
```diff
+ ancestorSlot                                                                               OK
```
## Attestation pool electra processing [Preset: mainnet]
```diff
+ Aggregated attestations with disjoint comittee bits into a single on-chain aggregate [Pres OK
+ Aggregating across committees [Preset: mainnet]                                            OK
+ Attestations with disjoint comittee bits and equal data into single on-chain aggregate [Pr OK
+ Cache coherence on chain aggregates [Preset: mainnet]                                      OK
+ Can add and retrieve simple electra attestations [Preset: mainnet]                         OK
+ Simple add and get with electra nonzero committee [Preset: mainnet]                        OK
+ Working with electra aggregates [Preset: mainnet]                                          OK
```
## Attestation pool processing [Preset: mainnet]
```diff
+ Attestation from different branch [Preset: mainnet]                                        OK
+ Attestations may arrive in any order [Preset: mainnet]                                     OK
+ Attestations may overlap, bigger first [Preset: mainnet]                                   OK
+ Attestations may overlap, smaller first [Preset: mainnet]                                  OK
+ Attestations should be combined [Preset: mainnet]                                          OK
+ Can add and retrieve simple attestations [Preset: mainnet]                                 OK
+ Everyone voting for something different [Preset: mainnet]                                  OK
+ Fork choice returns block with attestation                                                 OK
+ Fork choice returns latest block with no attestations                                      OK
+ Trying to add a block twice tags the second as an error                                    OK
+ Trying to add a duplicate block from an old pruned epoch is tagged as an error             OK
+ Working with aggregates [Preset: mainnet]                                                  OK
```
## Backfill
```diff
+ Backfill to genesis                                                                        OK
+ Init without genesis / block                                                               OK
+ Reload backfill position                                                                   OK
+ Restart after each block                                                                   OK
```
## Beacon chain DB [Preset: mainnet]
```diff
+ empty database [Preset: mainnet]                                                           OK
+ find ancestors [Preset: mainnet]                                                           OK
+ sanity check Altair and cross-fork getState rollback [Preset: mainnet]                     OK
+ sanity check Altair blocks [Preset: mainnet]                                               OK
+ sanity check Altair states [Preset: mainnet]                                               OK
+ sanity check Altair states, reusing buffers [Preset: mainnet]                              OK
+ sanity check Bellatrix and cross-fork getState rollback [Preset: mainnet]                  OK
+ sanity check Bellatrix blocks [Preset: mainnet]                                            OK
+ sanity check Bellatrix states [Preset: mainnet]                                            OK
+ sanity check Bellatrix states, reusing buffers [Preset: mainnet]                           OK
+ sanity check Capella and cross-fork getState rollback [Preset: mainnet]                    OK
+ sanity check Capella blocks [Preset: mainnet]                                              OK
+ sanity check Capella states [Preset: mainnet]                                              OK
+ sanity check Capella states, reusing buffers [Preset: mainnet]                             OK
+ sanity check Deneb and cross-fork getState rollback [Preset: mainnet]                      OK
+ sanity check Deneb blocks [Preset: mainnet]                                                OK
+ sanity check Deneb states [Preset: mainnet]                                                OK
+ sanity check Deneb states, reusing buffers [Preset: mainnet]                               OK
+ sanity check Electra and cross-fork getState rollback [Preset: mainnet]                    OK
+ sanity check Electra blocks [Preset: mainnet]                                              OK
+ sanity check Electra states [Preset: mainnet]                                              OK
+ sanity check Electra states, reusing buffers [Preset: mainnet]                             OK
+ sanity check Fulu and cross-fork getState rollback [Preset: mainnet]                       OK
+ sanity check Fulu blocks [Preset: mainnet]                                                 OK
+ sanity check Fulu states [Preset: mainnet]                                                 OK
+ sanity check Fulu states, reusing buffers [Preset: mainnet]                                OK
+ sanity check blobs [Preset: mainnet]                                                       OK
+ sanity check data columns [Preset: mainnet]                                                OK
+ sanity check genesis roundtrip [Preset: mainnet]                                           OK
+ sanity check phase 0 blocks [Preset: mainnet]                                              OK
+ sanity check phase 0 getState rollback [Preset: mainnet]                                   OK
+ sanity check phase 0 states [Preset: mainnet]                                              OK
+ sanity check phase 0 states, reusing buffers [Preset: mainnet]                             OK
+ sanity check state diff roundtrip [Preset: mainnet]                                        OK
```
## Beacon chain file test suite
```diff
+ Auto check/repair test (missing data)                                                      OK
+ Auto check/repair test (missing footer)                                                    OK
+ Auto check/repair test (missing last chunk)                                                OK
+ Auto check/repair test (only header)                                                       OK
+ Fixture file validation                                                                    OK
```
## Beacon state [Preset: mainnet]
```diff
+ Smoke test initialize_beacon_state_from_eth1 [Preset: mainnet]                             OK
+ can_advance_slots                                                                          OK
+ dependent_root                                                                             OK
+ get_beacon_proposer_index                                                                  OK
+ latest_block_root                                                                          OK
+ process_slots                                                                              OK
```
## Beacon time
```diff
+ Dependent slots                                                                            OK
+ basics                                                                                     OK
```
## Beacon validators test suite
```diff
+ builderBetterBid(builderBoostFactor) test                                                  OK
```
## Blinded block conversions
```diff
+ Bellatrix toSignedBlindedBeaconBlock                                                       OK
+ Capella toSignedBlindedBeaconBlock                                                         OK
+ Deneb toSignedBlindedBeaconBlock                                                           OK
+ Electra toSignedBlindedBeaconBlock                                                         OK
+ Fulu toSignedBlindedBeaconBlock                                                            OK
```
## BlobQuarantine data structure test suite  [Preset: mainnet]
```diff
+ database and memory overfill protection and pruning test                                   OK
+ database unload/load test                                                                  OK
+ overfill protection test                                                                   OK
+ popSidecars()/hasSidecars() return []/true on block without blobs                          OK
+ pruneAfterFinalization() test                                                              OK
+ put() duplicate items should not affect counters                                           OK
+ put()/fetchMissingSidecars/remove test                                                     OK
+ put()/hasSidecar(index, slot, proposer_index)/remove() test                                OK
+ put(sidecar)/put([sidecars])/hasSidecars/popSidecars/remove() test                         OK
```
## Block pool altair processing [Preset: mainnet]
```diff
+ Invalid signatures [Preset: mainnet]                                                       OK
```
## Block pool processing [Preset: mainnet]
```diff
+ Adding the same block twice returns a Duplicate error [Preset: mainnet]                    OK
+ Simple block add&get [Preset: mainnet]                                                     OK
+ basic ops                                                                                  OK
+ updateHead updates head and headState [Preset: mainnet]                                    OK
+ updateState sanity [Preset: mainnet]                                                       OK
```
## Block processor [Preset: mainnet]
```diff
+ Invalidate block root [Preset: mainnet]                                                    OK
+ Reverse order block add & get [Preset: mainnet]                                            OK
```
## Block quarantine
```diff
+ Don't re-download unviable blocks                                                          OK
+ Keep downloading parent chain even if we hit missing limit                                 OK
+ Recursive missing parent                                                                   OK
+ Unviable smoke test                                                                        OK
```
## BlockId and helpers
```diff
+ atSlot sanity                                                                              OK
+ parent sanity                                                                              OK
```
## BlockRef and helpers
```diff
+ get_ancestor sanity                                                                        OK
+ isAncestorOf sanity                                                                        OK
```
## BlockSlot and helpers
```diff
+ atSlot sanity                                                                              OK
+ parent sanity                                                                              OK
```
## ColumnQuarantine data structure test suite  [Preset: mainnet]
```diff
+ ColumnMap test                                                                             OK
+ database and memory overfill protection and pruning test                                   OK
+ database unload/load test                                                                  OK
+ overfill protection test                                                                   OK
+ popSidecars()/hasSidecars() return []/true on block without columns                        OK
+ pruneAfterFinalization() test                                                              OK
+ put() duplicate items should not affect counters                                           OK
+ put()/fetchMissingSidecars/remove test [node]                                              OK
+ put()/fetchMissingSidecars/remove test [supernode]                                         OK
+ put()/hasSidecar(index, slot, proposer_index)/remove() test                                OK
+ put(sidecar)/put([sidecars])/hasSidecars/popSidecars/remove() [node] test                  OK
+ put(sidecar)/put([sidecars])/hasSidecars/popSidecars/remove() [supernode] test             OK
```
## Combined scenarios [Beacon Node] [Preset: mainnet]
```diff
+ ImportKeystores should not be blocked by fee recipient setting [Beacon Node] [Preset: main OK
+ ImportKeystores should not be blocked by gas limit setting [Beacon Node] [Preset: mainnet] OK
+ ImportRemoteKeys should not be blocked by fee recipient setting [Beacon Node] [Preset: mai OK
+ ImportRemoteKeys should not be blocked by gas limit setting [Beacon Node] [Preset: mainnet OK
```
## DeleteKeys requests [Beacon Node] [Preset: mainnet]
```diff
+ Deleting not existing key [Beacon Node] [Preset: mainnet]                                  OK
+ Invalid Authorization Header [Beacon Node] [Preset: mainnet]                               OK
+ Invalid Authorization Token [Beacon Node] [Preset: mainnet]                                OK
+ Missing Authorization header [Beacon Node] [Preset: mainnet]                               OK
```
## DeleteRemoteKeys requests [Beacon Node] [Preset: mainnet]
```diff
+ Deleting existing local key and remote key [Beacon Node] [Preset: mainnet]                 OK
+ Deleting not existing key [Beacon Node] [Preset: mainnet]                                  OK
+ Invalid Authorization Header [Beacon Node] [Preset: mainnet]                               OK
+ Invalid Authorization Token [Beacon Node] [Preset: mainnet]                                OK
+ Missing Authorization header [Beacon Node] [Preset: mainnet]                               OK
```
## Discovery fork ID
```diff
+ Expected fork IDs                                                                          OK
```
## Diverging hardforks
```diff
+ Non-tail block in common                                                                   OK
+ Tail block only in common                                                                  OK
```
## EF - KZG
```diff
+ KZG - Blob to KZG commitment - blob_to_kzg_commitment_case_invalid_blob_0                  OK
+ KZG - Blob to KZG commitment - blob_to_kzg_commitment_case_invalid_blob_1                  OK
+ KZG - Blob to KZG commitment - blob_to_kzg_commitment_case_invalid_blob_2                  OK
+ KZG - Blob to KZG commitment - blob_to_kzg_commitment_case_invalid_blob_3                  OK
+ KZG - Blob to KZG commitment - blob_to_kzg_commitment_case_valid_blob_0                    OK
+ KZG - Blob to KZG commitment - blob_to_kzg_commitment_case_valid_blob_1                    OK
+ KZG - Blob to KZG commitment - blob_to_kzg_commitment_case_valid_blob_2                    OK
+ KZG - Blob to KZG commitment - blob_to_kzg_commitment_case_valid_blob_3                    OK
+ KZG - Blob to KZG commitment - blob_to_kzg_commitment_case_valid_blob_4                    OK
+ KZG - Blob to KZG commitment - blob_to_kzg_commitment_case_valid_blob_5                    OK
+ KZG - Blob to KZG commitment - blob_to_kzg_commitment_case_valid_blob_6                    OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_invalid_blob_0                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_invalid_blob_1                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_invalid_blob_2                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_invalid_blob_3                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_invalid_z_0                               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_invalid_z_1                               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_invalid_z_2                               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_invalid_z_3                               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_invalid_z_4                               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_invalid_z_5                               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_0_0                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_0_1                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_0_2                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_0_3                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_0_4                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_0_5                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_1_0                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_1_1                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_1_2                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_1_3                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_1_4                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_1_5                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_2_0                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_2_1                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_2_2                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_2_3                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_2_4                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_2_5                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_3_0                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_3_1                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_3_2                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_3_3                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_3_4                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_3_5                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_4_0                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_4_1                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_4_2                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_4_3                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_4_4                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_4_5                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_5_0                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_5_1                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_5_2                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_5_3                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_5_4                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_5_5                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_6_0                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_6_1                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_6_2                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_6_3                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_6_4                            OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_6_5                            OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_invalid_blob_0                  OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_invalid_blob_1                  OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_invalid_blob_2                  OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_invalid_blob_3                  OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_invalid_commitment_0            OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_invalid_commitment_1            OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_invalid_commitment_2            OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_invalid_commitment_3            OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_valid_blob_0                    OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_valid_blob_1                    OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_valid_blob_2                    OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_valid_blob_3                    OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_valid_blob_4                    OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_valid_blob_5                    OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_valid_blob_6                    OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_0_0                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_0_1                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_0_2                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_0_3                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_0_4                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_0_5                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_1_0                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_1_1                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_1_2                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_1_3                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_1_4                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_1_5                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_2_0                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_2_1                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_2_2                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_2_3                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_2_4                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_2_5                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_3_0                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_3_1                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_3_2                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_3_3                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_3_4                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_3_5                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_4_0                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_4_1                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_4_2                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_4_3                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_4_4                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_4_5                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_5_0                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_5_1                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_5_2                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_5_3                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_5_4                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_5_5                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_6_0                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_6_1                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_6_2                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_6_3                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_6_4                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_6_5                           OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_po OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_po OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_po OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_po OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_po OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_po OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_po OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_po OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_po OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_po OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_po OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_po OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_0_0                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_0_1                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_0_2                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_0_3                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_0_4                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_0_5                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_1_0                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_1_1                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_1_2                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_1_3                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_1_4                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_1_5                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_2_0                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_2_1                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_2_2                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_2_3                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_2_4                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_2_5                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_3_0                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_3_1                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_3_2                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_3_3                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_3_4                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_3_5                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_4_0                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_4_1                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_4_2                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_4_3                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_4_4                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_4_5                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_5_0                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_5_1                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_5_2                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_5_3                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_5_4                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_5_5                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_6_0                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_6_1                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_6_2                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_6_3                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_6_4                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_6_5                         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_point_at_infinity_0         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_point_at_infinity_1         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_point_at_infinity_2         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_point_at_infinity_3         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_point_at_infinity_4         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_point_at_infinity_5         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_commitment_0                        OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_commitment_1                        OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_commitment_2                        OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_commitment_3                        OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_proof_0                             OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_proof_1                             OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_proof_2                             OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_proof_3                             OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_y_0                                 OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_y_1                                 OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_y_2                                 OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_y_3                                 OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_y_4                                 OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_y_5                                 OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_z_0                                 OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_z_1                                 OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_z_2                                 OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_z_3                                 OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_z_4                                 OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_z_5                                 OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_correct_proof_0                   OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_correct_proof_1                   OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_correct_proof_2                   OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_correct_proof_3                   OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_correct_proof_4                   OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_correct_proof_5                   OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_correct_proof_6                   OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_correct_proof_point_at_infinity_f OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_correct_proof_point_at_infinity_f OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_incorrect_proof_0                 OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_incorrect_proof_1                 OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_incorrect_proof_2                 OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_incorrect_proof_3                 OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_incorrect_proof_4                 OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_incorrect_proof_5                 OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_incorrect_proof_6                 OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_incorrect_proof_point_at_infinity OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_invalid_blob_0                    OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_invalid_blob_1                    OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_invalid_blob_2                    OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_invalid_blob_3                    OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_invalid_commitment_0              OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_invalid_commitment_1              OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_invalid_commitment_2              OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_invalid_commitment_3              OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_invalid_proof_0                   OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_invalid_proof_1                   OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_invalid_proof_2                   OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_invalid_proof_3                   OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_0                     OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_1                     OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_2                     OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_3                     OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_4                     OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_5                     OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_6                     OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_blob_length_different OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_commitment_length_dif OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_incorrect_proof_add_o OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_incorrect_proof_point OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_invalid_blob_0        OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_invalid_blob_1        OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_invalid_blob_2        OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_invalid_blob_3        OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_invalid_commitment_0  OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_invalid_commitment_1  OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_invalid_commitment_2  OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_invalid_commitment_3  OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_invalid_proof_0       OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_invalid_proof_1       OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_invalid_proof_2       OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_invalid_proof_3       OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_proof_length_differen OK
```
## EF - KZG - PeerDAS
```diff
+ KZG - Compute Cells - compute_cells_case_valid_0                                           OK
+ KZG - Compute Cells - compute_cells_case_valid_1                                           OK
+ KZG - Compute Cells - compute_cells_case_valid_2                                           OK
+ KZG - Compute Cells - compute_cells_case_valid_3                                           OK
+ KZG - Compute Cells - compute_cells_case_valid_4                                           OK
+ KZG - Compute Cells - compute_cells_case_valid_5                                           OK
+ KZG - Compute Cells - compute_cells_case_valid_6                                           OK
+ KZG - Compute Cells - compute_cells_invalid_blob_0                                         OK
+ KZG - Compute Cells - compute_cells_invalid_blob_1                                         OK
+ KZG - Compute Cells - compute_cells_invalid_blob_2                                         OK
+ KZG - Compute Cells - compute_cells_invalid_blob_3                                         OK
+ KZG - Compute Cells And Proofs - compute_cells_and_kzg_proofs_case_invalid_blob_0          OK
+ KZG - Compute Cells And Proofs - compute_cells_and_kzg_proofs_case_invalid_blob_1          OK
+ KZG - Compute Cells And Proofs - compute_cells_and_kzg_proofs_case_invalid_blob_2          OK
+ KZG - Compute Cells And Proofs - compute_cells_and_kzg_proofs_case_invalid_blob_3          OK
+ KZG - Compute Cells And Proofs - compute_cells_and_kzg_proofs_case_valid_0                 OK
+ KZG - Compute Cells And Proofs - compute_cells_and_kzg_proofs_case_valid_1                 OK
+ KZG - Compute Cells And Proofs - compute_cells_and_kzg_proofs_case_valid_2                 OK
+ KZG - Compute Cells And Proofs - compute_cells_and_kzg_proofs_case_valid_3                 OK
+ KZG - Compute Cells And Proofs - compute_cells_and_kzg_proofs_case_valid_4                 OK
+ KZG - Compute Cells And Proofs - compute_cells_and_kzg_proofs_case_valid_5                 OK
+ KZG - Compute Cells And Proofs - compute_cells_and_kzg_proofs_case_valid_6                 OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_invalid_all_cells_a OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_invalid_cell_0      OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_invalid_cell_1      OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_invalid_cell_2      OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_invalid_cell_3      OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_invalid_cell_index  OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_invalid_duplicate_c OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_invalid_more_cell_i OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_invalid_more_cells_ OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_invalid_more_cells_ OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_invalid_more_than_h OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_valid_half_missing_ OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_valid_half_missing_ OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_valid_half_missing_ OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_valid_no_missing    OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_incorrect_cell        OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_incorrect_commitment  OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_incorrect_proof       OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_cell_0        OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_cell_1        OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_cell_2        OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_cell_3        OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_cell_index    OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_commitment_0  OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_commitment_1  OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_commitment_2  OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_commitment_3  OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_missing_cell  OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_missing_cell_ OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_missing_commi OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_missing_proof OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_proof_0       OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_proof_1       OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_proof_2       OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_proof_3       OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_valid_0               OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_valid_1               OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_valid_2               OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_valid_3               OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_valid_4               OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_valid_5               OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_valid_6               OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_valid_multiple_blobs  OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_valid_same_cell_multi OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_valid_zero_cells      OK
```
## EF - PeerDAS - Networking [Preset: mainnet]
```diff
+ Networking - Compute Columns for Custody Group - mainnet/fulu/networking/compute_columns_f OK
+ Networking - Compute Columns for Custody Group - mainnet/fulu/networking/compute_columns_f OK
+ Networking - Compute Columns for Custody Group - mainnet/fulu/networking/compute_columns_f OK
+ Networking - Compute Columns for Custody Group - mainnet/fulu/networking/compute_columns_f OK
+ Networking - Compute Columns for Custody Group - mainnet/fulu/networking/compute_columns_f OK
+ Networking - Get Custody Groups - mainnet/fulu/networking/get_custody_groups/pyspec_tests/ OK
+ Networking - Get Custody Groups - mainnet/fulu/networking/get_custody_groups/pyspec_tests/ OK
+ Networking - Get Custody Groups - mainnet/fulu/networking/get_custody_groups/pyspec_tests/ OK
+ Networking - Get Custody Groups - mainnet/fulu/networking/get_custody_groups/pyspec_tests/ OK
+ Networking - Get Custody Groups - mainnet/fulu/networking/get_custody_groups/pyspec_tests/ OK
+ Networking - Get Custody Groups - mainnet/fulu/networking/get_custody_groups/pyspec_tests/ OK
+ Networking - Get Custody Groups - mainnet/fulu/networking/get_custody_groups/pyspec_tests/ OK
+ Networking - Get Custody Groups - mainnet/fulu/networking/get_custody_groups/pyspec_tests/ OK
+ Networking - Get Custody Groups - mainnet/fulu/networking/get_custody_groups/pyspec_tests/ OK
+ Networking - Get Custody Groups - mainnet/fulu/networking/get_custody_groups/pyspec_tests/ OK
+ Networking - Get Custody Groups - mainnet/fulu/networking/get_custody_groups/pyspec_tests/ OK
```
## EF - SSZ generic types
```diff
  Testing basic_vector inputs - invalid                                                      Skip
+ Testing basic_vector inputs - valid                                                        OK
+ Testing bitlist      inputs - invalid                                                      OK
+ Testing bitlist      inputs - valid                                                        OK
  Testing bitvector    inputs - invalid                                                      Skip
+ Testing bitvector    inputs - valid                                                        OK
+ Testing boolean      inputs - invalid                                                      OK
+ Testing boolean      inputs - valid                                                        OK
+ Testing containers   inputs - invalid - skipping BitsStruct                                OK
+ Testing containers   inputs - valid - skipping BitsStruct                                  OK
+ Testing uints        inputs - invalid                                                      OK
+ Testing uints        inputs - valid                                                        OK
```
## EIP-7594 Unit Tests
```diff
+ EIP-7594: Compute Matrix                                                                   OK
+ EIP:7594: Recover Matrix                                                                   OK
```
## EL Configuration
```diff
+ Empty config file                                                                          OK
+ Invalid URls                                                                               OK
+ New style config files                                                                     OK
+ Old style config files                                                                     OK
+ URL parsing                                                                                OK
```
## Engine API conversions
```diff
+ Roundtrip engine RPC V1 and bellatrix ExecutionPayload representations                     OK
+ Roundtrip engine RPC V2 and capella ExecutionPayload representations                       OK
+ Roundtrip engine RPC V3 and deneb ExecutionPayload representations                         OK
```
## Eth1 monitor
```diff
+ Rewrite URLs                                                                               OK
```
## Eth2 specific discovery tests
```diff
+ Invalid attnets field                                                                      OK
+ Subnet query                                                                               OK
+ Subnet query after ENR update                                                              OK
```
## Fee recipient management [Beacon Node] [Preset: mainnet]
```diff
+ Configuring the fee recipient [Beacon Node] [Preset: mainnet]                              OK
+ Configuring the fee recipient for dynamic validator [Beacon Node] [Preset: mainnet]        OK
+ Invalid Authorization Header [Beacon Node] [Preset: mainnet]                               OK
+ Invalid Authorization Token [Beacon Node] [Preset: mainnet]                                OK
+ Missing Authorization header [Beacon Node] [Preset: mainnet]                               OK
+ Obtaining the fee recipient for dynamic validator returns suggested default [Beacon Node]  OK
+ Obtaining the fee recipient of a missing validator returns 404 [Beacon Node] [Preset: main OK
+ Obtaining the fee recipient of an unconfigured validator returns the suggested default [Be OK
+ Setting the fee recipient on a missing validator creates a record for it [Beacon Node] [Pr OK
```
## FinalizedBlocks [Preset: mainnet]
```diff
+ Basic ops [Preset: mainnet]                                                                OK
```
## Fork id compatibility test
```diff
+ Digest check                                                                               OK
+ Fork check                                                                                 OK
+ Next fork epoch check                                                                      OK
```
## Forked SSZ readers
```diff
+ load altair block                                                                          OK
+ load altair state                                                                          OK
+ load bellatrix block                                                                       OK
+ load bellatrix state                                                                       OK
+ load capella block                                                                         OK
+ load capella state                                                                         OK
+ load deneb block                                                                           OK
+ load deneb state                                                                           OK
+ load phase0 block                                                                          OK
+ load phase0 state                                                                          OK
+ should raise on unknown data                                                               OK
```
## Gas limit management [Beacon Node] [Preset: mainnet]
```diff
+ Configuring the gas limit [Beacon Node] [Preset: mainnet]                                  OK
+ Configuring the gas limit for dynamic validator [Beacon Node] [Preset: mainnet]            OK
+ Invalid Authorization Header [Beacon Node] [Preset: mainnet]                               OK
+ Invalid Authorization Token [Beacon Node] [Preset: mainnet]                                OK
+ Missing Authorization header [Beacon Node] [Preset: mainnet]                               OK
+ Obtaining the gas limit for dynamic validator returns suggested default [Beacon Node] [Pre OK
+ Obtaining the gas limit of a missing validator returns 404 [Beacon Node] [Preset: mainnet] OK
+ Obtaining the gas limit of an unconfigured validator returns the suggested default [Beacon OK
+ Setting the gas limit on a missing validator creates a record for it [Beacon Node] [Preset OK
```
## Gossip fork transition
```diff
+ Gossip fork transition                                                                     OK
```
## Gossip validation  [Preset: mainnet]
```diff
+ Empty committee when no committee for slot                                                 OK
+ validateAttestation                                                                        OK
```
## Gossip validation - Altair
```diff
+ Period boundary                                                                            OK
+ validateSyncCommitteeMessage - Duplicate pubkey                                            OK
```
## Graffiti management [Beacon Node] [Preset: mainnet]
```diff
+ Configuring the graffiti [Beacon Node] [Preset: mainnet]                                   OK
+ Invalid Authorization Header [Beacon Node] [Preset: mainnet]                               OK
+ Invalid Authorization Token [Beacon Node] [Preset: mainnet]                                OK
+ Missing Authorization header [Beacon Node] [Preset: mainnet]                               OK
+ Obtaining the graffiti of a missing validator returns 404 [Beacon Node] [Preset: mainnet]  OK
+ Obtaining the graffiti of an unconfigured validator returns the suggested default [Beacon  OK
+ Setting the graffiti on a missing validator creates a record for it [Beacon Node] [Preset: OK
```
## Honest validator
```diff
+ General pubsub topics                                                                      OK
+ Index shuffling and unshuffling invert                                                     OK
+ Liveness failsafe conditions                                                               OK
+ Mainnet attestation topics                                                                 OK
+ Stability subnets                                                                          OK
+ isNearSyncCommitteePeriod                                                                  OK
+ is_aggregator                                                                              OK
```
## ImportKeystores requests [Beacon Node] [Preset: mainnet]
```diff
+ ImportKeystores/ListKeystores/DeleteKeystores [Beacon Node] [Preset: mainnet]              OK
+ Invalid Authorization Header [Beacon Node] [Preset: mainnet]                               OK
+ Invalid Authorization Token [Beacon Node] [Preset: mainnet]                                OK
+ Missing Authorization header [Beacon Node] [Preset: mainnet]                               OK
```
## ImportRemoteKeys/ListRemoteKeys/DeleteRemoteKeys [Beacon Node] [Preset: mainnet]
```diff
+ Importing list of remote keys [Beacon Node] [Preset: mainnet]                              OK
+ Invalid Authorization Header [Beacon Node] [Preset: mainnet]                               OK
+ Invalid Authorization Token [Beacon Node] [Preset: mainnet]                                OK
+ Missing Authorization header [Beacon Node] [Preset: mainnet]                               OK
```
## Key spliting
```diff
+ k < n                                                                                      OK
+ k == n                                                                                     OK
+ k == n == 100                                                                              OK
+ single share                                                                               OK
```
## KeyStorage testing suite
```diff
+ Load Prysm keystore                                                                        OK
+ Pbkdf2 errors                                                                              OK
+ [PBKDF2] Keystore decryption                                                               OK
+ [PBKDF2] Keystore decryption (requireAllFields, allowUnknownFields)                        OK
+ [PBKDF2] Keystore encryption                                                               OK
+ [PBKDF2] Network Keystore decryption                                                       OK
+ [PBKDF2] Network Keystore encryption                                                       OK
+ [SCRYPT] Keystore decryption                                                               OK
+ [SCRYPT] Keystore decryption (requireAllFields, allowUnknownFields)                        OK
+ [SCRYPT] Keystore encryption                                                               OK
+ [SCRYPT] Network Keystore decryption                                                       OK
+ [SCRYPT] Network Keystore encryption                                                       OK
```
## Latest valid hash [Preset: mainnet]
```diff
+ LVH searching                                                                              OK
```
## Light client [Preset: mainnet]
```diff
+ Init from checkpoint                                                                       OK
+ Light client sync                                                                          OK
+ Pre-Altair                                                                                 OK
```
## Light client processor [Preset: mainnet]
```diff
+ Duplicate bootstrap (Optimistic) [Preset: mainnet]                                         OK
+ Duplicate bootstrap (Strict) [Preset: mainnet]                                             OK
+ Invalid bootstrap (Optimistic) [Preset: mainnet]                                           OK
+ Invalid bootstrap (Strict) [Preset: mainnet]                                               OK
+ Missing bootstrap (finality update) (Optimistic) [Preset: mainnet]                         OK
+ Missing bootstrap (finality update) (Strict) [Preset: mainnet]                             OK
+ Missing bootstrap (optimistic update) (Optimistic) [Preset: mainnet]                       OK
+ Missing bootstrap (optimistic update) (Strict) [Preset: mainnet]                           OK
+ Missing bootstrap (update) (Optimistic) [Preset: mainnet]                                  OK
+ Missing bootstrap (update) (Strict) [Preset: mainnet]                                      OK
+ Sync (Optimistic) [Preset: mainnet]                                                        OK
+ Sync (Strict) [Preset: mainnet]                                                            OK
```
## ListKeys requests [Beacon Node] [Preset: mainnet]
```diff
+ Correct token provided [Beacon Node] [Preset: mainnet]                                     OK
+ Invalid Authorization Header [Beacon Node] [Preset: mainnet]                               OK
+ Invalid Authorization Token [Beacon Node] [Preset: mainnet]                                OK
+ Missing Authorization header [Beacon Node] [Preset: mainnet]                               OK
```
## ListRemoteKeys requests [Beacon Node] [Preset: mainnet]
```diff
+ Correct token provided [Beacon Node] [Preset: mainnet]                                     OK
+ Invalid Authorization Header [Beacon Node] [Preset: mainnet]                               OK
+ Invalid Authorization Token [Beacon Node] [Preset: mainnet]                                OK
+ Missing Authorization header [Beacon Node] [Preset: mainnet]                               OK
```
## MEV calls serialization/deserialization and behavior test suite
```diff
+ /eth/v1/builder/blinded_blocks [json/json] test                                            OK
+ /eth/v1/builder/blinded_blocks [json/ssz] test                                             OK
+ /eth/v1/builder/blinded_blocks [ssz/json] test                                             OK
+ /eth/v1/builder/blinded_blocks [ssz/ssz] test                                              OK
+ /eth/v1/builder/header [json] test                                                         OK
+ /eth/v1/builder/header [ssz] test                                                          OK
+ /eth/v1/builder/status test                                                                OK
+ /eth/v1/builder/validators [json] test                                                     OK
+ /eth/v1/builder/validators [ssz] test                                                      OK
```
## Message signatures
```diff
+ Aggregate and proof signatures                                                             OK
+ Attestation signatures                                                                     OK
+ Deposit signatures                                                                         OK
+ Slot signatures                                                                            OK
+ Sync committee message signatures                                                          OK
+ Sync committee selection proof signatures                                                  OK
+ Sync committee signed contribution and proof signatures                                    OK
+ Voluntary exit signatures                                                                  OK
```
## Network metadata
```diff
+ mainnet                                                                                    OK
+ sepolia                                                                                    OK
```
## Nimbus remote signer/signing test (verifying-web3signer)
```diff
+ Signing BeaconBlock (getBlockSignature(electra))                                           OK
+ Waiting for signing node (/upcheck) test                                                   OK
```
## Nimbus remote signer/signing test (web3signer)
```diff
+ Connection timeout test                                                                    OK
+ Public keys enumeration (/api/v1/eth2/publicKeys) test                                     OK
+ Public keys reload (/reload) test                                                          OK
+ Signing BeaconBlock (getBlockSignature(electra))                                           OK
+ Signing SC contribution and proof (getContributionAndProofSignature())                     OK
+ Signing SC message (getSyncCommitteeMessage())                                             OK
+ Signing SC selection proof (getSyncCommitteeSelectionProof())                              OK
+ Signing aggregate and proof (getAggregateAndProofSignature(electra))                       OK
+ Signing aggregate and proof (getAggregateAndProofSignature(phase0))                        OK
+ Signing aggregation slot (getSlotSignature())                                              OK
+ Signing attestation (getAttestationSignature())                                            OK
+ Signing deposit message (getDepositMessageSignature())                                     OK
+ Signing randao reveal (getEpochSignature())                                                OK
+ Signing validator registration (getBuilderSignature())                                     OK
+ Signing voluntary exit (getValidatorExitSignature())                                       OK
+ Waiting for signing node (/upcheck) test                                                   OK
```
## Old database versions [Preset: mainnet]
```diff
+ pre-1.1.0                                                                                  OK
```
## PeerDAS Sampling Tests
```diff
+ PeerDAS: Extended Sample Count                                                             OK
```
## PeerPool testing suite
```diff
+ Access peers by key test                                                                   OK
+ Acquire from empty pool                                                                    OK
+ Acquire/Sorting and consistency test                                                       OK
+ Custom filters test                                                                        OK
+ Delete peer on release text                                                                OK
+ Iterators test                                                                             OK
+ Peer lifetime test                                                                         OK
+ Safe/Clear test                                                                            OK
+ Score check test                                                                           OK
+ Space tests                                                                                OK
+ addPeer() test                                                                             OK
+ addPeerNoWait() test                                                                       OK
+ deletePeer() test                                                                          OK
```
## Pruning
```diff
+ prune states                                                                               OK
```
## Quarantine [Preset: mainnet]
```diff
+ put/iterate/remove test [BlobSidecars]                                                     OK
+ put/iterate/remove test [DataColumnSidecar]                                                OK
```
## REST JSON encoding and decoding
```diff
+ Blob                                                                                       OK
+ DenebSignedBlockContents decoding                                                          OK
+ KzgCommitment                                                                              OK
+ KzgProof                                                                                   OK
+ Validator pubkey hack                                                                      OK
```
## Remove keystore testing suite
```diff
+ Many remotes                                                                               OK
+ Single remote                                                                              OK
+ Verifying Signer / Many remotes                                                            OK
+ Verifying Signer / Single remote                                                           OK
+ vesion 1                                                                                   OK
```
## Serialization/deserialization [Beacon Node] [Preset: mainnet]
```diff
+ Deserialization test vectors                                                               OK
```
## Serialization/deserialization test suite
```diff
+ RestErrorMessage parser tests                                                              OK
+ RestErrorMessage writer tests                                                              OK
+ strictParse(Stuint) tests                                                                  OK
```
## Shufflings
```diff
+ Accelerated shuffling computation                                                          OK
+ Accelerated shuffling computation (with epochRefState jump)                                OK
```
## Shufflings (merged)
```diff
+ Accelerated shuffling computation                                                          OK
+ Accelerated shuffling computation (with epochRefState jump)                                OK
```
## Size bounds
```diff
+ SignedBeaconBlockDeneb                                                                     OK
```
## Slashing Interchange tests  [Preset: mainnet]
```diff
+ Slashing test: duplicate_pubkey_not_slashable.json                                         OK
+ Slashing test: duplicate_pubkey_slashable_attestation.json                                 OK
+ Slashing test: duplicate_pubkey_slashable_block.json                                       OK
+ Slashing test: multiple_interchanges_multiple_validators_repeat_idem.json                  OK
+ Slashing test: multiple_interchanges_overlapping_validators_merge_stale.json               OK
+ Slashing test: multiple_interchanges_overlapping_validators_repeat_idem.json               OK
+ Slashing test: multiple_interchanges_single_validator_fail_iff_imported.json               OK
+ Slashing test: multiple_interchanges_single_validator_first_surrounds_second.json          OK
+ Slashing test: multiple_interchanges_single_validator_multiple_blocks_out_of_order.json    OK
+ Slashing test: multiple_interchanges_single_validator_second_surrounds_first.json          OK
+ Slashing test: multiple_interchanges_single_validator_single_att_out_of_order.json         OK
+ Slashing test: multiple_interchanges_single_validator_single_block_out_of_order.json       OK
+ Slashing test: multiple_interchanges_single_validator_single_message_gap.json              OK
+ Slashing test: multiple_validators_multiple_blocks_and_attestations.json                   OK
+ Slashing test: multiple_validators_same_slot_blocks.json                                   OK
+ Slashing test: single_validator_genesis_attestation.json                                   OK
+ Slashing test: single_validator_import_only.json                                           OK
+ Slashing test: single_validator_multiple_block_attempts.json                               OK
+ Slashing test: single_validator_multiple_blocks_and_attestations.json                      OK
+ Slashing test: single_validator_out_of_order_attestations.json                             OK
+ Slashing test: single_validator_out_of_order_blocks.json                                   OK
  Slashing test: single_validator_resign_attestation.json                                    Skip
+ Slashing test: single_validator_resign_block.json                                          OK
+ Slashing test: single_validator_single_attestation.json                                    OK
+ Slashing test: single_validator_single_block.json                                          OK
+ Slashing test: single_validator_single_block_and_attestation.json                          OK
+ Slashing test: single_validator_single_block_and_attestation_signing_root.json             OK
+ Slashing test: single_validator_slashable_attestations_double_vote.json                    OK
+ Slashing test: single_validator_slashable_attestations_surrounded_by_existing.json         OK
+ Slashing test: single_validator_slashable_attestations_surrounds_existing.json             OK
+ Slashing test: single_validator_slashable_blocks.json                                      OK
+ Slashing test: single_validator_slashable_blocks_no_root.json                              OK
+ Slashing test: single_validator_source_greater_than_target.json                            OK
+ Slashing test: single_validator_source_greater_than_target_sensible_iff_minified.json      OK
  Slashing test: single_validator_source_greater_than_target_surrounded.json                 Skip
  Slashing test: single_validator_source_greater_than_target_surrounding.json                Skip
+ Slashing test: single_validator_two_blocks_no_signing_root.json                            OK
+ Slashing test: wrong_genesis_validators_root.json                                          OK
```
## Slashing Protection DB [Preset: mainnet]
```diff
+ Attestation ordering #1698                                                                 OK
+ Don't prune the very last attestation(s) even by mistake                                   OK
+ Don't prune the very last block even by mistake                                            OK
+ Empty database [Preset: mainnet]                                                           OK
+ Pruning attestations works                                                                 OK
+ Pruning blocks works                                                                       OK
+ SP for block proposal - backtracking append                                                OK
+ SP for block proposal - linear append                                                      OK
+ SP for same epoch attestation target - linear append                                       OK
+ SP for surrounded attestations                                                             OK
+ SP for surrounding attestations                                                            OK
+ Test valid attestation #1699                                                               OK
```
## Spec datatypes
```diff
+ Graffiti bytes                                                                             OK
```
## Spec helpers
```diff
+ build_proof - BeaconState                                                                  OK
+ hypergeom_cdf                                                                              OK
+ integer_squareroot                                                                         OK
```
## Specific field types
```diff
+ root update                                                                                OK
+ roundtrip                                                                                  OK
```
## Starting states
```diff
+ Starting state without block                                                               OK
```
## State history
```diff
+ getBlockIdAtSlot                                                                           OK
```
## Sync committee pool
```diff
+ Aggregating votes                                                                          OK
+ An empty pool is safe to prune                                                             OK
+ An empty pool is safe to prune 2                                                           OK
+ An empty pool is safe to use                                                               OK
+ Missed slots across fork transition                                                        OK
+ Missed slots across sync committee period boundary                                         OK
+ isSeen                                                                                     OK
```
## SyncManager test suite
```diff
+ [SyncManager] groupBlobs() test                                                            OK
+ [SyncQueue# & Backward] Combination of missing parent and good blocks [3 peers] test       OK
+ [SyncQueue# & Backward] Empty responses should not advance queue until other peers will no OK
+ [SyncQueue# & Backward] Failure request push test                                          OK
+ [SyncQueue# & Backward] Invalid block [3 peers] test                                       OK
+ [SyncQueue# & Backward] Smoke [3 peers] test                                               OK
+ [SyncQueue# & Backward] Smoke [single peer] test                                           OK
+ [SyncQueue# & Backward] Unviable block [3 peers] test                                      OK
+ [SyncQueue# & Forward] Combination of missing parent and good blocks [3 peers] test        OK
+ [SyncQueue# & Forward] Empty responses should not advance queue until other peers will not OK
+ [SyncQueue# & Forward] Failure request push test                                           OK
+ [SyncQueue# & Forward] Invalid block [3 peers] test                                        OK
+ [SyncQueue# & Forward] Smoke [3 peers] test                                                OK
+ [SyncQueue# & Forward] Smoke [single peer] test                                            OK
+ [SyncQueue# & Forward] Unviable block [3 peers] test                                       OK
+ [SyncQueue#Backward] Missing parent and exponential rewind [3 peers] test                  OK
+ [SyncQueue#Backward] getRewindPoint() test                                                 OK
+ [SyncQueue#Forward] Missing parent and exponential rewind [3 peers] test                   OK
+ [SyncQueue#Forward] getRewindPoint() test                                                  OK
+ [SyncQueue] checkBlobsResponse() test                                                      OK
+ [SyncQueue] checkResponse() test                                                           OK
+ [SyncQueue] hasEndGap() test                                                               OK
```
## Type helpers
```diff
+ BeaconBlock                                                                                OK
```
## Validator Client test suite
```diff
+ /eth/v1/validator/beacon_committee_selections serialization/deserialization test           OK
+ /eth/v1/validator/sync_committee_selections serialization/deserialization test             OK
+ bestSuccess() API timeout test                                                             OK
+ firstSuccessParallel() API timeout test                                                    OK
+ getAggregatedAttestationDataScore() default test                                           OK
+ getAggregatedAttestationDataScore() test vectors                                           OK
+ getAttestationDataScore() test vectors                                                     OK
+ getLiveness() response deserialization test                                                OK
+ getProduceBlockResponseV3Score() default test                                              OK
+ getProduceBlockResponseV3Score() test vectors                                              OK
+ getSyncCommitteeContributionDataScore() test vectors                                       OK
+ getSyncCommitteeMessageDataScore() test vectors                                            OK
+ getUniqueVotes() test vectors                                                              OK
+ normalizeUri() test vectors                                                                OK
```
## Validator change pool testing suite
```diff
+ addValidatorChangeMessage/getAttesterSlashingMessage (Electra)                             OK
+ addValidatorChangeMessage/getAttesterSlashingMessage (Phase 0)                             OK
+ addValidatorChangeMessage/getBlsToExecutionChange (post-capella)                           OK
+ addValidatorChangeMessage/getBlsToExecutionChange (pre-capella)                            OK
+ addValidatorChangeMessage/getProposerSlashingMessage                                       OK
+ addValidatorChangeMessage/getVoluntaryExitMessage                                          OK
+ pre-pre-fork voluntary exit                                                                OK
```
## Validator pool
```diff
+ Doppelganger for genesis validator                                                         OK
+ Doppelganger for validator that activates in same epoch as check                           OK
+ Dynamic validator set: queryValidatorsSource() test                                        OK
+ Dynamic validator set: updateDynamicValidators() test                                      OK
```
## ValidatorPubKey bucket sort
```diff
+ incremental construction                                                                   OK
+ one-shot construction                                                                      OK
```
## Zero signature sanity checks
```diff
+ SSZ serialization roundtrip of SignedBeaconBlockHeader                                     OK
+ Zero signatures cannot be loaded into a BLS signature object                               OK
+ default initialization of signatures                                                       OK
```
## chain DAG finalization tests [Preset: mainnet]
```diff
+ init with gaps [Preset: mainnet]                                                           OK
+ orphaned epoch block [Preset: mainnet]                                                     OK
+ prune heads on finalization [Preset: mainnet]                                              OK
+ shutdown during finalization [Preset: mainnet]                                             OK
```
## createValidatorFiles()
```diff
+ Add keystore files [LOCAL]                                                                 OK
+ Add keystore files [REMOTE]                                                                OK
+ Add keystore files twice [LOCAL]                                                           OK
+ Add keystore files twice [REMOTE]                                                          OK
+ `createLocalValidatorFiles` with `keystoreDir` without permissions                         OK
+ `createLocalValidatorFiles` with `secretsDir` without permissions                          OK
+ `createLocalValidatorFiles` with `validatorsDir` without permissions                       OK
+ `createValidatorFiles` with already existing dirs and any error                            OK
```
## engine API authentication
```diff
+ HS256 JWS iat token signing                                                                OK
+ HS256 JWS signing                                                                          OK
+ getIatToken                                                                                OK
```
## eth2.0-deposits-cli compatibility
```diff
+ restoring mnemonic with password                                                           OK
+ restoring mnemonic without password                                                        OK
```
## removeValidatorFiles()
```diff
+ Remove nonexistent validator                                                               OK
+ Remove validator files                                                                     OK
+ Remove validator files twice                                                               OK
```
## removeValidatorFiles() multiple keystore types
```diff
+ Remove [LOCAL] when [LOCAL] is missing                                                     OK
+ Remove [LOCAL] when [LOCAL] is present                                                     OK
+ Remove [LOCAL] when [REMOTE] is present                                                    OK
+ Remove [REMOTE] when [LOCAL] is present                                                    OK
+ Remove [REMOTE] when [REMOTE] is missing                                                   OK
+ Remove [REMOTE] when [REMOTE] is present                                                   OK
```
## saveKeystore()
```diff
+ Save [LOCAL] keystore after [LOCAL] keystore with different id                             OK
+ Save [LOCAL] keystore after [LOCAL] keystore with same id                                  OK
+ Save [LOCAL] keystore after [REMOTE] keystore with different id                            OK
+ Save [LOCAL] keystore after [REMOTE] keystore with same id                                 OK
+ Save [REMOTE] keystore after [LOCAL] keystore with different id                            OK
+ Save [REMOTE] keystore after [LOCAL] keystore with same id                                 OK
+ Save [REMOTE] keystore after [REMOTE] keystore with different id                           OK
+ Save [REMOTE] keystore after [REMOTE] keystore with same id                                OK
```
## state diff tests [Preset: mainnet]
```diff
+ random slot differences [Preset: mainnet]                                                  OK
```
## subnet tracker
```diff
+ should register stability subnets on attester duties                                       OK
+ should register sync committee duties                                                      OK
```
## weak-subjectivity-checkpoint
```diff
+ Correct values                                                                             OK
+ invalid characters in root                                                                 OK
+ longer root                                                                                OK
+ missing epoch                                                                              OK
+ missing root                                                                               OK
+ missing separator                                                                          OK
+ negative epoch                                                                             OK
+ non-number epoch                                                                           OK
+ shorter root                                                                               OK
```
