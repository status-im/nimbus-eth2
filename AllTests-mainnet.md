AllTests-mainnet
===
## Ancestry
```diff
+ ancestorSlot                                                                               OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Attestation pool electra processing [Preset: mainnet]
```diff
+ Aggregated attestations with disjoint comittee bits into a single on-chain aggregate [Pres OK
+ Attestations with disjoint comittee bits and equal data into single on-chain aggregate [Pr OK
+ Can add and retrieve simple electra attestations [Preset: mainnet]                         OK
+ Working with electra aggregates [Preset: mainnet]                                          OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
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
OK: 12/12 Fail: 0/12 Skip: 0/12
## Backfill
```diff
+ Backfill to genesis                                                                        OK
+ Init without genesis / block                                                               OK
+ Reload backfill position                                                                   OK
+ Restart after each block                                                                   OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
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
+ sanity check blobs [Preset: mainnet]                                                       OK
+ sanity check genesis roundtrip [Preset: mainnet]                                           OK
+ sanity check phase 0 blocks [Preset: mainnet]                                              OK
+ sanity check phase 0 getState rollback [Preset: mainnet]                                   OK
+ sanity check phase 0 states [Preset: mainnet]                                              OK
+ sanity check phase 0 states, reusing buffers [Preset: mainnet]                             OK
+ sanity check state diff roundtrip [Preset: mainnet]                                        OK
```
OK: 29/29 Fail: 0/29 Skip: 0/29
## Beacon state [Preset: mainnet]
```diff
+ Smoke test initialize_beacon_state_from_eth1 [Preset: mainnet]                             OK
+ can_advance_slots                                                                          OK
+ dependent_root                                                                             OK
+ get_beacon_proposer_index                                                                  OK
+ latest_block_root                                                                          OK
+ merklizer state roundtrip                                                                  OK
+ process_slots                                                                              OK
```
OK: 7/7 Fail: 0/7 Skip: 0/7
## Beacon time
```diff
+ Dependent slots                                                                            OK
+ basics                                                                                     OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## Beacon validators test suite
```diff
+ builderBetterBid(builderBoostFactor) test                                                  OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Blinded block conversions
```diff
+ Bellatrix toSignedBlindedBeaconBlock                                                       OK
+ Capella toSignedBlindedBeaconBlock                                                         OK
+ Deneb toSignedBlindedBeaconBlock                                                           OK
+ Electra toSignedBlindedBeaconBlock                                                         OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
## Block pool altair processing [Preset: mainnet]
```diff
+ Invalid signatures [Preset: mainnet]                                                       OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Block pool processing [Preset: mainnet]
```diff
+ Adding the same block twice returns a Duplicate error [Preset: mainnet]                    OK
+ Simple block add&get [Preset: mainnet]                                                     OK
+ basic ops                                                                                  OK
+ updateHead updates head and headState [Preset: mainnet]                                    OK
+ updateState sanity [Preset: mainnet]                                                       OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## Block processor [Preset: mainnet]
```diff
+ Reverse order block add & get [Preset: mainnet]                                            OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Block quarantine
```diff
+ Recursive missing parent                                                                   OK
+ Unviable smoke test                                                                        OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## BlockId and helpers
```diff
+ atSlot sanity                                                                              OK
+ parent sanity                                                                              OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## BlockRef and helpers
```diff
+ get_ancestor sanity                                                                        OK
+ isAncestorOf sanity                                                                        OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## BlockSlot and helpers
```diff
+ atSlot sanity                                                                              OK
+ parent sanity                                                                              OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## DeleteKeys requests [Beacon Node] [Preset: mainnet]
```diff
+ Deleting not existing key [Beacon Node] [Preset: mainnet]                                  OK
+ Invalid Authorization Header [Beacon Node] [Preset: mainnet]                               OK
+ Invalid Authorization Token [Beacon Node] [Preset: mainnet]                                OK
+ Missing Authorization header [Beacon Node] [Preset: mainnet]                               OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
## DeleteRemoteKeys requests [Beacon Node] [Preset: mainnet]
```diff
+ Deleting existing local key and remote key [Beacon Node] [Preset: mainnet]                 OK
+ Deleting not existing key [Beacon Node] [Preset: mainnet]                                  OK
+ Invalid Authorization Header [Beacon Node] [Preset: mainnet]                               OK
+ Invalid Authorization Token [Beacon Node] [Preset: mainnet]                                OK
+ Missing Authorization header [Beacon Node] [Preset: mainnet]                               OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## DepositContractSnapshot
```diff
+ Migration                                                                                  OK
+ SSZ                                                                                        OK
+ depositCount                                                                               OK
+ isValid                                                                                    OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
## Discovery fork ID
```diff
+ Expected fork IDs                                                                          OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Diverging hardforks
```diff
+ Non-tail block in common                                                                   OK
+ Tail block only in common                                                                  OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## EF - EIP7594 - Networking [Preset: mainnet]
```diff
+ Networking - Get Custody Columns - mainnet/eip7594/networking/get_custody_columns/pyspec_t OK
+ Networking - Get Custody Columns - mainnet/eip7594/networking/get_custody_columns/pyspec_t OK
+ Networking - Get Custody Columns - mainnet/eip7594/networking/get_custody_columns/pyspec_t OK
+ Networking - Get Custody Columns - mainnet/eip7594/networking/get_custody_columns/pyspec_t OK
+ Networking - Get Custody Columns - mainnet/eip7594/networking/get_custody_columns/pyspec_t OK
+ Networking - Get Custody Columns - mainnet/eip7594/networking/get_custody_columns/pyspec_t OK
+ Networking - Get Custody Columns - mainnet/eip7594/networking/get_custody_columns/pyspec_t OK
+ Networking - Get Custody Columns - mainnet/eip7594/networking/get_custody_columns/pyspec_t OK
+ Networking - Get Custody Columns - mainnet/eip7594/networking/get_custody_columns/pyspec_t OK
```
OK: 9/9 Fail: 0/9 Skip: 0/9
## EF - KZG
```diff
+ KZG - Blob to KZG commitment - blob_to_kzg_commitment_case_invalid_blob_59d64ff6b4648fad   OK
+ KZG - Blob to KZG commitment - blob_to_kzg_commitment_case_invalid_blob_635fb2de5b0dc429   OK
+ KZG - Blob to KZG commitment - blob_to_kzg_commitment_case_invalid_blob_a3b9ff28507767f8   OK
+ KZG - Blob to KZG commitment - blob_to_kzg_commitment_case_invalid_blob_d3afbd98123a3434   OK
+ KZG - Blob to KZG commitment - blob_to_kzg_commitment_case_valid_blob_0951cfd9ab47a8d3     OK
+ KZG - Blob to KZG commitment - blob_to_kzg_commitment_case_valid_blob_19b3f3f8c98ea31e     OK
+ KZG - Blob to KZG commitment - blob_to_kzg_commitment_case_valid_blob_84d8089232bc23a8     OK
+ KZG - Blob to KZG commitment - blob_to_kzg_commitment_case_valid_blob_a87a4e636e0f58fb     OK
+ KZG - Blob to KZG commitment - blob_to_kzg_commitment_case_valid_blob_c40b9b515df8721b     OK
+ KZG - Blob to KZG commitment - blob_to_kzg_commitment_case_valid_blob_cdb3e6d49eb12307     OK
+ KZG - Blob to KZG commitment - blob_to_kzg_commitment_case_valid_blob_fb324bc819407148     OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_invalid_blob_59d64ff6b4648fad             OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_invalid_blob_635fb2de5b0dc429             OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_invalid_blob_a3b9ff28507767f8             OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_invalid_blob_d3afbd98123a3434             OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_invalid_z_03265c1605637b1f                OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_invalid_z_881cc19564a97501                OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_invalid_z_8e021fdb13259641                OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_invalid_z_9683af102559ddf0                OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_invalid_z_9df8c89b61183887                OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_invalid_z_b30d81e81c1262b6                OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_02e696ada7d4631d               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_05c1f3685f3393f0               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_08f9e2f1cb3d39db               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_0cf79b17cb5f4ea2               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_177b58dc7a46b08f               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_1ce8e4f69d5df899               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_26b753dec0560daa               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_2b76dc9e3abf42f3               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_31ebd010e6098750               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_3208425794224c3f               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_36817bfd67de97a8               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_392169c16a2e5ef6               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_395cf6d697d1a743               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_3ac8dc31e9aa6a70               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_3c1e8b38219e3e12               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_3c87ec986c2656c2               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_3cd183d0bab85fb7               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_420f2a187ce77035               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_444b73ff54a19b44               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_53a9bdf4f75196da               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_585454b31673dd62               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_7db4f140a955dd1a               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_83e53423a2dd93fe               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_9b24f8997145435c               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_9b754afb690c47e1               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_a0be66af9a97ea52               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_af669445747d2585               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_af8b75f664ed7d43               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_b6cb6698327d9835               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_b6ec3736f9ff2c62               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_becf2e1641bbd4e6               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_c3d4322ec17fe7cd               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_c5e1490d672d026d               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_cae5d3491190b777               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_d0992bc0387790a4               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_d736268229bd87ec               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_e68d7111a2364a49               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_ed6b180ec759bcf6               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_f0ed3dc11cdeb130               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_f47eb9fc139f6bfd               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_f7f44e1e864aa967               OK
+ KZG - Compute KZG proof - compute_kzg_proof_case_valid_blob_ffa6e97b97146517               OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_invalid_blob_59d64ff6b4648fad   OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_invalid_blob_635fb2de5b0dc429   OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_invalid_blob_a3b9ff28507767f8   OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_invalid_blob_d3afbd98123a3434   OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_invalid_commitment_1a68c47b6814 OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_invalid_commitment_24b932fb4dec OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_invalid_commitment_3a6eb616efae OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_invalid_commitment_d070689c3e15 OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_valid_blob_0951cfd9ab47a8d3     OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_valid_blob_19b3f3f8c98ea31e     OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_valid_blob_84d8089232bc23a8     OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_valid_blob_a87a4e636e0f58fb     OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_valid_blob_c40b9b515df8721b     OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_valid_blob_cdb3e6d49eb12307     OK
+ KZG - Compute blob KZG proof - compute_blob_kzg_proof_case_valid_blob_fb324bc819407148     OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_02e696ada7d4631d              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_05c1f3685f3393f0              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_08f9e2f1cb3d39db              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_0cf79b17cb5f4ea2              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_177b58dc7a46b08f              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_1ce8e4f69d5df899              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_26b753dec0560daa              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_2b76dc9e3abf42f3              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_31ebd010e6098750              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_3208425794224c3f              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_36817bfd67de97a8              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_392169c16a2e5ef6              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_395cf6d697d1a743              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_3ac8dc31e9aa6a70              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_3c1e8b38219e3e12              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_3c87ec986c2656c2              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_3cd183d0bab85fb7              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_420f2a187ce77035              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_444b73ff54a19b44              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_53a9bdf4f75196da              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_585454b31673dd62              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_7db4f140a955dd1a              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_83e53423a2dd93fe              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_9b24f8997145435c              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_9b754afb690c47e1              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_a0be66af9a97ea52              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_af669445747d2585              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_af8b75f664ed7d43              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_b6cb6698327d9835              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_b6ec3736f9ff2c62              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_becf2e1641bbd4e6              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_c3d4322ec17fe7cd              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_c5e1490d672d026d              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_cae5d3491190b777              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_d0992bc0387790a4              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_d736268229bd87ec              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_e68d7111a2364a49              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_ed6b180ec759bcf6              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_f0ed3dc11cdeb130              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_f47eb9fc139f6bfd              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_f7f44e1e864aa967              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_correct_proof_ffa6e97b97146517              OK
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
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_02e696ada7d4631d            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_05c1f3685f3393f0            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_08f9e2f1cb3d39db            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_0cf79b17cb5f4ea2            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_177b58dc7a46b08f            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_1ce8e4f69d5df899            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_26b753dec0560daa            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_2b76dc9e3abf42f3            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_31ebd010e6098750            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_3208425794224c3f            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_36817bfd67de97a8            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_392169c16a2e5ef6            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_395cf6d697d1a743            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_3ac8dc31e9aa6a70            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_3c1e8b38219e3e12            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_3c87ec986c2656c2            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_3cd183d0bab85fb7            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_420f2a187ce77035            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_444b73ff54a19b44            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_53a9bdf4f75196da            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_585454b31673dd62            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_7db4f140a955dd1a            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_83e53423a2dd93fe            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_9b24f8997145435c            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_9b754afb690c47e1            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_a0be66af9a97ea52            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_af669445747d2585            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_af8b75f664ed7d43            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_b6cb6698327d9835            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_b6ec3736f9ff2c62            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_becf2e1641bbd4e6            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_c3d4322ec17fe7cd            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_c5e1490d672d026d            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_cae5d3491190b777            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_d0992bc0387790a4            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_d736268229bd87ec            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_e68d7111a2364a49            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_ed6b180ec759bcf6            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_f0ed3dc11cdeb130            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_f47eb9fc139f6bfd            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_f7f44e1e864aa967            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_ffa6e97b97146517            OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_point_at_infinity_392169c16 OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_point_at_infinity_3c1e8b382 OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_point_at_infinity_3c87ec986 OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_point_at_infinity_420f2a187 OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_point_at_infinity_83e53423a OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_incorrect_proof_point_at_infinity_ed6b180ec OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_commitment_1b44e341d56c757d         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_commitment_32afa9561a4b3b91         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_commitment_3e55802a5ed3c757         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_commitment_e9d3e9ec16fbc15f         OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_proof_1b44e341d56c757d              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_proof_32afa9561a4b3b91              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_proof_3e55802a5ed3c757              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_proof_e9d3e9ec16fbc15f              OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_y_35d08d612aad2197                  OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_y_4aa6def8c35c9097                  OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_y_4e51cef08a61606f                  OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_y_64b9ff2b8f7dddee                  OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_y_b358a2e763727b70                  OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_y_eb0601fec84cc5e9                  OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_z_35d08d612aad2197                  OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_z_4aa6def8c35c9097                  OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_z_4e51cef08a61606f                  OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_z_64b9ff2b8f7dddee                  OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_z_b358a2e763727b70                  OK
+ KZG - Verify KZG proof - verify_kzg_proof_case_invalid_z_eb0601fec84cc5e9                  OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_correct_proof_0951cfd9ab47a8d3    OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_correct_proof_19b3f3f8c98ea31e    OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_correct_proof_84d8089232bc23a8    OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_correct_proof_a87a4e636e0f58fb    OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_correct_proof_c40b9b515df8721b    OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_correct_proof_cdb3e6d49eb12307    OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_correct_proof_fb324bc819407148    OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_correct_proof_point_at_infinity_f OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_correct_proof_point_at_infinity_f OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_incorrect_proof_0951cfd9ab47a8d3  OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_incorrect_proof_19b3f3f8c98ea31e  OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_incorrect_proof_84d8089232bc23a8  OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_incorrect_proof_a87a4e636e0f58fb  OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_incorrect_proof_c40b9b515df8721b  OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_incorrect_proof_cdb3e6d49eb12307  OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_incorrect_proof_fb324bc819407148  OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_incorrect_proof_point_at_infinity OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_invalid_blob_59d64ff6b4648fad     OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_invalid_blob_635fb2de5b0dc429     OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_invalid_blob_a3b9ff28507767f8     OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_invalid_blob_d3afbd98123a3434     OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_invalid_commitment_1a68c47b68148e OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_invalid_commitment_24b932fb4dec5b OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_invalid_commitment_3a6eb616efae06 OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_invalid_commitment_d070689c3e1544 OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_invalid_proof_1a68c47b68148e78    OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_invalid_proof_24b932fb4dec5b2d    OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_invalid_proof_3a6eb616efae0627    OK
+ KZG - Verify blob KZG proof - verify_blob_kzg_proof_case_invalid_proof_d070689c3e15444c    OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_0951cfd9ab47a8d3      OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_0f3f1d3f48f71495      OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_12c097d7ca0261e3      OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_2ef482373a81e34e      OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_a271b78b8e869d69      OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_blob_length_different OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_cb3c3279a1afddcf      OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_commitment_length_dif OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_e61aafba051ddf79      OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_incorrect_proof_add_o OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_incorrect_proof_point OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_invalid_blob_59d64ff6 OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_invalid_blob_635fb2de OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_invalid_blob_a3b9ff28 OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_invalid_blob_d3afbd98 OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_invalid_commitment_1a OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_invalid_commitment_24 OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_invalid_commitment_3a OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_invalid_commitment_d0 OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_invalid_proof_1a68c47 OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_invalid_proof_24b932f OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_invalid_proof_3a6eb61 OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_invalid_proof_d070689 OK
+ KZG - Verify blob KZG proof batch - verify_blob_kzg_proof_batch_case_proof_length_differen OK
```
OK: 253/253 Fail: 0/253 Skip: 0/253
## EF - KZG - EIP7594
```diff
+ KZG - Compute Cells And Proofs - compute_cells_and_kzg_proofs_case_invalid_blob_26555bdcbf OK
+ KZG - Compute Cells And Proofs - compute_cells_and_kzg_proofs_case_invalid_blob_79fb3cb1ef OK
+ KZG - Compute Cells And Proofs - compute_cells_and_kzg_proofs_case_invalid_blob_7e99dea889 OK
+ KZG - Compute Cells And Proofs - compute_cells_and_kzg_proofs_case_invalid_blob_9d88c33852 OK
+ KZG - Compute Cells And Proofs - compute_cells_and_kzg_proofs_case_valid_419245fbfe69f145  OK
+ KZG - Compute Cells And Proofs - compute_cells_and_kzg_proofs_case_valid_4aedd1a2a3933c3e  OK
+ KZG - Compute Cells And Proofs - compute_cells_and_kzg_proofs_case_valid_6e773f256383918c  OK
+ KZG - Compute Cells And Proofs - compute_cells_and_kzg_proofs_case_valid_b0731ef77b166ca8  OK
+ KZG - Compute Cells And Proofs - compute_cells_and_kzg_proofs_case_valid_b81d309b22788820  OK
+ KZG - Compute Cells And Proofs - compute_cells_and_kzg_proofs_case_valid_ed8b5001151417d5  OK
+ KZG - Compute Cells And Proofs - compute_cells_and_kzg_proofs_case_valid_edeb8500a6507818  OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_invalid_all_cells_a OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_invalid_cell_047ee7 OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_invalid_cell_76ab46 OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_invalid_cell_77b669 OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_invalid_cell_c8e2ca OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_invalid_cell_index_ OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_invalid_duplicate_c OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_invalid_more_cell_i OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_invalid_more_cells_ OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_invalid_more_cells_ OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_invalid_more_than_h OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_valid_half_missing_ OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_valid_half_missing_ OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_valid_half_missing_ OK
+ KZG - Recover Cells And Kzg Proofs - recover_cells_and_kzg_proofs_case_valid_no_missing_a1 OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_incorrect_cell_48bcbf OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_incorrect_commitment_ OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_incorrect_proof_ba29f OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_cell_bcb1b35c OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_cell_d89304ce OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_cell_d939faf6 OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_cell_ef6ac828 OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_cell_index_5d OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_commitment_4b OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_commitment_53 OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_commitment_68 OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_commitment_d3 OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_missing_cell_ OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_missing_cell_ OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_missing_commi OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_missing_proof OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_proof_0424858 OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_proof_48fa9d1 OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_proof_8feaf47 OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_invalid_proof_a9d14f0 OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_valid_0cfba0f22152206 OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_valid_3073caf43016db4 OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_valid_5211d9e9ff34c00 OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_valid_92c0b5242fa34ae OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_valid_9fb9bff6fe1fb6b OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_valid_d3f60d6d484ddb6 OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_valid_fd341ee5517e590 OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_valid_multiple_blobs_ OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_valid_same_cell_multi OK
+ KZG - Verify Cell Kzg Proof Batch - verify_cell_kzg_proof_batch_case_valid_zero_cells_fbbd OK
```
OK: 56/56 Fail: 0/56 Skip: 0/56
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
OK: 10/12 Fail: 0/12 Skip: 2/12
## EIP-4881
```diff
+ deposit_cases                                                                              OK
+ empty_root                                                                                 OK
+ finalization                                                                               OK
+ invalid_snapshot                                                                           OK
+ snapshot_cases                                                                             OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## EIP-7594 Sampling Tests
```diff
+ EIP7594: Extended Sample Count                                                             OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## EIP-7594 Unit Tests
```diff
+ EIP-7594: Compute Matrix                                                                   OK
+ EIP:7594: Recover Matrix                                                                   OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## EL Configuration
```diff
+ Empty config file                                                                          OK
+ Invalid URls                                                                               OK
+ New style config files                                                                     OK
+ Old style config files                                                                     OK
+ URL parsing                                                                                OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## Engine API conversions
```diff
+ Roundtrip engine RPC V1 and bellatrix ExecutionPayload representations                     OK
+ Roundtrip engine RPC V2 and capella ExecutionPayload representations                       OK
+ Roundtrip engine RPC V3 and deneb ExecutionPayload representations                         OK
+ Roundtrip engine RPC V4 and electra ExecutionPayload representations                       OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
## Eth1 monitor
```diff
+ Deposits chain                                                                             OK
+ Rewrite URLs                                                                               OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## Eth2 specific discovery tests
```diff
+ Invalid attnets field                                                                      OK
+ Subnet query                                                                               OK
+ Subnet query after ENR update                                                              OK
```
OK: 3/3 Fail: 0/3 Skip: 0/3
## Fee recipient management [Beacon Node] [Preset: mainnet]
```diff
+ Configuring the fee recipient [Beacon Node] [Preset: mainnet]                              OK
+ Invalid Authorization Header [Beacon Node] [Preset: mainnet]                               OK
+ Invalid Authorization Token [Beacon Node] [Preset: mainnet]                                OK
+ Missing Authorization header [Beacon Node] [Preset: mainnet]                               OK
+ Obtaining the fee recipient of a missing validator returns 404 [Beacon Node] [Preset: main OK
+ Obtaining the fee recipient of an unconfigured validator returns the suggested default [Be OK
+ Setting the fee recipient on a missing validator creates a record for it [Beacon Node] [Pr OK
```
OK: 7/7 Fail: 0/7 Skip: 0/7
## FinalizedBlocks [Preset: mainnet]
```diff
+ Basic ops [Preset: mainnet]                                                                OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Fork id compatibility test
```diff
+ Digest check                                                                               OK
+ Fork check                                                                                 OK
+ Next fork epoch check                                                                      OK
```
OK: 3/3 Fail: 0/3 Skip: 0/3
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
OK: 11/11 Fail: 0/11 Skip: 0/11
## Gas limit management [Beacon Node] [Preset: mainnet]
```diff
+ Configuring the gas limit [Beacon Node] [Preset: mainnet]                                  OK
+ Invalid Authorization Header [Beacon Node] [Preset: mainnet]                               OK
+ Invalid Authorization Token [Beacon Node] [Preset: mainnet]                                OK
+ Missing Authorization header [Beacon Node] [Preset: mainnet]                               OK
+ Obtaining the gas limit of a missing validator returns 404 [Beacon Node] [Preset: mainnet] OK
+ Obtaining the gas limit of an unconfigured validator returns the suggested default [Beacon OK
+ Setting the gas limit on a missing validator creates a record for it [Beacon Node] [Preset OK
```
OK: 7/7 Fail: 0/7 Skip: 0/7
## Gossip fork transition
```diff
+ Gossip fork transition                                                                     OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Gossip validation  [Preset: mainnet]
```diff
+ Empty committee when no committee for slot                                                 OK
+ validateAttestation                                                                        OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## Gossip validation - Altair
```diff
+ Period boundary                                                                            OK
+ validateSyncCommitteeMessage - Duplicate pubkey                                            OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
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
OK: 7/7 Fail: 0/7 Skip: 0/7
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
OK: 7/7 Fail: 0/7 Skip: 0/7
## ImportKeystores requests [Beacon Node] [Preset: mainnet]
```diff
+ ImportKeystores/ListKeystores/DeleteKeystores [Beacon Node] [Preset: mainnet]              OK
+ Invalid Authorization Header [Beacon Node] [Preset: mainnet]                               OK
+ Invalid Authorization Token [Beacon Node] [Preset: mainnet]                                OK
+ Missing Authorization header [Beacon Node] [Preset: mainnet]                               OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
## ImportRemoteKeys/ListRemoteKeys/DeleteRemoteKeys [Beacon Node] [Preset: mainnet]
```diff
+ Importing list of remote keys [Beacon Node] [Preset: mainnet]                              OK
+ Invalid Authorization Header [Beacon Node] [Preset: mainnet]                               OK
+ Invalid Authorization Token [Beacon Node] [Preset: mainnet]                                OK
+ Missing Authorization header [Beacon Node] [Preset: mainnet]                               OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
## Key spliting
```diff
+ k < n                                                                                      OK
+ k == n                                                                                     OK
+ k == n == 100                                                                              OK
+ single share                                                                               OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
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
OK: 12/12 Fail: 0/12 Skip: 0/12
## Latest valid hash [Preset: mainnet]
```diff
+ LVH searching                                                                              OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Light client [Preset: mainnet]
```diff
+ Init from checkpoint                                                                       OK
+ Light client sync                                                                          OK
+ Pre-Altair                                                                                 OK
```
OK: 3/3 Fail: 0/3 Skip: 0/3
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
OK: 12/12 Fail: 0/12 Skip: 0/12
## ListKeys requests [Beacon Node] [Preset: mainnet]
```diff
+ Correct token provided [Beacon Node] [Preset: mainnet]                                     OK
+ Invalid Authorization Header [Beacon Node] [Preset: mainnet]                               OK
+ Invalid Authorization Token [Beacon Node] [Preset: mainnet]                                OK
+ Missing Authorization header [Beacon Node] [Preset: mainnet]                               OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
## ListRemoteKeys requests [Beacon Node] [Preset: mainnet]
```diff
+ Correct token provided [Beacon Node] [Preset: mainnet]                                     OK
+ Invalid Authorization Header [Beacon Node] [Preset: mainnet]                               OK
+ Invalid Authorization Token [Beacon Node] [Preset: mainnet]                                OK
+ Missing Authorization header [Beacon Node] [Preset: mainnet]                               OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
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
OK: 8/8 Fail: 0/8 Skip: 0/8
## Network metadata
```diff
+ mainnet                                                                                    OK
+ sepolia                                                                                    OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## Nimbus remote signer/signing test (verifying-web3signer)
```diff
+ Signing BeaconBlock (getBlockSignature(capella))                                           OK
+ Signing BeaconBlock (getBlockSignature(deneb))                                             OK
+ Waiting for signing node (/upcheck) test                                                   OK
```
OK: 3/3 Fail: 0/3 Skip: 0/3
## Nimbus remote signer/signing test (web3signer)
```diff
+ Connection timeout test                                                                    OK
+ Public keys enumeration (/api/v1/eth2/publicKeys) test                                     OK
+ Public keys reload (/reload) test                                                          OK
+ Signing BeaconBlock (getBlockSignature(capella))                                           OK
+ Signing BeaconBlock (getBlockSignature(deneb))                                             OK
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
OK: 17/17 Fail: 0/17 Skip: 0/17
## Old database versions [Preset: mainnet]
```diff
+ pre-1.1.0                                                                                  OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## PeerPool testing suite
```diff
+ Access peers by key test                                                                   OK
+ Acquire from empty pool                                                                    OK
+ Acquire/Sorting and consistency test                                                       OK
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
OK: 12/12 Fail: 0/12 Skip: 0/12
## Pruning
```diff
+ prune states                                                                               OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## REST JSON encoding and decoding
```diff
+ Blob                                                                                       OK
+ DenebSignedBlockContents decoding                                                          OK
+ KzgCommitment                                                                              OK
+ KzgProof                                                                                   OK
+ Validator pubkey hack                                                                      OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## Remove keystore testing suite
```diff
+ Many remotes                                                                               OK
+ Single remote                                                                              OK
+ Verifying Signer / Many remotes                                                            OK
+ Verifying Signer / Single remote                                                           OK
+ vesion 1                                                                                   OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## Serialization/deserialization [Beacon Node] [Preset: mainnet]
```diff
+ Deserialization test vectors                                                               OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Serialization/deserialization test suite
```diff
+ RestErrorMessage parser tests                                                              OK
+ RestErrorMessage writer tests                                                              OK
+ strictParse(Stuint) tests                                                                  OK
```
OK: 3/3 Fail: 0/3 Skip: 0/3
## Shufflings
```diff
+ Accelerated shuffling computation                                                          OK
+ Accelerated shuffling computation (with epochRefState jump)                                OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## Shufflings (merged)
```diff
+ Accelerated shuffling computation                                                          OK
+ Accelerated shuffling computation (with epochRefState jump)                                OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
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
OK: 35/38 Fail: 0/38 Skip: 3/38
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
OK: 12/12 Fail: 0/12 Skip: 0/12
## Spec datatypes
```diff
+ Graffiti bytes                                                                             OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Spec helpers
```diff
+ build_proof - BeaconState                                                                  OK
+ hypergeom_cdf                                                                              OK
+ integer_squareroot                                                                         OK
```
OK: 3/3 Fail: 0/3 Skip: 0/3
## Specific field types
```diff
+ root update                                                                                OK
+ roundtrip                                                                                  OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## Starting states
```diff
+ Starting state without block                                                               OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## State history
```diff
+ getBlockIdAtSlot                                                                           OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
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
OK: 7/7 Fail: 0/7 Skip: 0/7
## SyncManager test suite
```diff
+ Process all unviable blocks                                                                OK
+ [SyncManager] groupBlobs() test                                                            OK
+ [SyncQueue#Backward] Async unordered push test                                             OK
+ [SyncQueue#Backward] Async unordered push with rewind test                                 OK
+ [SyncQueue#Backward] Good response with missing values towards end                         OK
+ [SyncQueue#Backward] Handle out-of-band sync progress advancement                          OK
+ [SyncQueue#Backward] Pass through established limits test                                  OK
+ [SyncQueue#Backward] Smoke test                                                            OK
+ [SyncQueue#Backward] Start and finish slots equal                                          OK
+ [SyncQueue#Backward] Two full requests success/fail                                        OK
+ [SyncQueue#Backward] getRewindPoint() test                                                 OK
+ [SyncQueue#Forward] Async unordered push test                                              OK
+ [SyncQueue#Forward] Async unordered push with rewind test                                  OK
+ [SyncQueue#Forward] Good response with missing values towards end                          OK
+ [SyncQueue#Forward] Handle out-of-band sync progress advancement                           OK
+ [SyncQueue#Forward] Pass through established limits test                                   OK
+ [SyncQueue#Forward] Smoke test                                                             OK
+ [SyncQueue#Forward] Start and finish slots equal                                           OK
+ [SyncQueue#Forward] Two full requests success/fail                                         OK
+ [SyncQueue#Forward] getRewindPoint() test                                                  OK
+ [SyncQueue] checkResponse() test                                                           OK
+ [SyncQueue] contains() test                                                                OK
+ [SyncQueue] getLastNonEmptySlot() test                                                     OK
+ [SyncQueue] hasEndGap() test                                                               OK
```
OK: 24/24 Fail: 0/24 Skip: 0/24
## Type helpers
```diff
+ BeaconBlock                                                                                OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
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
OK: 14/14 Fail: 0/14 Skip: 0/14
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
OK: 7/7 Fail: 0/7 Skip: 0/7
## Validator pool
```diff
+ Doppelganger for genesis validator                                                         OK
+ Doppelganger for validator that activates in same epoch as check                           OK
+ Dynamic validator set: queryValidatorsSource() test                                        OK
+ Dynamic validator set: updateDynamicValidators() test                                      OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
## ValidatorPubKey bucket sort
```diff
+ incremental construction                                                                   OK
+ one-shot construction                                                                      OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## Zero signature sanity checks
```diff
+ SSZ serialization roundtrip of SignedBeaconBlockHeader                                     OK
+ Zero signatures cannot be loaded into a BLS signature object                               OK
+ default initialization of signatures                                                       OK
```
OK: 3/3 Fail: 0/3 Skip: 0/3
## chain DAG finalization tests [Preset: mainnet]
```diff
+ init with gaps [Preset: mainnet]                                                           OK
+ orphaned epoch block [Preset: mainnet]                                                     OK
+ prune heads on finalization [Preset: mainnet]                                              OK
+ shutdown during finalization [Preset: mainnet]                                             OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
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
OK: 8/8 Fail: 0/8 Skip: 0/8
## engine API authentication
```diff
+ HS256 JWS iat token signing                                                                OK
+ HS256 JWS signing                                                                          OK
+ getIatToken                                                                                OK
```
OK: 3/3 Fail: 0/3 Skip: 0/3
## eth2.0-deposits-cli compatibility
```diff
+ restoring mnemonic with password                                                           OK
+ restoring mnemonic without password                                                        OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## removeValidatorFiles()
```diff
+ Remove nonexistent validator                                                               OK
+ Remove validator files                                                                     OK
+ Remove validator files twice                                                               OK
```
OK: 3/3 Fail: 0/3 Skip: 0/3
## removeValidatorFiles() multiple keystore types
```diff
+ Remove [LOCAL] when [LOCAL] is missing                                                     OK
+ Remove [LOCAL] when [LOCAL] is present                                                     OK
+ Remove [LOCAL] when [REMOTE] is present                                                    OK
+ Remove [REMOTE] when [LOCAL] is present                                                    OK
+ Remove [REMOTE] when [REMOTE] is missing                                                   OK
+ Remove [REMOTE] when [REMOTE] is present                                                   OK
```
OK: 6/6 Fail: 0/6 Skip: 0/6
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
OK: 8/8 Fail: 0/8 Skip: 0/8
## state diff tests [Preset: mainnet]
```diff
+ random slot differences [Preset: mainnet]                                                  OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## subnet tracker
```diff
+ should register stability subnets on attester duties                                       OK
+ should register sync committee duties                                                      OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
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
OK: 9/9 Fail: 0/9 Skip: 0/9

---TOTAL---
OK: 766/771 Fail: 0/771 Skip: 5/771
