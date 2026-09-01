AllTests-mainnet
===
## Ancestry
```diff
+ ancestorSlot                                                                               OK
```
## Attestation pool electra processing [Preset: mainnet]
```diff
+ Aggregated attestations with disjoint committee bits into a single on-chain aggregate [Pre OK
+ Aggregating across committees [Preset: mainnet]                                            OK
+ Attestation from different branch [Preset: mainnet]                                        OK
+ Attestations may arrive in any order [Preset: mainnet]                                     OK
+ Attestations may overlap, bigger first [Preset: mainnet]                                   OK
+ Attestations may overlap, smaller first [Preset: mainnet]                                  OK
+ Attestations should be combined [Preset: mainnet]                                          OK
+ Attestations with disjoint committee bits and equal data into single on-chain aggregate [P OK
+ Attester slashing marks validator as equivocating                                          OK
+ Attester slashing retains unrealized checkpoints                                           OK
+ Cache coherence on chain aggregates [Preset: mainnet]                                      OK
+ Can add and retrieve simple electra attestations [Preset: mainnet]                         OK
+ Everyone voting for something different [Preset: mainnet]                                  OK
+ Fork choice returns block with attestation                                                 OK
+ Fork choice returns latest block with no attestations                                      OK
+ Invalid block weight does not propagate to ancestors                                       OK
+ Simple add and get with electra nonzero committee [Preset: mainnet]                        OK
+ Trying to add a block twice tags the second as an error                                    OK
+ Trying to add a duplicate block from an old pruned epoch is tagged as an error             OK
+ Working with electra aggregates [Preset: mainnet]                                          OK
```
## Attestation pool gloas processing [Preset: mainnet]
```diff
+ EL-invalid payload only invalidates the FULL variant                                       OK
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
+ batch delete data columns [Preset: mainnet]                                                OK
+ batch put data columns [Preset: mainnet]                                                   OK
+ empty database [Preset: mainnet]                                                           OK
+ find ancestors [Preset: mainnet]                                                           OK
+ head blocks roundtrip [Preset: mainnet]                                                    OK
+ sanity check altair and cross-fork getState rollback [Preset: mainnet]                     OK
+ sanity check altair blocks [Preset: mainnet]                                               OK
+ sanity check altair states [Preset: mainnet]                                               OK
+ sanity check altair states, reusing buffers [Preset: mainnet]                              OK
+ sanity check bellatrix and cross-fork getState rollback [Preset: mainnet]                  OK
+ sanity check bellatrix blocks [Preset: mainnet]                                            OK
+ sanity check bellatrix states [Preset: mainnet]                                            OK
+ sanity check bellatrix states, reusing buffers [Preset: mainnet]                           OK
+ sanity check blobs [Preset: mainnet]                                                       OK
+ sanity check capella and cross-fork getState rollback [Preset: mainnet]                    OK
+ sanity check capella blocks [Preset: mainnet]                                              OK
+ sanity check capella states [Preset: mainnet]                                              OK
+ sanity check capella states, reusing buffers [Preset: mainnet]                             OK
+ sanity check deneb and cross-fork getState rollback [Preset: mainnet]                      OK
+ sanity check deneb blocks [Preset: mainnet]                                                OK
+ sanity check deneb states [Preset: mainnet]                                                OK
+ sanity check deneb states, reusing buffers [Preset: mainnet]                               OK
+ sanity check electra and cross-fork getState rollback [Preset: mainnet]                    OK
+ sanity check electra blocks [Preset: mainnet]                                              OK
+ sanity check electra states [Preset: mainnet]                                              OK
+ sanity check electra states, reusing buffers [Preset: mainnet]                             OK
+ sanity check execution payload envelopes [Preset: mainnet]                                 OK
+ sanity check fulu and cross-fork getState rollback [Preset: mainnet]                       OK
+ sanity check fulu blocks [Preset: mainnet]                                                 OK
+ sanity check fulu data columns [Preset: mainnet]                                           OK
+ sanity check fulu states [Preset: mainnet]                                                 OK
+ sanity check fulu states, reusing buffers [Preset: mainnet]                                OK
+ sanity check genesis roundtrip [Preset: mainnet]                                           OK
  sanity check gloas and cross-fork getState rollback [Preset: mainnet]                      Skip
  sanity check gloas blocks [Preset: mainnet]                                                Skip
+ sanity check gloas data columns [Preset: mainnet]                                          OK
  sanity check gloas states [Preset: mainnet]                                                Skip
  sanity check gloas states, reusing buffers [Preset: mainnet]                               Skip
  sanity check heze and cross-fork getState rollback [Preset: mainnet]                       Skip
  sanity check heze blocks [Preset: mainnet]                                                 Skip
  sanity check heze states [Preset: mainnet]                                                 Skip
  sanity check heze states, reusing buffers [Preset: mainnet]                                Skip
+ sanity check phase0 blocks [Preset: mainnet]                                               OK
+ sanity check phase0 getState rollback [Preset: mainnet]                                    OK
+ sanity check phase0 states [Preset: mainnet]                                               OK
+ sanity check phase0 states, reusing buffers [Preset: mainnet]                              OK
+ sanity check state diff roundtrip [Preset: mainnet]                                        OK
```
## Beacon chain file test suite
```diff
+ Auto check/repair test (missing data)                                                      OK
+ Auto check/repair test (missing footer)                                                    OK
+ Auto check/repair test (missing last chunk)                                                OK
+ Auto check/repair test (only header)                                                       OK
+ Auto check/repair test (zero-filled file)                                                  OK
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
+ basics (SLOT_DURATION_MS=12000)                                                            OK
+ basics (SLOT_DURATION_MS=5000)                                                             OK
+ basics (SLOT_DURATION_MS=6000)                                                             OK
```
## Beacon validators test suite
```diff
+ builderBetterBid(builderBoostFactor) test                                                  OK
+ builderBetterBid(localBlockValueBoost) with Gwei-to-Wei conversion                         OK
```
## Blinded block conversions
```diff
+ bellatrix toSignedBlindedBeaconBlock                                                       OK
+ capella toSignedBlindedBeaconBlock                                                         OK
+ deneb toSignedBlindedBeaconBlock                                                           OK
+ electra toSignedBlindedBeaconBlock                                                         OK
+ fulu toSignedBlindedBeaconBlock                                                            OK
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
+ isAncestorOf                                                                               OK
+ updateHead updates head and headState [Preset: mainnet]                                    OK
+ updateState sanity [Preset: mainnet]                                                       OK
```
## Block processor [Preset: mainnet]
```diff
+ Gloas block pops pre-arrived envelope from quarantine [Preset: mainnet]                    OK
+ Gloas block without envelope marks missing [Preset: mainnet]                               OK
+ Gloas chain with no envelopes delivered [Preset: mainnet]                                  OK
+ Gloas consecutive blocks accumulate missing envelopes [Preset: mainnet]                    OK
+ Gloas reverse order blocks with missing parent [Preset: mainnet]                           OK
+ Invalidate block root [Preset: mainnet]                                                    OK
+ Invalidate existing block root [Preset: mainnet]                                           OK
+ Multiple heads [Preset: mainnet]                                                           OK
+ Process Deneb block without blob sidecars [Preset: mainnet]                                OK
+ Process Fulu block with data column sidecars [Preset: mainnet]                             OK
+ Process Fulu block without data column sidecars [Preset: mainnet]                          OK
+ Process a block from each fork (without blobs) [Preset: mainnet]                           OK
+ Reverse order block add & get [Preset: mainnet]                                            OK
```
## Block quarantine
```diff
+ Don't re-download unviable blocks                                                          OK
+ Keep downloading parent chain even if we hit missing limit                                 OK
+ No new missing/orphans while processing                                                    OK
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
+ executionParent sanity                                                                     OK
+ get_ancestor sanity                                                                        OK
+ isAncestorOf sanity                                                                        OK
```
## BlockSlot and helpers
```diff
+ atSlot sanity                                                                              OK
+ parent sanity                                                                              OK
```
## BlocksRangeBuffer test suite
```diff
+ Add and query blocks test [backward]                                                       OK
+ Add and query blocks test [forward]                                                        OK
+ Block insertion test [backward]                                                            OK
+ Block insertion test [forward]                                                             OK
+ Buffer advance test [backward]                                                             OK
+ Buffer advance test [forward]                                                              OK
+ Buffer invalidate test [backward]                                                          OK
+ Buffer invalidate test [forward]                                                           OK
+ Range peek real test cases [forward]                                                       OK
+ Range peek test [backward]                                                                 OK
+ Range peek test [forward]                                                                  OK
```
## Column reconstruction backfiller cursors
```diff
+ a TooFew slot blocks the trail until its columns arrive                                    OK
+ a head extension reconstructs only the new slot, not the whole run                         OK
+ a reorg refills only the post-finalized window                                             OK
+ a reorg retracts the advertised slot, then re-extends it                                   OK
+ a reorg whose run is entirely post-finalized resets it                                     OK
+ an advancing retention floor lifts runBottom                                               OK
+ fresh backfill descends from head to the retention floor                                   OK
```
## ColumnMap test suite
```diff
+ and() operation test                                                                       OK
+ contains() test                                                                            OK
+ fill test                                                                                  OK
+ incl()/excl() test                                                                         OK
+ supernode test                                                                             OK
```
## ColumnQuarantine data structure test suite  [Preset: mainnet]
```diff
+ ColumnQuarantine: update(empty:grow) [node->node] test                                     OK
+ ColumnQuarantine: update(empty:grow) [node->supernode] test                                OK
+ ColumnQuarantine: update(empty:shrink) [node->node] test                                   OK
+ ColumnQuarantine: update(empty:shrink) [supernode->node] test                              OK
+ ColumnQuarantine: update(memory+disk:grow) [node->node] test                               OK
+ ColumnQuarantine: update(memory+disk:grow) [node->supernode] test                          OK
+ ColumnQuarantine: update(memory+disk:shrink) [node->node] test                             OK
+ ColumnQuarantine: update(memory+disk:shrink) [supernode->node] test                        OK
+ ColumnQuarantine: update(memory:grow) [node->node] test                                    OK
+ ColumnQuarantine: update(memory:grow) [node->supernode] test                               OK
+ ColumnQuarantine: update(memory:shrink) [node->node] test                                  OK
+ ColumnQuarantine: update(memory:shrink) [supernode->node] test                             OK
+ Empty in-memory scenario test [node]                                                       OK
+ Empty in-memory scenario test [supernode]                                                  OK
+ Mixed entries scenario test [node]                                                         OK
+ Mixed entries scenario test [supernode]                                                    OK
+ database and memory overfill protection and pruning test [node]                            OK
+ database unload/load test [node]                                                           OK
+ overfill protection test [node]                                                            OK
+ overfill test [node]                                                                       OK
+ overfill test [supernode]                                                                  OK
+ popSidecars tolerates partial custody at DA threshold [node]                               OK
+ pruneAfterFinalization() test [node]                                                       OK
+ put() duplicate items should not affect counters [node]                                    OK
+ put()/fetchMissingSidecars/remove test [node]                                              OK
+ put()/fetchMissingSidecars/remove test [supernode]                                         OK
+ put()/hasSidecar(index, slot, proposer_index)/remove() test                                OK
+ put(sidecar)/put([sidecars])/hasSidecars/popSidecars/remove() [node] test                  OK
+ put(sidecar)/put([sidecars])/hasSidecars/popSidecars/remove() [supernode] test             OK
+ verified flag survives database unload/load [node]                                         OK
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
## EF - BPO forkdigests
```diff
+ Different fork versions                                                                    OK
+ Different genesis validators roots                                                         OK
+ Different lengths and blob limits                                                          OK
+ ENR fork ID transitions from Fulu to Gloas                                                 OK
+ Fulu fork digest resolved via bpos list                                                    OK
+ Fusaka devnet-2                                                                            OK
+ Glamsterdam bal-devnet-2                                                                   OK
+ Non-scheduled post-Electra fork has no bpos entries                                        OK
+ nextForkEpochAtEpoch includes Gloas from Fulu                                              OK
+ nextForkEpochAtEpoch with BPO before Gloas                                                 OK
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
## EIP-7594 Unit Tests
```diff
+ EIP-7594: Batch Verify DataColumnSidecar KZG Proofs (fulu)                                 OK
+ EIP-7594: Batch Verify DataColumnSidecar KZG Proofs (gloas)                                OK
+ EIP-7594: Verify DataColumnSidecar KZG Proofs (fulu, single)                               OK
+ EIP-7594: Verify DataColumnSidecar KZG Proofs (gloas, single)                              OK
+ KZG: Recover Cells And Kzg Proofs Parallel - invalid                                       OK
+ KZG: Recover Cells And Kzg Proofs Parallel - valid                                         OK
```
## EL Configuration
```diff
+ Empty config file                                                                          OK
+ New style config files                                                                     OK
+ Old style config files                                                                     OK
+ URL parsing                                                                                OK
```
## EL Manager - Async Operations
```diff
+ ELManager can be started and stopped safely                                                OK
+ ELManager with custom chain network                                                        OK
```
## EL Manager - Helpers
```diff
+ Rewrite URLs                                                                               OK
```
## EL Manager - Multiple Engines
```diff
+ forkchoiceUpdated with multiple engines                                                    OK
+ getPayload with multiple engines                                                           OK
+ newPayload with multiple engines                                                           OK
+ two engines, one broken, retry                                                             OK
```
## EL Manager - Payload Request Caching
```diff
+ concurrent forkchoiceUpdated calls                                                         OK
+ forkchoiceUpdated without payload attributes doesn't cache                                 OK
+ getPayload makes new forkchoiceUpdated when parameters change                              OK
+ getPayload reuses cached forkchoiceUpdated when parameters match                           OK
+ getPayload with different forkchoiceUpdated attributes                                     OK
+ multiple sequential forkchoiceUpdated calls with payload attributes                        OK
```
## EL Manager - WebSocket reconnection
```diff
+ reconnects after EL restart (degraded connection)                                          OK
+ reconnects after EL restart (working connection)                                           OK
```
## EL Manager - forkchoiceUpdated
```diff
+ forkchoiceUpdated basic call                                                               OK
+ forkchoiceUpdated multiple sequential calls                                                OK
+ forkchoiceUpdated times out without selected response                                      OK
+ forkchoiceUpdated with payload attributes                                                  OK
+ forkchoiceUpdated with response delay                                                      OK
+ forkchoiceUpdatedV4 basic call                                                             OK
```
## EL Manager - getPayload
```diff
+ success without retry                                                                      OK
+ success without retry using getPayloadV6                                                   OK
```
## EL Manager - newPayload
```diff
+ newPayload times out without selected response                                             OK
+ success without retry                                                                      OK
+ success without retry using newPayloadV5                                                   OK
```
## Engine API conversions
```diff
+ Roundtrip engine RPC V1 and bellatrix ExecutionPayload representations                     OK
+ Roundtrip engine RPC V2 and capella ExecutionPayload representations                       OK
+ Roundtrip engine RPC V3 and deneb ExecutionPayload representations                         OK
+ Roundtrip engine RPC V4 and deneb ExecutionPayload representations                         OK
```
## Envelope Quarantine
```diff
+ Add missing                                                                                OK
+ Add orphan                                                                                 OK
+ Add unviable                                                                               OK
+ Clean up orphans                                                                           OK
+ Has orphan                                                                                 OK
+ Pop orphan                                                                                 OK
```
## Eth2 specific discovery tests
```diff
+ Attestation subnet query                                                                   OK
+ Columns subcustody query                                                                   OK
+ Combination subnet query                                                                   OK
+ Invalid attnets field                                                                      OK
+ Subnet query after ENR update                                                              OK
+ Sync subnet query                                                                          OK
```
## Execution Payload Bid Pool
```diff
+ Add and retrieve highest bid                                                               OK
+ Duplicate detection - same builder same slot                                               OK
+ Empty pool returns none                                                                    OK
+ Highest bid selection - different builders                                                 OK
+ Multiple bids for different beacon parent roots same slot                                  OK
+ Multiple bids for different execution parent hashes same slot                              OK
+ Pruning removes old bids                                                                   OK
+ Track seen bids                                                                            OK
```
## Fast confirmation [Preset: mainnet]
```diff
+ Assign shufflings [Preset: mainnet]                                                        OK
+ Assigned slots cross-check [Preset: mainnet]                                               OK
+ Epoch 1 shares dependent root for both epochs [Preset: mainnet]                            OK
+ Genesis epoch [Preset: mainnet]                                                            OK
+ Older epochRef with current shufflings [Preset: mainnet]                                   OK
+ Shuffling dependent roots [Preset: mainnet]                                                OK
+ Shuffling epoch transition [Preset: mainnet]                                               OK
+ Shuffling preserves effective balance [Preset: mainnet]                                    OK
+ Shuffling update idempotency [Preset: mainnet]                                             OK
+ Update shufflings for current and previous epoch [Preset: mainnet]                         OK
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
## Gloas Partial Columns
```diff
+ Assemble partial data column sidecars                                                      OK
+ Assemble partial data column sidecars with missing rows                                    OK
+ Assemble rejects mismatched blob and proof counts                                          OK
+ Partial KZG inputs skip cells already verified                                             OK
+ PartialDataColumnGroupID encoding                                                          OK
+ Verify PartialDataColumnSidecar KZG proofs                                                 OK
+ Verify PartialDataColumnSidecar self-consistency                                           OK
```
## Gloas block validity
```diff
+ Execution valid                                                                            OK
+ Execution valid after checkpoint sync                                                      OK
```
## GloasColumnQuarantine data structure test suite  [Preset: mainnet]
```diff
+ Empty in-memory scenario test [node]                                                       OK
+ Empty in-memory scenario test [supernode]                                                  OK
+ GloasColumnQuarantine: update(empty:grow) [node->node] test                                OK
+ GloasColumnQuarantine: update(empty:grow) [node->supernode] test                           OK
+ GloasColumnQuarantine: update(empty:shrink) [node->node] test                              OK
+ GloasColumnQuarantine: update(empty:shrink) [supernode->node] test                         OK
+ GloasColumnQuarantine: update(memory+disk:grow) [node->node] test                          OK
+ GloasColumnQuarantine: update(memory+disk:grow) [node->supernode] test                     OK
+ GloasColumnQuarantine: update(memory+disk:shrink) [node->node] test                        OK
+ GloasColumnQuarantine: update(memory+disk:shrink) [supernode->node] test                   OK
+ GloasColumnQuarantine: update(memory:grow) [node->node] test                               OK
+ GloasColumnQuarantine: update(memory:grow) [node->supernode] test                          OK
+ GloasColumnQuarantine: update(memory:shrink) [node->node] test                             OK
+ GloasColumnQuarantine: update(memory:shrink) [supernode->node] test                        OK
+ Mixed entries scenario test [node]                                                         OK
+ Mixed entries scenario test [supernode]                                                    OK
+ database and memory overfill protection and pruning test [node]                            OK
+ database unload/load test [node]                                                           OK
+ overfill protection test [node]                                                            OK
+ overfill test [node]                                                                       OK
+ overfill test [supernode]                                                                  OK
+ popSidecars tolerates partial custody at DA threshold [node]                               OK
+ pruneAfterFinalization() test [node]                                                       OK
+ put() duplicate items should not affect counters [node]                                    OK
+ put()/fetchMissingSidecars/remove test [node]                                              OK
+ put()/fetchMissingSidecars/remove test [supernode]                                         OK
+ put()/hasSidecar(index, slot, proposer_index)/remove() test                                OK
+ put(sidecar)/put([sidecars])/hasSidecars/popSidecars/remove() [node] test                  OK
+ put(sidecar)/put([sidecars])/hasSidecars/popSidecars/remove() [supernode] test             OK
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
## Gossip validation - Gloas
```diff
+ validateBeaconBlock - finalized head execution parent                                      OK
+ validateBeaconBlock - mismatched execution parent                                          OK
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
+ Payload failsafe conditions                                                                OK
+ Stability subnets                                                                          OK
+ isNearSyncCommitteePeriod                                                                  OK
+ is_aggregator                                                                              OK
+ nextForkEpochAtEpoch with BPOs                                                             OK
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
## Inclusion list [Preset: mainnet]
```diff
+ end-to-end: committee members sign, validate, and are collected                            OK
+ get_inclusion_list_committee                                                               OK
+ get_inclusion_list_transactions dedups and filters                                         OK
+ is_valid_inclusion_list_signature                                                          OK
+ process_inclusion_list detects equivocation                                                OK
```
## Inclusion list pool [Preset: mainnet]
```diff
+ A list for a future slot is rejected [Preset: mainnet]                                     OK
+ A list one slot behind the wall slot is still accepted [Preset: mainnet]                   OK
+ A list past the lookback window is rejected [Preset: mainnet]                              OK
+ Accepts two distinct lists then drops the third [Preset: mainnet]                          OK
+ Byte-identical resubmission is a no-op [Preset: mainnet]                                   OK
+ Stale slots are pruned [Preset: mainnet]                                                   OK
+ Stores transactions for the slot [Preset: mainnet]                                         OK
+ Untimely lists are excluded unless requested [Preset: mainnet]                             OK
```
## Key splitting
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
+ Different Authorization Header spelling [Beacon Node] [Preset: mainnet]                    OK
+ Empty Authorization Token [Beacon Node] [Preset: mainnet]                                  OK
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
+ /eth/v1/builder/header [json] test                                                         OK
+ /eth/v1/builder/header [ssz] test                                                          OK
+ /eth/v1/builder/status test                                                                OK
+ /eth/v1/builder/validators [json] test                                                     OK
+ /eth/v1/builder/validators [ssz] test                                                      OK
+ /eth/v2/builder/blinded_blocks [json/json] test                                            OK
+ /eth/v2/builder/blinded_blocks [json/ssz] test                                             OK
+ /eth/v2/builder/blinded_blocks [ssz/json] test                                             OK
+ /eth/v2/builder/blinded_blocks [ssz/ssz] test                                              OK
```
## Message signatures
```diff
+ Aggregate and proof signatures                                                             OK
+ Attestation signatures                                                                     OK
+ BLS to execution change signatures                                                         OK
+ Builder request auth v1                                                                    OK
+ Builder signatures (ValidatorRegistrationV1)                                               OK
+ Deposit signatures                                                                         OK
+ Slot signatures                                                                            OK
+ Sync committee message signatures                                                          OK
+ Sync committee selection proof signatures                                                  OK
+ Sync committee signed contribution and proof signatures                                    OK
+ Voluntary exit signatures                                                                  OK
+ execution payload bid signatures                                                           OK
+ execution payload envelope signatures                                                      OK
+ inclusion list signatures                                                                  OK
+ payload attestation message signatures                                                     OK
+ proposer preferences message signatures                                                    OK
```
## Missing Table
```diff
+ Add and delete missing                                                                     OK
+ Check missing with exponential backoff                                                     OK
```
## Network metadata
```diff
+ mainnet                                                                                    OK
+ sepolia                                                                                    OK
```
## Nimbus remote signer/signing test (verifying-web3signer)
```diff
+ Signing BeaconBlock (getBlockSignature(electra))                                           OK
+ Signing BeaconBlock (getBlockSignature(fulu))                                              OK
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
+ Signing aggregation slot (getSlotSignature())                                              OK
+ Signing attestation (getAttestationSignature())                                            OK
+ Signing payload attestation (getPayloadAttestationSignature())                             OK
+ Signing randao reveal (getEpochSignature())                                                OK
+ Signing validator registration (getBuilderSignature())                                     OK
+ Signing voluntary exit (getValidatorExitSignature())                                       OK
+ Waiting for signing node (/upcheck) test                                                   OK
```
## Old database versions [Preset: mainnet]
```diff
+ pre-1.1.0                                                                                  OK
```
## Partial Column Quarantine
```diff
+ Assemble multiple columns for the same block independently                                 OK
+ Cell tracking is per-column                                                                OK
+ Different column indices are independent                                                   OK
+ Different group ids with same column index are independent                                 OK
+ Get entry for unknown key returns none                                                     OK
+ Get group id for unknown key returns none                                                  OK
+ Group ID LRU evicts oldest entry when full                                                 OK
+ Group IDs with same root but different slots are distinct keys                             OK
+ Group id arriving after the cells still completes the entry                                OK
+ GroupID hash and equality                                                                  OK
+ Init creates empty quarantine                                                              OK
+ Mark all cells received                                                                    OK
+ Mark and check cell received                                                               OK
+ Mark cell received for non-existent entry is no-op                                         OK
+ Mark cell received with out-of-bounds blob index is no-op                                  OK
+ Multiple group ids coexist                                                                 OK
+ PartialColumnKey equality                                                                  OK
+ PartialColumnKey hash differs for different keys                                           OK
+ Put and get entry                                                                          OK
+ Put and get group id                                                                       OK
+ Remove entry                                                                               OK
+ Remove entry does not affect other entries                                                 OK
+ Remove group id                                                                            OK
+ Remove non-existent entry is no-op                                                         OK
+ Remove non-existent group id is no-op                                                      OK
+ Removing entry does not remove group id                                                    OK
+ Removing group id does not remove entries                                                  OK
+ addCells accumulates across multiple sidecars                                              OK
+ addCells ingests cells from a PartialDataColumnSidecar                                     OK
+ addCells is independent across columns                                                     OK
+ addCells on non-existent entry is no-op                                                    OK
+ addCells with overlapping bitmap overwrites existing cells                                 OK
+ assembleDataColumnSidecar produces correct DataColumnSidecar                               OK
+ assembleDataColumnSidecar returns none for non-existent entry                              OK
+ assembleDataColumnSidecar returns none when cells incomplete                               OK
+ assembleDataColumnSidecar returns none when group id missing from cache                    OK
+ assembleDataColumnSidecar returns none when group id not validated                         OK
+ assembleDataColumnSidecar with cells added incrementally                                   OK
+ assembleDataColumnSidecar with markCellReceived (data overload)                            OK
+ cellsConsistent is false when an overlapping cell differs                                  OK
+ cellsConsistent is false when an overlapping proof differs                                 OK
+ cellsConsistent is true when cells do not overlap                                          OK
+ cellsConsistent is true when no entry exists                                               OK
+ cellsConsistent is true when overlapping cells match                                       OK
+ getOrCreateEntry creates new entry                                                         OK
+ getOrCreateEntry new entry has properly sized cells and proofs                             OK
+ getOrCreateEntry returns existing entry                                                    OK
+ hasCellReceived for non-existent entry returns false                                       OK
+ hasCellReceived for out-of-bounds index returns false                                      OK
+ isComplete becomes true after incremental addCells                                         OK
+ isComplete returns false for non-existent entry                                            OK
+ isComplete returns false when cells are missing                                            OK
+ isComplete returns false when group id not validated                                       OK
+ isComplete returns true when group id validated and all cells received                     OK
+ isComplete with single blob                                                                OK
+ markCellReceived with data on non-existent entry is no-op                                  OK
+ markCellReceived with data out-of-bounds is no-op                                          OK
+ markCellReceived with data stores cell and proof                                           OK
+ pruneForBlock drops the group id and its entries                                           OK
+ pruneForBlock leaves other group ids alone                                                 OK
```
## Payload attestation pool [Preset: mainnet]
```diff
+ Can add and retrieve payload attestations [Preset: mainnet]                                OK
+ Can get payload attestations for block production [Preset: mainnet]                        OK
+ Different 'blob data available' and 'payload presence' values [Preset: mainnet]            OK
+ Duplicate validator in PTC - multiple signatures [Preset: mainnet]                         OK
+ Get all payload attestations in the pool [Preset: mainnet]                                 OK
+ Multiple validators in PTC can attest [Preset: mainnet]                                    OK
+ Payload attestations get pruned [Preset: mainnet]                                          OK
+ get_ptc with ShufflingRef matches StateCache version [Preset: mainnet]                     OK
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
## Proposer preferences validation  [Preset: mainnet]
```diff
+ validateProposerPreferences - duplicate ignored                                            OK
+ validateProposerPreferences - happy case                                                   OK
+ validateProposerPreferences - invalid signature rejected                                   OK
+ validateProposerPreferences - proposal_slot already passed                                 OK
+ validateProposerPreferences - proposal_slot outside current/next epoch                     OK
+ validateProposerPreferences - wrong proposer rejected                                      OK
```
## Pruning
```diff
+ prune states                                                                               OK
```
## Quarantine [Preset: mainnet]
```diff
+ put/iterate/remove test [fulu DataColumnSidecar]                                           OK
+ put/iterate/remove test [gloas DataColumnSidecar]                                          OK
```
## REST encoding and decoding
```diff
+ Blob                                                                                       OK
+ DenebSignedBlockContents decoding                                                          OK
+ KzgCommitment                                                                              OK
+ KzgProof                                                                                   OK
+ RestErrorMessage parser tests                                                              OK
+ RestErrorMessage writer tests                                                              OK
+ Validator pubkey hack                                                                      OK
+ remote signing example AGGREGATE_AND_PROOF (DEPRECATED)                                    OK
+ remote signing example AGGREGATE_AND_PROOF_V2 (ELECTRA)                                    OK
+ remote signing example AGGREGATION_SLOT                                                    OK
+ remote signing example ATTESTATION                                                         OK
+ remote signing example BLOCK_V2 (FULU)                                                     OK
+ remote signing example DEPOSIT                                                             OK
+ remote signing example RANDAO_REVEAL                                                       OK
+ remote signing example SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF                               OK
+ remote signing example SYNC_COMMITTEE_MESSAGE                                              OK
+ remote signing example SYNC_COMMITTEE_SELECTION_PROOF                                      OK
+ remote signing example VALIDATOR_REGISTRATION                                              OK
+ remote signing example VOLUNTARY_EXIT                                                      OK
+ strictParse(Stuint) tests                                                                  OK
```
## Remote keystore testing suite
```diff
+ Many remotes                                                                               OK
+ Single remote                                                                              OK
+ Verifying Signer / Many remotes                                                            OK
+ Verifying Signer / Single remote                                                           OK
+ version 1                                                                                  OK
```
## Response utilities test suite
```diff
+ checkResponse(SyncRange, ForkedSignedBeaconBlock) failures test                            OK
+ checkResponse(SyncRange, ForkedSignedBeaconBlock) test                                     OK
+ checkResponse(SyncRange, SignedExecutionPayloadEnvelope) test                              OK
+ checkResponse(roots, ForkedSignedBeaconBlock) test                                         OK
+ checkResponse(roots, SignedExecutionPayloadEnvelope) test                                  OK
+ combineResponse() test                                                                     OK
+ groupSidecars(DataColumnsByRootIdentifier, fulu.DataColumnSidecar) [node] test             OK
+ groupSidecars(DataColumnsByRootIdentifier, fulu.DataColumnSidecar) [supernode] test        OK
+ groupSidecars(DataColumnsByRootIdentifier, gloas.DataColumnSidecar) [node] test            OK
+ groupSidecars(DataColumnsByRootIdentifier, gloas.DataColumnSidecar) [supernode] test       OK
+ groupSidecars(SyncRange, ColumnMap, fulu.DataColumnSidecar) [node] test                    OK
+ groupSidecars(SyncRange, ColumnMap, fulu.DataColumnSidecar) [supernode] test               OK
+ groupSidecars(SyncRange, ColumnMap, gloas.DataColumnSidecar) [node] test                   OK
+ groupSidecars(SyncRange, ColumnMap, gloas.DataColumnSidecar) [supernode] test              OK
+ validateBlocks(SyncRange, SyncResponseItem, FuluColumnSidecarResponseRecord) [node] test   OK
+ validateBlocks(SyncRange, SyncResponseItem, FuluColumnSidecarResponseRecord) [supernode] t OK
+ validateBlocks(SyncRange, SyncResponseItem, GloasColumnSidecarResponseRecord) [node] test  OK
+ validateBlocks(SyncRange, SyncResponseItem, GloasColumnSidecarResponseRecord) [supernode]  OK
```
## Serialization/deserialization [Beacon Node] [Preset: mainnet]
```diff
+ Deserialization test vectors                                                               OK
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
+ integer_squareroot                                                                         OK
```
## Specific field types
```diff
+ root update                                                                                OK
+ roundtrip                                                                                  OK
```
## Starting states
```diff
+ Checkpoint with missed epoch start slot                                                    OK
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
## SyncDag test suite
```diff
+ Multiple chains and ancestors iterator test                                                OK
+ Pruning test                                                                               OK
+ Single chain and iterator test                                                             OK
+ getMissingEnvelopeRoots()/cleanMissingEnvelopeRoots() test                                 OK
+ getMissingSidecarsRoots()/cleanMissingSidecarsRoots() test                                 OK
+ mgetOrPut(bid)/getRootEntry(root) test                                                     OK
+ mgetOrPut(checkpoint)/getRootEntry(root) test                                              OK
+ mgetOrPut(peer)/getPeerEntry() test                                                        OK
```
## SyncManager test suite
```diff
+ [SyncQueue# & Backward] Combination of missing parent and good blocks [3 peers] test       OK
+ [SyncQueue# & Backward] Empty responses should not advance queue until other peers will no OK
+ [SyncQueue# & Backward] Empty responses should not be accounted [3 peers] test             OK
+ [SyncQueue# & Backward] Failure request push test                                          OK
+ [SyncQueue# & Backward] Invalid block [3 peers] test                                       OK
+ [SyncQueue# & Backward] Smoke [3 peers] test                                               OK
+ [SyncQueue# & Backward] Smoke [single peer] test                                           OK
+ [SyncQueue# & Backward] Unviable block [3 peers] test                                      OK
+ [SyncQueue# & Backward] epochFilter() test                                                 OK
+ [SyncQueue# & Forward] Combination of missing parent and good blocks [3 peers] test        OK
+ [SyncQueue# & Forward] Empty responses should not advance queue until other peers will not OK
+ [SyncQueue# & Forward] Empty responses should not be accounted [3 peers] test              OK
+ [SyncQueue# & Forward] Failure request push test                                           OK
+ [SyncQueue# & Forward] Invalid block [3 peers] test                                        OK
+ [SyncQueue# & Forward] Smoke [3 peers] test                                                OK
+ [SyncQueue# & Forward] Smoke [single peer] test                                            OK
+ [SyncQueue# & Forward] Unviable block [3 peers] test                                       OK
+ [SyncQueue# & Forward] epochFilter() test                                                  OK
+ [SyncQueue#Backward] Missing parent and exponential rewind [3 peers] test                  OK
+ [SyncQueue#Backward] getRewindPoint() test                                                 OK
+ [SyncQueue#Forward] Missing parent and exponential rewind [3 peers] test                   OK
+ [SyncQueue#Forward] getRewindPoint() test                                                  OK
+ [SyncQueue] checkBlobsResponse() test                                                      OK
+ [SyncQueue] checkResponse() test                                                           OK
+ [SyncQueue] hasEndGap() test                                                               OK
```
## SyncRange test suite
```diff
+ contains() test                                                                            OK
+ init() test                                                                                OK
+ iterator test                                                                              OK
+ split() test                                                                               OK
```
## Type helpers
```diff
+ BeaconBlock                                                                                OK
```
## Validator Client test suite
```diff
+ /eth/v1/validator/beacon_committee_selections serialization/deserialization test           OK
+ /eth/v1/validator/sync_committee_selections serialization/deserialization test             OK
+ bestSuccess() API hard timeout test                                                        OK
+ bestSuccess() API soft timeout test                                                        OK
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
+ addValidatorChangeMessage/getBlsToExecutionChange                                          OK
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
+ discard unloadable and duplicate heads on init [Preset: mainnet]                           OK
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
## get_ancestor_info
```diff
+ All slots filled - end of epoch                                                            OK
+ All slots filled - mid epoch                                                               OK
+ All slots filled - start of epoch                                                          OK
+ Current_slot = 0                                                                           OK
+ Current_slot = 1                                                                           OK
+ Entire prev epoch empty                                                                    OK
+ Gap crossing epoch boundary                                                                OK
+ Gap in current epoch                                                                       OK
+ Mid epoch 0                                                                                OK
+ Only genesis                                                                               OK
+ Only one block after genesis                                                               OK
+ Sparse chain with terminal mid-gap                                                         OK
+ Start of epoch 1                                                                           OK
+ Start of epoch 2                                                                           OK
+ Terminal in current epoch                                                                  OK
+ Terminal in prev epoch                                                                     OK
+ Terminal not an ancestor                                                                   OK
```
## get_ancestor_support_by_slot
```diff
+ Balance source, all validator states                                                       OK
+ Basic support                                                                              OK
+ Early epochs                                                                               OK
+ Early epochs with 3 shufflings                                                             OK
+ Empty result                                                                               OK
+ Equivocating, assigned slot at current_slot                                                OK
+ Equivocating, cross-epoch, different blocks                                                OK
+ Equivocating, cross-epoch, same block                                                      OK
+ Equivocating, duties on different blocks                                                   OK
+ Equivocating, last block before previous epoch                                             OK
+ Equivocating, single slot in range                                                         OK
+ Gap in chain                                                                               OK
+ Gap in chain, vote from earlier epoch                                                      OK
+ Gap in chain, vote from later epoch                                                        OK
+ Gap in chain, vote in both epochs                                                          OK
+ Mixed validators                                                                           OK
+ No match                                                                                   OK
+ Non-canonical, deep fork                                                                   OK
+ Non-canonical, fork before range                                                           OK
+ Non-canonical, mixed with canonical                                                        OK
+ Non-canonical, single vote                                                                 OK
+ Non-canonical, three forks                                                                 OK
+ Running totals verification                                                                OK
+ Slashed validator                                                                          OK
+ Stale view, no assigned slot at stale block                                                OK
+ Stale view, vote from later epoch                                                          OK
+ Vote at terminal slot, duty in gap                                                         OK
+ Votes outside range                                                                        OK
+ assign_shufflings dst longer than src                                                      OK
+ assign_shufflings replaces duties                                                          OK
```
## get_current_target_info
```diff
+ Basic support                                                                              OK
+ Empty votes                                                                                OK
+ Equivocating excluded                                                                      OK
+ Gap at epoch start                                                                         OK
+ Inactive excluded                                                                          OK
+ Mixed                                                                                      OK
+ Multiple heads                                                                             OK
+ Multiple voters                                                                            OK
+ Slashed excluded                                                                           OK
+ Vote for target at epoch start                                                             OK
+ Vote for unknown block                                                                     OK
+ Vote in previous epoch                                                                     OK
```
## lookupCgcFromPeer testing suite
```diff
+ Metadata cgc below CUSTODY_REQUIREMENT, valid ENR cgc                                      OK
+ Metadata cgc below CUSTODY_REQUIREMENT, valid ENR cgc updates metadata                     OK
+ Metadata cgc exceeds NUMBER_OF_CUSTODY_GROUPS - returns OutOfRange                         OK
+ No metadata, ENR cgc exceeds NUMBER_OF_CUSTODY_GROUPS - returns OutOfRange                 OK
+ No metadata, ENR without cgc field - returns default                                       OK
+ No metadata, no ENR - returns default CUSTODY_REQUIREMENT                                  OK
+ No metadata, valid ENR cgc                                                                 OK
+ Valid metadata with cgc == CUSTODY_REQUIREMENT (boundary)                                  OK
+ Valid metadata with cgc == NUMBER_OF_CUSTODY_GROUPS (supernode)                            OK
+ Valid metadata with cgc >= CUSTODY_REQUIREMENT                                             OK
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
+ should register and prune PTC duties                                                       OK
+ should register stability subnets on attester duties                                       OK
+ should register sync committee duties                                                      OK
+ should subscribe to all subnets when flag is enabled                                       OK
+ should track PTC duties in slot bitmaps                                                    OK
```
## toPeerAddr port handling
```diff
+ Skips zero tcp/quic ports                                                                  OK
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
