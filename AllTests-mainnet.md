AllTests-mainnet
===
## Attestation pool processing [Preset: mainnet]
```diff
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
OK: 11/11 Fail: 0/11 Skip: 0/11
## Beacon chain DB [Preset: mainnet]
```diff
+ empty database [Preset: mainnet]                                                           OK
+ find ancestors [Preset: mainnet]                                                           OK
+ sanity check Altair and cross-fork getState rollback [Preset: mainnet]                     OK
+ sanity check Altair blocks [Preset: mainnet]                                               OK
+ sanity check Altair states [Preset: mainnet]                                               OK
+ sanity check Altair states, reusing buffers [Preset: mainnet]                              OK
+ sanity check genesis roundtrip [Preset: mainnet]                                           OK
+ sanity check phase 0 blocks [Preset: mainnet]                                              OK
+ sanity check phase 0 getState rollback [Preset: mainnet]                                   OK
+ sanity check phase 0 states [Preset: mainnet]                                              OK
+ sanity check phase 0 states, reusing buffers [Preset: mainnet]                             OK
+ sanity check state diff roundtrip [Preset: mainnet]                                        OK
```
OK: 12/12 Fail: 0/12 Skip: 0/12
## Beacon state [Preset: mainnet]
```diff
+ Smoke test initialize_beacon_state_from_eth1 [Preset: mainnet]                             OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Bit fields
```diff
+ isZeros                                                                                    OK
+ iterating words                                                                            OK
+ overlaps                                                                                   OK
+ roundtrips BitArray                                                                        OK
+ roundtrips BitSeq                                                                          OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## Block pool processing [Preset: mainnet]
```diff
+ Adding the same block twice returns a Duplicate error [Preset: mainnet]                    OK
+ Reverse order block add & get [Preset: mainnet]                                            OK
+ Simple block add&get [Preset: mainnet]                                                     OK
+ getRef returns nil for missing blocks                                                      OK
+ loading tail block works [Preset: mainnet]                                                 OK
+ updateHead updates head and headState [Preset: mainnet]                                    OK
+ updateStateData sanity [Preset: mainnet]                                                   OK
```
OK: 7/7 Fail: 0/7 Skip: 0/7
## BlockRef and helpers [Preset: mainnet]
```diff
+ epochAncestor sanity [Preset: mainnet]                                                     OK
+ get_ancestor sanity [Preset: mainnet]                                                      OK
+ isAncestorOf sanity [Preset: mainnet]                                                      OK
```
OK: 3/3 Fail: 0/3 Skip: 0/3
## BlockSlot and helpers [Preset: mainnet]
```diff
+ atSlot sanity [Preset: mainnet]                                                            OK
+ parent sanity [Preset: mainnet]                                                            OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## Eth1 monitor
```diff
+ Rewrite HTTPS Infura URLs                                                                  OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Eth2 specific discovery tests
```diff
+ Invalid attnets field                                                                      OK
+ Subnet query                                                                               OK
+ Subnet query after ENR update                                                              OK
```
OK: 3/3 Fail: 0/3 Skip: 0/3
## Exit pool testing suite
```diff
+ addExitMessage/getAttesterSlashingMessage                                                  OK
+ addExitMessage/getProposerSlashingMessage                                                  OK
+ addExitMessage/getVoluntaryExitMessage                                                     OK
```
OK: 3/3 Fail: 0/3 Skip: 0/3
## Fork Choice + Finality  [Preset: mainnet]
```diff
+ fork_choice - testing finality #01                                                         OK
+ fork_choice - testing finality #02                                                         OK
+ fork_choice - testing no votes                                                             OK
+ fork_choice - testing with votes                                                           OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
## Gossip validation  [Preset: mainnet]
```diff
+ Any committee index is valid                                                               OK
+ Validation sanity                                                                          OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## Honest validator
```diff
+ General pubsub topics                                                                      OK
+ Mainnet attestation topics                                                                 OK
+ is_aggregator                                                                              OK
```
OK: 3/3 Fail: 0/3 Skip: 0/3
## Interop
```diff
+ Interop genesis                                                                            OK
+ Interop signatures                                                                         OK
+ Mocked start private key                                                                   OK
```
OK: 3/3 Fail: 0/3 Skip: 0/3
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
## SSZ dynamic navigator
```diff
+ navigating fields                                                                          OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## SSZ generic roundtrip tests
```diff
+ case objects                                                                               OK
+ lists                                                                                      OK
+ objects                                                                                    OK
+ sets                                                                                       OK
+ simple values                                                                              OK
+ tables                                                                                     OK
+ tuple                                                                                      OK
```
OK: 7/7 Fail: 0/7 Skip: 0/7
## SSZ navigator
```diff
+ basictype                                                                                  OK
+ lists with max size                                                                        OK
+ simple object fields                                                                       OK
```
OK: 3/3 Fail: 0/3 Skip: 0/3
## Slashing Protection DB - Interchange [Preset: mainnet]
```diff
+ Smoke test - Complete format - Invalid database is refused [Preset: mainnet]               OK
+ Smoke test - Complete format [Preset: mainnet]                                             OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## Slashing Protection DB - v1 and v2 migration [Preset: mainnet]
```diff
+ Minimal format migration [Preset: mainnet]                                                 OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
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
+ integer_squareroot                                                                         OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Specific field types
```diff
+ root update                                                                                OK
+ roundtrip                                                                                  OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## Sync committee pool
```diff
+ Aggregating votes                                                                          OK
+ An empty pool is safe to prune                                                             OK
+ An empty pool is safe to prune 2                                                           OK
+ An empty pool is safe to use                                                               OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
## SyncManager test suite
```diff
+ [SyncQueue] Async pending and resetWait() test                                             OK
+ [SyncQueue] Async unordered push start from zero                                           OK
+ [SyncQueue] Async unordered push with not full start from non-zero                         OK
+ [SyncQueue] Full and incomplete success/fail start from non-zero                           OK
+ [SyncQueue] Full and incomplete success/fail start from zero                               OK
+ [SyncQueue] One smart and one stupid + debt split + empty                                  OK
+ [SyncQueue] Smart and stupid success/fail                                                  OK
+ [SyncQueue] Start and finish slots equal                                                   OK
+ [SyncQueue] Two full requests success/fail                                                 OK
+ [SyncQueue] checkResponse() test                                                           OK
+ [SyncQueue] contains() test                                                                OK
+ [SyncQueue] getLastNonEmptySlot() test                                                     OK
+ [SyncQueue] getRewindPoint() test                                                          OK
+ [SyncQueue] hasEndGap() test                                                               OK
```
OK: 14/14 Fail: 0/14 Skip: 0/14
## Zero signature sanity checks
```diff
+ SSZ serialization roundtrip of SignedBeaconBlockHeader                                     OK
+ Zero signatures cannot be loaded into a BLS signature object                               OK
+ default initialization of signatures                                                       OK
```
OK: 3/3 Fail: 0/3 Skip: 0/3
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
+ Invalid deposit at MAX_EFFECTIVE_BALANCE balance (32 ETH)                                  OK
+ Validator top-up                                                                           OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
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
## chain DAG finalization tests [Preset: mainnet]
```diff
+ init with gaps [Preset: mainnet]                                                           OK
+ orphaned epoch block [Preset: mainnet]                                                     OK
+ prune heads on finalization [Preset: mainnet]                                              OK
```
OK: 3/3 Fail: 0/3 Skip: 0/3
## hash
```diff
+ HashArray                                                                                  OK
+ HashList fixed                                                                             OK
+ HashList variable                                                                          OK
```
OK: 3/3 Fail: 0/3 Skip: 0/3
## state diff tests [Preset: mainnet]
```diff
+ random slot differences [Preset: mainnet]                                                  OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## underlong values
```diff
  Overlong SSZ.decode: BitArray[32]                                                          Skip
  Overlong SSZ.decode: BitList[32]                                                           Skip
  Overlong SSZ.decode: HashArray[32, system.uint8]                                           Skip
+ Overlong SSZ.decode: HashList[system.uint64, 32]                                           OK
+ Overlong SSZ.decode: List[system.uint64, 32]                                               OK
  Overlong SSZ.decode: Simple                                                                Skip
  Overlong SSZ.decode: array[0..31, byte]                                                    Skip
  Overlong SSZ.decode: bool                                                                  Skip
  Overlong SSZ.decode: limb_t                                                                Skip
  Overlong SSZ.decode: uint16                                                                Skip
  Overlong SSZ.decode: uint32                                                                Skip
  Overlong SSZ.decode: uint8                                                                 Skip
+ Overlong readSszBytes: BitArray[32]                                                        OK
  Overlong readSszBytes: BitList[32]                                                         Skip
+ Overlong readSszBytes: HashArray[32, system.uint8]                                         OK
+ Overlong readSszBytes: HashList[system.uint64, 32]                                         OK
+ Overlong readSszBytes: List[system.uint64, 32]                                             OK
  Overlong readSszBytes: Simple                                                              Skip
+ Overlong readSszBytes: array[0..31, byte]                                                  OK
+ Overlong readSszBytes: bool                                                                OK
+ Overlong readSszBytes: limb_t                                                              OK
+ Overlong readSszBytes: uint16                                                              OK
+ Overlong readSszBytes: uint32                                                              OK
+ Overlong readSszBytes: uint8                                                               OK
+ Underlong SSZ.decode: BitArray[32]                                                         OK
+ Underlong SSZ.decode: BitList[32]                                                          OK
+ Underlong SSZ.decode: HashArray[32, system.uint8]                                          OK
+ Underlong SSZ.decode: HashList[system.uint64, 32]                                          OK
+ Underlong SSZ.decode: List[system.uint64, 32]                                              OK
+ Underlong SSZ.decode: Simple                                                               OK
+ Underlong SSZ.decode: array[0..31, byte]                                                   OK
+ Underlong SSZ.decode: bool                                                                 OK
+ Underlong SSZ.decode: limb_t                                                               OK
+ Underlong SSZ.decode: uint16                                                               OK
+ Underlong SSZ.decode: uint32                                                               OK
+ Underlong SSZ.decode: uint8                                                                OK
+ Underlong readSszBytes: BitArray[32]                                                       OK
+ Underlong readSszBytes: BitList[32]                                                        OK
+ Underlong readSszBytes: HashArray[32, system.uint8]                                        OK
+ Underlong readSszBytes: HashList[system.uint64, 32]                                        OK
+ Underlong readSszBytes: List[system.uint64, 32]                                            OK
+ Underlong readSszBytes: Simple                                                             OK
+ Underlong readSszBytes: array[0..31, byte]                                                 OK
+ Underlong readSszBytes: bool                                                               OK
+ Underlong readSszBytes: limb_t                                                             OK
+ Underlong readSszBytes: uint16                                                             OK
+ Underlong readSszBytes: uint32                                                             OK
+ Underlong readSszBytes: uint8                                                              OK
```
OK: 36/48 Fail: 0/48 Skip: 12/48

---TOTAL---
OK: 190/202 Fail: 0/202 Skip: 12/202
