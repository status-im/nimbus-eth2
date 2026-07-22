# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/sequtils,
  chronicles,
  ../beacon_chain/beacon_chain_db,
  ../beacon_chain/consensus_object_pools/[attestation_pool, blockchain_dag],
  ../beacon_chain/spec/[forks, state_transition],
  eth/db/[kvstore, kvstore_sqlite3],
  ./[testblockutil, teststateutil]

export beacon_chain_db, testblockutil, kvstore, kvstore_sqlite3

proc makeTestDB*(
    cfg: RuntimeConfig,
    validators: Natural,
    eth1Data = Opt.none(Eth1Data),
    lightClientDataImportBackfill = true): BeaconChainDB =
  # Blob support requires DENEB_FORK_EPOCH != FAR_FUTURE_EPOCH
  # Data column support requires GLOAS_FORK_EPOCH != FAR_FUTURE_EPOCH
  var cfg = cfg
  if cfg.CAPELLA_FORK_EPOCH == FAR_FUTURE_EPOCH:
    cfg.CAPELLA_FORK_EPOCH = 90000.Epoch
  if cfg.DENEB_FORK_EPOCH == FAR_FUTURE_EPOCH:
    cfg.DENEB_FORK_EPOCH = 100000.Epoch
  if cfg.ELECTRA_FORK_EPOCH == FAR_FUTURE_EPOCH:
    cfg.ELECTRA_FORK_EPOCH = 110000.Epoch
  if cfg.FULU_FORK_EPOCH == FAR_FUTURE_EPOCH:
    cfg.FULU_FORK_EPOCH = 120000.Epoch
  if cfg.GLOAS_FORK_EPOCH == FAR_FUTURE_EPOCH:
    cfg.GLOAS_FORK_EPOCH = 130000.Epoch
  debugHezeComment "..."

  let genState = initGenesisState(cfg, validators.uint64)

  # Override Eth1Data on request, skipping the lengthy Eth1 voting process
  if eth1Data.isOk:
    withState(genState[]):
      forkyState.data.eth1_data = eth1Data.get
      forkyState.root = hash_tree_root(forkyState.data)

  result = BeaconChainDB.new(
    "", cfg, inMemory = true,
    lightClientDataImportBackfill = lightClientDataImportBackfill)
  ChainDAGRef.preInit(result, genState[])

proc getEarliestInvalidBlockRoot*(
    dag: ChainDAGRef, initialSearchRoot: Eth2Digest,
    latestValidHash: Eth2Digest, defaultEarliestInvalidBlockRoot: Eth2Digest):
    Eth2Digest =
  # Earliest within a chain/fork in question, per LVH definition. Intended to
  # be called with `initialRoot` as the parent of the block regarding which a
  # newPayload or forkchoiceUpdated execution_status has been received as the
  # tests effectively require being able to access this before the BlockRef's
  # made. Therefore, to accommodate the EF consensus spec sync tests, and the
  # possibilities that the LVH might be an immediate parent or a more distant
  # ancestor special-case handling of an earliest invalid root as potentially
  # not being from this function's search, but being provided as a default by
  # the caller with access to the block.
  var curBlck = dag.getBlockRef(initialSearchRoot).valueOr:
    # Being asked to traverse a chain which the DAG doesn't know about -- but
    # that'd imply the block's otherwise invalid for CL as well as EL.
    return ZERO_HASH

  # Only allow this special case outside loop; it's when the LVH is the direct
  # parent of the reported invalid block
  if  curBlck.executionBlockHash.isSome and
      curBlck.executionBlockHash.get == latestValidHash:
    return defaultEarliestInvalidBlockRoot

  while true:
    # This was supposed to have been either caught by the pre-loop check or the
    # parent check.
    if  curBlck.executionBlockHash.isSome and
        curBlck.executionBlockHash.get == latestValidHash:
      doAssert false, "getEarliestInvalidBlockRoot: unexpected LVH in loop body"

    if (curBlck.parent.isNil) or
       curBlck.parent.executionBlockHash.get(latestValidHash) ==
         latestValidHash:
      break
    curBlck = curBlck.parent

  curBlck.root

func allExpectedBlockIds(
    dag: ChainDAGRef, minSlot = GENESIS_SLOT): HashSet[BlockId] =
  for head in dag.heads:
    var cur = head
    while cur != nil and cur.slot >= minSlot and
        not result.containsOrIncl(cur.bid):
      cur = cur.parent

func forkBlocksMatchHeads*(dag: ChainDAGRef): bool =
  let expected = dag.allExpectedBlockIds
  expected.len == dag.forkBlocks.len and
  expected.allIt(dag.containsForkBlock(it.root))

func forkChoiceMatchesHeads*(pool: AttestationPool): bool =
  let expected = pool.dag.allExpectedBlockIds
  expected.len == pool.forkChoice.backend.proto_array.indices.len and
  expected.allIt(it.root in pool.forkChoice.backend)

func lcDataMatchesHeads*(dag: ChainDAGRef): bool =
  let expected =
    if dag.lcDataStore.importMode != LightClientDataImportMode.None:
      dag.allExpectedBlockIds(minSlot = dag.lcDataStore.cache.tailSlot)
    else:
      HashSet[BlockId]()
  expected.len == dag.lcDataStore.cache.data.len and
  expected.allIt(it in dag.lcDataStore.cache.data)
