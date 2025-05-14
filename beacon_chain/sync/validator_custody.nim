# beacon_chain
# Copyright (c) 2018-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import chronos, chronicles
import ssz_serialization/[proofs, types]
import
  ../validators/action_tracker,
  ../spec/[beaconstate, forks, network, helpers, peerdas_helpers],
  ../networking/eth2_network,
  ../consensus_object_pools/blockchain_dag,
  ../consensus_object_pools/block_dag,
  ../consensus_object_pools/data_column_quarantine,
  "."/[request_manager, sync_manager, sync_protocol]

from std/algorithm import sort
from std/sequtils import toSeq
from ../beacon_clock import GetBeaconTimeFn

logScope: topics = "validator_custody"

const
    PARALLEL_REFILL_REQUESTS = 32

type
  InhibitFn = proc: bool {.gcsafe, raises: [].}

  ValidatorCustody* = object
    network*: Eth2Node
    dag*: ChainDAGRef
    supernode*: bool
    getLocalHeadSlot*: GetSlotCallback
    older_column_set*: HashSet[ColumnIndex]
    newer_column_set*: HashSet[ColumnIndex]
    global_refill_list*: HashSet[DataColumnIdentifier]
    requested_columns*: seq[DataColumnsByRootIdentifier]
    getBeaconTime: GetBeaconTimeFn
    inhibit: InhibitFn
    dataColumnQuarantine: ref DataColumnQuarantine
    validatorCustodyLoopFuture: Future[void].Raising([CancelledError])

  ValidatorCustodyRef* = ref ValidatorCustody

proc init*(T: type ValidatorCustodyRef, network: Eth2Node,
           dag: ChainDAGRef,
           supernode: bool,
           getLocalHeadSlotCb: GetSlotCallback,
           older_column_set: HashSet[ColumnIndex],
           getBeaconTime: GetBeaconTimeFn,
           inhibit: InhibitFn,
           dataColumnQuarantine: ref DataColumnQuarantine): ValidatorCustodyRef =
  let localHeadSlot = getLocalHeadSlotCb
  (ValidatorCustodyRef)(
    network: network,
    dag: dag,
    supernode: supernode,
    getLocalHeadSlot: getLocalHeadSlotCb,
    older_column_set: older_column_set,
    getBeaconTime: getBeaconTime,
    inhibit: inhibit,
    dataColumnQuarantine: dataColumnQuarantine)

proc detectNewValidatorCustody(vcus: ValidatorCustodyRef, cache: var StateCache): seq[ColumnIndex] =
  var
    diff_set: HashSet[ColumnIndex]
  withState(vcus.dag.headState):
    when consensusFork >= ConsensusFork.Fulu:
      let total_node_balance =
        get_total_active_balance(forkyState.data, cache)
      let vcustody =
        vcus.dag.cfg.get_validators_custody_requirement(forkyState, total_node_balance)

      let
        newer_columns =
          vcus.dag.cfg.resolve_columns_from_custody_groups(
            vcus.network.nodeId,
            max(vcus.dag.cfg.SAMPLES_PER_SLOT.uint64,
            vcustody))
        newer_column_set = newer_columns.toHashSet()

      # update data column quarantine custody requirements
      vcus.dataColumnQuarantine[].custody_columns =
        newer_columns

      # check which custody set is larger
      if newer_column_set.len > vcus.older_column_set.len:
        diff_set = newer_column_set.difference(vcus.older_column_set)
      vcus.newer_column_set = newer_column_set

  toSeq(diff_set)

proc makeRefillList(vcus: ValidatorCustodyRef, diff: seq[ColumnIndex]) =
  let
    slot = vcus.getLocalHeadSlot()

  let dataColumnRefillEpoch = (slot.epoch -
                              vcus.dag.cfg.MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS - 1)
  if slot.is_epoch() and dataColumnRefillEpoch >= vcus.dag.cfg.FULU_FORK_EPOCH:
    var blocks: array[SLOTS_PER_EPOCH.int, BlockId]
    let startIndex = vcus.dag.getBlockRange(
      dataColumnRefillEpoch.start_slot, blocks.toOpenArray(0, SLOTS_PER_EPOCH - 1))
    for i in startIndex..<SLOTS_PER_EPOCH:
      let blck = vcus.dag.getForkedBlock(blocks[int(i)]).valueOr: continue
      withBlck(blck):
        # No need to check for fork version, as this loop is triggered post Fulu
        let entry1 =
          DataColumnsByRootIdentifier(block_root: blocks[int(i)].root,
                                      indices: DataColumnIndices.init(diff))
        vcus.requested_columns.add entry1
        for column in vcus.newer_column_set:
          let entry2 =
            DataColumnIdentifier(block_root: blocks[int(i)].root,
                                  index: ColumnIndex(column))
          vcus.global_refill_list.incl(entry2)

proc checkIntersectingCustody(vcus: ValidatorCustodyRef,
                              peer: Peer): seq[DataColumnsByRootIdentifier] =
  var columnList: seq[DataColumnsByRootIdentifier]

  # Fetch the remote custody count
  let remoteCustodyGroupCount =
    peer.lookupCgcFromPeer()

  # Extract remote peer's nodeID from peerID
  # Fetch custody columns form remote peer
  let
    remoteNodeId = fetchNodeIdFromPeerId(peer)
    remoteCustodyColumns =
      vcus.dag.cfg.resolve_columns_from_custody_groups(
        remoteNodeId,
        max(vcus.dag.cfg.SAMPLES_PER_SLOT.uint64,
            remoteCustodyGroupCount))
  for request_item in vcus.requested_columns:
    var colIds: seq[ColumnIndex]
    for cindex in request_item.indices:
      let lookup = DataColumnIdentifier(block_root: request_item.block_root,
                                        index: cindex)
      if lookup notin vcus.global_refill_list and cindex in remoteCustodyColumns:
        colIds.add cindex
    columnList.add DataColumnsByRootIdentifier(block_root: request_item.block_root,
                                               indices: DataColumnIndices.init(colIds))

  columnList

proc refillDataColumnsFromNetwork(vcus: ValidatorCustodyRef)
                                 {.async: (raises: [CancelledError]).} =
  var peer = await vcus.network.peerPool.acquire()
  let colIdList = vcus.checkIntersectingCustody(peer)
  try:
    if colIdList.len > 0:
      debug "Requesting data columns by root for refill", peer = peer,
             columns = shortLog(colIdList), peer_score = peer.getScore()
    let columns =
      await dataColumnSidecarsByRoot(peer, DataColumnsByRootIdentifierList colIdList)
    if columns.isOk:
      var ucolumns = columns.get().asSeq()
      ucolumns.sort(cmpSidecarIndexes)
      if not checkColumnResponse(colIdList, ucolumns):
        debug "Response to columns by root is not a subset",
          peer = peer, columns = shortLog(colIdList), ucolumns = len(ucolumns)
        peer.updateScore(PeerScoreBadResponse)
        return
      for col in ucolumns:
        let
          block_root =
            hash_tree_root(col[].signed_block_header.message)
          exclude =
            DataColumnIdentifier(block_root: block_root,
                                 index: col[].index)
        vcus.global_refill_list.excl(exclude)
        # write new columns to database, no need of BlockVerifier
        # in this scenario as the columns historically did pass DA,
        # and did meet the historical custody requirements
        vcus.dag.db.putDataColumnSidecar(col[])

    else:
      debug "Data columns by root request not done, peer doesn't have custody column",
        peer = peer, columns = shortLog(colIdList), err = columns.error()
      peer.updateScore(PeerScoreNoValues)

  finally:
    if not(isNil(peer)):
      vcus.network.peerPool.release(peer)

proc validatorCustodyColumnLoop(
    vcus: ValidatorCustodyRef) {.async: (raises: [CancelledError]).} =
  var cache = StateCache()
  while true:
    let diff = vcus.detectNewValidatorCustody(cache)

    await sleepAsync(POLL_INTERVAL)
    if diff.len == 0:
      # Validator custody same as previous interval
      continue

    if vcus.inhibit():
      continue

    vcus.makeRefillList(diff)

    if vcus.global_refill_list.len != 0:
      debug "Requesting detected missing data columns for refill",
            columns = shortLog(vcus.requested_columns)
      let start = SyncMoment.now(0)
      var workers:
        array[PARALLEL_REFILL_REQUESTS, Future[void].Raising([CancelledError])]
      for i in 0..<PARALLEL_REFILL_REQUESTS:
        workers[i] = vcus.refillDataColumnsFromNetwork()

      await allFutures(workers)
      let finish = SyncMoment.now(uint64(len(vcus.global_refill_list)))

      debug "Validator custody backfill tick",
            backfill_speed = speed(start, finish)

    else:
      ## Done with column refilling
      ## hence now advertise the updated cgc count
      ## in ENR and metadata.
      if vcus.older_column_set.len != vcus.newer_column_set.len:
        # Newer cgc count can also drop from previous if validators detach
        vcus.network.loadCgcnetMetadataAndEnr(CgcCount vcus.newer_column_set.lenu64)
        # Make the newer set older
        vcus.older_column_set = vcus.newer_column_set
        # Clear the newer for future validator custody detection
        vcus.newer_column_set.clear()

proc start*(vcus: ValidatorCustodyRef) =
  ## Start Validator Custody detection loop
  vcus.validatorCustodyLoopFuture = vcus.validatorCustodyColumnLoop()

proc stop*(vcus: ValidatorCustodyRef) =
  ## Stop Request Manager's loop.
  if not(isNil(vcus.validatorCustodyLoopFuture)):
    vcus.validatorCustodyLoopFuture.cancelSoon()
