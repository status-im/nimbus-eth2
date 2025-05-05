# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import chronos, chronicles
import ssz_serialization/types
import
  ../validators/action_tracker,
  ../spec/[forks, network, helpers, peerdas_helpers],
  ../networking/eth2_network,
  ../consensus_object_pools/blockchain_dag,
  ../consensus_object_pools/block_dag,
  ../consensus_object_pools/data_column_quarantine,
  "."/[request_manager, sync_protocol]

from std/algorithm import binarySearch, sort
from std/sequtils import mapIt
from std/strutils import join
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
    fuluEpoch*: Epoch
    getBeaconTime: GetBeaconTimeFn
    inhibit: InhibitFn
    dataColumnQuarantine: ref DataColumnQuarantine
    validatorCustodyLoopFuture: Future[void].Raising([CancelledError])

proc init*(T: type ValidatorCustody, network: Eth2Node,
              dag: ChainDAGRef,
              supernode: bool,
              getLocalHeadSlotCb: GetSlotCallback,
              older_column_set: HashSet[ColumnIndex],
              fuluEpoch: Epoch,
              getBeaconTime: GetBeaconTimeFn,
              inhibit: InhibitFn,
              dataColumnQuarantine: ref DataColumnQuarantine): ValidatorCustody =
  let localHeadSlot = getLocalHeadSlotCb
  ValidatorCustody(
    network: network,
    dag: dag,
    supernode: supernode,
    getLocalHeadSlot: getLocalHeadSlotCb,
    older_column_set: older_column_set,
    fuluEpoch: fuluEpoch,
    getBeaconTime: getBeaconTime,
    inhibit: inhibit,
    dataColumnQuarantine: dataColumnQuarantine)

proc detectNewValidatorCustody(vcus: var ValidatorCustody): seq[ColumnIndex] =
  let
    headState =  vcus.dag.headState
  var
    res: seq[ColumnIndex]
    diff_set: HashSet[ColumnIndex]
  withState(headState):
    when consensusFork >= ConsensusFork.Fulu:
      var validator_indices =
        get_active_validator_indices(forkyState.data, vcus.network.getBeaconTime().slotOrZero.epoch)
      let vcustody =
        vcus.dag.cfg.get_validators_custody_requirement(forkyState, validator_indices)

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

  for i in diff_set.items():
    res.add(i)

  res


proc makeRefillList(vcus: var ValidatorCustody) =
  let
    slot = vcus.getLocalHeadSlot()
    diff = vcus.detectNewValidatorCustody()
  let dataColumnRefillEpoch = (slot.epoch -
                              vcus.dag.cfg.MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS - 1)
  if slot.is_epoch() and dataColumnRefillEpoch >= vcus.dag.cfg.FULU_FORK_EPOCH:
    var blocks: array[SLOTS_PER_EPOCH.int, BlockId]
    let startIndex = vcus.dag.getBlockRange(
      dataColumnRefillEpoch.start_slot, blocks.toOpenArray(0, SLOTS_PER_EPOCH - 1))
    for i in startIndex..<SLOTS_PER_EPOCH:
      let blck = vcus.dag.getForkedBlock(blocks[int(i)]).valueOr: continue
      withBlck(blck):
        when typeof(forkyBlck).kind < ConsensusFork.Fulu: continue
        else:
          let entry1 =
            DataColumnsByRootIdentifier(block_root: blocks[int(i)].root,
                                        indices: DataColumnIndices.init(diff))
          vcus.requested_columns.add entry1
          for column in vcus.newer_column_set:
            let entry2 =
              DataColumnIdentifier(block_root: blocks[int(i)].root,
                                   index: ColumnIndex(column))
            vcus.global_refill_list.incl(entry2)


proc checkInteresectingCustody(vcus: ValidatorCustody,
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

proc refillDataColumnsFromNetwork(vcus: ValidatorCustody.
                                  colIdList: seq[DataColumnsByRootIdentifier])
                                  {.async: (raise: [CancelledError]).} =
  var peer = await vcus.network.peerPool.acquire()

















