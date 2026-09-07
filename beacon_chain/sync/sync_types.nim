# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import results, chronos,
       ../spec/[forks_light_client, signatures_batch, weak_subjectivity],
       ../consensus_object_pools/[block_pools_types, blockchain_dag,
         attestation_pool, blockchain_list, column_quarantine, block_quarantine,
         envelope_quarantine, consensus_manager],
       ../gossip_processing/block_processor,
       ../validators/validator_monitor,
       ../[beacon_clock, conf],
       ../networking/eth2_network,
       ./[validator_custody, sync_dag, sync_queue, block_buffer]

export results, chronos, block_pools_types, conf, sync_dag

const
  WeakSubjectivityLogMessage* =
    "Database state missing or too old, cannot sync - resync the client " &
    "using a trusted node or allow lenient long-range syncing with the " &
    "`--long-range-sync=lenient` option. See " &
    "https://nimbus.guide/faq.html#what-is-long-range-sync " &
    "for more information"

type
  SyncMoment* = object
    stamp*: chronos.Moment
    slots*: uint64

  BlockDataChunk* = ref object
    resfut*: Future[Result[void, string]].Raising([CancelledError])
    onStateUpdatedCb*: OnStateUpdated
    blocks*: seq[BlockData]

  SyncKind* {.pure.} = enum
    ForwardSync, TrustedNodeSync,
    UntrustedSyncInit,
    UntrustedSyncDownload,
    UntrustedSyncRebuild

  SyncOverseer2* = object
    network*: Eth2Node
    consensusManager*: ref ConsensusManager
    config*: BeaconNodeConf
    getBeaconTimeFn*: GetBeaconTimeFn
    beaconClock*: BeaconClock
    loopFuture*: Future[void].Raising([])
    pool*: PeerPool[Peer, PeerId]
    blockProcessor*: ref BlockProcessor
    validatorCustody*: ref ValidatorCustody
    fblockBuffer*: BlocksRangeBuffer
    bblockBuffer*: BlocksRangeBuffer
    rblockBuffer*: BlocksRootBuffer
    blockQuarantine*: ref Quarantine
    fuluColumnQuarantine*: ref FuluColumnQuarantine
    gloasColumnQuarantine*: ref GloasColumnQuarantine
    gloasEnvelopeQuarantine*: ref EnvelopeQuarantine
    blockGossipBus*: AsyncEventQueue[EventBeaconBlockGossipPeerObject]
    blocksQueueBus*: AsyncEventQueue[EventBeaconBlockObject]
    blockFinalizationBus*: AsyncEventQueue[FinalizationInfoObject]
    missingRoots*: HashSet[Eth2Digest]
    missingSidecars*: HashSet[Eth2Digest]
    missingEnvelopes*: HashSet[Eth2Digest]
    blocksChunkSize*: int
    sidecarsChunkSize*: int
    fqueue*: SyncQueue[Peer, BlockCompleteness]
    fsqueue*: SyncQueue[Peer, ColumnCompleteness]
    bqueue*: SyncQueue[Peer, BlockCompleteness]
    bsqueue*: SyncQueue[Peer, ColumnCompleteness]
    localPeerId*: PeerId
    lastSeenCheckpoint*: Opt[Checkpoint]
    lastSeenHead*: Opt[BlockId]
    statusMessages*: array[2, string]
    sdag*: SyncDag[Peer, PeerId]
    eraBid*: Opt[BlockId]

  SyncOverseerRef2* = ref SyncOverseer2

proc new*(
    t: typedesc[SyncOverseerRef2],
    net: Eth2Node,
    cm: ref ConsensusManager,
    configuration: BeaconNodeConf,
    bt: GetBeaconTimeFn,
    clock: BeaconClock,
    blockProcessor: ref BlockProcessor,
    validatorCustody: ref ValidatorCustody,
    blockQuarantine: ref Quarantine,
    fuluColumnQuarantine: ref FuluColumnQuarantine,
    gloasColumnQuarantine: ref GloasColumnQuarantine,
    gloasEnvelopeQuarantine: ref EnvelopeQuarantine,
    gossipQueue: AsyncEventQueue[EventBeaconBlockGossipPeerObject],
    blocksQueue: AsyncEventQueue[EventBeaconBlockObject],
    finalizationQueue: AsyncEventQueue[FinalizationInfoObject],
    blocksChunkSize = int(SLOTS_PER_EPOCH),
    sidecarsChunkSize = int(SLOTS_PER_EPOCH)
): SyncOverseerRef2 =
  SyncOverseerRef2(
    network: net,
    consensusManager: cm,
    config: configuration,
    getBeaconTimeFn: bt,
    beaconClock: clock,
    pool: net.peerPool,
    blockProcessor: blockProcessor,
    validatorCustody: validatorCustody,
    fuluColumnQuarantine: fuluColumnQuarantine,
    gloasColumnQuarantine: gloasColumnQuarantine,
    gloasEnvelopeQuarantine: gloasEnvelopeQuarantine,
    blockQuarantine: blockQuarantine,
    blockGossipBus: gossipQueue,
    blocksQueueBus: blocksQueue,
    blockFinalizationBus: finalizationQueue,
    blocksChunkSize: blocksChunkSize,
    sidecarsChunkSize: sidecarsChunkSize,
    localPeerId: net.peerId(),
    sdag: SyncDag.init(Peer, PeerId, cm.dag.cfg),
  )

proc now*(sm: typedesc[SyncMoment], slots: uint64): SyncMoment {.inline.} =
  SyncMoment(stamp: now(chronos.Moment), slots: slots)

proc speed*(start, finish: SyncMoment): float {.inline.} =
  ## Returns number of slots per second.
  if finish.slots <= start.slots or finish.stamp <= start.stamp:
    0.0 # replays for example
  else:
    let
      slots = float(finish.slots - start.slots)
      dur = toFloatSeconds(finish.stamp - start.stamp)
    slots / dur

proc toTimeLeftString*(d: Duration): string =
  if d == InfiniteDuration:
    "<calculation pending>"
  else:
    var v = d
    var res = ""
    let ndays = chronos.days(v)
    if ndays > 0:
      res = res & (if ndays < 10: "0" & $ndays else: $ndays) & "d"
      v = v - chronos.days(ndays)

    let nhours = chronos.hours(v)
    if nhours > 0:
      res = res & (if nhours < 10: "0" & $nhours else: $nhours) & "h"
      v = v - chronos.hours(nhours)
    else:
      res =  res & "00h"

    let nmins = chronos.minutes(v)
    if nmins > 0:
      res = res & (if nmins < 10: "0" & $nmins else: $nmins) & "m"
      v = v - chronos.minutes(nmins)
    else:
      res = res & "00m"
    res

func isSlotWithinWeakSubjectivityPeriod*(dag: ChainDAGRef, slot: Slot): bool =
  let
    checkpoint = Checkpoint(
      epoch: dag.headState.slot.epoch(),
      root: dag.headState.latest_block_header.state_root)
  is_within_weak_subjectivity_period(dag.cfg, slot,
                                     dag.headState, checkpoint)
