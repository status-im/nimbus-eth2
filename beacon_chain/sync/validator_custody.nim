# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import std/[sets]
import chronicles
import ssz_serialization/[proofs, types]
import
  ../validators/action_tracker,
  ../spec/[beaconstate, forks, network, helpers, peerdas_helpers, column_map],
  ../networking/eth2_network,
  ../conf,
  ../consensus_object_pools/[blockchain_dag, block_dag, blob_quarantine]

from ../beacon_clock import GetBeaconTimeFn

logScope: topics = "validator_custody"

const
  MaxSyncDistanceDeviationSlots = 5'u64
    ## Distance from wall slot after which Validator Custody will think that
    ## node is out of sync.
  StabilityDistanceSlots = 32'u64
    ## Distance which Validator Custody will wait until it switches back to
    ## full custody.

type
  ValidatorCustodyState* {.pure.} = enum
    Init,
      ## Period when node has been started, but validators balance is not yet
      ## known.
    FullCustody,
      ## When node is in sync it uses full validator custody columns set.
    LimitedCustody,
      ## When node is out of sync it uses `CUSTODY_REQUIREMENT` validator
      ## custody columns set
    StabilityPeriod
      ## When node recently become synced it should stay synced for some period
      ## of time before switch from `LimitedCustody` to `FullCustody`.

  ## Init -> FullCustody -> LimitedCustody -> StablePeriod -> FullCustody
  ## Init -> LimitedCustody -> StablePeriod -> FullCustody

  ValidatorCustody* = object
    network: Eth2Node
    dag: ChainDAGRef
    config: BeaconNodeConf
    curGroupsCount: CgcCount
    curColumnMap: ColumnMap
    fuluColumnQuarantine: ref ColumnQuarantine
    gloasColumnQuarantine: ref GloasColumnQuarantine
    state: ValidatorCustodyState
    stabilitySlot: Opt[Slot]

  ValidatorCustodyRef* = ref ValidatorCustody

  ColumnQuarantines* = ref ColumnQuarantine | ref GloasColumnQuarantine

func getGroupsCount(
  state: ValidatorCustodyState,
  config: BeaconNodeConf,
  network: Eth2Node,
  dag: ChainDAGRef,
  nodeBalance: Opt[Gwei]
): CgcCount =
  case state
  of ValidatorCustodyState.Init:
    if config.peerdasSupernode:
      CgcCount(dag.cfg.NUMBER_OF_CUSTODY_GROUPS)
    elif config.lightSupernode:
      CgcCount((dag.cfg.NUMBER_OF_CUSTODY_GROUPS div 2) + 1)
    else:
      CgcCount(dag.cfg.CUSTODY_REQUIREMENT)
  of ValidatorCustodyState.FullCustody:
    if config.peerdasSupernode:
      CgcCount(dag.cfg.NUMBER_OF_CUSTODY_GROUPS)
    elif config.lightSupernode:
      CgcCount((dag.cfg.NUMBER_OF_CUSTODY_GROUPS div 2) + 1)
    else:
      if nodeBalance.isSome():
        CgcCount(
          dag.cfg.get_validators_custody_requirement(nodeBalance.get()))
      else:
        CgcCount(dag.cfg.CUSTODY_REQUIREMENT)
  of ValidatorCustodyState.LimitedCustody:
    CgcCount(dag.cfg.CUSTODY_REQUIREMENT)
  of ValidatorCustodyState.StabilityPeriod:
    CgcCount(dag.cfg.CUSTODY_REQUIREMENT)

func getColumnMap(
    config: BeaconNodeConf,
    network: Eth2Node,
    dag: ChainDagRef,
    groupsCount: CgcCount
): ColumnMap =
  if uint64(groupsCount) == dag.cfg.NUMBER_OF_CUSTODY_GROUPS:
    var res: ColumnMap
    for i in 0 ..< dag.cfg.NUMBER_OF_CUSTODY_GROUPS:
      res.incl(ColumnIndex(i))
    res
  elif uint64(groupsCount) == (dag.cfg.NUMBER_OF_CUSTODY_GROUPS div 2) + 1:
    var res: ColumnMap
    for i in 0 ..< (dag.cfg.NUMBER_OF_CUSTODY_GROUPS div 2) + 1:
      res.incl(ColumnIndex(i))
    res
  else:
    dag.cfg.resolve_column_map_from_custody_groups(
      network.nodeId, CustodyIndex(groupsCount))

func getGroupsCount(
    vcus: ValidatorCustodyRef,
    nodeBalance: Opt[Gwei]
): CgcCount =
  getGroupsCount(vcus.state, vcus.config, vcus.network, vcus.dag, nodeBalance)

func getColumnMap(
    vcus: ValidatorCustodyRef,
    groupsCount: CgcCount
): ColumnMap =
  getColumnMap(vcus.config, vcus.network, vcus.dag, groupsCount)

func syncDistance(
  vcus: ValidatorCustodyRef,
  currentSlot: Slot
): uint64 =
  let headSlot = vcus.dag.head.slot
  if currentSlot <= headSlot:
    0'u64
  else:
    currentSlot - headSlot

func updateState(vcus: ValidatorCustodyRef, currentSlot: Slot) =
  let distance = vcus.syncDistance(currentSlot)
  case vcus.state
  of ValidatorCustodyState.Init:
    if distance <= MaxSyncDistanceDeviationSlots:
      vcus.state = ValidatorCustodyState.FullCustody
    else:
      vcus.state = ValidatorCustodyState.LimitedCustody
  of ValidatorCustodyState.FullCustody:
    if distance > MaxSyncDistanceDeviationSlots:
      vcus.state = ValidatorCustodyState.LimitedCustody
  of ValidatorCustodyState.LimitedCustody:
    if distance > MaxSyncDistanceDeviationSlots:
      vcus.state = ValidatorCustodyState.StabilityPeriod
      vcus.stabilitySlot = Opt.some(currentSlot)
  of ValidatorCustodyState.StabilityPeriod:
    if distance > MaxSyncDistanceDeviationSlots:
      vcus.state = ValidatorCustodyState.LimitedCustody
      vcus.stabilitySlot = Opt.none(Slot)
    else:
      doAssert(vcus.stabilitySlot.isSome(),
        "Stability start slot should be set at this moment")
      doAssert(vcus.stabilitySlot.get() <= currentSlot,
        "Invalid time? Current slot is less than stability start slot")
      if currentSlot - vcus.stabilitySlot.get() >= StabilityDistanceSlots:
        vcus.state = ValidatorCustodyState.FullCustody
        vcus.stabilitySlot = Opt.none(Slot)

proc init*(
    T: type ValidatorCustodyRef,
    config: BeaconNodeConf,
    network: Eth2Node,
    dag: ChainDAGRef
): ValidatorCustodyRef =
  let
    localGroupsCount = getGroupsCount(
      ValidatorCustodyState.Init, config, network, dag, Opt.none(Gwei))
    columnMap = getColumnMap(config, network, dag, localGroupsCount)

  network.loadCgcnetMetadataAndEnr(localGroupsCount.uint8)

  ValidatorCustodyRef(
    network: network,
    config: config,
    dag: dag,
    curColumnMap: columnMap,
    state: ValidatorCustodyState.Init
  )

proc setQuarantine*[T: ColumnQuarantines](
    vcus: ValidatorCustodyRef,
    q: T
) =
  when T is ColumnQuarantine:
    vcus.fuluColumnQuarantine = q
  elif T is GloasColumnQuarantine:
    vcus.gloasColumnQuarantine = q

proc setValidatorCustody*(
  vcus: ValidatorCustodyRef,
  currentSlot: Slot,
  newGroupsCount: CgcCount,
  newMap: ColumnMap
) =
  if len(newMap) != len(vcus.curColumnMap):
    if not(isNil(vcus.fuluColumnQuarantine)):
      vcus.fuluColumnQuarantine[].update(vcus.dag.cfg, newMap)
    if not(isNil(vcus.gloasColumnQuarantine)):
      vcus.gloasColumnQuarantine[].update(vcus.dag.cfg, newMap)
    vcus.network.loadCgcnetMetadataAndEnr(newGroupsCount)
    vcus.curColumnMap = newMap
    vcus.curGroupsCount = newGroupsCount

    # We only update the `ea_slot` when the new validator custody set is larger
    # than the old one.
    if len(newMap) > len(vcus.curColumnMap):
      vcus.dag.eaSlot = currentSlot

    info "New validator custody set", custody_columns = len(newMap)

proc updateValidatorCustody*(
    vcus: ValidatorCustodyRef,
    currentSlot: Slot,
    totalNodeBalance: Gwei
) =
  if totalNodeBalance == Gwei(0):
    return

  logScope:
    total_node_balance = totalNodeBalance
    current_state = vcus.state

  debug "Total node balance before applying validator custody"

  vcus.updateState(currentSlot)

  let
    newGroupsCount = vcus.getGroupsCount(Opt.some(totalNodeBalance))
    newMap = vcus.getColumnMap(newGroupsCount)

  if len(vcus.curColumnMap) != len(newMap):
    info "New validator custody count detected"
    vcus.setValidatorCustody(currentSlot, newGroupsCount, newMap)

func getMap*(vcus: ValidatorCustodyRef): ColumnMap =
  vcus.curColumnMap

func getSet*(vcus: ValidatorCustodyRef): HashSet[ColumnIndex] =
  var res: HashSet[ColumnIndex]
  for index in vcus.curColumnMap:
    res.incl(index)
  res

func getCustodyGroupSubnets*(vcus: ValidatorCustodyRef): uint64 =
  uint64(vcus.curGroupsCount)

func isSupernode*(vcus: ValidatorCustodyRef): bool =
  uint64(vcus.curGroupsCount) == vcus.dag.cfg.NUMBER_OF_CUSTODY_GROUPS

func isLightSupernode*(vcus: ValidatorCustodyRef): bool =
  uint64(vcus.curGroupsCount) ==
    (vcus.dag.cfg.NUMBER_OF_CUSTODY_GROUPS div 2) + 1

func getCustodyGroups*(vcus: ValidatorCustodyRef): seq[CustodyIndex] =
  if vcus.isLightSupernode():
    let custodyGroups = (vcus.dag.cfg.NUMBER_OF_CUSTODY_GROUPS div 2) + 1
    var res = newSeqOfCap[CustodyIndex](custodyGroups)
    for i in 0 ..< custodyGroups:
      res.add CustodyIndex(i)
    res
  else:
    vcus.dag.cfg.get_custody_groups(vcus.network.nodeId, vcus.curGroupsCount)
