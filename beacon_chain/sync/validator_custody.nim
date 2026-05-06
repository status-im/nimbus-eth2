# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import chronicles
import ssz_serialization/[proofs, types]
import
  ../validators/action_tracker,
  ../spec/[beaconstate, forks, network, helpers, peerdas_helpers, column_map],
  ../networking/eth2_network,
  ../conf,
  ../consensus_object_pools/[blockchain_dag, block_dag, column_quarantine]

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

  ## Init -> FullCustody -> LimitedCustody -> StabilityPeriod -> FullCustody
  ## Init -> LimitedCustody -> StabilityPeriod -> FullCustody

  ValidatorCustody* = object
    network: Eth2Node
    dag: ChainDAGRef
    config: BeaconNodeConf
    curGroupsCount: CgcCount
    curColumnMap: ColumnMap
    totalNodeBalance: Gwei
    fuluColumnQuarantine: ref ColumnQuarantine
    gloasColumnQuarantine: ref GloasColumnQuarantine
    state: ValidatorCustodyState
    stabilitySlot: Opt[Slot]
    stabilityMoment: Opt[chronos.Moment]

  ValidatorCustodyRef* = ref ValidatorCustody

func shortLog*(state: ValidatorCustodyState): string =
  case state
  of ValidatorCustodyState.Init: "init"
  of ValidatorCustodyState.FullCustody: "full"
  of ValidatorCustodyState.LimitedCustody: "limited"
  of ValidatorCustodyState.StabilityPeriod: "stability"

func supernodeGroupsCount*(cfg: RuntimeConfig): CgcCount =
  CgcCount(cfg.NUMBER_OF_CUSTODY_GROUPS)

func lightSupernodeGroupsCount*(cfg: RuntimeConfig): CgcCount =
  let columnsPerGroup =
    NUMBER_OF_COLUMNS div cfg.NUMBER_OF_CUSTODY_GROUPS
  CgcCount((NUMBER_OF_COLUMNS div 2) div columnsPerGroup)

func supernodeGroupsCount*(vcus: ValidatorCustodyRef): CgcCount =
  supernodeGroupsCount(vcus.dag.cfg)

func lightSupernodeGroupsCount*(vcus: ValidatorCustodyRef): CgcCount =
  lightSupernodeGroupsCount(vcus.dag.cfg)

func supernodeColumnsCount*(): int =
  NUMBER_OF_COLUMNS

func lightSupernodeColumnsCount*(): int =
  NUMBER_OF_COLUMNS div 2

func getGroupsCount(
  state: ValidatorCustodyState,
  config: BeaconNodeConf,
  dag: ChainDAGRef,
  nodeBalance: Gwei
): CgcCount =
  case state
  of ValidatorCustodyState.Init, ValidatorCustodyState.FullCustody:
    if config.peerdasSupernode:
      supernodeGroupsCount(dag.cfg)
    elif config.lightSupernode:
      lightSupernodeGroupsCount(dag.cfg)
    else:
      if nodeBalance == Gwei(0):
        # While there no active validators attached.
        CgcCount(dag.cfg.CUSTODY_REQUIREMENT)
      else:
        CgcCount(dag.cfg.get_validators_custody_requirement(nodeBalance))
  of ValidatorCustodyState.LimitedCustody:
    CgcCount(dag.cfg.CUSTODY_REQUIREMENT)
  of ValidatorCustodyState.StabilityPeriod:
    CgcCount(dag.cfg.CUSTODY_REQUIREMENT)

func getColumnMap(
    config: BeaconNodeConf,
    network: Eth2Node,
    dag: ChainDAGRef,
    groupsCount: CgcCount
): ColumnMap =
  if config.peerdasSupernode:
    # Supernode
    var res: ColumnMap
    for i in 0 ..< supernodeColumnsCount():
      res.incl(ColumnIndex(i))
    res
  elif config.lightSupernode:
    # Light supernode
    var res: ColumnMap
    for i in 0 ..< lightSupernodeColumnsCount():
      res.incl(ColumnIndex(i))
    res
  else:
    dag.cfg.resolve_column_map_from_custody_groups(
      network.nodeId, CustodyIndex(groupsCount))

func getGroupsCount(
    vcus: ValidatorCustodyRef,
    nodeBalance: Gwei
): CgcCount =
  getGroupsCount(vcus.state, vcus.config, vcus.dag, nodeBalance)

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

proc updateStability(vcus: ValidatorCustodyRef, slot: Opt[Slot]) =
  vcus.stabilitySlot = slot
  if slot.isNone():
    vcus.stabilityMoment = Opt.none(chronos.Moment)
  else:
    vcus.stabilityMoment = Opt.some(Moment.now())

proc updateState(vcus: ValidatorCustodyRef, currentSlot: Slot) =
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
    if distance <= MaxSyncDistanceDeviationSlots:
      vcus.state = ValidatorCustodyState.StabilityPeriod
      vcus.updateStability(Opt.some(currentSlot))
  of ValidatorCustodyState.StabilityPeriod:
    if distance > MaxSyncDistanceDeviationSlots:
      vcus.state = ValidatorCustodyState.LimitedCustody
      vcus.updateStability(Opt.none(Slot))
    else:
      doAssert(vcus.stabilitySlot.isSome(),
        "Stability start slot should be set at this moment")
      if vcus.stabilitySlot.get() > currentSlot:
        # Invalid time, or time shift, so we just update stability slot.
        vcus.updateStability(Opt.some(currentSlot))
      if currentSlot - vcus.stabilitySlot.get() >= StabilityDistanceSlots:
        vcus.state = ValidatorCustodyState.FullCustody
        vcus.updateStability(Opt.none(Slot))

proc init*(
    T: type ValidatorCustodyRef,
    config: BeaconNodeConf,
    network: Eth2Node,
    dag: ChainDAGRef,
    totalNodeBalance: Gwei
): ValidatorCustodyRef =
  let
    localGroupsCount = getGroupsCount(
      ValidatorCustodyState.Init, config, dag, totalNodeBalance)
    columnMap = getColumnMap(config, network, dag, localGroupsCount)

  network.loadCgcnetMetadataAndEnr(localGroupsCount.uint8, columnMap)

  ValidatorCustodyRef(
    network: network,
    config: config,
    dag: dag,
    curGroupsCount: localGroupsCount,
    curColumnMap: columnMap,
    state: ValidatorCustodyState.Init
  )

func setQuarantine*(vcus: ValidatorCustodyRef, q: ref ColumnQuarantine) =
  vcus.fuluColumnQuarantine = q

func setQuarantine*(vcus: ValidatorCustodyRef, q: ref GloasColumnQuarantine) =
  vcus.gloasColumnQuarantine = q

proc setValidatorCustody*(
  vcus: ValidatorCustodyRef,
  currentSlot: Slot,
  newGroupsCount: CgcCount,
  newMap: ColumnMap,
  nodeBalance: Gwei
) =
  if len(newMap) != len(vcus.curColumnMap):
    let oldMapLen = len(vcus.curColumnMap)
    if not(isNil(vcus.fuluColumnQuarantine)):
      vcus.fuluColumnQuarantine[].update(vcus.dag.cfg, newMap)
    if not(isNil(vcus.gloasColumnQuarantine)):
      vcus.gloasColumnQuarantine[].update(vcus.dag.cfg, newMap)
    vcus.network.loadCgcnetMetadataAndEnr(newGroupsCount, newMap)
    vcus.curColumnMap = newMap
    vcus.curGroupsCount = newGroupsCount

    # We only update the `ea_slot` when the new validator custody set is larger
    # than the old one.
    if len(newMap) > oldMapLen:
      vcus.dag.eaSlot = currentSlot

    info "New validator custody set",
      custody_columns = len(newMap),
      current_slot = currentSlot,
      ea_slot = vcus.dag.eaSlot

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
    current_slot = currentSlot

  debug "Total node balance before applying validator custody"

  vcus.totalNodeBalance = totalNodeBalance

  vcus.updateState(currentSlot)

  let
    newGroupsCount = vcus.getGroupsCount(totalNodeBalance)
    newMap = vcus.getColumnMap(newGroupsCount)

  if len(vcus.curColumnMap) != len(newMap):
    info "New validator custody count detected"
    vcus.setValidatorCustody(
      currentSlot, newGroupsCount, newMap, totalNodeBalance)

func getMap*(vcus: ValidatorCustodyRef): ColumnMap =
  vcus.curColumnMap

func getGroupsCount*(vcus: ValidatorCustodyRef): CgcCount =
  vcus.curGroupsCount

iterator getSet*(vcus: ValidatorCustodyRef): ColumnIndex =
  for index in vcus.curColumnMap:
    yield index

func isSupernode*(vcus: ValidatorCustodyRef): bool =
  ## This function returns current value, based on current state, so if we are
  ## not in `LimitedCustody` state it will returns ``true``.
  vcus.config.peerdasSupernode and
    vcus.curGroupsCount == vcus.supernodeGroupsCount()

func isLightSupernode*(vcus: ValidatorCustodyRef): bool =
  ## This function returns current value, based on current state, so if we are
  ## not in `LimitedCustody` state it will returns ``true``.
  vcus.config.lightSupernode and
    vcus.curGroupsCount == vcus.lightSupernodeGroupsCount()

iterator custodyGroups*(vcus: ValidatorCustodyRef): CustodyIndex =
  ## Returns current dynamic state of custody groups.
  if vcus.isLightSupernode():
    let groups = vcus.lightSupernodeGroupsCount()
    for i in CgcCount(0) ..< groups:
      yield CustodyIndex(i)
  else:
    for i in vcus.dag.cfg.get_custody_groups(
      vcus.network.nodeId, vcus.curGroupsCount):
      yield CustodyIndex(i)

func getCurrentState*(vcus: ValidatorCustodyRef): ValidatorCustodyState =
  vcus.state

func getStabilityDistance*(
    vcus: ValidatorCustodyRef,
    currentSlot: Slot
): Opt[uint64] =
  if vcus.state != ValidatorCustodyState.StabilityPeriod:
    return Opt.none(uint64)
  if vcus.stabilitySlot.isNone():
    return Opt.none(uint64)
  if currentSlot < vcus.stabilitySlot.get():
    return Opt.some(0'u64)
  Opt.some(currentSlot - vcus.stabilitySlot.get())

proc getStabilityDuration*(
    vcus: ValidatorCustodyRef,
): Opt[chronos.Duration] =
  if vcus.stabilityMoment.isNone():
    return Opt.none(chronos.Duration)
  Opt.some(Moment.now() - vcus.stabilityMoment.get())

proc debugCustodyJsonDump*(vcus: ValidatorCustodyRef, slot: Slot): string =
  let
    distance =
      block:
        let res = vcus.getStabilityDistance(slot)
        if res.isNone():
          "not available"
        else:
          $res.get()
    duration =
      block:
        let res = vcus.getStabilityDuration()
        if res.isNone():
          "not available"
        else:
          $res.get()

  "{" &
  "\"state\":\"" & shortLog(vcus.getCurrentState()) & "\"," &
  "\"custody_groups_count\":" & $vcus.curGroupsCount & "," &
  "\"custody_columns\":" & $vcus.getMap() & "," &
  "\"total_node_balance\":\"" & $vcus.totalNodeBalance & "\"," &
  "\"supernode_config\":" & $vcus.config.peerdasSupernode & "," &
  "\"light_supernode_config\":" & $vcus.config.lightSupernode & "," &
  "\"is_supernode_check\":" & $vcus.isSupernode() & "," &
  "\"is_lightsupernode_check\":" & $vcus.isLightSupernode() & "," &
  "\"stability_distance\":\"" & distance & "\"," &
  "\"stability_duration\":\"" & duration & "\"" &
  "}"
