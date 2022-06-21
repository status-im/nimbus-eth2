# beacon_chain
# Copyright (c) 2021-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import std/[tables, os, sets, sequtils]
import chronos, presto, presto/client as presto_client, chronicles, confutils,
       json_serialization/std/[options, net],
       stew/[base10, results, byteutils]

# Local modules
import
  ../spec/datatypes/[phase0, altair],
  ../spec/[eth2_merkleization, helpers, signatures,
    validator],
  ../spec/eth2_apis/[eth2_rest_serialization, rest_beacon_client],
  ../validators/[keystore_management, validator_pool, slashing_protection],
  ".."/[conf, beacon_clock, version, nimbus_binary_common],
   ../spec/eth2_apis/eth2_rest_serialization

export os, sets, sequtils, sequtils, chronos, presto, chronicles, confutils,
       nimbus_binary_common, version, conf, options, tables, results, base10,
       byteutils, presto_client

export eth2_rest_serialization, rest_beacon_client,
       phase0, altair, helpers, signatures, validator, eth2_merkleization,
       beacon_clock,
       keystore_management, slashing_protection, validator_pool

const
  SYNC_TOLERANCE* = 4'u64
  SLOT_LOOKAHEAD* = 1.seconds
  HISTORICAL_DUTIES_EPOCHS* = 2'u64
  TIME_DELAY_FROM_SLOT* = 79.milliseconds
  SUBSCRIPTION_BUFFER_SLOTS* = 2'u64

type
  ServiceState* {.pure.} = enum
    Initialized, Running, Error, Closing, Closed

  BlockServiceEventRef* = ref object of RootObj
    slot*: Slot
    proposers*: seq[ValidatorPubKey]

  ClientServiceRef* = ref object of RootObj
    state*: ServiceState
    lifeFut*: Future[void]
    client*: ValidatorClientRef

  DutiesServiceRef* = ref object of ClientServiceRef

  FallbackServiceRef* = ref object of ClientServiceRef
    onlineEvent*: AsyncEvent

  ForkServiceRef* = ref object of ClientServiceRef

  AttestationServiceRef* = ref object of ClientServiceRef

  BlockServiceRef* = ref object of ClientServiceRef

  SyncCommitteeServiceRef* = ref object of ClientServiceRef

  DutyAndProof* = object
    epoch*: Epoch
    dependentRoot*: Eth2Digest
    data*: RestAttesterDuty
    slotSig*: Option[ValidatorSig]

  SyncCommitteeDuty* = object
    pubkey*: ValidatorPubKey
    validator_index*: ValidatorIndex
    validator_sync_committee_index*: IndexInSyncCommittee

  SyncDutyAndProof* = object
    epoch*: Epoch
    data*: SyncCommitteeDuty
    slotSig*: Option[ValidatorSig]

  SyncCommitteeSubscriptionInfo* = object
    validator_index*: ValidatorIndex
    validator_sync_committee_indices*: seq[IndexInSyncCommittee]

  ProposerTask* = object
    duty*: RestProposerDuty
    future*: Future[void]

  ProposedData* = object
    epoch*: Epoch
    dependentRoot*: Eth2Digest
    duties*: seq[ProposerTask]

  BeaconNodeServer* = object
    client*: RestClientRef
    endpoint*: string
    config*: Option[RestSpecVC]
    ident*: Option[string]
    genesis*: Option[RestGenesis]
    syncInfo*: Option[RestSyncInfo]
    status*: RestBeaconNodeStatus

  EpochDuties* = object
    duties*: Table[Epoch, DutyAndProof]

  EpochSyncDuties* = object
    duties*: Table[Epoch, SyncDutyAndProof]

  RestBeaconNodeStatus* {.pure.} = enum
    Uninitalized, Offline, Incompatible, NotSynced, Online

  BeaconNodeServerRef* = ref BeaconNodeServer

  AttesterMap* = Table[ValidatorPubKey, EpochDuties]
  SyncCommitteeDutiesMap* = Table[ValidatorPubKey, EpochSyncDuties]
  ProposerMap* = Table[Epoch, ProposedData]

  ValidatorClient* = object
    config*: ValidatorClientConf
    graffitiBytes*: GraffitiBytes
    beaconNodes*: seq[BeaconNodeServerRef]
    nodesAvailable*: AsyncEvent
    fallbackService*: FallbackServiceRef
    forkService*: ForkServiceRef
    dutiesService*: DutiesServiceRef
    attestationService*: AttestationServiceRef
    blockService*: BlockServiceRef
    syncCommitteeService*: SyncCommitteeServiceRef
    runSlotLoop*: Future[void]
    beaconClock*: BeaconClock
    attachedValidators*: ValidatorPool
    forks*: seq[Fork]
    forksAvailable*: AsyncEvent
    attesters*: AttesterMap
    proposers*: ProposerMap
    syncCommitteeDuties*: SyncCommitteeDutiesMap
    beaconGenesis*: RestGenesis
    proposerTasks*: Table[Slot, seq[ProposerTask]]

  ValidatorClientRef* = ref ValidatorClient

  ValidatorClientError* = object of CatchableError
  ValidatorApiError* = object of ValidatorClientError

const
  DefaultDutyAndProof* = DutyAndProof(epoch: Epoch(0xFFFF_FFFF_FFFF_FFFF'u64))
  DefaultSyncDutyAndProof* =
    SyncDutyAndProof(epoch: Epoch(0xFFFF_FFFF_FFFF_FFFF'u64))
  SlotDuration* = int64(SECONDS_PER_SLOT).seconds
  OneThirdDuration* = int64(SECONDS_PER_SLOT).seconds div INTERVALS_PER_SLOT

proc `$`*(bn: BeaconNodeServerRef): string =
  if bn.ident.isSome():
    bn.client.address.hostname & ":" &
      Base10.toString(bn.client.address.port) & " [" & bn.ident.get() & "]"
  else:
    bn.client.address.hostname & ":" &
      Base10.toString(bn.client.address.port)

chronicles.formatIt BeaconNodeServerRef:
  $it

chronicles.expandIt(RestAttesterDuty):
  pubkey = shortLog(it.pubkey)
  slot = it.slot
  validator_index = it.validator_index
  committee_index = it.committee_index
  committee_length = it.committee_length
  committees_at_slot = it.committees_at_slot
  validator_committee_index = it.validator_committee_index

proc stop*(csr: ClientServiceRef) {.async.} =
  if csr.state == ServiceState.Running:
    csr.state = ServiceState.Closing
    if not(csr.lifeFut.finished()):
      await csr.lifeFut.cancelAndWait()
    csr.state = ServiceState.Closed

proc isDefault*(dap: DutyAndProof): bool =
  dap.epoch == Epoch(0xFFFF_FFFF_FFFF_FFFF'u64)

proc isDefault*(sdap: SyncDutyAndProof): bool =
  sdap.epoch == Epoch(0xFFFF_FFFF_FFFF_FFFF'u64)

proc isDefault*(prd: ProposedData): bool =
  prd.epoch == Epoch(0xFFFF_FFFF_FFFF_FFFF'u64)

proc init*(t: typedesc[DutyAndProof], epoch: Epoch, dependentRoot: Eth2Digest,
           duty: RestAttesterDuty,
           slotSig: Option[ValidatorSig]): DutyAndProof =
  DutyAndProof(epoch: epoch, dependentRoot: dependentRoot, data: duty,
               slotSig: slotSig)

proc init*(t: typedesc[SyncDutyAndProof], epoch: Epoch,
           duty: SyncCommitteeDuty,
           slotSig: Option[ValidatorSig]): SyncDutyAndProof =
  SyncDutyAndProof(epoch: epoch, data: duty, slotSig: slotSig)

proc init*(t: typedesc[ProposedData], epoch: Epoch, dependentRoot: Eth2Digest,
           data: openArray[ProposerTask]): ProposedData =
  ProposedData(epoch: epoch, dependentRoot: dependentRoot, duties: @data)

proc getCurrentSlot*(vc: ValidatorClientRef): Option[Slot] =
  let
    wallTime = vc.beaconClock.now()
    wallSlot = wallTime.toSlot()

  if not(wallSlot.afterGenesis):
    let checkGenesisTime = vc.beaconClock.fromNow(start_beacon_time(Slot(0)))
    warn "Jump in time detected, something wrong with wallclock",
         wall_time = wallTime, genesisIn = checkGenesisTime.offset
    none[Slot]()
  else:
    some(wallSlot.slot)

proc getAttesterDutiesForSlot*(vc: ValidatorClientRef,
                               slot: Slot): seq[DutyAndProof] =
  ## Returns all `DutyAndProof` for the given `slot`.
  var res: seq[DutyAndProof]
  let epoch = slot.epoch()
  for key, item in vc.attesters:
    let duty = item.duties.getOrDefault(epoch, DefaultDutyAndProof)
    if not(duty.isDefault()):
      if duty.data.slot == slot:
        res.add(duty)
  res

proc getSyncCommitteeDutiesForSlot*(vc: ValidatorClientRef,
                                    slot: Slot): seq[SyncDutyAndProof] =
  ## Returns all `SyncDutyAndProof` for the given `slot`.
  var res: seq[SyncDutyAndProof]
  let epoch = slot.epoch()
  for key, item in mpairs(vc.syncCommitteeDuties):
    item.duties.withValue(epoch, duty):
      res.add(duty[])
  res

proc removeOldSyncPeriodDuties*(vc: ValidatorClientRef,
                                slot: Slot) =
  if slot.is_sync_committee_period:
    let epoch = slot.epoch()
    var prunedDuties = SyncCommitteeDutiesMap()
    for key, item in vc.syncCommitteeDuties:
      var curPeriodDuties = EpochSyncDuties()
      for epochKey, epochDuty in item.duties:
        if epochKey >= epoch:
          curPeriodDuties.duties[epochKey] = epochDuty
      prunedDuties[key] = curPeriodDuties
    vc.syncCommitteeDuties = prunedDuties

proc getDurationToNextAttestation*(vc: ValidatorClientRef,
                                   slot: Slot): string =
  var minSlot = FAR_FUTURE_SLOT
  let currentEpoch = slot.epoch()
  for epoch in [currentEpoch, currentEpoch + 1'u64]:
    for key, item in vc.attesters:
      let duty = item.duties.getOrDefault(epoch, DefaultDutyAndProof)
      if not(duty.isDefault()):
        let dutySlotTime = duty.data.slot
        if duty.data.slot < minSlot:
          minSlot = duty.data.slot
    if minSlot != FAR_FUTURE_SLOT:
      break

  if minSlot == FAR_FUTURE_SLOT:
    "<unknown>"
  else:
    $(minSlot.attestation_deadline() - slot.start_beacon_time())

proc getDurationToNextBlock*(vc: ValidatorClientRef, slot: Slot): string =
  var minSlot = FAR_FUTURE_SLOT
  let currentEpoch = slot.epoch()
  for epoch in [currentEpoch, currentEpoch + 1'u64]:
    let data = vc.proposers.getOrDefault(epoch)
    if not(data.isDefault()):
      for item in data.duties:
        if item.duty.pubkey in vc.attachedValidators:
          if item.duty.slot < minSlot:
            minSlot = item.duty.slot
    if minSlot != FAR_FUTURE_SLOT:
      break
  if minSlot == FAR_FUTURE_SLOT:
    "<unknown>"
  else:
    $(minSlot.block_deadline() - slot.start_beacon_time())

iterator attesterDutiesForEpoch*(vc: ValidatorClientRef,
                                 epoch: Epoch): DutyAndProof =
  for key, item in vc.attesters:
    let epochDuties = item.duties.getOrDefault(epoch)
    if not(isDefault(epochDuties)):
      yield epochDuties

proc syncMembersSubscriptionInfoForEpoch*(
    vc: ValidatorClientRef,
    epoch: Epoch): seq[SyncCommitteeSubscriptionInfo] =
  var res: seq[SyncCommitteeSubscriptionInfo]
  for key, item in mpairs(vc.syncCommitteeDuties):
    var cur: SyncCommitteeSubscriptionInfo
    var initialized = false

    item.duties.withValue(epoch, epochDuties):
      if not initialized:
        cur.validator_index = epochDuties.data.validator_index
        initialized = true
      cur.validator_sync_committee_indices.add(
        epochDuties.data.validator_sync_committee_index)

    if initialized:
      res.add cur

  res

proc getDelay*(vc: ValidatorClientRef, deadline: BeaconTime): TimeDiff =
  vc.beaconClock.now() - deadline

proc getValidator*(vc: ValidatorClientRef,
                   key: ValidatorPubKey): Option[AttachedValidator] =
  let validator = vc.attachedValidators.getValidator(key)
  if isNil(validator):
    warn "Validator not in pool anymore", validator = shortLog(validator)
    none[AttachedValidator]()
  else:
    if validator.index.isNone():
      warn "Validator index is missing", validator = shortLog(validator)
      none[AttachedValidator]()
    else:
      some(validator)

proc forkAtEpoch*(vc: ValidatorClientRef, epoch: Epoch): Fork =
  # If schedule is present, it MUST not be empty.
  doAssert(len(vc.forks) > 0)
  var res: Fork
  for item in vc.forks:
    if item.epoch <= epoch:
      res = item
    else:
      break
  res

proc getSubcommitteeIndex*(index: IndexInSyncCommittee): SyncSubcommitteeIndex =
  SyncSubcommitteeIndex(uint16(index) div SYNC_SUBCOMMITTEE_SIZE)
