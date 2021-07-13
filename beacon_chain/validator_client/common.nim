import std/[tables, os, sequtils, strutils]
import chronos, presto, presto/client as presto_client, chronicles, confutils,
       json_serialization/std/[options, net],
       stew/[base10, results, byteutils]
# Local modules
import ".."/networking/[eth2_network, eth2_discovery],
       ".."/spec/[datatypes, digest, crypto, helpers, signatures],
       ".."/rpc/[beacon_rest_api, node_rest_api, validator_rest_api,
                 config_rest_api, rest_utils, eth2_json_rest_serialization],
       ".."/validators/[attestation_aggregation, keystore_management,
                        validator_pool, slashing_protection],
       ".."/[conf, beacon_clock, version, beacon_node_types,
             nimbus_binary_common],
       ".."/ssz/merkleization,
       ./eth/db/[kvstore, kvstore_sqlite3]

export os, tables, sequtils, sequtils, chronos, presto, chronicles, confutils,
       nimbus_binary_common, version, conf, options, tables, results, base10,
       byteutils, eth2_json_rest_serialization, presto_client

export beacon_rest_api, node_rest_api, validator_rest_api, config_rest_api,
       rest_utils,
       datatypes, crypto, digest, signatures, merkleization,
       beacon_clock,
       kvstore, kvstore_sqlite3,
       keystore_management, slashing_protection, validator_pool,
       attestation_aggregation, beacon_node_types

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

  ForkServiceRef* = ref object of ClientServiceRef

  AttestationServiceRef* = ref object of ClientServiceRef

  BlockServiceRef* = ref object of ClientServiceRef

  DutyAndProof* = object
    epoch*: Epoch
    dependentRoot*: Eth2Digest
    data*: RestAttesterDuty
    slotSig*: Option[ValidatorSig]

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
    config*: Option[RestConfig]
    ident*: Option[string]
    genesis*: Option[RestBeaconGenesis]
    syncInfo*: Option[RestSyncInfo]
    status*: RestBeaconNodeStatus

  EpochDuties* = object
    duties*: Table[Epoch, DutyAndProof]

  RestBeaconNodeStatus* {.pure.} = enum
    Uninitalized, Offline, Incompatible, NotSynced, Online

  BeaconNodeServerRef* = ref BeaconNodeServer

  AttesterMap* = Table[ValidatorPubKey, EpochDuties]
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
    runSlotLoop*: Future[void]
    beaconClock*: BeaconClock
    attachedValidators*: ValidatorPool
    fork*: Option[Fork]
    attesters*: AttesterMap
    proposers*: ProposerMap
    beaconGenesis*: RestBeaconGenesis
    proposerTasks*: Table[Slot, seq[ProposerTask]]

  ValidatorClientRef* = ref ValidatorClient

  ValidatorClientError* = object of CatchableError
  ValidatorApiError* = object of ValidatorClientError

const
  DefaultDutyAndProof* = DutyAndProof(epoch: Epoch(0xFFFF_FFFF_FFFF_FFFF'u64))
  SlotDuration* = int64(SECONDS_PER_SLOT).seconds
  EpochDuration* = int64(SLOTS_PER_EPOCH * SECONDS_PER_SLOT).seconds
  OneThirdDuration* = int64(SECONDS_PER_SLOT div 3).seconds

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

proc isDefault*(prd: ProposedData): bool =
  prd.epoch == Epoch(0xFFFF_FFFF_FFFF_FFFF'u64)

proc init*(t: typedesc[DutyAndProof], epoch: Epoch, dependentRoot: Eth2Digest,
           duty: RestAttesterDuty,
           slotSig: Option[ValidatorSig]): DutyAndProof =
  DutyAndProof(epoch: epoch, dependentRoot: dependentRoot, data: duty,
               slotSig: slotSig)

proc init*(t: typedesc[ProposedData], epoch: Epoch, dependentRoot: Eth2Digest,
           data: openarray[ProposerTask]): ProposedData =
  ProposedData(epoch: epoch, dependentRoot: dependentRoot, duties: @data)

proc getCurrentSlot*(vc: ValidatorClientRef): Option[Slot] =
  let
    wallTime = vc.beaconClock.now()
    wallSlot = wallTime.toSlot()

  if not(wallSlot.afterGenesis):
    let checkGenesisTime = vc.beaconClock.fromNow(toBeaconTime(Slot(0)))
    warn "Jump in time detected, something wrong with wallclock",
         wall_time = wallTime, genesisIn = checkGenesisTime.offset
    none[Slot]()
  else:
    some(wallSlot.slot)

proc getAttesterDutiesForSlot*(vc: ValidatorClientRef,
                               slot: Slot): seq[RestAttesterDuty] =
  ## Returns all `DutyAndPrrof` for the given `slot`.
  var res: seq[RestAttesterDuty]
  let epoch = slot.epoch()
  for key, item in vc.attesters.pairs():
    let duty = item.duties.getOrDefault(epoch, DefaultDutyAndProof)
    if not(duty.isDefault()):
      if duty.data.slot == slot:
        res.add(duty.data)
  res

proc getDurationToNextAttestation*(vc: ValidatorClientRef,
                                   slot: Slot): string =
  var minimumDuration = InfiniteDuration
  let currentSlotTime = Duration(slot.toBeaconTime())
  let currentEpoch = slot.epoch()
  for epoch in [currentEpoch, currentEpoch + 1'u64]:
    for key, item in vc.attesters.pairs():
      let duty = item.duties.getOrDefault(epoch, DefaultDutyAndProof)
      if not(duty.isDefault()):
        let dutySlotTime = Duration(duty.data.slot.toBeaconTime())
        if dutySlotTime >= currentSlotTime:
          let timeLeft = dutySlotTime - currentSlotTime
          if timeLeft < minimumDuration:
            minimumDuration = timeLeft
    if minimumDuration != InfiniteDuration:
      break
  if minimumDuration == InfiniteDuration:
    "<unknown>"
  else:
    $(minimumDuration + seconds(int64(SECONDS_PER_SLOT) div 3))

proc getDurationToNextBlock*(vc: ValidatorClientRef, slot: Slot): string =
  var minimumDuration = InfiniteDuration
  var currentSlotTime = Duration(slot.toBeaconTime())
  let currentEpoch = slot.epoch()
  for epoch in [currentEpoch, currentEpoch + 1'u64]:
    let data = vc.proposers.getOrDefault(epoch)
    if not(data.isDefault()):
      for item in data.duties:
        if item.duty.pubkey in vc.attachedValidators:
          let proposalSlotTime = Duration(item.duty.slot.toBeaconTime())
          if proposalSlotTime >= currentSlotTime:
            let timeLeft = proposalSlotTime - currentSlotTime
            if timeLeft < minimumDuration:
              minimumDuration = timeLeft
    if minimumDuration != InfiniteDuration:
      break
  if minimumDuration == InfiniteDuration:
    "<unknown>"
  else:
    $minimumDuration

iterator attesterDutiesForEpoch*(vc: ValidatorClientRef,
                                 epoch: Epoch): DutyAndProof =
  for key, item in vc.attesters.pairs():
    let epochDuties = item.duties.getOrDefault(epoch)
    if not(isDefault(epochDuties)):
      yield epochDuties

proc getDelay*(vc: ValidatorClientRef, instant: Duration): Duration =
  let currentBeaconTime = vc.beaconClock.now()
  let currentTime = Duration(currentBeaconTime)
  let slotStartTime = currentBeaconTime.slotOrZero().toBeaconTime()
  let idealTime = Duration(slotStartTime) + instant
  currentTime - idealTime
