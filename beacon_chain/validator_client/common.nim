# beacon_chain
# Copyright (c) 2021-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/[tables, os, sets, sequtils, strutils, uri],
  stew/[base10, results, byteutils],
  bearssl/rand, chronos, presto, presto/client as presto_client,
  chronicles, confutils, json_serialization/std/[options, net],
  metrics, metrics/chronos_httpserver,
  ".."/spec/datatypes/[phase0, altair],
  ".."/spec/[eth2_merkleization, helpers, signatures, validator],
  ".."/spec/eth2_apis/[eth2_rest_serialization, rest_beacon_client,
                       dynamic_fee_recipients],
  ".."/validators/[keystore_management, validator_pool, slashing_protection],
  ".."/[conf, beacon_clock, version, nimbus_binary_common]

from std/times import Time, toUnix, fromUnix, getTime

export
  os, sets, sequtils, chronos, presto, chronicles, confutils,
  nimbus_binary_common, version, conf, options, tables, results, base10,
  byteutils, presto_client, eth2_rest_serialization, rest_beacon_client,
  phase0, altair, helpers, signatures, validator, eth2_merkleization,
  beacon_clock, keystore_management, slashing_protection, validator_pool,
  dynamic_fee_recipients, Time, toUnix, fromUnix, getTime

const
  SYNC_TOLERANCE* = 4'u64
  SLOT_LOOKAHEAD* = 1.seconds
  HISTORICAL_DUTIES_EPOCHS* = 2'u64
  TIME_DELAY_FROM_SLOT* = 79.milliseconds
  SUBSCRIPTION_BUFFER_SLOTS* = 2'u64
  EPOCHS_BETWEEN_VALIDATOR_REGISTRATION* = 1

  DelayBuckets* = [-Inf, -4.0, -2.0, -1.0, -0.5, -0.1, -0.05,
                   0.05, 0.1, 0.5, 1.0, 2.0, 4.0, 8.0, Inf]

type
  ServiceState* {.pure.} = enum
    Initialized, Running, Error, Closing, Closed

  BlockServiceEventRef* = ref object of RootObj
    slot*: Slot
    proposers*: seq[ValidatorPubKey]

  RegistrationKind* {.pure.} = enum
    Cached, IncorrectTime, MissingIndex, MissingFee, MissingGasLimit
      ErrorSignature, NoSignature

  PendingValidatorRegistration* = object
    registration*: SignedValidatorRegistrationV1
    future*: Future[SignatureResult]

  ClientServiceRef* = ref object of RootObj
    name*: string
    state*: ServiceState
    lifeFut*: Future[void]
    client*: ValidatorClientRef

  DutiesServiceRef* = ref object of ClientServiceRef

  FallbackServiceRef* = ref object of ClientServiceRef
    changesEvent*: AsyncEvent

  ForkServiceRef* = ref object of ClientServiceRef

  AttestationServiceRef* = ref object of ClientServiceRef

  BlockServiceRef* = ref object of ClientServiceRef

  SyncCommitteeServiceRef* = ref object of ClientServiceRef

  DoppelgangerServiceRef* = ref object of ClientServiceRef
    enabled*: bool

  DutyAndProof* = object
    epoch*: Epoch
    dependentRoot*: Eth2Digest
    data*: RestAttesterDuty
    slotSig*: Option[ValidatorSig]

  SyncCommitteeDuty* = object
    pubkey*: ValidatorPubKey
    validator_index*: ValidatorIndex
    validator_sync_committee_index*: IndexInSyncCommittee

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

  BeaconNodeRole* {.pure.} = enum
    Duties,
    AttestationData, AttestationPublish,
    AggregatedData, AggregatedPublish,
    BlockProposalData, BlockProposalPublish,
    SyncCommitteeData, SyncCommitteePublish

  BeaconNodeServer* = object
    client*: RestClientRef
    endpoint*: string
    config*: Option[RestSpecVC]
    ident*: Option[string]
    genesis*: Option[RestGenesis]
    syncInfo*: Option[RestSyncInfo]
    status*: RestBeaconNodeStatus
    roles*: set[BeaconNodeRole]
    logIdent*: string
    index*: int

  EpochDuties* = object
    duties*: Table[Epoch, DutyAndProof]

  EpochSyncDuties* = object
    duties*: Table[Epoch, SyncCommitteeDuty]

  RestBeaconNodeStatus* {.pure.} = enum
    Offline,      ## BN is offline.
    Online,       ## BN is online, passed checkOnline() check.
    Incompatible, ## BN configuration is NOT compatible with VC configuration.
    Compatible,   ## BN configuration is compatible with VC configuration.
    NotSynced,    ## BN is not in sync.
    OptSynced,    ## BN is optimistically synced (EL is not in sync).
    Synced,       ## BN and EL are synced.
    Unexpected,   ## BN sends unexpected/incorrect response.
    InternalError ## BN reports internal error.

  BeaconNodesCounters* = object
    data*: array[int(high(RestBeaconNodeStatus)) + 1, int]

  BeaconNodeServerRef* = ref BeaconNodeServer

  AttesterMap* = Table[ValidatorPubKey, EpochDuties]
  SyncCommitteeDutiesMap* = Table[ValidatorPubKey, EpochSyncDuties]
  ProposerMap* = Table[Epoch, ProposedData]

  DoppelgangerStatus* {.pure.} = enum
    None, Checking, Passed

  DoppelgangerAttempt* {.pure.} = enum
    None, Failure, SuccessTrue, SuccessFalse

  ValidatorClient* = object
    config*: ValidatorClientConf
    metricsServer*: Option[MetricsHttpServerRef]
    graffitiBytes*: GraffitiBytes
    beaconNodes*: seq[BeaconNodeServerRef]
    fallbackService*: FallbackServiceRef
    forkService*: ForkServiceRef
    dutiesService*: DutiesServiceRef
    attestationService*: AttestationServiceRef
    blockService*: BlockServiceRef
    syncCommitteeService*: SyncCommitteeServiceRef
    doppelgangerService*: DoppelgangerServiceRef
    runSlotLoopFut*: Future[void]
    runKeystoreCachePruningLoopFut*: Future[void]
    sigintHandleFut*: Future[void]
    sigtermHandleFut*: Future[void]
    keymanagerHost*: ref KeymanagerHost
    keymanagerServer*: RestServerRef
    keystoreCache*: KeystoreCacheRef
    beaconClock*: BeaconClock
    attachedValidators*: ref ValidatorPool
    forks*: seq[Fork]
    forksAvailable*: AsyncEvent
    nodesAvailable*: AsyncEvent
    indicesAvailable*: AsyncEvent
    doppelExit*: AsyncEvent
    attesters*: AttesterMap
    proposers*: ProposerMap
    syncCommitteeDuties*: SyncCommitteeDutiesMap
    beaconGenesis*: RestGenesis
    proposerTasks*: Table[Slot, seq[ProposerTask]]
    dynamicFeeRecipientsStore*: ref DynamicFeeRecipientsStore
    validatorsRegCache*: Table[ValidatorPubKey, SignedValidatorRegistrationV1]
    rng*: ref HmacDrbgContext

  ApiFailure* {.pure.} = enum
    Communication, Invalid, NotFound, NotSynced, Internal, Unexpected

  ApiNodeFailure* = object
    node*: BeaconNodeServerRef
    failure*: ApiFailure

  ValidatorClientRef* = ref ValidatorClient

  ValidatorClientError* = object of CatchableError
  ValidatorApiError* = object of ValidatorClientError
    data*: seq[ApiNodeFailure]

const
  DefaultDutyAndProof* = DutyAndProof(epoch: Epoch(0xFFFF_FFFF_FFFF_FFFF'u64))
  SlotDuration* = int64(SECONDS_PER_SLOT).seconds
  OneThirdDuration* = int64(SECONDS_PER_SLOT).seconds div INTERVALS_PER_SLOT
  AllBeaconNodeRoles* = {
    BeaconNodeRole.Duties,
    BeaconNodeRole.AttestationData,
    BeaconNodeRole.AttestationPublish,
    BeaconNodeRole.AggregatedData,
    BeaconNodeRole.AggregatedPublish,
    BeaconNodeRole.BlockProposalData,
    BeaconNodeRole.BlockProposalPublish,
    BeaconNodeRole.SyncCommitteeData,
    BeaconNodeRole.SyncCommitteePublish,
  }

proc `$`*(roles: set[BeaconNodeRole]): string =
  if card(roles) > 0:
    if roles != AllBeaconNodeRoles:
      var res: seq[string]
      if BeaconNodeRole.Duties in roles:
        res.add("duties")
      if BeaconNodeRole.AttestationData in roles:
        res.add("attestation-data")
      if BeaconNodeRole.AttestationPublish in roles:
        res.add("attestation-publish")
      if BeaconNodeRole.AggregatedData in roles:
        res.add("aggregated-data")
      if BeaconNodeRole.AggregatedPublish in roles:
        res.add("aggregated-publish")
      if BeaconNodeRole.BlockProposalData in roles:
        res.add("block-data")
      if BeaconNodeRole.BlockProposalPublish in roles:
        res.add("block-publish")
      if BeaconNodeRole.SyncCommitteeData in roles:
        res.add("sync-data")
      if BeaconNodeRole.SyncCommitteePublish in roles:
        res.add("sync-publish")
      res.join(",")
    else:
      "{all}"
  else:
    "{}"

proc `$`*(status: RestBeaconNodeStatus): string =
  case status
  of RestBeaconNodeStatus.Offline: "offline"
  of RestBeaconNodeStatus.Online: "online"
  of RestBeaconNodeStatus.Incompatible: "incompatible"
  of RestBeaconNodeStatus.Compatible: "compatible"
  of RestBeaconNodeStatus.NotSynced: "bn-unsynced"
  of RestBeaconNodeStatus.OptSynced: "el-unsynced"
  of RestBeaconNodeStatus.Synced: "synced"
  of RestBeaconNodeStatus.Unexpected: "unexpected data"
  of RestBeaconNodeStatus.InternalError: "internal error"

proc `$`*(failure: ApiFailure): string =
  case failure
  of ApiFailure.Communication: "Connection with beacon node has been lost"
  of ApiFailure.Invalid: "Invalid response received from beacon node"
  of ApiFailure.NotFound: "Beacon node did not found requested entity"
  of ApiFailure.NotSynced: "Beacon node not in sync with network"
  of ApiFailure.Internal: "Beacon node reports internal failure"
  of ApiFailure.Unexpected: "Beacon node reports unexpected status"

proc getNodeCounts*(vc: ValidatorClientRef): BeaconNodesCounters =
  var res = BeaconNodesCounters()
  for node in vc.beaconNodes: inc(res.data[int(node.status)])
  res

proc getFailureReason*(exc: ref ValidatorApiError): string =
  var counts: array[int(high(ApiFailure)) + 1, int]
  let
    errors = exc[].data
    errorsCount = len(errors)

  if errorsCount > 1:
    var maxFailure =
      block:
        var maxCount = -1
        var res = ApiFailure.Unexpected
        for item in errors:
          inc(counts[int(item.failure)])
          if counts[int(item.failure)] > maxCount:
            maxCount = counts[int(item.failure)]
            res = item.failure
        res
    $maxFailure
  elif errorsCount == 1:
    $errors[0].failure
  else:
    exc.msg

proc shortLog*(roles: set[BeaconNodeRole]): string =
  var r = "AGBSD"
  if BeaconNodeRole.AttestationData in roles:
    if BeaconNodeRole.AttestationPublish in roles: r[0] = 'A' else: r[0] = 'a'
  else:
    if BeaconNodeRole.AttestationPublish in roles: r[0] = '+' else: r[0] = '-'
  if BeaconNodeRole.AggregatedData in roles:
    if BeaconNodeRole.AggregatedPublish in roles: r[1] = 'G' else: r[1] = 'g'
  else:
    if BeaconNodeRole.AggregatedPublish in roles: r[1] = '+' else: r[1] = '-'
  if BeaconNodeRole.BlockProposalData in roles:
    if BeaconNodeRole.BlockProposalPublish in roles: r[2] = 'B' else: r[2] = 'b'
  else:
    if BeaconNodeRole.BlockProposalPublish in roles: r[2] = '+' else: r[2] = '-'
  if BeaconNodeRole.SyncCommitteeData in roles:
    if BeaconNodeRole.SyncCommitteePublish in roles:
      r[3] = 'S' else: r[3] = 's'
  else:
    if BeaconNodeRole.SyncCommitteePublish in roles:
      r[3] = '+' else: r[3] = '-'
  if BeaconNodeRole.Duties in roles: r[4] = 'D' else: r[4] = '-'
  r

proc `$`*(bn: BeaconNodeServerRef): string =
  if bn.ident.isSome():
    bn.logIdent & "[" & bn.ident.get() & "]"
  else:
    bn.logIdent

proc validatorLog*(key: ValidatorPubKey,
                  index: ValidatorIndex): string =
  var res = shortLog(key)
  res.add('@')
  res.add(Base10.toString(uint64(index)))
  res

chronicles.expandIt(BeaconNodeServerRef):
  node = $it
  node_index = it.index
  node_roles = shortLog(it.roles)

chronicles.expandIt(RestAttesterDuty):
  pubkey = shortLog(it.pubkey)
  slot = it.slot
  validator_index = it.validator_index
  committee_index = it.committee_index
  committee_length = it.committee_length
  committees_at_slot = it.committees_at_slot
  validator_committee_index = it.validator_committee_index

chronicles.expandIt(SyncCommitteeDuty):
  pubkey = shortLog(it.pubkey)
  validator_index = it.validator_index
  validator_sync_committee_index = it.validator_sync_committee_index

proc checkConfig*(info: RestSpecVC): bool =
  # /!\ Keep in sync with `spec/eth2_apis/rest_types.nim` > `RestSpecVC`.
  info.MAX_VALIDATORS_PER_COMMITTEE == MAX_VALIDATORS_PER_COMMITTEE and
  info.SLOTS_PER_EPOCH == SLOTS_PER_EPOCH and
  info.SECONDS_PER_SLOT == SECONDS_PER_SLOT and
  info.EPOCHS_PER_ETH1_VOTING_PERIOD == EPOCHS_PER_ETH1_VOTING_PERIOD and
  info.SLOTS_PER_HISTORICAL_ROOT == SLOTS_PER_HISTORICAL_ROOT and
  info.EPOCHS_PER_HISTORICAL_VECTOR == EPOCHS_PER_HISTORICAL_VECTOR and
  info.EPOCHS_PER_SLASHINGS_VECTOR == EPOCHS_PER_SLASHINGS_VECTOR and
  info.HISTORICAL_ROOTS_LIMIT == HISTORICAL_ROOTS_LIMIT and
  info.VALIDATOR_REGISTRY_LIMIT == VALIDATOR_REGISTRY_LIMIT and
  info.MAX_PROPOSER_SLASHINGS == MAX_PROPOSER_SLASHINGS and
  info.MAX_ATTESTER_SLASHINGS == MAX_ATTESTER_SLASHINGS and
  info.MAX_ATTESTATIONS == MAX_ATTESTATIONS and
  info.MAX_DEPOSITS == MAX_DEPOSITS and
  info.MAX_VOLUNTARY_EXITS == MAX_VOLUNTARY_EXITS and
  info.DOMAIN_BEACON_PROPOSER == DOMAIN_BEACON_PROPOSER and
  info.DOMAIN_BEACON_ATTESTER == DOMAIN_BEACON_ATTESTER and
  info.DOMAIN_RANDAO == DOMAIN_RANDAO and
  info.DOMAIN_DEPOSIT == DOMAIN_DEPOSIT and
  info.DOMAIN_VOLUNTARY_EXIT == DOMAIN_VOLUNTARY_EXIT and
  info.DOMAIN_SELECTION_PROOF == DOMAIN_SELECTION_PROOF and
  info.DOMAIN_AGGREGATE_AND_PROOF == DOMAIN_AGGREGATE_AND_PROOF

proc updateStatus*(node: BeaconNodeServerRef, status: RestBeaconNodeStatus) =
  logScope:
    endpoint = node
  case status
  of RestBeaconNodeStatus.Offline:
    if node.status != status:
      warn "Beacon node down"
      node.status = status
  of RestBeaconNodeStatus.Online:
    if node.status != status:
      let version = if node.ident.isSome(): node.ident.get() else: "<missing>"
      notice "Beacon node is online", agent_version = version
      node.status = status
  of RestBeaconNodeStatus.Incompatible:
    if node.status != status:
      warn "Beacon node has incompatible configuration"
      node.status = status
  of RestBeaconNodeStatus.Compatible:
    if node.status != status:
      notice "Beacon node is compatible"
      node.status = status
  of RestBeaconNodeStatus.NotSynced:
    if node.status notin {RestBeaconNodeStatus.NotSynced,
                          RestBeaconNodeStatus.OptSynced}:
      doAssert(node.syncInfo.isSome())
      let si = node.syncInfo.get()
      warn "Beacon node not in sync",
           last_head_slot = si.head_slot,
           last_sync_distance = si.sync_distance,
           last_optimistic = si.is_optimistic.get(false)
      node.status = status
  of RestBeaconNodeStatus.OptSynced:
    if node.status != status:
      doAssert(node.syncInfo.isSome())
      let si = node.syncInfo.get()
      notice "Execution client not in sync (beacon node optimistically synced)",
             last_head_slot = si.head_slot,
             last_sync_distance = si.sync_distance,
             last_optimistic = si.is_optimistic.get(false)
      node.status = status
  of RestBeaconNodeStatus.Synced:
    if node.status != status:
      doAssert(node.syncInfo.isSome())
      let si = node.syncInfo.get()
      notice "Beacon node is in sync",
             head_slot = si.head_slot, sync_distance = si.sync_distance,
             is_optimistic = si.is_optimistic.get(false)
      node.status = status
  of RestBeaconNodeStatus.Unexpected:
    if node.status != status:
      error "Beacon node provides unexpected response"
      node.status = status
  of RestBeaconNodeStatus.InternalError:
    if node.status != status:
      warn "Beacon node reports internal error"
      node.status = status

proc stop*(csr: ClientServiceRef) {.async.} =
  debug "Stopping service", service = csr.name
  if csr.state == ServiceState.Running:
    csr.state = ServiceState.Closing
    if not(csr.lifeFut.finished()):
      await csr.lifeFut.cancelAndWait()
    csr.state = ServiceState.Closed
    debug "Service stopped", service = csr.name

proc isDefault*(dap: DutyAndProof): bool =
  dap.epoch == Epoch(0xFFFF_FFFF_FFFF_FFFF'u64)

proc isDefault*(prd: ProposedData): bool =
  prd.epoch == Epoch(0xFFFF_FFFF_FFFF_FFFF'u64)

proc parseRoles*(data: string): Result[set[BeaconNodeRole], cstring] =
  var res: set[BeaconNodeRole]
  if len(data) == 0:
    return ok(AllBeaconNodeRoles)
  let parts = data.split("roles=")
  if (len(parts) != 2) or (len(parts[0]) != 0):
    return err("Invalid beacon node roles string")
  let sroles = parts[1].split(",")
  for srole in sroles:
    case toLower(strip(srole))
    of "":
      discard
    of "all":
      res.incl(AllBeaconNodeRoles)
    of "attestation":
      res.incl({BeaconNodeRole.AttestationData,
                BeaconNodeRole.AttestationPublish})
    of "block":
      res.incl({BeaconNodeRole.BlockProposalData,
                BeaconNodeRole.BlockProposalPublish})
    of "aggregated":
      res.incl({BeaconNodeRole.AggregatedData,
                BeaconNodeRole.AggregatedPublish})
    of "sync":
      res.incl({BeaconNodeRole.SyncCommitteeData,
                BeaconNodeRole.SyncCommitteePublish})
    of "attestation-data":
      res.incl(BeaconNodeRole.AttestationData)
    of "attestation-publish":
      res.incl(BeaconNodeRole.AttestationPublish)
    of "aggregated-data":
      res.incl(BeaconNodeRole.AggregatedData)
    of "aggregated-publish":
      res.incl(BeaconNodeRole.AggregatedPublish)
    of "block-data":
      res.incl(BeaconNodeRole.BlockProposalData)
    of "block-publish":
      res.incl(BeaconNodeRole.BlockProposalPublish)
    of "sync-data":
      res.incl(BeaconNodeRole.SyncCommitteeData)
    of "sync-publish":
      res.incl(BeaconNodeRole.SyncCommitteePublish)
    of "duties":
      res.incl(BeaconNodeRole.Duties)
    else:
      return err("Invalid beacon node role string found")
  ok(res)

proc init*(t: typedesc[BeaconNodeServerRef], remote: Uri,
           index: int): Result[BeaconNodeServerRef, string] =
  doAssert(index >= 0)
  let
    flags = {RestClientFlag.CommaSeparatedArray}
    client =
      block:
        let res = RestClientRef.new($remote, flags = flags)
        if res.isErr(): return err($res.error())
        res.get()
    roles =
      block:
        let res = parseRoles(remote.anchor)
        if res.isErr(): return err($res.error())
        res.get()

  let server = BeaconNodeServerRef(
    client: client, endpoint: $remote, index: index, roles: roles,
    logIdent: client.address.hostname & ":" &
              Base10.toString(client.address.port),
    status: RestBeaconNodeStatus.Offline
  )
  ok(server)

proc getMissingRoles*(n: openArray[BeaconNodeServerRef]): set[BeaconNodeRole] =
  var res: set[BeaconNodeRole] = AllBeaconNodeRoles
  for node in n.items():
    res.excl(node.roles)
  res

proc init*(t: typedesc[DutyAndProof], epoch: Epoch, dependentRoot: Eth2Digest,
           duty: RestAttesterDuty,
           slotSig: Option[ValidatorSig]): DutyAndProof =
  DutyAndProof(epoch: epoch, dependentRoot: dependentRoot, data: duty,
               slotSig: slotSig)

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
                                    slot: Slot): seq[SyncCommitteeDuty] =
  ## Returns all `SyncCommitteeDuty` for the given `slot`.
  var res: seq[SyncCommitteeDuty]
  let epoch = slot.epoch()
  for key, item in mpairs(vc.syncCommitteeDuties):
    item.duties.withValue(epoch, duty):
      res.add(duty[])
  res

proc getDurationToNextAttestation*(vc: ValidatorClientRef,
                                   slot: Slot): string =
  var minSlot = FAR_FUTURE_SLOT
  let currentEpoch = slot.epoch()
  for epoch in [currentEpoch, currentEpoch + 1'u64]:
    for key, item in vc.attesters:
      let duty = item.duties.getOrDefault(epoch, DefaultDutyAndProof)
      if not(duty.isDefault()):
        let dutySlotTime = duty.data.slot
        if (duty.data.slot < minSlot) and (duty.data.slot >= slot):
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
        if item.duty.pubkey in vc.attachedValidators[]:
          if (item.duty.slot < minSlot) and (item.duty.slot >= slot):
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
        cur.validator_index = epochDuties.validator_index
        initialized = true
      cur.validator_sync_committee_indices.add(
        epochDuties.validator_sync_committee_index)

    if initialized:
      res.add cur

  res

proc getDelay*(vc: ValidatorClientRef, deadline: BeaconTime): TimeDiff =
  vc.beaconClock.now() - deadline

proc getValidatorForDuties*(vc: ValidatorClientRef,
                            key: ValidatorPubKey, slot: Slot,
                            slashingSafe = false): Opt[AttachedValidator] =
  vc.attachedValidators[].getValidatorForDuties(key, slot, slashingSafe)

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

proc currentSlot*(vc: ValidatorClientRef): Slot =
  vc.beaconClock.now().slotOrZero()

proc addValidator*(vc: ValidatorClientRef, keystore: KeystoreData) =
  let
    slot = vc.currentSlot()
    feeRecipient = vc.config.validatorsDir.getSuggestedFeeRecipient(
      keystore.pubkey, vc.config.defaultFeeRecipient).valueOr(
        vc.config.defaultFeeRecipient)
    gasLimit = vc.config.validatorsDir.getSuggestedGasLimit(
      keystore.pubkey, vc.config.suggestedGasLimit).valueOr(
        vc.config.suggestedGasLimit)

  discard vc.attachedValidators[].addValidator(keystore, feeRecipient, gasLimit)

proc removeValidator*(vc: ValidatorClientRef,
                      pubkey: ValidatorPubKey) {.async.} =
  let validator = vc.attachedValidators[].getValidator(pubkey).valueOr:
    return
  # Remove validator from ValidatorPool.
  vc.attachedValidators[].removeValidator(pubkey)

  case validator.kind
  of ValidatorKind.Local:
    discard
  of ValidatorKind.Remote:
    # We must close all the REST clients running for the remote validator.
    let pending =
      block:
        var res: seq[Future[void]]
        for item in validator.clients:
          res.add(item[0].closeWait())
        res
    await allFutures(pending)

proc getFeeRecipient*(vc: ValidatorClientRef, pubkey: ValidatorPubKey,
                      validatorIdx: ValidatorIndex,
                      epoch: Epoch): Opt[Eth1Address] =
  let dynamicRecipient = vc.dynamicFeeRecipientsStore[].getDynamicFeeRecipient(
                           validatorIdx, epoch)
  if dynamicRecipient.isSome():
    Opt.some(dynamicRecipient.get())
  else:
    let staticRecipient = getSuggestedFeeRecipient(
      vc.config.validatorsDir, pubkey, vc.config.defaultFeeRecipient)
    if staticRecipient.isOk():
      Opt.some(staticRecipient.get())
    else:
      Opt.none(Eth1Address)

proc getGasLimit*(vc: ValidatorClientRef,
                  pubkey: ValidatorPubKey): uint64 =
  getSuggestedGasLimit(
    vc.config.validatorsDir, pubkey, vc.config.suggestedGasLimit).valueOr:
      vc.config.suggestedGasLimit

proc prepareProposersList*(vc: ValidatorClientRef,
                           epoch: Epoch): seq[PrepareBeaconProposer] =
  var res: seq[PrepareBeaconProposer]
  for validator in vc.attachedValidators[].items():
    if validator.index.isSome():
      let
        index = validator.index.get()
        feeRecipient = vc.getFeeRecipient(validator.pubkey, index, epoch)
      if feeRecipient.isSome():
        res.add(PrepareBeaconProposer(validator_index: index,
                                      fee_recipient: feeRecipient.get()))
  res

proc isDefault*(reg: SignedValidatorRegistrationV1): bool =
  (reg.message.timestamp == 0'u64) or (reg.message.gas_limit == 0'u64)

proc isExpired*(vc: ValidatorClientRef,
                reg: SignedValidatorRegistrationV1, slot: Slot): bool =
  let
    regTime = fromUnix(int64(reg.message.timestamp))
    regSlot =
      block:
        let res = vc.beaconClock.toSlot(regTime)
        if not(res.afterGenesis):
          # This case should not be happend, but it could in case of time jumps
          # (time could be modified by admin or ntpd).
          return false
        uint64(res.slot)

  if regSlot > slot:
    # This case should not be happened, but if it happens (time could be
    # modified by admin or ntpd).
    false
  else:
    if (slot - regSlot) div SLOTS_PER_EPOCH >=
      EPOCHS_BETWEEN_VALIDATOR_REGISTRATION:
      false
    else:
      true

proc getValidatorRegistration(
       vc: ValidatorClientRef,
       validator: AttachedValidator,
       timestamp: Time,
       fork: Fork
     ): Result[PendingValidatorRegistration, RegistrationKind] =
  if validator.index.isNone():
    debug "Validator registration missing validator index",
          validator = shortLog(validator)
    return err(RegistrationKind.MissingIndex)

  let
    vindex = validator.index.get()
    cached = vc.validatorsRegCache.getOrDefault(validator.pubkey)
    currentSlot =
      block:
        let res = vc.beaconClock.toSlot(timestamp)
        if not(res.afterGenesis):
          return err(RegistrationKind.IncorrectTime)
        res.slot

  if cached.isDefault() or vc.isExpired(cached, currentSlot):
    let feeRecipient = vc.getFeeRecipient(validator.pubkey, vindex,
                                          currentSlot.epoch())
    if feeRecipient.isNone():
      debug "Could not get fee recipient for registration data",
            validator = shortLog(validator)
      return err(RegistrationKind.MissingFee)
    let gasLimit = vc.getGasLimit(validator.pubkey)
    var registration =
      SignedValidatorRegistrationV1(
        message: ValidatorRegistrationV1(
          fee_recipient:
            ExecutionAddress(data: distinctBase(feeRecipient.get())),
          gas_limit: gasLimit,
          timestamp: uint64(timestamp.toUnix()),
          pubkey: validator.pubkey
        )
      )

    let sigfut = validator.getBuilderSignature(fork, registration.message)
    if sigfut.finished():
      # This is short-path if we able to create signature locally.
      if not(sigfut.done()):
        let exc = sigfut.readError()
        debug "Got unexpected exception while signing validator registration",
              validator = shortLog(validator), error_name = $exc.name,
              error_msg = $exc.msg
        return err(RegistrationKind.ErrorSignature)
      let sigres = sigfut.read()
      if sigres.isErr():
        debug "Failed to get signature for validator registration",
              validator = shortLog(validator), error = sigres.error()
        return err(RegistrationKind.NoSignature)
      registration.signature = sigres.get()
      # Updating cache table with new signed registration data
      vc.validatorsRegCache[registration.message.pubkey] = registration
      ok(PendingValidatorRegistration(registration: registration, future: nil))
    else:
      # Remote signature service involved, cache will be updated later.
      ok(PendingValidatorRegistration(registration: registration,
                                      future: sigfut))
  else:
    # Returning cached result.
    err(RegistrationKind.Cached)

proc prepareRegistrationList*(
       vc: ValidatorClientRef,
       timestamp: Time,
       fork: Fork
     ): Future[seq[SignedValidatorRegistrationV1]] {.async.} =

  var
    messages: seq[SignedValidatorRegistrationV1]
    futures: seq[Future[SignatureResult]]
    registrations: seq[SignedValidatorRegistrationV1]
    total = vc.attachedValidators[].count()
    succeed = 0
    bad = 0
    errors = 0
    indexMissing = 0
    feeMissing = 0
    gasLimit = 0
    cached = 0
    timed = 0

  for validator in vc.attachedValidators[].items():
    let res = vc.getValidatorRegistration(validator, timestamp, fork)
    if res.isOk():
      let preg = res.get()
      if preg.future.isNil():
        registrations.add(preg.registration)
      else:
        messages.add(preg.registration)
        futures.add(preg.future)
    else:
      case res.error()
      of RegistrationKind.Cached: inc(cached)
      of RegistrationKind.IncorrectTime: inc(timed)
      of RegistrationKind.NoSignature: inc(bad)
      of RegistrationKind.ErrorSignature: inc(errors)
      of RegistrationKind.MissingIndex: inc(indexMissing)
      of RegistrationKind.MissingFee: inc(feeMissing)
      of RegistrationKind.MissingGasLimit: inc(gasLimit)

  succeed = len(registrations)

  if len(futures) > 0:
    await allFutures(futures)

  for index, future in futures.pairs():
    if future.done():
      let sres = future.read()
      if sres.isOk():
        var reg = messages[index]
        reg.signature = sres.get()
        registrations.add(reg)
        # Updating cache table
        vc.validatorsRegCache[reg.message.pubkey] = reg
        inc(succeed)
      else:
        inc(bad)
    else:
      inc(errors)

  debug "Validator registrations prepared", total = total, succeed = succeed,
        cached = cached, bad = bad, errors = errors,
        index_missing = indexMissing, fee_missing = feeMissing,
        incorrect_time = timed

  return registrations

proc init*(t: typedesc[ApiNodeFailure], node: BeaconNodeServerRef,
           failure: ApiFailure): ApiNodeFailure =
  ApiNodeFailure(node: node, failure: failure)
