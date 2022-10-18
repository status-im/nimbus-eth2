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
  ".."/spec/eth2_apis/[eth2_rest_serialization, rest_beacon_client],
  ".."/validators/[keystore_management, validator_pool, slashing_protection],
  ".."/[conf, beacon_clock, version, nimbus_binary_common]

export
  os, sets, sequtils, chronos, presto, chronicles, confutils,
  nimbus_binary_common, version, conf, options, tables, results, base10,
  byteutils, presto_client, eth2_rest_serialization, rest_beacon_client,
  phase0, altair, helpers, signatures, validator, eth2_merkleization,
  beacon_clock, keystore_management, slashing_protection, validator_pool

const
  SYNC_TOLERANCE* = 4'u64
  SLOT_LOOKAHEAD* = 1.seconds
  HISTORICAL_DUTIES_EPOCHS* = 2'u64
  TIME_DELAY_FROM_SLOT* = 79.milliseconds
  SUBSCRIPTION_BUFFER_SLOTS* = 2'u64

  DelayBuckets* = [-Inf, -4.0, -2.0, -1.0, -0.5, -0.1, -0.05,
                   0.05, 0.1, 0.5, 1.0, 2.0, 4.0, 8.0, Inf]

type
  ServiceState* {.pure.} = enum
    Initialized, Running, Error, Closing, Closed

  BlockServiceEventRef* = ref object of RootObj
    slot*: Slot
    proposers*: seq[ValidatorPubKey]

  ClientServiceRef* = ref object of RootObj
    name*: string
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
    duties*: Table[Epoch, SyncDutyAndProof]

  RestBeaconNodeStatus* {.pure.} = enum
    Uninitalized, Offline, Incompatible, NotSynced, Online

  BeaconNodeServerRef* = ref BeaconNodeServer

  AttesterMap* = Table[ValidatorPubKey, EpochDuties]
  SyncCommitteeDutiesMap* = Table[ValidatorPubKey, EpochSyncDuties]
  ProposerMap* = Table[Epoch, ProposedData]

  DoppelgangerStatus* {.pure.} = enum
    None, Checking, Passed

  DoppelgangerAttempt* {.pure.} = enum
    None, Failure, SuccessTrue, SuccessFalse

  DoppelgangerState* = object
    startEpoch*: Epoch
    epochsCount*: uint64
    lastAttempt*: DoppelgangerAttempt
    status*: DoppelgangerStatus

  DoppelgangerDetection* = object
    startSlot*: Slot
    validators*: Table[ValidatorIndex, DoppelgangerState]

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
    sigintHandleFut*: Future[void]
    sigtermHandleFut*: Future[void]
    keymanagerHost*: ref KeymanagerHost
    keymanagerServer*: RestServerRef
    beaconClock*: BeaconClock
    doppelgangerDetection*: DoppelgangerDetection
    attachedValidators*: ref ValidatorPool
    forks*: seq[Fork]
    forksAvailable*: AsyncEvent
    nodesAvailable*: AsyncEvent
    gracefulExit*: AsyncEvent
    attesters*: AttesterMap
    proposers*: ProposerMap
    syncCommitteeDuties*: SyncCommitteeDutiesMap
    beaconGenesis*: RestGenesis
    proposerTasks*: Table[Slot, seq[ProposerTask]]
    rng*: ref HmacDrbgContext

  ValidatorClientRef* = ref ValidatorClient

  ValidatorClientError* = object of CatchableError
  ValidatorApiError* = object of ValidatorClientError

const
  DefaultDutyAndProof* = DutyAndProof(epoch: Epoch(0xFFFF_FFFF_FFFF_FFFF'u64))
  DefaultSyncDutyAndProof* =
    SyncDutyAndProof(epoch: Epoch(0xFFFF_FFFF_FFFF_FFFF'u64))
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

proc isDefault*(sdap: SyncDutyAndProof): bool =
  sdap.epoch == Epoch(0xFFFF_FFFF_FFFF_FFFF'u64)

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
              Base10.toString(client.address.port)
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
                   key: ValidatorPubKey): Opt[AttachedValidator] =
  let validator = vc.attachedValidators[].getValidator(key)
  if isNil(validator):
    info "Validator not in pool anymore", validator = shortLog(validator)
    Opt.none(AttachedValidator)
  else:
    if validator.index.isNone():
      info "Validator index is missing", validator = shortLog(validator)
      Opt.none(AttachedValidator)
    else:
      Opt.some(validator)

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

proc addDoppelganger*(vc: ValidatorClientRef,
                      validators: openArray[AttachedValidator]) =
  if vc.config.doppelgangerDetection:
    let startEpoch = vc.currentSlot().epoch()
    var
      check: seq[string]
      skip: seq[string]
      exist: seq[string]

    for validator in validators:
      let
        vindex = validator.index.get()
        state =
          if (startEpoch == GENESIS_EPOCH) and
             (validator.startSlot == GENESIS_SLOT):
            DoppelgangerState(startEpoch: startEpoch, epochsCount: 0'u64,
                              lastAttempt: DoppelgangerAttempt.None,
                              status: DoppelgangerStatus.Passed)
          else:
            if validator.activationEpoch.isSome() and
               (validator.activationEpoch.get() >= startEpoch):
              DoppelgangerState(startEpoch: startEpoch, epochsCount: 0'u64,
                                lastAttempt: DoppelgangerAttempt.None,
                                status: DoppelgangerStatus.Passed)
            else:
              DoppelgangerState(startEpoch: startEpoch, epochsCount: 0'u64,
                                lastAttempt: DoppelgangerAttempt.None,
                                status: DoppelgangerStatus.Checking)
        res = vc.doppelgangerDetection.validators.hasKeyOrPut(vindex, state)
      if res:
        exist.add(validatorLog(validator.pubkey, vindex))
      else:
        if state.status == DoppelgangerStatus.Checking:
          check.add(validatorLog(validator.pubkey, vindex))
        else:
          skip.add(validatorLog(validator.pubkey, vindex))
    info "Validator's doppelganger protection activated",
         validators_count = len(validators),
         pending_check_count = len(check),
         skipped_count = len(skip),
         exist_count = len(exist)
    debug "Validator's doppelganger protection dump",
          checking_validators = check,
          skip_validators = skip,
          existing_validators = exist

proc addDoppelganger*(vc: ValidatorClientRef, validator: AttachedValidator) =
  logScope:
    validator = shortLog(validator)

  if vc.config.doppelgangerDetection:
    let
      vindex = validator.index.get()
      startEpoch = vc.currentSlot().epoch()
      state =
        if (startEpoch == GENESIS_EPOCH) and
           (validator.startSlot == GENESIS_SLOT):
          DoppelgangerState(startEpoch: startEpoch, epochsCount: 0'u64,
                            lastAttempt: DoppelgangerAttempt.None,
                            status: DoppelgangerStatus.Passed)
        else:
          DoppelgangerState(startEpoch: startEpoch, epochsCount: 0'u64,
                            lastAttempt: DoppelgangerAttempt.None,
                            status: DoppelgangerStatus.Checking)
      res = vc.doppelgangerDetection.validators.hasKeyOrPut(vindex, state)

    if res:
      warn "Validator is already in doppelganger table",
           validator_index = vindex, start_epoch = startEpoch,
           start_slot = validator.startSlot
    else:
      if state.status == DoppelgangerStatus.Checking:
        info "Doppelganger protection activated", validator_index = vindex,
             start_epoch = startEpoch, start_slot = validator.startSlot
      else:
        info "Doppelganger protection skipped", validator_index = vindex,
             start_epoch = startEpoch, start_slot = validator.startSlot

proc removeDoppelganger*(vc: ValidatorClientRef, index: ValidatorIndex) =
  if vc.config.doppelgangerDetection:
    var state: DoppelgangerState
    # We do not care about race condition, when validator is not yet added to
    # the doppelganger's table, but it should be removed.
    discard vc.doppelgangerDetection.validators.pop(index, state)

proc addValidator*(vc: ValidatorClientRef, keystore: KeystoreData) =
  let
    slot = vc.currentSlot()
    feeRecipient = vc.config.validatorsDir.getSuggestedFeeRecipient(
      keystore.pubkey, vc.config.defaultFeeRecipient).valueOr(
        vc.config.defaultFeeRecipient)
  case keystore.kind
  of KeystoreKind.Local:
    vc.attachedValidators[].addLocalValidator(keystore, Opt.none ValidatorIndex,
                                              feeRecipient, slot)
  of KeystoreKind.Remote:
    let
      httpFlags =
        block:
          var res: set[HttpClientFlag]
          if RemoteKeystoreFlag.IgnoreSSLVerification in keystore.flags:
            res.incl({HttpClientFlag.NoVerifyHost,
                      HttpClientFlag.NoVerifyServerName})
          res
      prestoFlags = {RestClientFlag.CommaSeparatedArray}
      clients =
        block:
          var res: seq[(RestClientRef, RemoteSignerInfo)]
          for remote in keystore.remotes:
            let client = RestClientRef.new($remote.url, prestoFlags,
                                           httpFlags)
            if client.isErr():
              warn "Unable to resolve distributed signer address",
                   remote_url = $remote.url, validator = $remote.pubkey
            else:
              res.add((client.get(), remote))
          res
    if len(clients) > 0:
      vc.attachedValidators[].addRemoteValidator(keystore, clients,
                                                 Opt.none ValidatorIndex,
                                                 feeRecipient, slot)
    else:
      warn "Unable to initialize remote validator",
           validator = $keystore.pubkey

proc removeValidator*(vc: ValidatorClientRef,
                      pubkey: ValidatorPubKey) {.async.} =
  let validator = vc.attachedValidators[].getValidator(pubkey)
  if not(isNil(validator)):
    if vc.config.doppelgangerDetection:
      if validator.index.isSome():
        vc.removeDoppelganger(validator.index.get())
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
    # Remove validator from ValidatorPool.
    vc.attachedValidators[].removeValidator(pubkey)

proc doppelgangerCheck*(vc: ValidatorClientRef,
                        validator: AttachedValidator): bool =
  if vc.config.doppelgangerDetection:
    if validator.index.isNone():
      false
    else:
      let
        vindex = validator.index.get()
        default = DoppelgangerState(status: DoppelgangerStatus.None)
        state = vc.doppelgangerDetection.validators.getOrDefault(vindex,
                                                                 default)
      state.status == DoppelgangerStatus.Passed
  else:
    true

proc doppelgangerCheck*(vc: ValidatorClientRef,
                        key: ValidatorPubKey): bool =
  let validator = vc.getValidator(key).valueOr: return false
  vc.doppelgangerCheck(validator)

proc doppelgangerFilter*(
       vc: ValidatorClientRef,
       duties: openArray[DutyAndProof]
     ): tuple[filtered: seq[DutyAndProof], skipped: seq[string]] =
  var
    pending: seq[string]
    ready: seq[DutyAndProof]
  for duty in duties:
    let
      vindex = duty.data.validator_index
      vkey = duty.data.pubkey
    if vc.doppelgangerCheck(vkey):
      ready.add(duty)
    else:
      pending.add(validatorLog(vkey, vindex))
  (ready, pending)
