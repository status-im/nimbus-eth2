# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/[tables, os, sets, sequtils, strutils, uri, algorithm],
  stew/[base10, results, byteutils],
  bearssl/rand, chronos, presto, presto/client as presto_client,
  chronicles, confutils,
  metrics, metrics/chronos_httpserver,
  ".."/spec/datatypes/[base, phase0, altair],
  ".."/spec/[eth2_merkleization, helpers, signatures, validator],
  ".."/spec/eth2_apis/[eth2_rest_serialization, rest_beacon_client,
                       dynamic_fee_recipients],
  ".."/consensus_object_pools/block_pools_types,
  ".."/validators/[keystore_management, validator_pool, slashing_protection,
                   validator_duties],
  ".."/[conf, beacon_clock, version, nimbus_binary_common]

from std/times import Time, toUnix, fromUnix, getTime

export
  os, sets, sequtils, chronos, presto, chronicles, confutils,
  nimbus_binary_common, version, conf, tables, results, base10,
  byteutils, presto_client, eth2_rest_serialization, rest_beacon_client,
  phase0, altair, helpers, signatures, validator, eth2_merkleization,
  beacon_clock, keystore_management, slashing_protection, validator_pool,
  dynamic_fee_recipients, Time, toUnix, fromUnix, getTime, block_pools_types,
  base, metrics

const
  SYNC_TOLERANCE* = 4'u64
  SLOT_LOOKAHEAD* = 1.seconds
  HISTORICAL_DUTIES_EPOCHS* = 2'u64
  TIME_DELAY_FROM_SLOT* = 79.milliseconds
  SUBSCRIPTION_BUFFER_SLOTS* = 2'u64

  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/validator.md#constants
  EPOCHS_BETWEEN_VALIDATOR_REGISTRATION* = 1

  ZeroTimeDiff* = TimeDiff(nanoseconds: 0'i64)

type
  ServiceState* {.pure.} = enum
    Initialized, Running, Error, Closing, Closed

  RegistrationKind* {.pure.} = enum
    Cached, IncorrectTime, MissingIndex, MissingFee, MissingGasLimit,
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
    pollingAttesterDutiesTask*: Future[void]
    pollingSyncDutiesTask*: Future[void]
    pruneSlashingDatabaseTask*: Future[void]
    syncSubscriptionEpoch*: Opt[Epoch]
    lastSlashingEpoch*: Opt[Epoch]

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
    slotSig*: Opt[ValidatorSig]

  SyncCommitteeDuty* = RestSyncCommitteeDuty

  SyncCommitteeSubscriptionInfo* = object
    validator_index*: ValidatorIndex
    validator_sync_committee_indices*: seq[IndexInSyncCommittee]

  ProposerTask* = object
    duty*: RestProposerDuty
    proposeFut*: Future[void]
    randaoFut*: Future[void]

  ProposedData* = object
    epoch*: Epoch
    dependentRoot*: Eth2Digest
    duties*: seq[ProposerTask]

  BeaconNodeRole* {.pure.} = enum
    Duties,
    AttestationData, AttestationPublish,
    AggregatedData, AggregatedPublish,
    BlockProposalData, BlockProposalPublish,
    SyncCommitteeData, SyncCommitteePublish,
    NoTimeCheck

  RestBeaconNodeFeature* {.pure.} = enum
    NoNimbusExtensions  ## BN do not supports Nimbus Extensions

  TimeOffset* = object
    value: int64

  BeaconNodeServer* = object
    client*: RestClientRef
    uri*: Uri
    endpoint*: string
    config*: VCRuntimeConfig
    ident*: Opt[string]
    genesis*: Opt[RestGenesis]
    syncInfo*: Opt[RestSyncInfo]
    status*: RestBeaconNodeStatus
    features*: set[RestBeaconNodeFeature]
    roles*: set[BeaconNodeRole]
    logIdent*: string
    index*: int
    timeOffset*: Opt[TimeOffset]

  EpochSelectionProof* = object
    signatures*: array[SLOTS_PER_EPOCH.int, Opt[ValidatorSig]]
    sync_committee_index*: IndexInSyncCommittee

  SyncCommitteeSelectionProof* = seq[EpochSelectionProof]

  EpochDuties* = object
    duties*: Table[Epoch, DutyAndProof]

  SyncPeriodDuties* = object
    duties*: Table[SyncCommitteePeriod, SyncCommitteeDuty]

  SyncCommitteeProofs* = object
    proofs*: Table[ValidatorPubKey, SyncCommitteeSelectionProof]

  RestBeaconNodeStatus* {.pure.} = enum
    Invalid,            ## BN address is invalid.
    Noname,             ## BN address could not be resolved yet.
    Offline,            ## BN is offline.
    Online,             ## BN is online, passed checkOnline() check.
    Incompatible,       ## BN configuration is NOT compatible with VC.
    Compatible,         ## BN configuration is compatible with VC configuration.
    NotSynced,          ## BN is not in sync.
    OptSynced,          ## BN is optimistically synced (EL is not in sync).
    Synced,             ## BN and EL are synced.
    UnexpectedCode,     ## BN sends unexpected/incorrect HTTP status code .
    UnexpectedResponse, ## BN sends unexpected/incorrect response.
    BrokenClock,        ## BN wall clock is broken or has significan offset.
    InternalError       ## BN reports internal error.

  BeaconNodesCounters* = object
    data*: array[int(high(RestBeaconNodeStatus)) + 1, int]

  BeaconNodeServerRef* = ref BeaconNodeServer

  AttesterMap* = Table[ValidatorPubKey, EpochDuties]
  SyncCommitteeDutiesMap* = Table[ValidatorPubKey, SyncPeriodDuties]
  ProposerMap* = Table[Epoch, ProposedData]
  SyncCommitteeProofsMap* = Table[Epoch, SyncCommitteeProofs]

  DoppelgangerStatus* {.pure.} = enum
    None, Checking, Passed

  DoppelgangerAttempt* {.pure.} = enum
    None, Failure, SuccessTrue, SuccessFalse

  BlockWaiter* = object
    future*: Future[seq[Eth2Digest]]
    count*: int

  BlockDataItem* = object
    blocks: seq[Eth2Digest]
    waiters*: seq[BlockWaiter]

  ValidatorRuntimeConfig* = object
    altairEpoch*: Opt[Epoch]

  ValidatorClient* = object
    config*: ValidatorClientConf
    runtimeConfig*: ValidatorRuntimeConfig
    metricsServer*: Opt[MetricsHttpServerRef]
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
    preGenesisEvent*: AsyncEvent
    genesisEvent*: AsyncEvent
    forksAvailable*: AsyncEvent
    nodesAvailable*: AsyncEvent
    indicesAvailable*: AsyncEvent
    doppelExit*: AsyncEvent
    attesters*: AttesterMap
    proposers*: ProposerMap
    syncCommitteeDuties*: SyncCommitteeDutiesMap
    syncCommitteeProofs*: SyncCommitteeProofsMap
    beaconGenesis*: RestGenesis
    proposerTasks*: Table[Slot, seq[ProposerTask]]
    dynamicFeeRecipientsStore*: ref DynamicFeeRecipientsStore
    validatorsRegCache*: Table[ValidatorPubKey, SignedValidatorRegistrationV1]
    blocksSeen*: Table[Slot, BlockDataItem]
    rootsSeen*: Table[Eth2Digest, Slot]
    processingDelay*: Opt[Duration]
    finalizedEpoch*: Opt[Epoch]
    rng*: ref HmacDrbgContext

  ApiStrategyKind* {.pure.} = enum
    Priority, Best, First

  ApiFailure* {.pure.} = enum
    Communication, Invalid, NotFound, OptSynced, NotSynced, Internal,
    NotImplemented, UnexpectedCode, UnexpectedResponse, NoError

  ApiNodeFailure* = object
    node*: BeaconNodeServerRef
    request*: string
    strategy*: Opt[ApiStrategyKind]
    failure*: ApiFailure
    status*: Opt[int]
    reason*: string

  ValidatorClientRef* = ref ValidatorClient

  ValidatorClientError* = object of CatchableError
  ValidatorApiError* = object of ValidatorClientError
    data*: seq[ApiNodeFailure]

const
  DefaultDutyAndProof* = DutyAndProof(epoch: FAR_FUTURE_EPOCH)
  DefaultSyncCommitteeDuty* = SyncCommitteeDuty()
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
    BeaconNodeRole.SyncCommitteePublish
  }
    ## AllBeaconNodeRoles missing BeaconNodeRole.NoTimeCheck, because timecheks
    ## are enabled by default.

  AllBeaconNodeStatuses* = {
    RestBeaconNodeStatus.Invalid,
    RestBeaconNodeStatus.Noname,
    RestBeaconNodeStatus.Offline,
    RestBeaconNodeStatus.Online,
    RestBeaconNodeStatus.Incompatible,
    RestBeaconNodeStatus.Compatible,
    RestBeaconNodeStatus.NotSynced,
    RestBeaconNodeStatus.OptSynced,
    RestBeaconNodeStatus.Synced,
    RestBeaconNodeStatus.UnexpectedCode,
    RestBeaconNodeStatus.UnexpectedResponse,
    RestBeaconNodeStatus.BrokenClock,
    RestBeaconNodeStatus.InternalError
  }

  ResolvedBeaconNodeStatuses* = {
    RestBeaconNodeStatus.Offline,
    RestBeaconNodeStatus.Online,
    RestBeaconNodeStatus.Incompatible,
    RestBeaconNodeStatus.Compatible,
    RestBeaconNodeStatus.NotSynced,
    RestBeaconNodeStatus.OptSynced,
    RestBeaconNodeStatus.Synced,
    RestBeaconNodeStatus.UnexpectedCode,
    RestBeaconNodeStatus.UnexpectedResponse,
    RestBeaconNodeStatus.BrokenClock,
    RestBeaconNodeStatus.InternalError
  }

proc `$`*(to: TimeOffset): string =
  if to.value < 0:
    "-" & $chronos.nanoseconds(-to.value)
  else:
    $chronos.nanoseconds(to.value)

chronicles.formatIt(TimeOffset):
  $it

chronicles.formatIt(Opt[TimeOffset]):
  if it.isSome(): $(it.get()) else: "<unknown>"

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
      if BeaconNodeRole.NoTimeCheck in roles:
        res.add("no-timecheck")
      res.join(",")
    else:
      "{all}"
  else:
    "{}"

proc `$`*(status: RestBeaconNodeStatus): string =
  case status
  of RestBeaconNodeStatus.Invalid: "invalid-address"
  of RestBeaconNodeStatus.Noname: "dns-error"
  of RestBeaconNodeStatus.Offline: "offline"
  of RestBeaconNodeStatus.Online: "online"
  of RestBeaconNodeStatus.Incompatible: "incompatible"
  of RestBeaconNodeStatus.Compatible: "compatible"
  of RestBeaconNodeStatus.NotSynced: "bn-unsynced"
  of RestBeaconNodeStatus.OptSynced: "el-unsynced"
  of RestBeaconNodeStatus.Synced: "synced"
  of RestBeaconNodeStatus.UnexpectedCode: "unexpected code"
  of RestBeaconNodeStatus.UnexpectedResponse: "unexpected data"
  of RestBeaconNodeStatus.InternalError: "internal error"
  of RestBeaconNodeStatus.BrokenClock: "broken clock"

proc `$`*(failure: ApiFailure): string =
  case failure
  of ApiFailure.Communication: "communication"
  of ApiFailure.Invalid: "invalid-request"
  of ApiFailure.NotFound: "not-found"
  of ApiFailure.NotSynced: "not-synced"
  of ApiFailure.OptSynced: "opt-synced"
  of ApiFailure.Internal: "internal-issue"
  of ApiFailure.NotImplemented: "not-implemented"
  of ApiFailure.UnexpectedCode: "unexpected-code"
  of ApiFailure.UnexpectedResponse: "unexpected-data"
  of ApiFailure.NoError: "status-update"

proc getNodeCounts*(vc: ValidatorClientRef): BeaconNodesCounters =
  var res = BeaconNodesCounters()
  for node in vc.beaconNodes: inc(res.data[int(node.status)])
  res

proc hash*(f: ApiNodeFailure): Hash =
  hash(f.failure)

proc toString*(strategy: ApiStrategyKind): string =
  case strategy
  of ApiStrategyKind.First:
    "first"
  of ApiStrategyKind.Best:
    "best"
  of ApiStrategyKind.Priority:
    "priority"

func getFailureReason*(failure: ApiNodeFailure): string =
  let status =
    if failure.status.isSome():
      Base10.toString(uint32(failure.status.get()))
    else:
      "n/a"
  let request =
    if failure.strategy.isSome():
      failure.request & "(" & failure.strategy.get().toString() & ")"
    else:
      failure.request & "()"
  [failure.reason, status, request, $failure.failure].join(";")

proc getFailureReason*(exc: ref ValidatorApiError): string =
  let
    errors = exc[].data
    errorsCount = len(errors)

  if errorsCount > 1:
    let distinctErrors =
      block:
        var res: seq[ApiNodeFailure]
        for item in errors.toHashSet().items():
          res.add(item)
        res
    if len(distinctErrors) > 1:
      # If we have many unique errors, we going to report only failures,
      # full reasons could be obtained via previosly made log statements.
      "[" & distinctErrors.mapIt($it.failure).join(",") & "]"
    else:
      getFailureReason(distinctErrors[0])
  elif errorsCount == 1:
    getFailureReason(errors[0])
  else:
    exc.msg

proc shortLog*(roles: set[BeaconNodeRole]): string =
  var r = "AGBSDT"
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
  if BeaconNodeRole.NoTimeCheck notin roles: r[5] = 'T' else: r[5] = '-'
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

proc validatorLog*(validator: AttachedValidator): string =
  var res = shortLog(validator)
  res.add('@')
  if validator.index.isSome():
    res.add(Base10.toString(uint64(validator.index.get())))
  else:
    res.add("<missing>")
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
  validator_sync_committee_indices = it.validator_sync_committee_indices

proc equals*(info: VCRuntimeConfig, name: string, check: uint64): bool =
  let numstr = info.getOrDefault(name, "missing")
  if numstr == "missing": return false
  let value = Base10.decode(uint64, numstr).valueOr:
    return false
  value == check

proc equals*(info: VCRuntimeConfig, name: string, check: DomainType): bool =
  let domstr = info.getOrDefault(name, "missing")
  if domstr == "missing": return false
  let value =
    try:
      var dres: DomainType
      hexToByteArray(domstr, distinctBase(dres))
      dres
    except ValueError:
      return false
  value == check

proc equals*(info: VCRuntimeConfig, name: string, check: Epoch): bool =
  info.equals(name, uint64(check))

proc getOrDefault*(info: VCRuntimeConfig, name: string,
                   default: uint64): uint64 =
  let numstr = info.getOrDefault(name, "missing")
  if numstr == "missing": return default
  Base10.decode(uint64, numstr).valueOr:
    return default

proc getOrDefault*(info: VCRuntimeConfig, name: string, default: Epoch): Epoch =
  Epoch(info.getOrDefault(name, uint64(default)))

proc checkConfig*(c: VCRuntimeConfig): bool =
  c.equals("MAX_VALIDATORS_PER_COMMITTEE", MAX_VALIDATORS_PER_COMMITTEE) and
  c.equals("SLOTS_PER_EPOCH", SLOTS_PER_EPOCH) and
  c.equals("SECONDS_PER_SLOT", SECONDS_PER_SLOT) and
  c.equals("EPOCHS_PER_ETH1_VOTING_PERIOD", EPOCHS_PER_ETH1_VOTING_PERIOD) and
  c.equals("SLOTS_PER_HISTORICAL_ROOT", SLOTS_PER_HISTORICAL_ROOT) and
  c.equals("EPOCHS_PER_HISTORICAL_VECTOR", EPOCHS_PER_HISTORICAL_VECTOR) and
  c.equals("EPOCHS_PER_SLASHINGS_VECTOR", EPOCHS_PER_SLASHINGS_VECTOR) and
  c.equals("HISTORICAL_ROOTS_LIMIT", HISTORICAL_ROOTS_LIMIT) and
  c.equals("VALIDATOR_REGISTRY_LIMIT", VALIDATOR_REGISTRY_LIMIT) and
  c.equals("MAX_PROPOSER_SLASHINGS", MAX_PROPOSER_SLASHINGS) and
  c.equals("MAX_ATTESTER_SLASHINGS", MAX_ATTESTER_SLASHINGS) and
  c.equals("MAX_ATTESTATIONS", MAX_ATTESTATIONS) and
  c.equals("MAX_DEPOSITS", MAX_DEPOSITS) and
  c.equals("MAX_VOLUNTARY_EXITS", MAX_VOLUNTARY_EXITS) and
  c.equals("DOMAIN_BEACON_PROPOSER", DOMAIN_BEACON_PROPOSER) and
  c.equals("DOMAIN_BEACON_ATTESTER", DOMAIN_BEACON_ATTESTER) and
  c.equals("DOMAIN_RANDAO", DOMAIN_RANDAO) and
  c.equals("DOMAIN_DEPOSIT", DOMAIN_DEPOSIT) and
  c.equals("DOMAIN_VOLUNTARY_EXIT", DOMAIN_VOLUNTARY_EXIT) and
  c.equals("DOMAIN_SELECTION_PROOF", DOMAIN_SELECTION_PROOF) and
  c.equals("DOMAIN_AGGREGATE_AND_PROOF", DOMAIN_AGGREGATE_AND_PROOF) and
  c.hasKey("ALTAIR_FORK_VERSION") and c.hasKey("ALTAIR_FORK_EPOCH") and
  not(c.equals("ALTAIR_FORK_EPOCH", FAR_FUTURE_EPOCH))

proc updateStatus*(node: BeaconNodeServerRef,
                   status: RestBeaconNodeStatus,
                   failure: ApiNodeFailure) =
  logScope:
    node = node

  case status
  of RestBeaconNodeStatus.Invalid:
    if node.status != status:
      warn "Beacon node could not be used"
      node.status = status
  of RestBeaconNodeStatus.Noname:
    if node.status != status:
      warn "Beacon node address cannot be resolved"
      node.status = status
  of RestBeaconNodeStatus.Offline:
    if node.status != status:
      if node.status in {RestBeaconNodeStatus.Invalid,
                         RestBeaconNodeStatus.Noname}:
        notice "Beacon node address has been resolved"
        node.status = status
      else:
        warn "Beacon node down", reason = failure.getFailureReason()
        node.status = status
  of RestBeaconNodeStatus.Online:
    if node.status != status:
      let version = if node.ident.isSome(): node.ident.get() else: "<missing>"
      notice "Beacon node is online", agent_version = version
      node.status = status
  of RestBeaconNodeStatus.Incompatible:
    if node.status != status:
      warn "Beacon node has incompatible configuration",
           reason = failure.getFailureReason()
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
      warn "Beacon node not in sync", reason = failure.getFailureReason(),
           last_head_slot = si.head_slot,
           last_sync_distance = si.sync_distance,
           last_optimistic = si.is_optimistic.get(false)
      node.status = status
  of RestBeaconNodeStatus.OptSynced:
    if node.status != status:
      doAssert(node.syncInfo.isSome())
      let si = node.syncInfo.get()
      notice "Beacon node optimistically synced (Execution client not in sync)",
             reason = failure.getFailureReason(),
             last_head_slot = si.head_slot,
             last_sync_distance = si.sync_distance,
             last_optimistic = si.is_optimistic.get(false)
      node.status = status
  of RestBeaconNodeStatus.Synced:
    if node.status != status:
      doAssert(node.syncInfo.isSome())
      let si = node.syncInfo.get()
      notice "Beacon node is in sync",
             head_slot = si.head_slot,
             sync_distance = si.sync_distance,
             is_optimistic = si.is_optimistic.get(false)
      node.status = status
  of RestBeaconNodeStatus.UnexpectedResponse:
    if node.status != status:
      error "Beacon node provides unexpected response",
            reason = failure.getFailureReason()
      node.status = status
  of RestBeaconNodeStatus.UnexpectedCode:
    if node.status != status:
      error "Beacon node provides unexpected status code",
            reason = failure.getFailureReason()
      node.status = status
  of RestBeaconNodeStatus.InternalError:
    if node.status != status:
      warn "Beacon node reports internal error",
           reason = failure.getFailureReason()
      node.status = status
  of RestBeaconNodeStatus.BrokenClock:
    if node.status != status:
      warn "Beacon node's clock is out of order, (beacon node is unusable)"
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
  dap.epoch == FAR_FUTURE_EPOCH

proc isDefault*(prd: ProposedData): bool =
  prd.epoch == FAR_FUTURE_EPOCH

proc isDefault*(scd: SyncCommitteeDuty): bool =
  len(scd.validator_sync_committee_indices) == 0

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
    of "no-timecheck":
      res.incl(BeaconNodeRole.NoTimeCheck)
    else:
      return err("Invalid beacon node role string found")
  if res == {BeaconNodeRole.NoTimeCheck}:
    res.incl(AllBeaconNodeRoles)
  ok(res)

proc normalizeUri*(r: Uri): Result[Uri, cstring] =
  const
    MissingPortNumber = cstring("Missing port number")
    MissingHostname = cstring("Missing hostname")
    UnknownScheme = cstring("Unknown scheme value")

  if ($r).toLowerAscii().startsWith("http://") or
     ($r).toLowerAscii().startsWith("https://"):
    # When a scheme is provided, only a hostname is required
    if len(r.hostname) == 0: return err(MissingHostname)
    return ok(r)

  # Check for unknown scheme
  if ($r).contains("://"):
    return err(UnknownScheme)

  # Add the default scheme (http)
  let normalized =
    if ($r).startsWith("//"):
      parseUri("http:" & $r)
    else:
      parseUri("http://" & $r)

  if len(normalized.hostname) == 0:
    return err(MissingHostname)

  if len(normalized.port) == 0:
    return err(MissingPortNumber)

  ok(normalized)

proc initClient*(uri: Uri): Result[RestClientRef, HttpAddressErrorType] =
  let
    flags = {RestClientFlag.CommaSeparatedArray}
    socketFlags = {SocketFlags.TcpNoDelay}
    address = ? getHttpAddress(uri)
    client = RestClientRef.new(address, flags = flags,
                               socketFlags = socketFlags)
  ok(client)

proc init*(t: typedesc[BeaconNodeServerRef], remote: Uri,
           index: int): Result[BeaconNodeServerRef, string] =
  doAssert(index >= 0)
  let
    remoteUri = normalizeUri(remote).valueOr:
      return err($error)
    roles = parseRoles(remoteUri.anchor).valueOr:
      return err($error)
    server =
      block:
        let res = initClient(remoteUri)
        if res.isOk():
          BeaconNodeServerRef(
            client: res.get(), endpoint: $remoteUri, index: index,
            roles: roles, logIdent: $(res.get().address.getUri()),
            uri: remoteUri, status: RestBeaconNodeStatus.Offline)
        else:
          if res.error.isCriticalError():
            return err(res.error.toString())
          BeaconNodeServerRef(
            client: nil, endpoint: $remoteUri, index: index,
            roles: roles, logIdent: $remoteUri, uri: remoteUri,
            status: RestBeaconNodeStatus.Noname)
  ok(server)

proc getMissingRoles*(n: openArray[BeaconNodeServerRef]): set[BeaconNodeRole] =
  var res: set[BeaconNodeRole] = AllBeaconNodeRoles
  for node in n.items():
    res.excl(node.roles)
  res

proc init*(t: typedesc[DutyAndProof], epoch: Epoch, dependentRoot: Eth2Digest,
           duty: RestAttesterDuty,
           slotSig: Opt[ValidatorSig]): DutyAndProof =
  DutyAndProof(epoch: epoch, dependentRoot: dependentRoot, data: duty,
               slotSig: slotSig)

proc init*(t: typedesc[ProposedData], epoch: Epoch, dependentRoot: Eth2Digest,
           data: openArray[ProposerTask]): ProposedData =
  ProposedData(epoch: epoch, dependentRoot: dependentRoot, duties: @data)

proc getCurrentSlot*(vc: ValidatorClientRef): Opt[Slot] =
  let res = vc.beaconClock.now().toSlot()
  if res.afterGenesis:
    Opt.some(res.slot)
  else:
    Opt.none(Slot)

proc getAttesterDutiesForSlot*(vc: ValidatorClientRef,
                               slot: Slot): seq[DutyAndProof] =
  ## Returns all `DutyAndProof` for the given `slot`.
  var res: seq[DutyAndProof]
  let epoch = slot.epoch()
  for key, item in mpairs(vc.attesters):
    item.duties.withValue(epoch, duty):
      if duty[].data.slot == slot:
        res.add(duty[])
  res

proc getSyncCommitteeDutiesForSlot*(vc: ValidatorClientRef,
                                    slot: Slot): seq[SyncCommitteeDuty] =
  ## Returns all `SyncCommitteeDuty` for the given `slot`.
  var res: seq[SyncCommitteeDuty]
  let period = slot.sync_committee_period()
  for key, item in mpairs(vc.syncCommitteeDuties):
    item.duties.withValue(period, duty):
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

iterator syncDutiesForPeriod*(vc: ValidatorClientRef,
                              period: SyncCommitteePeriod): SyncCommitteeDuty =
  for key, item in vc.syncCommitteeDuties:
    let periodDuties = item.duties.getOrDefault(period)
    if not(isDefault(periodDuties)):
      yield periodDuties

proc syncMembersSubscriptionInfoForPeriod*(
       vc: ValidatorClientRef,
       period: SyncCommitteePeriod
     ): seq[SyncCommitteeSubscriptionInfo] =
  var res: seq[SyncCommitteeSubscriptionInfo]
  for key, item in mpairs(vc.syncCommitteeDuties):
    var cur: SyncCommitteeSubscriptionInfo
    var initialized = false

    item.duties.withValue(period, periodDuties):
      if not(initialized):
        cur.validator_index = periodDuties[].validator_index
        initialized = true
      cur.validator_sync_committee_indices.add(
        periodDuties[].validator_sync_committee_indices)

    if initialized:
      res.add(cur)
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
    withdrawalAddress =
      if vc.keymanagerHost.isNil:
        Opt.none Eth1Address
      else:
        vc.keymanagerHost[].getValidatorWithdrawalAddress(keystore.pubkey)
    perValidatorDefaultFeeRecipient = getPerValidatorDefaultFeeRecipient(
      vc.config.defaultFeeRecipient, withdrawalAddress)
    feeRecipient = vc.config.validatorsDir.getSuggestedFeeRecipient(
      keystore.pubkey, perValidatorDefaultFeeRecipient).valueOr(
        perValidatorDefaultFeeRecipient)
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
    let
      withdrawalAddress =
        if vc.keymanagerHost.isNil:
          Opt.none Eth1Address
        else:
          vc.keymanagerHost[].getValidatorWithdrawalAddress(pubkey)
      perValidatorDefaultFeeRecipient = getPerValidatorDefaultFeeRecipient(
        vc.config.defaultFeeRecipient, withdrawalAddress)
      staticRecipient = getSuggestedFeeRecipient(
        vc.config.validatorsDir, pubkey, perValidatorDefaultFeeRecipient)
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

proc isExpired(vc: ValidatorClientRef,
               reg: SignedValidatorRegistrationV1, slot: Slot): bool =
  # https://github.com/ethereum/builder-specs/blob/v0.3.0/specs/bellatrix/validator.md#registration-dissemination
  # This specification suggests validators re-submit to builder software every
  # `EPOCHS_PER_VALIDATOR_REGISTRATION_SUBMISSION` epochs.
  let
    regTime = fromUnix(int64(reg.message.timestamp))
    regSlot =
      block:
        let res = vc.beaconClock.toSlot(regTime)
        if not(res.afterGenesis):
          # This case should not have happened, but it could in case of time
          # jumps (time could be modified by admin or ntpd).
          return false
        uint64(res.slot)

  if regSlot > slot:
    # This case should not have happened, but if it happens (time could be
    # modified by admin or ntpd).
    false
  else:
    (slot - regSlot) div SLOTS_PER_EPOCH >=
      EPOCHS_BETWEEN_VALIDATOR_REGISTRATION

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
    if not cached.isDefault():
      # Want to send it to relay, but not recompute perfectly fine cache
      return ok(PendingValidatorRegistration(registration: cached, future: nil))

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
      if not(sigfut.completed()):
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
    if future.completed():
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

func init*(t: typedesc[ApiNodeFailure], failure: ApiFailure,
           request: string, strategy: ApiStrategyKind,
           node: BeaconNodeServerRef): ApiNodeFailure =
  ApiNodeFailure(node: node, request: request, strategy: Opt.some(strategy),
                 failure: failure)

func init*(t: typedesc[ApiNodeFailure], failure: ApiFailure,
           request: string, strategy: ApiStrategyKind,
           node: BeaconNodeServerRef, reason: string): ApiNodeFailure =
  ApiNodeFailure(node: node, request: request, strategy: Opt.some(strategy),
                 failure: failure, reason: reason)

func init*(t: typedesc[ApiNodeFailure], failure: ApiFailure,
           request: string, strategy: ApiStrategyKind,
           node: BeaconNodeServerRef, status: int,
           reason: string): ApiNodeFailure =
  ApiNodeFailure(node: node, request: request, strategy: Opt.some(strategy),
                 failure: failure, status: Opt.some(status), reason: reason)

func init*(t: typedesc[ApiNodeFailure], failure: ApiFailure,
           request: string, node: BeaconNodeServerRef, status: int,
           reason: string): ApiNodeFailure =
  ApiNodeFailure(node: node, request: request,
                 failure: failure, status: Opt.some(status), reason: reason)

func init*(t: typedesc[ApiNodeFailure], failure: ApiFailure,
           request: string, node: BeaconNodeServerRef,
           reason: string): ApiNodeFailure =
  ApiNodeFailure(node: node, request: request, failure: failure, reason: reason)

proc checkedWaitForSlot*(vc: ValidatorClientRef, destinationSlot: Slot,
                         offset: TimeDiff,
                         showLogs: bool): Future[Opt[Slot]] {.async.} =
  let
    currentTime = vc.beaconClock.now()
    currentSlot = currentTime.slotOrZero()
    chronosOffset = chronos.nanoseconds(
      if offset.nanoseconds < 0: 0'i64 else: offset.nanoseconds)

  var timeToSlot = (destinationSlot.start_beacon_time() - currentTime) +
                   chronosOffset

  logScope:
    start_time = shortLog(currentTime)
    start_slot = shortLog(currentSlot)
    dest_slot = shortLog(destinationSlot)
    time_to_slot = shortLog(timeToSlot)

  while true:
    await sleepAsync(timeToSlot)

    let
      wallTime = vc.beaconClock.now()
      wallSlot = wallTime.slotOrZero()

    logScope:
      wall_time = shortLog(wallTime)
      wall_slot = shortLog(wallSlot)

    if wallSlot < destinationSlot:
      # While we were sleeping, the system clock changed and time moved
      # backwards!
      if wallSlot + 1 < destinationSlot:
        # This is a critical condition where it's hard to reason about what
        # to do next - we'll call the attention of the user here by shutting
        # down.
        if showLogs:
          fatal "System time adjusted backwards significantly - " &
                "clock may be inaccurate - shutting down"
        return Opt.none(Slot)
      else:
        # Time moved back by a single slot - this could be a minor adjustment,
        # for example when NTP does its thing after not working for a while
        timeToSlot = destinationSlot.start_beacon_time() - wallTime +
                     chronosOffset
        if showLogs:
          warn "System time adjusted backwards, rescheduling slot actions"
        continue

    elif wallSlot > destinationSlot + SLOTS_PER_EPOCH:
      if showLogs:
        warn "Time moved forwards by more than an epoch, skipping ahead"
      return Opt.some(wallSlot)

    elif wallSlot > destinationSlot:
      if showLogs:
        notice "Missed expected slot start, catching up"
      return Opt.some(wallSlot)

    else:
      return Opt.some(destinationSlot)

proc checkedWaitForNextSlot*(vc: ValidatorClientRef, curSlot: Opt[Slot],
                             offset: TimeDiff,
                             showLogs: bool): Future[Opt[Slot]] =
  let
    currentTime = vc.beaconClock.now()
    currentSlot = curSlot.valueOr: currentTime.slotOrZero()
    nextSlot = currentSlot + 1

  vc.checkedWaitForSlot(nextSlot, offset, showLogs)

proc checkedWaitForNextSlot*(vc: ValidatorClientRef, offset: TimeDiff,
                             showLogs: bool): Future[Opt[Slot]] =
  let
    currentTime = vc.beaconClock.now()
    currentSlot = currentTime.slotOrZero()
    nextSlot = currentSlot + 1

  vc.checkedWaitForSlot(nextSlot, offset, showLogs)

proc expectBlock*(vc: ValidatorClientRef, slot: Slot,
                  confirmations: int = 1): Future[seq[Eth2Digest]] =
  var
    retFuture = newFuture[seq[Eth2Digest]]("expectBlock")
    waiter = BlockWaiter(future: retFuture, count: confirmations)

  proc cancellation(udata: pointer) =
    vc.blocksSeen.withValue(slot, adata):
      adata[].waiters.keepItIf(it.future != retFuture)

  proc scheduleCallbacks(data: var BlockDataItem,
                         waiter: BlockWaiter) =
    data.waiters.add(waiter)
    for mitem in data.waiters.mitems():
      if mitem.count <= len(data.blocks):
        if not(mitem.future.finished()): mitem.future.complete(data.blocks)

  vc.blocksSeen.mgetOrPut(slot, BlockDataItem()).scheduleCallbacks(waiter)
  if not(retFuture.finished()): retFuture.cancelCallback = cancellation
  retFuture

proc registerBlock*(vc: ValidatorClientRef, eblck: EventBeaconBlockObject,
                    node: BeaconNodeServerRef) =
  let
    wallTime = vc.beaconClock.now()
    delay = wallTime - eblck.slot.start_beacon_time()

  debug "Block received", slot = eblck.slot,
        block_root = shortLog(eblck.block_root), optimistic = eblck.optimistic,
        node = node, delay = delay

  proc scheduleCallbacks(data: var BlockDataItem,
                         blck: EventBeaconBlockObject) =
    vc.rootsSeen[blck.block_root] = blck.slot
    data.blocks.add(blck.block_root)
    for mitem in data.waiters.mitems():
      if mitem.count >= len(data.blocks):
        if not(mitem.future.finished()): mitem.future.complete(data.blocks)

  vc.blocksSeen.mgetOrPut(eblck.slot, BlockDataItem()).scheduleCallbacks(eblck)

proc pruneBlocksSeen*(vc: ValidatorClientRef, epoch: Epoch) =
  var blocksSeen: Table[Slot, BlockDataItem]
  for slot, item in vc.blocksSeen.pairs():
    if (slot.epoch() + HISTORICAL_DUTIES_EPOCHS) >= epoch:
      blocksSeen[slot] = item
    else:
      for root in item.blocks: vc.rootsSeen.del(root)
      let blockRoot =
        if len(item.blocks) == 0:
          "<missing>"
        elif len(item.blocks) == 1:
          shortLog(item.blocks[0])
        else:
          "[" & item.blocks.mapIt(shortLog(it)).join(", ") & "]"
      debug "Block data has been pruned", slot = slot, blocks = blockRoot
  vc.blocksSeen = blocksSeen

proc waitForBlock*(
       vc: ValidatorClientRef,
       slot: Slot,
       timediff: TimeDiff,
       confirmations: int = 1
     ) {.async.} =
  ## This procedure will wait for a block proposal for a ``slot`` received
  ## by the beacon node.
  let
    startTime = Moment.now()
    waitTime = (start_beacon_time(slot) + timediff) - vc.beaconClock.now()

  logScope:
    slot = slot
    timediff = timediff
    wait_time = waitTime

  debug "Waiting for block proposal"

  if waitTime.nanoseconds <= 0'i64:
    # We do not have time to wait for block.
    return

  let blocks =
    try:
      let timeout = nanoseconds(waitTime.nanoseconds)
      await vc.expectBlock(slot, confirmations).wait(timeout)
    except AsyncTimeoutError:
      let dur = Moment.now() - startTime
      debug "Block has not been received in time", duration = dur
      return
    except CancelledError as exc:
      let dur = Moment.now() - startTime
      debug "Block awaiting was interrupted", duration = dur
      raise exc
    except CatchableError as exc:
      let dur = Moment.now() - startTime
      error "Unexpected error occured while waiting for block publication",
            err_name = exc.name, err_msg = exc.msg, duration = dur
      return

  let
    dur = Moment.now() - startTime
    blockRoot =
      if len(blocks) == 0:
        "<missing>"
      elif len(blocks) == 1:
        shortLog(blocks[0])
      else:
        "[" & blocks.mapIt(shortLog(it)).join(", ") & "]"

  debug "Block proposal awaited", duration = dur,
        block_root = blockRoot

  try:
    await waitAfterBlockCutoff(vc.beaconClock, slot)
  except CancelledError as exc:
    let dur = Moment.now() - startTime
    debug "Waiting for block cutoff was interrupted", duration = dur
    raise exc

iterator chunks*[T](data: openArray[T], maxCount: Positive): seq[T] =
  for i in countup(0, len(data) - 1, maxCount):
    yield @(data.toOpenArray(i, min(i + maxCount, len(data)) - 1))

func init*(t: typedesc[TimeOffset], duration: Duration): TimeOffset =
  TimeOffset(value: duration.nanoseconds)

func init*(t: typedesc[TimeOffset], offset: int64): TimeOffset =
  TimeOffset(value: offset)

func abs*(to: TimeOffset): TimeOffset =
  TimeOffset(value: abs(to.value))

func milliseconds*(to: TimeOffset): int64 =
  if to.value < 0:
    -nanoseconds(-to.value).milliseconds
  else:
    nanoseconds(-to.value).milliseconds

func `<`*(a, b: TimeOffset): bool = a.value < b.value
func `<=`*(a, b: TimeOffset): bool = a.value <= b.value
func `==`*(a, b: TimeOffset): bool = a.value == b.value

func nanoseconds*(to: TimeOffset): int64 = to.value

proc waitForNextEpoch*(service: ClientServiceRef,
                       delay: Duration) {.async.} =
  let
    vc = service.client
    sleepTime = vc.beaconClock.durationToNextEpoch() + delay
  debug "Sleeping until next epoch", service = service.name,
                                     sleep_time = sleepTime, delay = delay
  await sleepAsync(sleepTime)

proc waitForNextEpoch*(service: ClientServiceRef): Future[void] =
  waitForNextEpoch(service, ZeroDuration)

proc waitForNextSlot*(service: ClientServiceRef) {.async.} =
  let vc = service.client
  let sleepTime = vc.beaconClock.durationToNextSlot()
  await sleepAsync(sleepTime)

func compareUnsorted*[T](a, b: openArray[T]): bool =
  if len(a) != len(b):
    return false

  return
    case len(a)
    of 0:
      true
    of 1:
      a[0] == b[0]
    of 2:
      ((a[0] == b[0]) and (a[1] == b[1])) or ((a[0] == b[1]) and (a[1] == b[0]))
    else:
      let asorted = sorted(a)
      let bsorted = sorted(b)
      for index, item in asorted.pairs():
        if item != bsorted[index]:
          return false
      true

func `==`*(a, b: SyncCommitteeDuty): bool =
  (a.pubkey == b.pubkey) and
  (a.validator_index == b.validator_index) and
  compareUnsorted(a.validator_sync_committee_indices,
                  b.validator_sync_committee_indices)

proc updateRuntimeConfig*(vc: ValidatorClientRef,
                          node: BeaconNodeServerRef,
                          info: VCRuntimeConfig): Result[void, string] =
  if not(info.hasKey("ALTAIR_FORK_EPOCH")):
    debug "Beacon node's configuration missing ALTAIR_FORK_EPOCH value",
          node = node

  let
    res = info.getOrDefault("ALTAIR_FORK_EPOCH", FAR_FUTURE_EPOCH)
    wallEpoch = vc.beaconClock.now().slotOrZero().epoch()

  return
    if vc.runtimeConfig.altairEpoch.get(FAR_FUTURE_EPOCH) == FAR_FUTURE_EPOCH:
      vc.runtimeConfig.altairEpoch = Opt.some(res)
      ok()
    else:
      if res == vc.runtimeConfig.altairEpoch.get():
        ok()
      else:
        if res == FAR_FUTURE_EPOCH:
          if wallEpoch < vc.runtimeConfig.altairEpoch.get():
            debug "Beacon node must be updated before Altair activates",
                  node = node,
                  altairForkEpoch = vc.runtimeConfig.altairEpoch.get()
            ok()
          else:
            err("Beacon node must be updated and report correct " &
                "ALTAIR_FORK_EPOCH value")
        else:
          err("Beacon node has conflicting ALTAIR_FORK_EPOCH value")

proc `+`*(slot: Slot, epochs: Epoch): Slot =
  slot + uint64(epochs) * SLOTS_PER_EPOCH

func finish_slot*(epoch: Epoch): Slot =
  ## Return the last slot of ``epoch``.
  Slot((epoch + 1).start_slot() - 1)
