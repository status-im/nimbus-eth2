import presto,
       nimcrypto/utils as ncrutils,
       ../spec/[forks],
       ../spec/eth2_apis/[rest_types, eth2_rest_serialization],
       ../beacon_node_common,
       ../consensus_object_pools/[block_pools_types, blockchain_dag]

export
  eth2_rest_serialization, blockchain_dag, presto, rest_types

const
  MaxEpoch* = compute_epoch_at_slot(not(0'u64))

  BlockValidationError* =
    "The block failed validation, but was successfully broadcast anyway. It " &
    "was not integrated into the beacon node's database."
  BlockValidationSuccess* =
    "The block was validated successfully and has been broadcast"
  BeaconNodeInSyncError* =
    "Beacon node is currently syncing and not serving request on that endpoint"
  BlockNotFoundError* =
    "Block header/data has not been found"
  BlockProduceError* =
    "Could not produce the block"
  EmptyRequestBodyError* =
    "Empty request's body"
  InvalidBlockObjectError* =
    "Unable to decode block object(s)"
  InvalidAttestationObjectError* =
    "Unable to decode attestation object(s)"
  AttestationValidationError* =
    "Some errors happened while validating attestation(s)"
  AttestationValidationSuccess* =
    "Attestation object(s) was broadcasted"
  InvalidAttesterSlashingObjectError* =
    "Unable to decode attester slashing object(s)"
  AttesterSlashingValidationError* =
    "Invalid attester slashing, it will never pass validation so it's rejected"
  AttesterSlashingValidationSuccess* =
    "Attester slashing object was broadcasted"
  InvalidProposerSlashingObjectError* =
    "Unable to decode proposer slashing object(s)"
  ProposerSlashingValidationError* =
    "Invalid proposer slashing, it will never pass validation so it's rejected"
  ProposerSlashingValidationSuccess* =
    "Proposer slashing object was broadcasted"
  InvalidVoluntaryExitObjectError* =
    "Unable to decode voluntary exit object(s)"
  VoluntaryExitValidationError* =
    "Invalid voluntary exit, it will never pass validation so it's rejected"
  VoluntaryExitValidationSuccess* =
    "Voluntary exit object(s) was broadcasted"
  InvalidAggregateAndProofObjectError* =
    "Unable to decode aggregate and proof object(s)"
  AggregateAndProofValidationError* =
    "Invalid aggregate and proof, it will never pass validation so it's " &
    "rejected"
  AggregateAndProofValidationSuccess* =
    "Aggregate and proof object(s) was broadcasted"
  BeaconCommitteeSubscriptionSuccess* =
    "Beacon node processed committee subscription request"
  InvalidParentRootValueError* =
    "Invalid parent root value"
  MissingSlotValueError* =
    "Missing `slot` value"
  InvalidSlotValueError* =
    "Invalid slot value"
  MissingCommitteeIndexValueError* =
    "Missing `committee_index` value"
  InvalidCommitteeIndexValueError* =
    "Invalid committee index value"
  MissingAttestationDataRootValueError* =
    "Missing `attestation_data_root` value"
  InvalidAttestationDataRootValueError* =
    "Invalid attestation data root value"
  UnableToGetAggregatedAttestationError* =
    "Unable to retrieve an aggregated attestation"
  MissingRandaoRevealValue* =
    "Missing `randao_reveal` value"
  InvalidRandaoRevealValue* =
    "Invalid randao reveal value"
  InvalidGraffitiBytesValye* =
    "Invalid graffiti bytes value"
  InvalidEpochValueError* =
    "Invalid epoch value"
  InvalidStateIdValueError* =
    "Invalid state identifier value"
  InvalidBlockIdValueError* =
    "Invalid block identifier value"
  InvalidValidatorIdValueError* =
    "Invalid validator's identifier value(s)"
  MaximumNumberOfValidatorIdsError* =
    "Maximum number of validator identifier values exceeded"
  InvalidValidatorStatusValueError* =
    "Invalid validator's status value error"
  InvalidValidatorIndexValueError* =
    "Invalid validator's index value(s)"
  EmptyValidatorIndexArrayError* =
    "Empty validator's index array"
  InvalidSubscriptionRequestValueError* =
    "Invalid subscription request object(s)"
  ValidatorNotFoundError* =
    "Could not find validator"
  ValidatorStatusNotFoundError* =
    "Could not obtain validator's status"
  UniqueValidatorKeyError* =
    "Only unique validator's keys are allowed"
  TooHighValidatorIndexValueError* =
    "Validator index exceeds maximum number of validators allowed"
  UnsupportedValidatorIndexValueError* =
    "Validator index exceeds maximum supported number of validators"
  UniqueValidatorIndexError* =
    "Only unique validator's index are allowed"
  StateNotFoundError* =
    "State not found"
  SlotNotFoundError* =
    "Slot number is too far away"
  SlotNotInNextWallSlotEpochError* =
    "Requested slot not in next wall-slot epoch"
  SlotFromThePastError* =
    "Requested slot from the past"
  ProposerNotFoundError* =
    "Could not find proposer for the head and slot"
  NoHeadForSlotError* =
    "Cound not find head for slot"
  EpochOverflowValueError* =
    "Requesting epoch for which slot would overflow"
  InvalidPeerStateValueError* =
    "Invalid peer's state value(s) error"
  InvalidPeerDirectionValueError* =
    "Invalid peer's direction value(s) error"
  InvalidPeerIdValueError* =
    "Invalid peer's id value(s) error"
  PeerNotFoundError* =
    "Peer not found"
  InvalidLogLevelValueError* =
    "Invalid log level value error"
  ContentNotAcceptableError* =
    "Could not find out accepted content type"
  InvalidAcceptError* =
    "Incorrect accept response type"
  InternalServerError* =
    "Internal server error"
  NoImplementationError* =
    "Not implemented yet"

type
  ValidatorIndexError* {.pure.} = enum
    UnsupportedValue, TooHighValue

func match(data: openarray[char], charset: set[char]): int =
  for ch in data:
    if ch notin charset:
      return 1
  0

proc validate(key: string, value: string): int =
  ## This is rough validation procedure which should be simple and fast,
  ## because it will be used for query routing.
  case key
  of "{epoch}":
    0
  of "{slot}":
    0
  of "{peer_id}":
    0
  of "{state_id}":
    0
  of "{block_id}":
    0
  of "{validator_id}":
    0
  else:
    1

proc getCurrentHead*(node: BeaconNode,
                     slot: Slot): Result[BlockRef, cstring] =
  let res = node.dag.head
  # if not(node.isSynced(res)):
  #   return err("Cannot fulfill request until node is synced")
  if res.slot + uint64(2 * SLOTS_PER_EPOCH) < slot:
    return err("Requesting way ahead of the current head")
  ok(res)

proc getCurrentHead*(node: BeaconNode,
                     epoch: Epoch): Result[BlockRef, cstring] =
  if epoch > MaxEpoch:
    return err("Requesting epoch for which slot would overflow")
  node.getCurrentHead(compute_start_slot_at_epoch(epoch))

proc toBlockSlot*(blckRef: BlockRef): BlockSlot =
  blckRef.atSlot(blckRef.slot)

proc getBlockSlot*(node: BeaconNode,
                   stateIdent: StateIdent): Result[BlockSlot, cstring] =
  case stateIdent.kind
  of StateQueryKind.Slot:
    let head = ? getCurrentHead(node, stateIdent.slot)
    let bslot = head.atSlot(stateIdent.slot)
    if isNil(bslot.blck):
      return err("Block not found")
    ok(bslot)
  of StateQueryKind.Root:
    let blckRef = node.dag.getRef(stateIdent.root)
    if isNil(blckRef):
      return err("Block not found")
    ok(blckRef.toBlockSlot())
  of StateQueryKind.Named:
    case stateIdent.value
    of StateIdentType.Head:
      ok(node.dag.head.toBlockSlot())
    of StateIdentType.Genesis:
      ok(node.dag.getGenesisBlockSlot())
    of StateIdentType.Finalized:
      ok(node.dag.finalizedHead)
    of StateIdentType.Justified:
      ok(node.dag.head.atEpochStart(getStateField(
        node.dag.headState.data, current_justified_checkpoint).epoch))

proc getBlockDataFromBlockIdent*(node: BeaconNode,
                                 id: BlockIdent): Result[BlockData, cstring] =
  case id.kind
  of BlockQueryKind.Named:
    case id.value
    of BlockIdentType.Head:
      ok(node.dag.get(node.dag.head))
    of BlockIdentType.Genesis:
      ok(node.dag.getGenesisBlockData())
    of BlockIdentType.Finalized:
      ok(node.dag.get(node.dag.finalizedHead.blck))
  of BlockQueryKind.Root:
    let res = node.dag.get(id.root)
    if res.isNone():
      return err("Block not found")
    ok(res.get())
  of BlockQueryKind.Slot:
    let head = ? node.getCurrentHead(id.slot)
    let blockSlot = head.atSlot(id.slot)
    if isNil(blockSlot.blck):
      return err("Block not found")
    ok(node.dag.get(blockSlot.blck))

template withStateForBlockSlot*(node: BeaconNode,
                                blockSlot: BlockSlot, body: untyped): untyped =
  template isState(state: StateData): bool =
    state.blck.atSlot(getStateField(state.data, slot)) == blockSlot

  if isState(node.dag.headState):
    withStateVars(node.dag.headState):
      var cache {.inject.}: StateCache
      body
  else:
    let rpcState = assignClone(node.dag.headState)
    node.dag.withState(rpcState[], blockSlot):
      body

proc toValidatorIndex*(value: RestValidatorIndex): Result[ValidatorIndex,
                                                          ValidatorIndexError] =
  when sizeof(ValidatorIndex) == 4:
    if uint64(value) < VALIDATOR_REGISTRY_LIMIT:
      # On x86 platform Nim allows only `int32` indexes, so all the indexes in
      # range `2^31 <= x < 2^32` are not supported.
      if uint64(value) <= uint64(high(int32)):
        ok(ValidatorIndex(value))
      else:
        err(ValidatorIndexError.UnsupportedValue)
    else:
      err(ValidatorIndexError.TooHighValue)
  elif sizeof(ValidatorIndex) == 8:
    if uint64(value) < VALIDATOR_REGISTRY_LIMIT:
      ok(ValidatorIndex(value))
    else:
      err(ValidatorIndexError.TooHighValue)
  else:
    doAssert(false, "ValidatorIndex type size is incorrect")

proc getRouter*(): RestRouter =
  RestRouter.init(validate)
