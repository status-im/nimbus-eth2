{.experimental: "notnil".}

import
  std/[macros, hashes, sets, strutils, tables, typetraits],
  results,
  stew/[byteutils, endians2],
  ssz_serialization/types as sszTypes,
  ".."/[beacon_time, crypto, digest, presets]

export
  tables, results, endians2, sszTypes, beacon_time, crypto,
  digest, presets

const SPEC_VERSION = "1.4.0-beta.7-hotfix"

const
  ZERO_HASH = Eth2Digest()
  MAX_GRAFFITI_SIZE = 32

  SLOTS_PER_ETH1_VOTING_PERIOD =
    EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH

  DEPOSIT_CONTRACT_TREE_DEPTH* = 32
  BASE_REWARDS_PER_EPOCH = 4

template maxSize(n: int) {.pragma.}

type
  Wei = UInt256
  Gwei = uint64
  Ether = distinct uint64

type
  Eth2Domain = array[32, byte]

  ValidatorIndex = distinct uint32

  CommitteeIndex = distinct uint8

  SubnetId = distinct uint8

  BlobId = distinct uint8

  JustificationBits = distinct uint8

  Deposit* = object
    proof*: array[DEPOSIT_CONTRACT_TREE_DEPTH + 1, Eth2Digest]
      ## Merkle path to deposit root

    data*: DepositData

  DepositMessage* = object
    pubkey*: ValidatorPubKey
    withdrawal_credentials*: Eth2Digest
    amount*: Gwei

  DepositData* = object
    pubkey*: ValidatorPubKey
    withdrawal_credentials*: Eth2Digest
    amount*: Gwei
    signature*: ValidatorSig
      ## Signing over DepositMessage

  VoluntaryExit* = object
    epoch*: Epoch
      ## Earliest epoch when voluntary exit can be processed
    validator_index*: uint64 # `ValidatorIndex` after validation

  ImmutableValidatorData* = object
    pubkey*: ValidatorPubKey
    withdrawal_credentials*: Eth2Digest

  ImmutableValidatorDataDb2* = object
    pubkey*: UncompressedPubKey
    withdrawal_credentials*: Eth2Digest

  ImmutableValidatorData2* = object
    pubkey*: CookedPubKey
    withdrawal_credentials*: Eth2Digest

  HashedValidatorPubKeyItem* = object
    key*: ValidatorPubKey
    root*: Eth2Digest

  HashedValidatorPubKey* = object
    value*: ptr HashedValidatorPubKeyItem

  Validator* = object
    pubkey*: ValidatorPubKey

    withdrawal_credentials*: Eth2Digest
      ## Commitment to pubkey for withdrawals and transfers

    effective_balance*: Gwei
      ## Balance at stake

    slashed*: bool

    activation_eligibility_epoch*: Epoch
      ## When criteria for activation were met

    activation_epoch*: Epoch
    exit_epoch*: Epoch

    withdrawable_epoch*: Epoch
      ## When validator can withdraw funds

  HistoricalBatch* = object
    block_roots* : array[SLOTS_PER_HISTORICAL_ROOT, Eth2Digest]
    state_roots* : array[SLOTS_PER_HISTORICAL_ROOT, Eth2Digest]

  Fork* = object
    previous_version*: Version
    current_version*: Version

    epoch*: Epoch
      ## Epoch of latest fork

  Eth1Data* = object
    deposit_root*: Eth2Digest
    deposit_count*: uint64
    block_hash*: Eth2Digest

  SignedVoluntaryExit* = object
    message*: VoluntaryExit
    signature*: ValidatorSig

  TrustedSignedVoluntaryExit* = object
    message*: VoluntaryExit
    signature*: TrustedSig

  BeaconBlockHeader* = object
    slot*: Slot
    proposer_index*: uint64 # `ValidatorIndex` after validation
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body_root*: Eth2Digest

  SigningData* = object
    object_root*: Eth2Digest
    domain*: Eth2Domain

  GraffitiBytes* = distinct array[MAX_GRAFFITI_SIZE, byte]

  SignedBeaconBlockHeader* = object
    message*: BeaconBlockHeader
    signature*: ValidatorSig

  TrustedSignedBeaconBlockHeader* = object
    message*: BeaconBlockHeader
    signature*: TrustedSig

  SyncCommitteeCache* = object
    current_sync_committee*: array[SYNC_COMMITTEE_SIZE, ValidatorIndex]
    next_sync_committee*: array[SYNC_COMMITTEE_SIZE, ValidatorIndex]

  StateCache* = object
    total_active_balance*: Table[Epoch, Gwei]
    shuffled_active_validator_indices*: Table[Epoch, seq[ValidatorIndex]]
    beacon_proposer_indices*: Table[Slot, Opt[ValidatorIndex]]
    sync_committees*: Table[SyncCommitteePeriod, SyncCommitteeCache]

  DepositContractState* = object
    branch*: array[DEPOSIT_CONTRACT_TREE_DEPTH, Eth2Digest]
    deposit_count*: array[32, byte] # Uint256

  ValidatorStatus* = object

    pubkeyData* {.dontSerialize.}: HashedValidatorPubKey

    withdrawal_credentials* {.dontSerialize.}: Eth2Digest
      ## Commitment to pubkey for withdrawals

    effective_balance*: Gwei
      ## Balance at stake

    slashed*: bool

    activation_eligibility_epoch*: Epoch
      ## When criteria for activation were met

    activation_epoch*: Epoch
    exit_epoch*: Epoch

    withdrawable_epoch*: Epoch
      ## When validator can withdraw funds

  ValidatorStatusCapella* = object

    pubkeyData* {.dontSerialize.}: HashedValidatorPubKey

    withdrawal_credentials*: Eth2Digest
      ## Commitment to pubkey for withdrawals

    effective_balance*: Gwei
      ## Balance at stake

    slashed*: bool

    activation_eligibility_epoch*: Epoch
      ## When criteria for activation were met

    activation_epoch*: Epoch
    exit_epoch*: Epoch

    withdrawable_epoch*: Epoch
      ## When validator can withdraw funds

  AttnetBits* = BitArray[int ATTESTATION_SUBNET_COUNT]

type
  RewardDelta* = object
    rewards*: Gwei
    penalties*: Gwei

  InclusionInfo* = object
    delay*: uint64
      ## The distance between the attestation slot and the slot that attestation
      ## was included in block.
    proposer_index*: uint64 # `ValidatorIndex` after validation
      ## The index of the proposer at the slot where the attestation was included

  RewardFlags* {.pure.} = enum
    isSlashed
    canWithdrawInCurrentEpoch
    isActiveInPreviousEpoch
    isCurrentEpochAttester

    isCurrentEpochTargetAttester

    isPreviousEpochTargetAttester
    isPreviousEpochHeadAttester

  RewardStatus* = object

    current_epoch_effective_balance*: Gwei

    is_previous_epoch_attester*: Opt[InclusionInfo]

    delta*: RewardDelta

    flags*: set[RewardFlags]

func pubkey*(v: HashedValidatorPubKey): ValidatorPubKey =
  if isNil(v.value):
    ValidatorPubKey()
  else:
    v.value[].key

func hash_tree_root*(v: HashedValidatorPubKey): Eth2Digest =
  if isNil(v.value):
    const zeroPubkeyHash = Eth2Digest.fromHex(
      "fa324a462bcb0f10c24c9e17c326a4e0ebad204feced523eccaf346c686f06ee")
    zeroPubkeyHash
  else:
    v.value[].root

func getImmutableValidatorData*(validator: Validator): ImmutableValidatorData2 =
  let cookedKey = validator.pubkey.loadValid()  # `Validator` has valid key
  ImmutableValidatorData2(
    pubkey: cookedKey,
    withdrawal_credentials: validator.withdrawal_credentials)

template makeLimitedUInt*(T: untyped, limit: SomeUnsignedInt) =
  static: doAssert limit <= distinctBase(T).high()
  func init*(t: type T, value: uint64): Result[T, cstring] =
    if value < limit:
      ok(Result[T, cstring], T(value))
    else:
      err(Result[T, cstring], name(T) & " out of range")

  iterator items*(t: type T): T =
    for i in 0'u64..<limit:
      yield T(i)

  template `==`*(x, y: T): bool = distinctBase(x) == distinctBase(y)
  template `==`*(x: T, y: uint64): bool = distinctBase(x) == y
  template `==`*(x: uint64, y: T): bool = x == distinctBase(y)

  template `<`*(x, y: T): bool = distinctBase(x) < distinctBase(y)
  template `<`*(x: T, y: uint64): bool = distinctBase(x) < y
  template `<`*(x: uint64, y: T): bool = x < distinctBase(y)

  template hash*(x: T): Hash =
    hash distinctBase(x)

  template `$`*(x: T): string = $ distinctBase(x)

  template asInt*(x: T): int = int(distinctBase(x))
  template asUInt64*(x: T): uint64 = uint64(distinctBase(x))

  func toSszType*(x: T): uint64 {.error:
    "Limited types should not be used with SSZ (ABI differences)".}

template makeLimitedU8*(T: untyped, limit: uint8) =
  makeLimitedUInt(T, limit)

template makeLimitedU16*(T: type, limit: uint16) =
  makeLimitedUInt(T, limit)

template makeLimitedU64*(T: untyped, limit: uint64) =
  makeLimitedUInt(T, limit)

makeLimitedU64(CommitteeIndex, MAX_COMMITTEES_PER_SLOT)
makeLimitedU64(SubnetId, ATTESTATION_SUBNET_COUNT)
makeLimitedU64(BlobId, BLOB_SIDECAR_SUBNET_COUNT)

const
  validatorIndexLimit = min(uint64(int32.high), VALIDATOR_REGISTRY_LIMIT)
makeLimitedU64(ValidatorIndex, validatorIndexLimit)

func init*(T: type CommitteeIndex, index, committees_per_slot: uint64):
    Result[CommitteeIndex, cstring] =
  if index < min(committees_per_slot, MAX_COMMITTEES_PER_SLOT):
    ok(CommitteeIndex(index))
  else:
    err("Committee index out of range for epoch")

func `$`*(x: JustificationBits): string =
  "0x" & toHex(uint64(uint8(x)))

template `[]=`*[T](a: var seq[T], b: ValidatorIndex, c: T) =
  a[b.int] = c

template `[]`*[T](a: seq[T], b: ValidatorIndex): auto = # Also var seq (!)
  a[b.int]

iterator vindices*(
    a: HashList[Validator, Limit VALIDATOR_REGISTRY_LIMIT]): ValidatorIndex =
  static: doAssert distinctBase(ValidatorIndex) is uint32
  for i in 0..<a.len.uint32:
    yield i.ValidatorIndex

iterator vindices*(
    a: List[Validator, Limit VALIDATOR_REGISTRY_LIMIT]): ValidatorIndex =
  static: doAssert distinctBase(ValidatorIndex) is uint32
  for i in 0..<a.len.uint32:
    yield i.ValidatorIndex

template `==`*(x, y: JustificationBits): bool =
  distinctBase(x) == distinctBase(y)

func `as`*(d: DepositData, T: type DepositMessage): T =
  T(pubkey: d.pubkey,
    withdrawal_credentials: d.withdrawal_credentials,
    amount: d.amount)

template newClone*[T: not ref](x: T): ref T =
  let res = new typeof(x) # TODO safe to do noinit here?
  res[] = x
  res

template assignClone*[T: not ref](x: T): ref T =
  mixin assign
  let res = new typeof(x) # TODO safe to do noinit here?
  res[] = x
  res

template newClone*[T](x: ref T not nil): ref T =
  newClone(x[])

template hash*(header: BeaconBlockHeader): Hash =
  hash(header.state_root)
