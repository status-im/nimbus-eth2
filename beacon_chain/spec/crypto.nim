import
  results,
  stew/[bitseqs, objects, byteutils],
  blscurve

from std/sequtils import mapIt
from std/tables import Table, withValue, `[]=`

const
  RawSigSize = 96
  RawPubKeySize = 48

type
  ValidatorPubKey = object ##\
    blob* {.align: 16.}: array[RawPubKeySize, byte]

  CookedPubKey = distinct blscurve.PublicKey ## Valid deserialized key

  ValidatorSig = object
    blob* {.align: 16.}: array[RawSigSize, byte]

  ValidatorPrivKey = distinct blscurve.SecretKey

  BlsCurveType = ValidatorPrivKey | ValidatorPubKey | ValidatorSig

  BlsResult[T] = Result[T, cstring]

  CookedSig = distinct blscurve.Signature  ## \

template toRaw(x: CookedPubKey): auto =
  PublicKey(x).exportRaw()

func load(v: ValidatorPubKey): Opt[CookedPubKey] =
  var val: blscurve.PublicKey
  if fromBytes(val, v.blob):
    Opt.some CookedPubKey(val)
  else:
    Opt.none CookedPubKey

proc loadWithCache(v: ValidatorPubKey): Opt[CookedPubKey] =
  var cache {.threadvar.}: Table[typeof(v.blob), CookedPubKey]

  cache.withValue(v.blob, key) do:
    return Opt.some key[]
  do:
    let cooked = v.load()
    if cooked.isSome():
      cache[v.blob] = cooked.get()
    return cooked

func load(v: ValidatorSig): Opt[CookedSig] =
  var parsed: blscurve.Signature
  if fromBytes(parsed, v.blob):
    Opt.some(CookedSig(parsed))
  else:
    Opt.none(CookedSig)

func init(agg: var AggregatePublicKey, pubkey: CookedPubKey) =
  agg.init(blscurve.PublicKey(pubkey))

func init(T: type AggregatePublicKey, pubkey: CookedPubKey): T =
  result.init(pubkey)

func init(agg: var AggregateSignature, sig: CookedSig) =
  agg.init(blscurve.Signature(sig))

func init(T: type AggregateSignature, sig: CookedSig): T =
  result.init(sig)

func blsFastAggregateVerify(
       publicKeys: openArray[CookedPubKey],
       message: openArray[byte],
       signature: CookedSig
     ): bool =
  let keys = mapIt(publicKeys, PublicKey(it))
  fastAggregateVerify(keys, message, blscurve.Signature(signature))

proc blsFastAggregateVerify(
       publicKeys: openArray[ValidatorPubKey],
       message: openArray[byte],
       signature: CookedSig
     ): bool =
  var unwrapped: seq[PublicKey]
  for pubkey in publicKeys:
    let realkey = pubkey.loadWithCache()
    if realkey.isNone:
      return false
    unwrapped.add PublicKey(realkey.get)

  fastAggregateVerify(unwrapped, message, blscurve.Signature(signature))

proc blsFastAggregateVerify(
       publicKeys: openArray[ValidatorPubKey],
       message: openArray[byte],
       signature: ValidatorSig
     ): bool =
  let parsedSig = signature.load()
  parsedSig.isSome and blsFastAggregateVerify(publicKeys, message, parsedSig.get())

proc blsFastAggregateVerify(
       allPublicKeys: openArray[ValidatorPubKey],
       fullParticipationAggregatePublicKey: ValidatorPubKey,
       participantBits: BitArray,
       message: openArray[byte],
       signature: ValidatorSig
     ): bool =
  const maxParticipants = participantBits.bits
  var numParticipants = 0
  for idx in 0 ..< maxParticipants:
    if participantBits[idx]:
      inc numParticipants

  return block:
    var publicKeys = newSeqOfCap[ValidatorPubKey](numParticipants)
    for idx, pubkey in allPublicKeys:
      if participantBits[idx]:
        publicKeys.add pubkey
    blsFastAggregateVerify(publicKeys, message, signature)


func toRaw(x: ValidatorPrivKey): array[32, byte] =
  result = SecretKey(x).exportRaw()

template toRaw(x: ValidatorPubKey | ValidatorSig): auto =
  x.blob

func toHex(x: BlsCurveType): string =
  toHex(toRaw(x))

func fromRaw(T: type ValidatorPrivKey, bytes: openArray[byte]): BlsResult[T] =
  var val: SecretKey
  if val.fromBytes(bytes):
    ok ValidatorPrivKey(val)
  else:
    err "bls: invalid private key"

func fromRaw(BT: type[ValidatorPubKey | ValidatorSig], bytes: openArray[byte]): BlsResult[BT] =
  if bytes.len() != sizeof(BT):
    err "bls: invalid bls length"
  else:
    ok BT(blob: toArray(sizeof(BT), bytes))

func fromHex(T: type BlsCurveType, hexStr: string): BlsResult[T] {.inline.} =
  try:
    T.fromRaw(hexStr.hexToSeqByte())
  except ValueError:
    err "bls: cannot parse value"

func infinity(T: type ValidatorSig): T =
  result.blob[0] = byte 0xC0

import
  ssz_serialization/types as sszTypes,
  stew/bitops2,
  stew/bitseqs

from ssz_serialization/proofs import GeneralizedIndex

export
  sszTypes

type
  BeaconBlockHeader = object
    slot*: uint64
    proposer_index*: uint64 # `ValidatorIndex` after validation
    parent_root*: array[32, byte]
    state_root*: array[32, byte]
    body_root*: array[32, byte]

template newClone*[T: not ref](x: T): ref T =
  let res = new typeof(x) # TODO safe to do noinit here?
  res[] = x
  res

const
  FINALIZED_ROOT_GINDEX = 105.GeneralizedIndex
  CURRENT_SYNC_COMMITTEE_GINDEX = 54.GeneralizedIndex
  NEXT_SYNC_COMMITTEE_GINDEX = 55.GeneralizedIndex

type

  SyncAggregate = object
    sync_committee_bits: bitseqs.BitArray[32]
    sync_committee_signature: ValidatorSig

  SyncCommittee = object
    pubkeys*: HashArray[Limit 32, ValidatorPubKey]
    aggregate_pubkey*: ValidatorPubKey

  FinalityBranch =
    array[log2trunc(FINALIZED_ROOT_GINDEX), array[32, byte]]

  CurrentSyncCommitteeBranch =
    array[log2trunc(CURRENT_SYNC_COMMITTEE_GINDEX), array[32, byte]]

  NextSyncCommitteeBranch =
    array[log2trunc(NEXT_SYNC_COMMITTEE_GINDEX), array[32, byte]]

  LightClientHeader = object
    beacon*: BeaconBlockHeader

  LightClientBootstrap* = object
    header*: LightClientHeader

    current_sync_committee*: SyncCommittee
    current_sync_committee_branch*: CurrentSyncCommitteeBranch

  LightClientUpdate = object
    attested_header: LightClientHeader

    next_sync_committee: SyncCommittee
    next_sync_committee_branch: NextSyncCommitteeBranch

    finalized_header: LightClientHeader
    finality_branch: FinalityBranch

    sync_aggregate: SyncAggregate
    signature_slot: uint64

  LightClientStore = object
    finalized_header: LightClientHeader

    current_sync_committee: SyncCommittee
    next_sync_committee: SyncCommittee

    best_valid_update: Opt[LightClientUpdate]

    optimistic_header: LightClientHeader

    previous_max_active_participants: uint64
    current_max_active_participants: uint64

  SyncSubcommitteeIndex = distinct uint8
  IndexInSyncCommittee = distinct uint16

template `[]`(a: auto; i: SyncSubcommitteeIndex): auto =
  a[i.asInt]

template `[]`(arr: array[32, auto] | seq;
               idx: IndexInSyncCommittee): auto =
  arr[int idx]

type
  ExecutionPayloadHeader = object
    parent_hash: array[32, byte]
    fee_recipient: array[20, byte]
    state_root: array[32, byte]
    receipts_root: array[32, byte]
    logs_bloom: array[256, byte]
    prev_randao: array[32, byte]
    block_number: uint64
    gas_limit: uint64
    gas_used: uint64
    timestamp: uint64
    extra_data: List[byte, 32]
    base_fee_per_gas: UInt256

    block_hash: array[32, byte]
    transactions_root: array[32, byte]
    withdrawals_root: array[32, byte]

  ExecutionBranch =
    array[log2trunc(25.GeneralizedIndex), array[32, byte]]

  capellaLightClientHeader = object
    beacon*: BeaconBlockHeader

    execution*: ExecutionPayloadHeader
    execution_branch*: ExecutionBranch

  capellaLightClientBootstrap = object
    header: capellaLightClientHeader

    current_sync_committee: SyncCommittee
    current_sync_committee_branch: crypto.CurrentSyncCommitteeBranch

  capellaLightClientUpdate = object
    attested_header: capellaLightClientHeader

    next_sync_committee: SyncCommittee
    next_sync_committee_branch: crypto.NextSyncCommitteeBranch

    finalized_header: capellaLightClientHeader
    finality_branch: crypto.FinalityBranch

    sync_aggregate: SyncAggregate
    signature_slot: uint64

  capellaLightClientStore = object
    finalized_header: capellaLightClientHeader

    current_sync_committee: SyncCommittee
    next_sync_committee: SyncCommittee

    best_valid_update: Opt[capellaLightClientUpdate]

    optimistic_header: capellaLightClientHeader

    previous_max_active_participants: uint64
    current_max_active_participants: uint64

type altairLightClientHeader = crypto.LightClientHeader

func upgrade_lc_header_to_capella(
    pre: altairLightClientHeader): capellaLightClientHeader =
  capellaLightClientHeader(
    beacon: pre.beacon)

func upgrade_lc_bootstrap_to_capella(
    pre: crypto.LightClientBootstrap): capellaLightClientBootstrap =
  capellaLightClientBootstrap(
    header: upgrade_lc_header_to_capella(pre.header),
    current_sync_committee: pre.current_sync_committee,
    current_sync_committee_branch: pre.current_sync_committee_branch)

type
  LightClientDataFork* {.pure.} = enum  # Append only, used in DB data!
    Altair,
    Capella

  altairLightClientBootstrap = crypto.LightClientBootstrap

  ForkyLightClientBootstrap =
    altairLightClientBootstrap |
    capellaLightClientBootstrap

  altairLightClientStore = crypto.LightClientStore

  ForkyLightClientStore =
    altairLightClientStore |
    capellaLightClientStore

  ForkedLightClientBootstrap* = object
    case kind: LightClientDataFork
    of LightClientDataFork.Altair:
      altairData: altairLightClientBootstrap
    of LightClientDataFork.Capella:
      capellaData: capellaLightClientBootstrap

  ForkedLightClientStore* = object
    case kind: LightClientDataFork
    of LightClientDataFork.Altair:
      altairData: altairLightClientStore
    of LightClientDataFork.Capella:
      capellaData: capellaLightClientStore

template kind(
    x: typedesc[
      altairLightClientBootstrap |
      altairLightClientStore]): LightClientDataFork =
  LightClientDataFork.Altair

template kind(
    x: typedesc[
      capellaLightClientBootstrap |
      capellaLightClientStore]): LightClientDataFork =
  LightClientDataFork.Capella

template LightClientStore2(kind: static LightClientDataFork): auto =
  when kind == LightClientDataFork.Capella:
    typedesc[capellaLightClientStore]
  elif kind == LightClientDataFork.Altair:
    typedesc[altairLightClientStore]
  else:
    static: doAssert false

template Forked(x: typedesc[ForkyLightClientBootstrap]): auto =
  typedesc[ForkedLightClientBootstrap]

template Forked(x: typedesc[ForkyLightClientStore]): auto =
  typedesc[ForkedLightClientStore]

template withLcDataFork*(
    x: LightClientDataFork, body: untyped): untyped =
  case x
  of LightClientDataFork.Capella:
    const lcDataFork {.inject, used.} = LightClientDataFork.Capella
    body
  of LightClientDataFork.Altair:
    const lcDataFork {.inject, used.} = LightClientDataFork.Altair
    body

template withForkyStore*(
    x: ForkedLightClientStore, body: untyped): untyped =
  case x.kind
  of LightClientDataFork.Capella:
    const lcDataFork {.inject, used.} = LightClientDataFork.Capella
    template forkyStore: untyped {.inject, used.} = x.capellaData
    body
  of LightClientDataFork.Altair:
    const lcDataFork {.inject, used.} = LightClientDataFork.Altair
    template forkyStore: untyped {.inject, used.} = x.altairData
    body

func init*(
    x: typedesc[
      ForkedLightClientBootstrap |
      ForkedLightClientStore],
    forkyData:
      ForkyLightClientBootstrap |
      ForkyLightClientStore): auto =
  type ResultType = typeof(forkyData).Forked
  const kind = typeof(forkyData).kind
  when kind == LightClientDataFork.Capella:
    ResultType(kind: kind, capellaData: forkyData)
  elif kind == LightClientDataFork.Altair:
    ResultType(kind: kind, altairData: forkyData)
  else:
    static: doAssert false

template forky*(
    x:
      ForkedLightClientBootstrap |
      ForkedLightClientStore,
    kind: static LightClientDataFork): untyped =
  when kind == LightClientDataFork.Capella:
    x.capellaData
  elif kind == LightClientDataFork.Altair:
    x.altairData
  else:
    static: doAssert false

func migrateToDataFork*(
    x: var ForkedLightClientBootstrap,
    newKind: static LightClientDataFork) =
  if newKind == x.kind:
    discard
  elif newKind < x.kind:
    x = ForkedLightClientBootstrap(kind: newKind)
  else:
    when newKind >= LightClientDataFork.Capella:
      if x.kind == LightClientDataFork.Altair:
        x = ForkedLightClientBootstrap(
          kind: LightClientDataFork.Capella,
          capellaData: upgrade_lc_bootstrap_to_capella(
            x.forky(LightClientDataFork.Altair)))

func initialize_light_client_store*(
    bootstrap: ForkyLightClientBootstrap): auto =
  type ResultType =
    Result[typeof(bootstrap).kind.LightClientStore2, void]
  return ResultType.ok(typeof(bootstrap).kind.LightClientStore2(
    current_sync_committee: bootstrap.current_sync_committee))

proc validate_light_client_update(
    store: ForkyLightClientStore,
    update: crypto.LightClientUpdate) =
  discard store.next_sync_committee != default(typeof(store.next_sync_committee))
  var x: bitseqs.BitArray[32]
  let pubkey = ValidatorPubKey.fromHex("0xb4102a1f6c80e5c596a974ebd930c9f809c3587dc4d1d3634b77ff66db71e376dbc86c3252c6d140ce031f4ec6167798").get()
  x[0] = true
  discard blsFastAggregateVerify(
    allPublicKeys = [pubkey],
    fullParticipationAggregatePublicKey = pubkey, x,
    default(array[32, byte]), ValidatorSig.infinity())

proc process_light_client_update*(store: var ForkyLightClientStore) =
  validate_light_client_update(store, default(crypto.LightClientUpdate))
  store.best_valid_update = default(typeof(store.best_valid_update))
