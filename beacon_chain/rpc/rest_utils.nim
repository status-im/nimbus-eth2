import std/json
import presto
import libp2p/peerid
import stew/[base10, byteutils]
import nimcrypto/utils as ncrutils
import ../spec/[crypto, digest, datatypes]
import ../beacon_node_common, ../validator_duties
import ../block_pools/[block_pools_types, chain_dag]

export chain_dag, presto

const
  DecimalSet = {'0' .. '9'}
    # Base10 (decimal) set of chars
  HexadecimalSet = {'0'..'9', 'A'..'F', 'a'..'f'}
    # Base16 (hexadecimal) set of chars
  Base58Set = {'1'..'9', 'A'..'H', 'J'..'N', 'P'..'Z', 'a'..'k', 'm'..'z'}
    # Base58 set of chars
  MaxDecimalSize = len($high(uint64))
    # Maximum size of `uint64` decimal value
  MaxPeerIdSize = 128
    # Maximum size of `PeerID` base58 encoded value
  ValidatorKeySize = RawPubKeySize * 2
    # Size of `ValidatorPubKey` hexadecimal value (without 0x)
  ValidatorSigSize = RawSigSize * 2
    # Size of `ValidatorSig` hexadecimal value (without 0x)
  ValidatorIndexSize = len($(1 shl 40))
    # Maximum size of `ValidatorIndex` decimal value
  RootHashSize = sizeof(Eth2Digest) * 2
    # Size of `xxx_root` hexadecimal value (without 0x)

  FarFutureEpochString* = "18446744073709551615"

type
  ValidatorQueryKind* {.pure.} = enum
    Index, Key

  ValidatorIdent* = object
    case kind*: ValidatorQueryKind
    of ValidatorQueryKind.Index:
      index*: ValidatorIndex
    of ValidatorQueryKind.Key:
      key*: ValidatorPubKey

  ValidatorFilterKind* {.pure.} = enum
    PendingInitialized, PendingQueued,
    ActiveOngoing, ActiveExiting, ActiveSlashed,
    ExitedUnslashed, ExitedSlashed,
    WithdrawalPossible, WithdrawalDone

  ValidatorFilter* = set[ValidatorFilterKind]

  StateQueryKind* {.pure.} = enum
    Slot, Root, Named

  StateIdentType* {.pure.} = enum
    Head, Genesis, Finalized, Justified

  StateIdent* = object
    case kind*: StateQueryKind
    of StateQueryKind.Slot:
      slot*: Slot
    of StateQueryKind.Root:
      root*: Eth2Digest
    of StateQueryKind.Named:
      value*: StateIdentType

  BlockQueryKind* {.pure.} = enum
    Slot, Root, Named
  BlockIdentType* {.pure.} = enum
    Head, Genesis, Finalized

  BlockIdent* = object
    case kind*: BlockQueryKind
    of BlockQueryKind.Slot:
      slot*: Slot
    of BlockQueryKind.Root:
      root*: Eth2Digest
    of BlockQueryKind.Named:
      value*: BlockIdentType

  PeerStateKind* {.pure.} = enum
    Disconnected, Connecting, Connected, Disconnecting

  PeerDirectKind* {.pure.} = enum
    Inbound, Outbound

proc toString*(s: uint64): string =
  Base10.toString(s)

proc `%`*(s: Eth2Digest): JsonNode =
  JsonNode(kind: JString,
           str: "0x" & ncrutils.toHex(s.data, true))

proc toJsonHex(data: openArray[byte]): string =
  # Per the eth2 API spec, hex arrays are printed with leading 0x
  "0x" & ncrutils.toHex(data, true)

proc `%`*(list: List): JsonNode =
  %(asSeq(list))

proc `%`*(bitlist: BitList): JsonNode =
  newJString(toJsonHex(seq[byte](BitSeq(bitlist))))

proc `%`*(s: Version): JsonNode =
  JsonNode(kind: JString,
           str: "0x" & ncrutils.toHex(cast[array[4, byte]](s), true))

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
    # Can be any decimal 64bit value.
    if len(value) > MaxDecimalSize: 1 else: match(value, DecimalSet)
  of "{slot}":
    # Can be any decimal 64bit value.
    if len(value) > MaxDecimalSize: 1 else: match(value, DecimalSet)
  of "{peer_id}":
    # Can be base58 encoded value.
    if len(value) > MaxPeerIdSize: 1 else: match(value, Base58Set)
  of "{state_id}":
    # Can be one of: "head" (canonical head in node's view), "genesis",
    # "finalized", "justified", <slot>, <hex encoded stateRoot with 0x prefix>.
    if len(value) > 2:
      if (value[0] == '0') and (value[1] == 'x'):
        if len(value) != 2 + RootHashSize:
          1
        else:
          match(value.toOpenArray(2, len(value) - 1), HexadecimalSet)
      elif (value[0] in DecimalSet) and (value[1] in DecimalSet):
        if len(value) > MaxDecimalSize:
          1
        else:
          match(value.toOpenArray(2, len(value) - 1), DecimalSet)
      else:
        case value
        of "head": 0
        of "genesis": 0
        of "finalized": 0
        of "justified": 0
        else: 1
    else:
      match(value, DecimalSet)
  of "{block_id}":
    # Can be one of: "head" (canonical head in node's view), "genesis",
    # "finalized", <slot>, <hex encoded blockRoot with 0x prefix>.
    if len(value) > 2:
      if (value[0] == '0') and (value[1] == 'x'):
        if len(value) != 2 + RootHashSize:
          1
        else:
          match(value.toOpenArray(2, len(value) - 1), HexadecimalSet)
      elif (value[0] in DecimalSet) and (value[1] in DecimalSet):
        if len(value) > MaxDecimalSize:
          1
        else:
          match(value.toOpenArray(2, len(value) - 1), DecimalSet)
      else:
        case value
        of "head": 0
        of "genesis": 0
        of "finalized": 0
        else: 1
    else:
      match(value, DecimalSet)
  of "{validator_id}":
    # Either hex encoded public key (with 0x prefix) or validator index.
    if len(value) > 2:
      if (value[0] == '0') and (value[1] == 'x'):
        if len(value) != 2 + ValidatorKeySize:
          1
        else:
          match(value.toOpenArray(2, len(value) - 1), HexadecimalSet)
      else:
        if len(value) > ValidatorIndexSize:
          1
        else:
          match(value, DecimalSet)
    else:
      match(value, DecimalSet)
  else:
    1

proc parseRoot(value: string): Result[Eth2Digest, cstring] =
  try:
    ok(Eth2Digest(data: hexToByteArray[32](value)))
  except ValueError:
    err("Unable to decode root value")

proc decodeString*(t: typedesc[Slot], value: string): Result[Slot, cstring] =
  let res = ? Base10.decode(uint64, value)
  ok(Slot(res))

proc decodeString*(t: typedesc[Epoch], value: string): Result[Epoch, cstring] =
  let res = ? Base10.decode(uint64, value)
  ok(Epoch(res))

proc decodeString*(t: typedesc[StateIdent],
                   value: string): Result[StateIdent, cstring] =
  if len(value) > 2:
    if (value[0] == '0') and (value[1] == 'x'):
      if len(value) != RootHashSize + 2:
        err("Incorrect state root value length")
      else:
        let res = ? parseRoot(value)
        ok(StateIdent(kind: StateQueryKind.Root, root: res))
    elif (value[0] in DecimalSet) and (value[1] in DecimalSet):
      let res = ? Base10.decode(uint64, value)
      ok(StateIdent(kind: StateQueryKind.Slot, slot: Slot(res)))
    else:
      case value
      of "head":
        ok(StateIdent(kind: StateQueryKind.Named,
                      value: StateIdentType.Head))
      of "genesis":
        ok(StateIdent(kind: StateQueryKind.Named,
                      value: StateIdentType.Genesis))
      of "finalized":
        ok(StateIdent(kind: StateQueryKind.Named,
                      value: StateIdentType.Finalized))
      of "justified":
        ok(StateIdent(kind: StateQueryKind.Named,
                      value: StateIdentType.Justified))
      else:
        err("Incorrect state identifier value")
  else:
    let res = ? Base10.decode(uint64, value)
    ok(StateIdent(kind: StateQueryKind.Slot, slot: Slot(res)))

proc decodeString*(t: typedesc[BlockIdent],
                   value: string): Result[BlockIdent, cstring] =
  if len(value) > 2:
    if (value[0] == '0') and (value[1] == 'x'):
      if len(value) != RootHashSize + 2:
        err("Incorrect block root value length")
      else:
        let res = ? parseRoot(value)
        ok(BlockIdent(kind: BlockQueryKind.Root, root: res))
    elif (value[0] in DecimalSet) and (value[1] in DecimalSet):
      let res = ? Base10.decode(uint64, value)
      ok(BlockIdent(kind: BlockQueryKind.Slot, slot: Slot(res)))
    else:
      case value
        of "head":
          ok(BlockIdent(kind: BlockQueryKind.Named,
                        value: BlockIdentType.Head))
        of "genesis":
          ok(BlockIdent(kind: BlockQueryKind.Named,
                        value: BlockIdentType.Genesis))
        of "finalized":
          ok(BlockIdent(kind: BlockQueryKind.Named,
                        value: BlockIdentType.Finalized))
        else:
          err("Incorrect block identifier value")
  else:
    let res = ? Base10.decode(uint64, value)
    ok(BlockIdent(kind: BlockQueryKind.Slot, slot: Slot(res)))

proc decodeString*(t: typedesc[ValidatorIdent],
                   value: string): Result[ValidatorIdent, cstring] =
  # This should raise exception if ValidatorIndex type will be changed,
  # because currently it `uint32` but in 40bits size in specification.
  doAssert(sizeof(uint32) == sizeof(ValidatorIndex))
  if len(value) > 2:
    if (value[0] == '0') and (value[1] == 'x'):
      if len(value) != ValidatorKeySize + 2:
        err("Incorrect validator's key value length")
      else:
        let res = ? ValidatorPubKey.fromHex(value)
        ok(ValidatorIdent(kind: ValidatorQueryKind.Key,
                          key: res))
    elif (value[0] in DecimalSet) and (value[1] in DecimalSet):
      let res = ? Base10.decode(uint32, value)
      ok(ValidatorIdent(kind: ValidatorQueryKind.Index,
                        index: ValidatorIndex(res)))
    else:
      err("Incorrect validator identifier value")
  else:
    let res = ? Base10.decode(uint32, value)
    ok(ValidatorIdent(kind: ValidatorQueryKind.Index,
                      index: ValidatorIndex(res)))

proc decodeString*(t: typedesc[PeerID],
                   value: string): Result[PeerID, cstring] =
  PeerID.init(value)

proc decodeString*(t: typedesc[CommitteeIndex],
                   value: string): Result[CommitteeIndex, cstring] =
  let res = ? Base10.decode(uint64, value)
  ok(CommitteeIndex(res))

proc decodeString*(t: typedesc[Eth2Digest],
                   value: string): Result[Eth2Digest, cstring] =
  if len(value) != RootHashSize + 2:
    return err("Incorrect root value length")
  if value[0] != '0' and value[1] != 'x':
    return err("Incorrect root value encoding")
  parseRoot(value)

proc decodeString*(t: typedesc[ValidatorFilter],
                   value: string): Result[ValidatorFilter, cstring] =
  case value
  of "pending_initialized":
    ok({ValidatorFilterKind.PendingInitialized})
  of "pending_queued":
    ok({ValidatorFilterKind.PendingQueued})
  of "active_ongoing":
    ok({ValidatorFilterKind.ActiveOngoing})
  of "active_exiting":
    ok({ValidatorFilterKind.ActiveExiting})
  of "active_slashed":
    ok({ValidatorFilterKind.ActiveSlashed})
  of "exited_unslashed":
    ok({ValidatorFilterKind.ExitedUnslashed})
  of "exited_slashed":
    ok({ValidatorFilterKind.ExitedSlashed})
  of "withdrawal_possible":
    ok({ValidatorFilterKind.WithdrawalPossible})
  of "withdrawal_done":
    ok({ValidatorFilterKind.WithdrawalDone})
  of "pending":
    ok({
      ValidatorFilterKind.PendingInitialized,
      ValidatorFilterKind.PendingQueued
    })
  of "active":
    ok({
      ValidatorFilterKind.ActiveOngoing,
      ValidatorFilterKind.ActiveExiting,
      ValidatorFilterKind.ActiveSlashed
    })
  of "exited":
    ok({
      ValidatorFilterKind.ExitedUnslashed,
      ValidatorFilterKind.ExitedSlashed
    })
  of "withdrawal":
    ok({
      ValidatorFilterKind.WithdrawalPossible,
      ValidatorFilterKind.WithdrawalDone
    })
  else:
    err("Incorrect validator state identifier value")

proc decodeString*(t: typedesc[PeerStateKind],
                   value: string): Result[PeerStateKind, cstring] =
  case value
  of "disconnected":
    ok(PeerStateKind.Disconnected)
  of "connecting":
    ok(PeerStateKind.Connecting)
  of "connected":
    ok(PeerStateKind.Connected)
  of "disconnecting":
    ok(PeerStateKind.Disconnecting)
  else:
    err("Incorrect peer's state value")

proc decodeString*(t: typedesc[PeerDirectKind],
                   value: string): Result[PeerDirectKind, cstring] =
  case value
  of "inbound":
    ok(PeerDirectKind.Inbound)
  of "outbound":
    ok(PeerDirectKind.Outbound)
  else:
    err("Incorrect peer's direction value")

proc decodeString*(t: typedesc[ValidatorSig],
                   value: string): Result[ValidatorSig, cstring] =
  if len(value) != ValidatorSigSize + 2:
    return err("Incorrect validator signature value length")
  if value[0] != '0' and value[1] != 'x':
    return err("Incorrect validator signature encoding")
  ValidatorSig.fromHex(value)

proc decodeString*(t: typedesc[GraffitiBytes],
                   value: string): Result[GraffitiBytes, cstring] =
  try:
    ok(GraffitiBytes.init(value))
  except ValueError:
    err("Unable to decode graffiti value")

proc jsonResponse*(t: typedesc[RestApiResponse], j: JsonNode): RestApiResponse =
  let data =  %*{"data": j}
  ok(ContentBody(contentType: "application/json",
                 data: cast[seq[byte]]($data)))

proc getRouter*(): RestRouter =
  RestRouter.init(validate)

proc getCurrentHead*(node: BeaconNode,
                     slot: Slot): Result[BlockRef, cstring] =
  let res = node.chainDag.head
  # if not(node.isSynced(res)):
  #   return err("Cannot fulfill request until node is synced")
  if res.slot + uint64(2 * SLOTS_PER_EPOCH) < slot:
    return err("Requesting way ahead of the current head")
  ok(res)

proc getCurrentHead*(node: BeaconNode,
                     epoch: Epoch): Result[BlockRef, cstring] =
  const maxEpoch = compute_epoch_at_slot(not(0'u64))
  if epoch >= maxEpoch:
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
    let blckRef = node.chainDag.getRef(stateIdent.root)
    if isNil(blckRef):
      return err("Block not found")
    ok(blckRef.toBlockSlot())
  of StateQueryKind.Named:
    case stateIdent.value
    of StateIdentType.Head:
      ok(node.chainDag.head.toBlockSlot())
    of StateIdentType.Genesis:
      ok(node.chainDag.getGenesisBlockSlot())
    of StateIdentType.Finalized:
      ok(node.chainDag.finalizedHead)
    of StateIdentType.Justified:
      ok(node.chainDag.head.atEpochStart(
         node.chainDag.headState.data.data.current_justified_checkpoint.epoch))

proc getBlockDataFromBlockIdent*(node: BeaconNode,
                                 id: BlockIdent): Result[BlockData, cstring] =
  warn "Searching for block", ident = $id
  case id.kind
  of BlockQueryKind.Named:
    case id.value
    of BlockIdentType.Head:
      ok(node.chainDag.get(node.chainDag.head))
    of BlockIdentType.Genesis:
      ok(node.chainDag.getGenesisBlockData())
    of BlockIdentType.Finalized:
      ok(node.chainDag.get(node.chainDag.finalizedHead.blck))
  of BlockQueryKind.Root:
    let res = node.chainDag.get(id.root)
    if res.isNone():
      return err("Block not found")
    ok(res.get())
  of BlockQueryKind.Slot:
    let head = ? node.getCurrentHead(id.slot)
    let blockSlot = head.atSlot(id.slot)
    if isNil(blockSlot.blck):
      return err("Block not found")
    ok(node.chainDag.get(blockSlot.blck))

template withStateForStateIdent*(node: BeaconNode,
                                 blockSlot: BlockSlot, body: untyped): untyped =
  # TODO this can be optimized for the "head" case since that should be most
  # common.
  node.chainDag.withState(node.chainDag.tmpState, blockSlot):
    body

proc jsonError*(t: typedesc[RestApiResponse], status: HttpCode = Http200,
                msg: string = "", stacktrace: string = ""): RestApiResponse =
  let data =
    if len(stacktrace) > 0:
      %*{"code": status.toInt(), "message": msg, "stacktrace": stacktrace}
    else:
      %*{"code": status.toInt(), "message": msg}
  RestApiResponse.error(status, $data, "application/json")
