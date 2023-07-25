# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import std/[options, macros],
       stew/[byteutils, endians2], presto,
       ../spec/[forks, crypto],
       ../spec/eth2_apis/[rest_types, eth2_rest_serialization, rest_common],
       ../validators/validator_duties,
       ../consensus_object_pools/blockchain_dag,
       ../beacon_node,
       "."/[rest_constants, state_ttl_cache]

from std/math import isPowerOfTwo, nextPowerOfTwo

export
  options, eth2_rest_serialization, blockchain_dag, presto, rest_types,
  rest_constants, rest_common

type
  ValidatorIndexError* {.pure.} = enum
    UnsupportedValue, TooHighValue

  BloomFilter* = object
    words: seq[uint]
    length: int
    mask: uint
    used: int

func checkKey*(bf: BloomFilter, pubkey: ValidatorPubKey): bool {.
     raises: [].}

func match(data: openArray[char], charset: set[char]): int =
  for ch in data:
    if ch notin charset:
      return 1
  0

proc getSyncedHead*(
       node: BeaconNode,
       slot: Slot
     ): Result[BlockRef, cstring] =
  let head = node.dag.head

  if not node.isSynced(head):
    return err("Beacon node not fully and non-optimistically synced")

  # Enough ahead not to know the shuffling
  if slot > head.slot + SLOTS_PER_EPOCH * 2:
    return err("Requesting far ahead of the current head")

  ok(head)

func getCurrentSlot*(node: BeaconNode, slot: Slot):
    Result[Slot, cstring] =
  if slot <= (node.dag.head.slot + (SLOTS_PER_EPOCH * 2)):
    ok(slot)
  else:
    err("Requesting slot too far ahead of the current head")

proc getSyncedHead*(
       node: BeaconNode,
       epoch: Epoch,
     ): Result[BlockRef, cstring] =
  if epoch > MaxEpoch:
    return err("Requesting epoch for which slot would overflow")
  node.getSyncedHead(epoch.start_slot())

func getBlockSlotId*(node: BeaconNode,
                     stateIdent: StateIdent): Result[BlockSlotId, cstring] =
  case stateIdent.kind
  of StateQueryKind.Slot:
    # Limit requests by state id to the next epoch with respect to the current
    # head to avoid long empty slot replays (in particular a second epoch
    # transition)
    if stateIdent.slot.epoch > (node.dag.head.slot.epoch + 1):
      return err("Requesting state too far ahead of current head")

    let bsi = node.dag.getBlockIdAtSlot(stateIdent.slot).valueOr:
      return err("History for given slot not available")

    ok(bsi)

  of StateQueryKind.Root:
    if stateIdent.root == getStateRoot(node.dag.headState):
      ok(node.dag.head.bid.atSlot())
    else:
      # The `state_roots` field holds 8k historical state roots but not the
      # one of the current state - this trick allows us to lookup states without
      # keeping an on-disk index.
      let headSlot = getStateField(node.dag.headState, slot)
      for i in 0'u64..<SLOTS_PER_HISTORICAL_ROOT:
        if i >= headSlot:
          break
        if getStateField(node.dag.headState, state_roots).item(
            (headSlot - i - 1) mod SLOTS_PER_HISTORICAL_ROOT) ==
            stateIdent.root:
          return node.dag.getBlockIdAtSlot(headSlot - i - 1).orErr(
            cstring("History for for given root not available"))

      # We don't have a state root -> BlockSlot mapping
      err("State root not found - use by-slot lookup to query deep state history")
  of StateQueryKind.Named:
    case stateIdent.value
    of StateIdentType.Head:
      ok(node.dag.head.bid.atSlot())
    of StateIdentType.Genesis:
      let bid = node.dag.getBlockIdAtSlot(GENESIS_SLOT).valueOr:
        return err("Genesis state not available / pruned")
      ok bid
    of StateIdentType.Finalized:
      ok(node.dag.finalizedHead.toBlockSlotId().expect("not nil"))
    of StateIdentType.Justified:
      # Take checkpoint-synced nodes into account
      let justifiedEpoch =
        max(
          getStateField(node.dag.headState, current_justified_checkpoint).epoch,
          node.dag.finalizedHead.slot.epoch)
      ok(node.dag.head.atEpochStart(justifiedEpoch).toBlockSlotId().expect("not nil"))

proc getBlockId*(node: BeaconNode, id: BlockIdent): Opt[BlockId] =
  case id.kind
  of BlockQueryKind.Named:
    case id.value
    of BlockIdentType.Head:
      ok(node.dag.head.bid)
    of BlockIdentType.Genesis:
      node.dag.getBlockIdAtSlot(GENESIS_SLOT).map(proc(x: auto): auto = x.bid)
    of BlockIdentType.Finalized:
      ok(node.dag.finalizedHead.blck.bid)
  of BlockQueryKind.Root:
    node.dag.getBlockId(id.root)
  of BlockQueryKind.Slot:
    let bsid = node.dag.getBlockIdAtSlot(id.slot)
    if bsid.isSome and bsid.get().isProposed():
      ok bsid.get().bid
    else:
      err()

proc getForkedBlock*(node: BeaconNode, id: BlockIdent):
    Opt[ForkedTrustedSignedBeaconBlock] =
  let bid = ? node.getBlockId(id)

  node.dag.getForkedBlock(bid)

func disallowInterruptionsAux(body: NimNode) =
  for n in body:
    const because =
      "because the `state` variable may be mutated (and thus invalidated) " &
      "before the function resumes execution."

    if n.kind == nnkYieldStmt:
      macros.error "You cannot use yield in this block " & because, n

    if (n.kind in {nnkCall, nnkCommand} and
       n[0].kind in {nnkIdent, nnkSym} and
       $n[0] == "await"):
      macros.error "You cannot use await in this block " & because, n

    disallowInterruptionsAux(n)

macro disallowInterruptions(body: untyped) =
  disallowInterruptionsAux(body)

template withStateForBlockSlotId*(nodeParam: BeaconNode,
                                  blockSlotIdParam: BlockSlotId,
                                  body: untyped): untyped =

  block:
    let
      node = nodeParam
      blockSlotId = blockSlotIdParam

    template isState(state: ForkedHashedBeaconState): bool =
      state.matches_block_slot(blockSlotId.bid.root, blockSlotId.slot)

    var cache {.inject, used.}: StateCache

    # If we have a cache hit, there is a concern that the REST request
    # handler may continue executing asynchronously while we hit the same
    # advanced state is another request. We don't want the two requests
    # to work over the same state object because mutations to it will be
    # visible in both, so we must outlaw yielding within the `body` block.
    # Please note that the problem is not limited to the situations where
    # we have a cache hit. Working with the `headState` will result in the
    # same problem as it may change while the request is executing.
    #
    # TODO
    # The solution below is only partion, because it theory yields or awaits
    # can still be hidden in the body through the use of helper templates
    disallowInterruptions(body)

    # TODO view-types
    # Avoid the code bloat produced by the double `body` reference through a lent var
    if isState(node.dag.headState):
      template state: untyped {.inject, used.} = node.dag.headState
      template stateRoot: untyped {.inject, used.} =
        getStateRoot(node.dag.headState)
      body
    else:
      let cachedState = if node.stateTtlCache != nil:
        node.stateTtlCache.getClosestState(node.dag, blockSlotId)
      else:
        nil

      let stateToAdvance = if cachedState != nil:
        cachedState
      else:
        assignClone(node.dag.headState)

      if node.dag.updateState(stateToAdvance[], blockSlotId, false, cache):
        if cachedState == nil and node.stateTtlCache != nil:
          # This was not a cached state, we can cache it now
          node.stateTtlCache.add(stateToAdvance)

        template state: untyped {.inject, used.} = stateToAdvance[]
        template stateRoot: untyped {.inject, used.} = getStateRoot(stateToAdvance[])

        body

template strData*(body: ContentBody): string =
  bind fromBytes
  string.fromBytes(body.data)

func toValidatorIndex*(value: RestValidatorIndex): Result[ValidatorIndex,
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

func syncCommitteeParticipants*(forkedState: ForkedHashedBeaconState,
                                epoch: Epoch
                               ): Result[seq[ValidatorPubKey], cstring] =
  withState(forkedState):
    when consensusFork >= ConsensusFork.Altair:
      let
        epochPeriod = sync_committee_period(epoch)
        curPeriod = sync_committee_period(forkyState.data.slot)
      if epochPeriod == curPeriod:
        ok(@(forkyState.data.current_sync_committee.pubkeys.data))
      elif epochPeriod == curPeriod + 1:
        ok(@(forkyState.data.next_sync_committee.pubkeys.data))
      else:
        err("Epoch is outside the sync committee period of the state")
    else:
      err("State's fork do not support sync committees")

func keysToIndices*(cacheTable: var Table[ValidatorPubKey, ValidatorIndex],
                    forkedState: ForkedHashedBeaconState,
                    bloomFilter: BloomFilter,
                    recentValidators: var Table[ValidatorPubKey, ValidatorIndex],
                    keys: openArray[ValidatorPubKey]
                   ): seq[Option[ValidatorIndex]] =
  var indices = newSeq[Option[ValidatorIndex]](len(keys))
  let totalValidatorsInState = getStateField(forkedState, validators).lenu64
  var keyset =
    block:
      var res: Table[ValidatorPubKey, int]
      for inputIndex, pubkey in keys.pairs():
        if bloomFilter.checkKey(pubkey):
          # The validator's public key is possible in our registry, we will
          # check in cache first.
          cacheTable.withValue(pubkey, vindex):
            if uint64(vindex[]) < totalValidatorsInState:
              indices[inputIndex] = some(vindex[])
          do:
            res[pubkey] = inputIndex
        else:
          # The validator's public key is not in bloom filter, but it could
          # be inside `recentValidators`, so we check it.
          recentValidators.withValue(pubkey, rindex):
            indices[inputIndex] = some(rindex[])
          do:
            res[pubkey] = inputIndex
      res
  if len(keyset) > 0:
    for validatorIndex, validator in getStateField(forkedState, validators):
      keyset.withValue(validator.pubkey, listIndex):
        # Store pair (pubkey, index) into cache table.
        cacheTable[validator.pubkey] = ValidatorIndex(validatorIndex)
        # Fill result sequence.
        indices[listIndex[]] = some(ValidatorIndex(validatorIndex))
  indices

proc getShufflingOptimistic*(node: BeaconNode,
                             dependentSlot: Slot,
                             dependentRoot: Eth2Digest): Option[bool] =
  if node.currentSlot().epoch() >= node.dag.cfg.BELLATRIX_FORK_EPOCH:
    # `slot` in this `BlockId` may be higher than block's actual slot,
    # this is alright for the purpose of calling `is_optimistic`.
    let bid = BlockId(slot: dependentSlot, root: dependentRoot)
    some[bool](node.dag.is_optimistic(bid))
  else:
    none[bool]()

proc getStateOptimistic*(node: BeaconNode,
                         state: ForkedHashedBeaconState): Option[bool] =
  if node.currentSlot().epoch() >= node.dag.cfg.BELLATRIX_FORK_EPOCH:
    if state.kind >= ConsensusFork.Bellatrix:
      # A state is optimistic iff the block which created it is
      let stateBid = withState(state): forkyState.latest_block_id
      some[bool](node.dag.is_optimistic(stateBid))
    else:
      some[bool](false)
  else:
    none[bool]()

proc getBlockOptimistic*(node: BeaconNode,
                         blck: ForkedTrustedSignedBeaconBlock |
                               ForkedSignedBeaconBlock): Option[bool] =
  if node.currentSlot().epoch() >= node.dag.cfg.BELLATRIX_FORK_EPOCH:
    if blck.kind >= ConsensusFork.Bellatrix:
      some[bool](node.dag.is_optimistic(blck.toBlockId()))
    else:
      some[bool](false)
  else:
    none[bool]()

const
  jsonMediaType* = MediaType.init("application/json")
  sszMediaType* = MediaType.init("application/octet-stream")
  textEventStreamMediaType* = MediaType.init("text/event-stream")

proc verifyRandao*(
    node: BeaconNode, slot: Slot, proposer: ValidatorIndex,
    randao: ValidatorSig, skip_randao_verification: bool): bool =
  let
    proposer_pubkey = node.dag.validatorKey(proposer).valueOr:
      return false

  if skip_randao_verification:
    randao == ValidatorSig.infinity()
  else:
    let
      fork = node.dag.forkAtEpoch(slot.epoch)
      genesis_validators_root = node.dag.genesis_validators_root

    verify_epoch_signature(
      fork, genesis_validators_root, slot.epoch, proposer_pubkey, randao)

template len*(bf: BloomFilter): int =
  bf.used

template divShift(): uint =
  when sizeof(uint) == 8: 6'u else: 5'u

template modMask(): uint =
  when sizeof(uint) == 8: 63'u else: 31'u

func raiseBit*(bf: var BloomFilter, pos: Natural) {.inline.} =
  doAssert(pos < bf.length)
  let index = uint(pos) shr divShift()
  bf.words[index] = bf.words[index] or (1'u shl (uint(pos) and modMask()))

func getBit*(bf: BloomFilter, pos: Natural): bool {.inline.} =
  doAssert(pos < bf.length)
  let index = uint(pos) shr divShift()
  (bf.words[index] and (1'u shl (uint(pos) and modMask()))) != 0'u

proc getBitsCount*(itemsCount: int): int =
  ## We are using 8 hashes and we want to get 0.0001 false positive rate, so we
  ## should use `m/n == 21` according to Table 3 of
  ## https://pages.cs.wisc.edu/~cao/papers/summary-cache/node8.html
  itemsCount * 21

proc init*(T: typedesc[BloomFilter], bitsCount: int): T =
  when sizeof(int) == 8:
    doAssert bitsCount <= 0x4000_0000_0000_0000
  else:
    doAssert bitsCount <= 0x4000_0000

  let
    correctedBits = nextPowerOfTwo(bitsCount + 1)
    correctedSize = (correctedBits + int(modMask())) shr int(divShift())

  BloomFilter(
    words: newSeq[uint](correctedSize),
    mask: uint(correctedBits - 1),
    length: correctedBits
  )

func itemsCount*(bf: BloomFilter): int =
  len(bf.words)

func bytesCount*(bf: BloomFilter): int =
  len(bf.words) * sizeof(uint)

func bitsCount*(bf: BloomFilter): int =
  bf.length

template toHashes(pubkey: ValidatorPubKey): auto =
  var pos: array[8, uint32]
  when sizeof(int) == 8:
    let
      pos0 = uint64.fromBytesLE(pubkey.blob.toOpenArray(0, 7)) xor
             uint64.fromBytesLE(pubkey.blob.toOpenArray(8, 15))
      pos1 = uint64.fromBytesLE(pubkey.blob.toOpenArray(16, 23)) xor
             uint64.fromBytesLE(pubkey.blob.toOpenArray(24, 31))
      pos2 = uint64.fromBytesLE(pubkey.blob.toOpenArray(32, 39)) xor
             uint64.fromBytesLE(pubkey.blob.toOpenArray(40, 47))
      pos3 = uint64.fromBytesLE(pubkey.blob.toOpenArray(0, 7)) xor
             uint64.fromBytesLE(pubkey.blob.toOpenArray(40, 47))
    pos[0] = uint32(pos0 and uint64(bf.mask))
    pos[1] = uint32((pos0 shr 32) and uint64(bf.mask))
    pos[2] = uint32(pos1 and uint64(bf.mask))
    pos[3] = uint32((pos1 shr 32) and uint64(bf.mask))
    pos[4] = uint32(pos2 and uint64(bf.mask))
    pos[5] = uint32((pos2 shr 32) and uint64(bf.mask))
    pos[6] = uint32(pos3 and uint64(bf.mask))
    pos[7] = uint32((pos3 shr 32) and uint64(bf.mask))
  else:
    pos[0] = (uint32.fromBytesLE(pubkey.blob.toOpenArray(0, 3)) xor
              uint32.fromBytesLE(pubkey.blob.toOpenArray(4, 7))) and
             uint32(bf.mask)
    pos[1] = (uint32.fromBytesLE(pubkey.blob.toOpenArray(8, 11)) xor
              uint32.fromBytesLE(pubkey.blob.toOpenArray(12, 15))) and
             uint32(bf.mask)
    pos[2] = (uint32.fromBytesLE(pubkey.blob.toOpenArray(16, 19)) xor
              uint32.fromBytesLE(pubkey.blob.toOpenArray(20, 23))) and
             uint32(bf.mask)
    pos[3] = (uint32.fromBytesLE(pubkey.blob.toOpenArray(24, 27)) xor
              uint32.fromBytesLE(pubkey.blob.toOpenArray(28, 31))) and
             uint32(bf.mask)
    pos[4] = (uint32.fromBytesLE(pubkey.blob.toOpenArray(32, 35)) xor
              uint32.fromBytesLE(pubkey.blob.toOpenArray(36, 39))) and
             uint32(bf.mask)
    pos[5] = (uint32.fromBytesLE(pubkey.blob.toOpenArray(40, 43)) xor
              uint32.fromBytesLE(pubkey.blob.toOpenArray(44, 47))) and
             uint32(bf.mask)
    pos[6] = (uint32.fromBytesLE(pubkey.blob.toOpenArray(0, 3)) xor
              uint32.fromBytesLE(pubkey.blob.toOpenArray(44, 47))) and
             uint32(bf.mask)
    pos[7] = (uint32.fromBytesLE(pubkey.blob.toOpenArray(4, 7)) xor
              uint32.fromBytesLE(pubkey.blob.toOpenArray(40, 43))) and
             uint32(bf.mask)
  pos

proc registerKey*(bf: var BloomFilter, pubkey: ValidatorPubKey) =
  let hashes = pubkey.toHashes()
  bf.raiseBit(hashes[0])
  bf.raiseBit(hashes[1])
  bf.raiseBit(hashes[2])
  bf.raiseBit(hashes[3])
  bf.raiseBit(hashes[4])
  bf.raiseBit(hashes[5])
  bf.raiseBit(hashes[6])
  bf.raiseBit(hashes[7])
  inc(bf.used)

func checkKey*(bf: BloomFilter, pubkey: ValidatorPubKey): bool =
  let hashes = pubkey.toHashes()
  if not(bf.getBit(hashes[0])): return false
  if not(bf.getBit(hashes[1])): return false
  if not(bf.getBit(hashes[2])): return false
  if not(bf.getBit(hashes[3])): return false
  if not(bf.getBit(hashes[4])): return false
  if not(bf.getBit(hashes[5])): return false
  if not(bf.getBit(hashes[6])): return false
  if not(bf.getBit(hashes[7])): return false
  true
