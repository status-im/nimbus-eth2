# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import std/[options, macros],
       stew/byteutils, presto,
       ../spec/[forks],
       ../spec/eth2_apis/[rest_types, eth2_rest_serialization],
       ../beacon_node,
       ../validators/validator_duties,
       ../consensus_object_pools/blockchain_dag,
       "."/[rest_constants, state_ttl_cache]

export
  options, eth2_rest_serialization, blockchain_dag, presto, rest_types,
  rest_constants

type
  ValidatorIndexError* {.pure.} = enum
    UnsupportedValue, TooHighValue

func match(data: openArray[char], charset: set[char]): int =
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
  of "{block_root}":
    0
  of "{pubkey}":
    int(value.len != 98)
  else:
    1

proc getSyncedHead*(node: BeaconNode, slot: Slot): Result[BlockRef, cstring] =
  let head = node.dag.head

  if slot > head.slot and not node.isSynced(head):
    return err("Requesting way ahead of the current head")

  ok(head)

proc getSyncedHead*(node: BeaconNode,
                    epoch: Epoch): Result[BlockRef, cstring] =
  if epoch > MaxEpoch:
    return err("Requesting epoch for which slot would overflow")
  node.getSyncedHead(epoch.start_slot())

proc getBlockSlotId*(node: BeaconNode,
                     stateIdent: StateIdent): Result[BlockSlotId, cstring] =
  case stateIdent.kind
  of StateQueryKind.Slot:
    # Limit requests by state id to the next epoch with respect to the current
    # head to avoid long empty slot replays (in particular a second epoch
    # transition)
    if stateIdent.slot.epoch > (node.dag.head.slot.epoch + 1):
      return err("Requesting state too far ahead of current head")

    let bsi = node.dag.getBlockIdAtSlot(stateIdent.slot).valueOr:
      return err("State for given slot not found, history not available?")

    ok(bsi)

  of StateQueryKind.Root:
    if stateIdent.root == getStateRoot(node.dag.headState):
      ok(node.dag.head.bid.atSlot())
    else:
      # We don't have a state root -> BlockSlot mapping
      err("State for given root not found")
  of StateQueryKind.Named:
    case stateIdent.value
    of StateIdentType.Head:
      ok(node.dag.head.bid.atSlot())
    of StateIdentType.Genesis:
      ok(node.dag.genesis.atSlot())
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
      ok(node.dag.genesis)
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

proc disallowInterruptionsAux(body: NimNode) =
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

func syncCommitteeParticipants*(forkedState: ForkedHashedBeaconState,
                                epoch: Epoch
                               ): Result[seq[ValidatorPubKey], cstring] =
  withState(forkedState):
    when stateFork >= BeaconStateFork.Altair:
      let
        epochPeriod = sync_committee_period(epoch)
        curPeriod = sync_committee_period(state.data.slot)
      if epochPeriod == curPeriod:
        ok(@(state.data.current_sync_committee.pubkeys.data))
      elif epochPeriod == curPeriod + 1:
        ok(@(state.data.next_sync_committee.pubkeys.data))
      else:
        err("Epoch is outside the sync committee period of the state")
    else:
      err("State's fork do not support sync committees")

func keysToIndices*(cacheTable: var Table[ValidatorPubKey, ValidatorIndex],
                    forkedState: ForkedHashedBeaconState,
                    keys: openArray[ValidatorPubKey]
                   ): seq[Option[ValidatorIndex]] =
  var indices = newSeq[Option[ValidatorIndex]](len(keys))
  let totalValidatorsInState = getStateField(forkedState, validators).lenu64
  var keyset =
    block:
      var res: Table[ValidatorPubKey, int]
      for inputIndex, pubkey in keys:
        # Try to search in cache first.
        cacheTable.withValue(pubkey, vindex):
          if uint64(vindex[]) < totalValidatorsInState:
            indices[inputIndex] = some(vindex[])
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

proc getRouter*(allowedOrigin: Option[string]): RestRouter =
  RestRouter.init(validate, allowedOrigin = allowedOrigin)

proc getStateOptimistic*(node: BeaconNode,
                         state: ForkedHashedBeaconState): Option[bool] =
  if node.currentSlot().epoch() >= node.dag.cfg.BELLATRIX_FORK_EPOCH:
    case state.kind
    of BeaconStateFork.Phase0, BeaconStateFork.Altair:
      some[bool](false)
    of BeaconStateFork.Bellatrix:
      # A state is optimistic iff the block which created it is
      withState(state):
        # The block root which created the state at slot `n` is at slot `n-1`
        if state.data.slot == GENESIS_SLOT:
          some[bool](false)
        else:
          doAssert state.data.slot > 0
          some[bool](node.dag.is_optimistic(
            get_block_root_at_slot(state.data, state.data.slot - 1)))
  else:
    none[bool]()

proc getBlockOptimistic*(node: BeaconNode,
                         blck: ForkedTrustedSignedBeaconBlock |
                               ForkedSignedBeaconBlock): Option[bool] =
  if node.currentSlot().epoch() >= node.dag.cfg.BELLATRIX_FORK_EPOCH:
    case blck.kind
    of BeaconBlockFork.Phase0, BeaconBlockFork.Altair:
      some[bool](false)
    of BeaconBlockFork.Bellatrix:
      some[bool](node.dag.is_optimistic(blck.root))
  else:
    none[bool]()

proc getBlockRefOptimistic*(node: BeaconNode, blck: BlockRef): bool =
  let blck = node.dag.getForkedBlock(blck.bid).get()
  case blck.kind
  of BeaconBlockFork.Phase0, BeaconBlockFork.Altair:
    false
  of BeaconBlockFork.Bellatrix:
    node.dag.is_optimistic(blck.root)

const
  jsonMediaType* = MediaType.init("application/json")
  sszMediaType* = MediaType.init("application/octet-stream")
  textEventStreamMediaType* = MediaType.init("text/event-stream")
