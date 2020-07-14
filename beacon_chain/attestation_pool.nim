# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Standard libraries
  deques, sequtils, tables, options,
  # Status libraries
  chronicles, stew/[byteutils], json_serialization/std/sets,
  # Internal
  ./spec/[beaconstate, datatypes, crypto, digest, helpers],
  ./extras, ./block_pool, ./block_pools/candidate_chains, ./beacon_node_types,
  ./fork_choice/fork_choice

logScope: topics = "attpool"

proc init*(T: type AttestationPool, blockPool: BlockPool): T =
  ## Initialize an AttestationPool from the blockPool `headState`
  ## The `finalized_root` works around the finalized_checkpoint of the genesis block
  ## holding a zero_root.
  # TODO blockPool is only used when resolving orphaned attestations - it should
  #      probably be removed as a dependency of AttestationPool (or some other
  #      smart refactoring)

  # TODO: Return Value Optimization

  # TODO: In tests, on blockpool.init the finalized root
  #       from the `headState` and `justifiedState` is zero
  var forkChoice = initForkChoice(
    finalized_block_slot = default(Slot),             # This is unnecessary for fork choice but may help external components for example logging/debugging
    finalized_block_state_root = default(Eth2Digest), # This is unnecessary for fork choice but may help external components for example logging/debugging
    justified_epoch = blockPool.headState.data.data.current_justified_checkpoint.epoch,
    finalized_epoch = blockPool.headState.data.data.finalized_checkpoint.epoch,
    # We should use the checkpoint, but at genesis the headState finalized checkpoint is 0x0000...0000
    # finalized_root = blockPool.headState.data.data.finalized_checkpoint.root
    finalized_root = blockPool.finalizedHead.blck.root
  ).get()

  # Load all blocks since finalized head - TODO a proper test
  for blck in blockPool.dag.topoSortedSinceLastFinalization():
    if blck.root == blockPool.finalizedHead.blck.root:
      continue

    # BlockRef
    # should ideally contain the justified_epoch and finalized_epoch
    # so that we can pass them directly to `process_block` without having to
    # redo "updateStateData"
    #
    # In any case, `updateStateData` should shortcut
    # to `getStateDataCached`

    updateStateData(
      blockPool,
      blockPool.tmpState,
      BlockSlot(blck: blck, slot: blck.slot)
    )

    debug "Preloading fork choice with block",
      block_root = shortlog(blck.root),
      parent_root = shortlog(blck.parent.root),
      justified_epoch = $blockPool.tmpState.data.data.current_justified_checkpoint.epoch,
      finalized_epoch = $blockPool.tmpState.data.data.finalized_checkpoint.epoch,
      slot = $blck.slot

    let status = forkChoice.process_block(
      block_root = blck.root,
      parent_root = blck.parent.root,
      justified_epoch = blockPool.tmpState.data.data.current_justified_checkpoint.epoch,
      finalized_epoch = blockPool.tmpState.data.data.finalized_checkpoint.epoch,
      # Unused in fork choice - i.e. for logging or caching extra metadata
      slot = blck.slot,
      state_root = default(Eth2Digest)
    )

    doAssert status.isOk(), "Error in preloading the fork choice: " & $status.error

  info "Fork choice initialized",
    justified_epoch = $blockPool.headState.data.data.current_justified_checkpoint.epoch,
    finalized_epoch = $blockPool.headState.data.data.finalized_checkpoint.epoch,
    finalized_root = shortlog(blockPool.finalizedHead.blck.root)

  T(
    mapSlotsToAttestations: initDeque[AttestationsSeen](),
    blockPool: blockPool,
    unresolved: initTable[Eth2Digest, UnresolvedAttestation](),
    forkChoice_v2: forkChoice
  )

proc combine*(tgt: var Attestation, src: Attestation, flags: UpdateFlags) =
  ## Combine the signature and participation bitfield, with the assumption that
  ## the same data is being signed - if the signatures overlap, they are not
  ## combined.
  # TODO: Exported only for testing, all usage are internals

  doAssert tgt.data == src.data

  # In a BLS aggregate signature, one needs to count how many times a
  # particular public key has been added - since we use a single bit per key, we
  # can only it once, thus we can never combine signatures that overlap already!
  if not tgt.aggregation_bits.overlaps(src.aggregation_bits):
    tgt.aggregation_bits.combine(src.aggregation_bits)

    if skipBlsValidation notin flags:
      tgt.signature.aggregate(src.signature)
  else:
    trace "Ignoring overlapping attestations"


proc slotIndex(
    pool: var AttestationPool, state: BeaconState, attestationSlot: Slot): int =
  ## Grow and garbage collect pool, returning the deque index of the slot

  # We keep a sliding window of attestations, roughly from the last finalized
  # epoch to now, because these are the attestations that may affect the voting
  # outcome. Some of these attestations will already have been added to blocks,
  # while others are fresh off the network.
  # TODO only the latest vote of each validator counts. Can we use that somehow?
  logScope: pcs = "atp_slot_maintenance"

  doAssert attestationSlot >= pool.startingSlot,
    """
    We should have checked in addResolved that attestation is newer than
    finalized_slot and we never prune things before that, per below condition!
    """ &
    ", attestationSlot: " & $shortLog(attestationSlot) &
    ", startingSlot: " & $shortLog(pool.startingSlot)

  if pool.mapSlotsToAttestations.len == 0:
    # Because the first attestations may arrive in any order, we'll make sure
    # to start counting at the last finalized epoch start slot - anything
    # earlier than that is thrown out by the above check
    info "First attestation!",
      attestationSlot =  $shortLog(attestationSlot),
      cat = "init"
    pool.startingSlot =
      state.finalized_checkpoint.epoch.compute_start_slot_at_epoch()

  if pool.startingSlot + pool.mapSlotsToAttestations.len.uint64 <= attestationSlot:
    trace "Growing attestation pool",
      attestationSlot =  $shortLog(attestationSlot),
      startingSlot = $shortLog(pool.startingSlot),
      cat = "caching"

    # Make sure there's a pool entry for every slot, even when there's a gap
    while pool.startingSlot + pool.mapSlotsToAttestations.len.uint64 <= attestationSlot:
      pool.mapSlotsToAttestations.addLast(AttestationsSeen())

  if pool.startingSlot <
      state.finalized_checkpoint.epoch.compute_start_slot_at_epoch():
    debug "Pruning attestation pool",
      startingSlot = $shortLog(pool.startingSlot),
      finalizedSlot = $shortLog(
        state.finalized_checkpoint
             .epoch.compute_start_slot_at_epoch()),
      cat = "pruning"

    # TODO there should be a better way to remove a whole epoch of stuff..
    while pool.startingSlot <
        state.finalized_checkpoint.epoch.compute_start_slot_at_epoch():
      pool.mapSlotsToAttestations.popFirst()
      pool.startingSlot += 1

  int(attestationSlot - pool.startingSlot)

func updateLatestVotes(
    pool: var AttestationPool, state: BeaconState, attestationSlot: Slot,
    participants: seq[ValidatorIndex], blck: BlockRef) =

  # ForkChoice v2
  let target_epoch = compute_epoch_at_slot(attestationSlot)

  for validator in participants:
    # ForkChoice v1
    let
      pubKey = state.validators[validator].pubkey
      current = pool.latestAttestations.getOrDefault(pubKey)
    if current.isNil or current.slot < attestationSlot:
      pool.latestAttestations[pubKey] = blck

    # # ForkChoice v2
    # pool.forkChoice_v2.process_attestation(validator, blck.root, target_epoch)

func get_attesting_indices_seq(state: BeaconState,
                               attestation_data: AttestationData,
                               bits: CommitteeValidatorsBits,
                               cache: var StateCache): seq[ValidatorIndex] =
  toSeq(items(get_attesting_indices(
    state, attestation_data, bits, cache)))

func addUnresolved(pool: var AttestationPool, attestation: Attestation) =
  pool.unresolved[attestation.data.beacon_block_root] =
    UnresolvedAttestation(
      attestation: attestation,
    )

proc addResolved(pool: var AttestationPool, blck: BlockRef, attestation: Attestation) =
  doAssert blck.root == attestation.data.beacon_block_root

  # TODO Which state should we use to validate the attestation? It seems
  #      reasonable to involve the head being voted for as well as the intended
  #      slot of the attestation - double-check this with spec

  # TODO: How fast is state rewind?
  #       Can this be a DOS vector.

  # TODO: filter valid attestation as much as possible before state rewind
  # TODO: the below check does not respect the inclusion delay
  #       we should use isValidAttestationSlot instead
  if blck.slot > attestation.data.slot:
    notice "Invalid attestation (too new!)",
      attestation = shortLog(attestation),
      blockSlot = shortLog(blck.slot)
    return

  if attestation.data.slot < pool.startingSlot:
    # It can happen that attestations in blocks for example are included even
    # though they no longer are relevant for finalization - let's clear
    # these out
    debug "Old attestation",
      attestation = shortLog(attestation),
      startingSlot = pool.startingSlot
    return

  # if not isValidAttestationSlot(attestation.data.slot, blck.slot):
  #   # Logging in isValidAttestationSlot
  #   return

  # Get a temporary state at the (block, slot) targeted by the attestation
  updateStateData(
    pool.blockPool, pool.blockPool.tmpState,
    BlockSlot(blck: blck, slot: attestation.data.slot))

  template state(): BeaconState = pool.blockPool.tmpState.data.data

  # Check that the attestation is indeed valid
  # TODO: we might want to split checks that depend
  #       on the state and those that don't to cheaply
  #       discard invalid attestations before rewinding state.

  if not isValidAttestationTargetEpoch(state, attestation.data):
    notice "Invalid attestation",
      attestation = shortLog(attestation),
      current_epoch = get_current_epoch(state),
      cat = "filtering"
    return

  # TODO inefficient data structures..

  var cache = getEpochCache(blck, state)
  let
    attestationSlot = attestation.data.slot
    idx = pool.slotIndex(state, attestationSlot)
    attestationsSeen = addr pool.mapSlotsToAttestations[idx]
    validation = Validation(
      aggregation_bits: attestation.aggregation_bits,
      aggregate_signature: attestation.signature)
    participants = get_attesting_indices_seq(
      state, attestation.data, validation.aggregation_bits, cache)

  var found = false
  for a in attestationsSeen.attestations.mitems():
    if a.data == attestation.data:
      for v in a.validations:
        if validation.aggregation_bits.isSubsetOf(v.aggregation_bits):
          # The validations in the new attestation are a subset of one of the
          # attestations that we already have on file - no need to add this
          # attestation to the database
          # TODO what if the new attestation is useful for creating bigger
          #      sets by virtue of not overlapping with some other attestation
          #      and therefore being useful after all?
          trace "Ignoring subset attestation",
            newParticipants = participants,
            cat = "filtering"
          found = true
          break

      if not found:
        # Attestations in the pool that are a subset of the new attestation
        # can now be removed per same logic as above

        trace "Removing subset attestations",
          newParticipants = participants,
          cat = "pruning"

        a.validations.keepItIf(
          not it.aggregation_bits.isSubsetOf(validation.aggregation_bits))

        a.validations.add(validation)
        pool.updateLatestVotes(state, attestationSlot, participants, a.blck)

        info "Attestation resolved",
          attestation = shortLog(attestation),
          validations = a.validations.len(),
          current_epoch = get_current_epoch(state),
          blockSlot = shortLog(blck.slot),
          cat = "filtering"

        found = true

      break

  if not found:
    attestationsSeen.attestations.add(AttestationEntry(
      data: attestation.data,
      blck: blck,
      validations: @[validation]
    ))
    pool.updateLatestVotes(state, attestationSlot, participants, blck)

    info "Attestation resolved",
      attestation = shortLog(attestation),
      current_epoch = get_current_epoch(state),
      validations = 1,
      blockSlot = shortLog(blck.slot),
      cat = "filtering"

proc addAttestation*(pool: var AttestationPool, attestation: Attestation) =
  ## Add a verified attestation to the fork choice context
  logScope: pcs = "atp_add_attestation"

  # Fetch the target block or notify the block pool that it's needed
  let blck = pool.blockPool.getOrResolve(attestation.data.beacon_block_root)

  # If the block exist, add it to the fork choice context
  # Otherwise delay until it resolves
  if blck.isNil:
    pool.addUnresolved(attestation)
    return

  pool.addResolved(blck, attestation)

proc addForkChoice_v2*(pool: var AttestationPool, blck: BlockRef) =
  ## Add a verified block to the fork choice context
  ## The current justifiedState of the block pool is used as reference

  # TODO: add(BlockPool, blockRoot: Eth2Digest, SignedBeaconBlock): BlockRef
  # should ideally return the justified_epoch and finalized_epoch
  # so that we can pass them directly to this proc without having to
  # redo "updateStateData"
  #
  # In any case, `updateStateData` should shortcut
  # to `getStateDataCached`

  var state: Result[void, string]
  # A stack of block to add in case recovery is needed
  var blockStack: seq[BlockSlot]
  var current = BlockSlot(blck: blck, slot: blck.slot)

  while true: # The while loop should not be needed but it seems a block addition
              # scenario is unaccounted for
    updateStateData(
      pool.blockPool,
      pool.blockPool.tmpState,
      current
    )

    let blockData = pool.blockPool.get(current.blck)
    state = pool.forkChoice_v2.process_block(
      slot = current.blck.slot,
      block_root = current.blck.root,
      parent_root = if not current.blck.parent.isNil: current.blck.parent.root else: default(Eth2Digest),
      state_root = default(Eth2Digest), # This is unnecessary for fork choice but may help external components
      justified_epoch = pool.blockPool.tmpState.data.data.current_justified_checkpoint.epoch,
      finalized_epoch = pool.blockPool.tmpState.data.data.finalized_checkpoint.epoch,
    )

    # This should not happen and might lead to unresponsive networking while processing occurs
    if state.isErr:
      # TODO investigate, potential sources:
      # - Pruning
      # - Quarantine adding multiple blocks at once
      # - Own block proposal
      error "Desync between fork_choice and blockpool services, trying to recover.",
        msg = state.error,
        blck = shortlog(current.blck),
        parent = shortlog(current.blck.parent),
        finalizedHead = shortLog(pool.blockPool.finalizedHead),
        justifiedHead = shortLog(pool.blockPool.head.justified),
        head = shortLog(pool.blockPool.head.blck)
      blockStack.add(current)
      current = BlockSlot(blck: blck.parent, slot: blck.parent.slot)
    elif blockStack.len == 0:
      break
    else:
      info "Re-added missing or pruned block to fork choice",
        msg = state.error,
        blck = shortlog(current.blck),
        parent = shortlog(current.blck.parent),
        finalizedHead = shortLog(pool.blockPool.finalizedHead),
        justifiedHead = shortLog(pool.blockPool.head.justified),
        head = shortLog(pool.blockPool.head.blck)
      current = blockStack.pop()

proc getAttestationsForSlot*(pool: AttestationPool, newBlockSlot: Slot):
    Option[AttestationsSeen] =
  if newBlockSlot < (GENESIS_SLOT + MIN_ATTESTATION_INCLUSION_DELAY):
    debug "Too early for attestations",
      newBlockSlot = shortLog(newBlockSlot),
      cat = "query"
    return none(AttestationsSeen)

  if pool.mapSlotsToAttestations.len == 0: # startingSlot not set yet!
    info "No attestations found (pool empty)",
      newBlockSlot = shortLog(newBlockSlot),
      cat = "query"
    return none(AttestationsSeen)

  let
    # TODO in theory we could include attestations from other slots also, but
    # we're currently not tracking which attestations have already been included
    # in blocks on the fork we're aiming for.. this is a conservative approach
    # that's guaranteed to not include any duplicates, because it's the first
    # time the attestations are up for inclusion!
    attestationSlot = newBlockSlot - MIN_ATTESTATION_INCLUSION_DELAY

  if attestationSlot < pool.startingSlot or
      attestationSlot >= pool.startingSlot + pool.mapSlotsToAttestations.len.uint64:
    info "No attestations matching the slot range",
      attestationSlot = shortLog(attestationSlot),
      startingSlot = shortLog(pool.startingSlot),
      endingSlot = shortLog(pool.startingSlot + pool.mapSlotsToAttestations.len.uint64),
      cat = "query"
    return none(AttestationsSeen)

  let slotDequeIdx = int(attestationSlot - pool.startingSlot)
  some(pool.mapSlotsToAttestations[slotDequeIdx])

proc getAttestationsForBlock*(pool: AttestationPool,
                              state: BeaconState): seq[Attestation] =
  ## Retrieve attestations that may be added to a new block at the slot of the
  ## given state
  logScope: pcs = "retrieve_attestation"

  # TODO this shouldn't really need state -- it's to recheck/validate, but that
  # should be refactored
  let newBlockSlot = state.slot
  var attestations: seq[AttestationEntry]

  # This isn't maximally efficient -- iterators or other approaches would
  # avoid lots of memory allocations -- but this provides a more flexible
  # base upon which to experiment with, and isn't yet profiling hot-path,
  # while avoiding penalizing slow attesting too much (as, in the spec it
  # is supposed to be available two epochs back; it's not meant as). This
  # isn't a good solution, either -- see the set-packing comment below as
  # one issue. It also creates problems with lots of repeat attestations,
  # as a bunch of synchronized beacon_nodes do almost the opposite of the
  # intended thing -- sure, _blocks_ have to be popular (via attestation)
  # but _attestations_ shouldn't have to be so frequently repeated, as an
  # artifact of this state-free, identical-across-clones choice basis. In
  # addResolved, too, the new attestations get added to the end, while in
  # these functions, it's reading from the beginning, et cetera. This all
  # needs a single unified strategy.
  const LOOKBACK_WINDOW = 3
  for i in max(1, newBlockSlot.int64 - LOOKBACK_WINDOW) .. newBlockSlot.int64:
    let maybeSlotData = getAttestationsForSlot(pool, i.Slot)
    if maybeSlotData.isSome:
      insert(attestations, maybeSlotData.get.attestations)

  if attestations.len == 0:
    return

  var cache = StateCache()
  for a in attestations:
    var
      # https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/validator.md#construct-attestation
      attestation = Attestation(
        aggregation_bits: a.validations[0].aggregation_bits,
        data: a.data,
        signature: a.validations[0].aggregate_signature
      )

    # TODO what's going on here is that when producing a block, we need to
    #      include only such attestations that will not cause block validation
    #      to fail. How this interacts with voting and the acceptance of
    #      attestations into the pool in general is an open question that needs
    #      revisiting - for example, when attestations are added, against which
    #      state should they be validated, if at all?
    # TODO we're checking signatures here every time which is very slow and we don't want
    #      to include a broken attestation
    if not check_attestation(state, attestation, {}, cache):
      warn "Attestation no longer validates...",
        cat = "query"
      continue

    for v in a.validations[1..^1]:
      # TODO We need to select a set of attestations that maximise profit by
      #      adding the largest combined attestation set that we can find - this
      #      unfortunately looks an awful lot like
      #      https://en.wikipedia.org/wiki/Set_packing - here we just iterate
      #      and naively add as much as possible in one go, by we could also
      #      add the same attestation data twice, as long as there's at least
      #      one new attestation in there
      if not attestation.aggregation_bits.overlaps(v.aggregation_bits):
        attestation.aggregation_bits.combine(v.aggregation_bits)
        attestation.signature.aggregate(v.aggregate_signature)

    result.add(attestation)

    if result.len >= MAX_ATTESTATIONS.int:
      debug "getAttestationsForBlock: returning early after hitting MAX_ATTESTATIONS",
        attestationSlot = newBlockSlot - 1
      return

proc resolve*(pool: var AttestationPool) =
  ## Check attestations in our unresolved deque
  ## if they can be integrated to the fork choice
  logScope: pcs = "atp_resolve"

  var
    done: seq[Eth2Digest]
    resolved: seq[tuple[blck: BlockRef, attestation: Attestation]]

  for k, v in pool.unresolved.mpairs():
    if (let blck = pool.blockPool.getRef(k); not blck.isNil()):
      resolved.add((blck, v.attestation))
      done.add(k)
    elif v.tries > 8:
      done.add(k)
    else:
      inc v.tries

  for k in done:
    pool.unresolved.del(k)

  for a in resolved:
    pool.addResolved(a.blck, a.attestation)

# Fork choice v1
# ---------------------------------------------------------------

func latestAttestation(
    pool: AttestationPool, pubKey: ValidatorPubKey): BlockRef =
  pool.latestAttestations.getOrDefault(pubKey)

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.4/specs/core/0_fork-choice.md
# The structure of this code differs from the spec since we use a different
# strategy for storing states and justification points - it should nonetheless
# be close in terms of functionality.
func lmdGhost(
    pool: AttestationPool, start_state: BeaconState,
    start_block: BlockRef): BlockRef =
  # TODO: a Fenwick Tree datastructure to keep track of cumulated votes
  #       in O(log N) complexity
  #       https://en.wikipedia.org/wiki/Fenwick_tree
  #       Nim implementation for cumulative frequencies at
  #       https://github.com/numforge/laser/blob/990e59fffe50779cdef33aa0b8f22da19e1eb328/benchmarks/random_sampling/fenwicktree.nim

  let
    active_validator_indices =
      get_active_validator_indices(
        start_state, compute_epoch_at_slot(start_state.slot))

  var latest_messages: seq[tuple[validator: ValidatorIndex, blck: BlockRef]]
  for i in active_validator_indices:
    let pubKey = start_state.validators[i].pubkey
    if (let vote = pool.latestAttestation(pubKey); not vote.isNil):
      latest_messages.add((i, vote))

  # TODO: update to 0.10.1: https://github.com/ethereum/eth2.0-specs/pull/1589/files#diff-9fc3792aa94456eb29506fa77f77b918R143
  template get_latest_attesting_balance(blck: BlockRef): uint64 =
    var res: uint64
    for validator_index, target in latest_messages.items():
      if get_ancestor(target, blck.slot) == blck:
        res += start_state.validators[validator_index].effective_balance
    res

  var head = start_block
  while true:
    if head.children.len() == 0:
      return head

    if head.children.len() == 1:
      head = head.children[0]
    else:
      var
        winner = head.children[0]
        winCount = get_latest_attesting_balance(winner)

      for i in 1..<head.children.len:
        let
          candidate = head.children[i]
          candCount = get_latest_attesting_balance(candidate)

        if (candCount > winCount) or
            ((candCount == winCount and candidate.root.data < winner.root.data)):
          winner = candidate
          winCount = candCount
      head = winner

proc selectHead_v1(pool: AttestationPool): BlockRef =
  let
    justifiedHead = pool.blockPool.latestJustifiedBlock()

  let newHead =
    lmdGhost(pool, pool.blockPool.justifiedState.data.data, justifiedHead.blck)

  newHead

# Fork choice v2
# ---------------------------------------------------------------

func getAttesterBalances(state: StateData): seq[Gwei] {.noInit.}=
  ## Get the balances from a state
  result.newSeq(state.data.data.validators.len) # zero-init

  let epoch = state.data.data.slot.compute_epoch_at_slot()

  for i in 0 ..< result.len:
    # All non-active validators have a 0 balance
    template validator: Validator = state.data.data.validators[i]
    if validator.is_active_validator(epoch):
      result[i] = validator.effective_balance

proc selectHead_v2(pool: var AttestationPool): BlockRef =
  let attesterBalances = pool.blockPool.justifiedState.getAttesterBalances()

  let newHead = pool.forkChoice_v2.find_head(
    justified_epoch = pool.blockPool.justifiedState.data.data.slot.compute_epoch_at_slot(),
    justified_root = pool.blockPool.head.justified.blck.root,
    finalized_epoch = pool.blockPool.headState.data.data.finalized_checkpoint.epoch,
    justified_state_balances = attesterBalances
  ).get()

  pool.blockPool.getRef(newHead)

proc pruneBefore*(pool: var AttestationPool, finalizedhead: BlockSlot) =
  pool.forkChoice_v2.maybe_prune(finalizedHead.blck.root).get()

# Dual-Headed Fork choice
# ---------------------------------------------------------------

proc selectHead*(pool: var AttestationPool): BlockRef =
  let head_v1 = pool.selectHead_v1()
  # let head_v2 = pool.selectHead_v2()
  # 
  # if head_v1 != head_v2:
  #   error "Fork choice engines in disagreement, using block from v1.",
  #     v1_block = shortlog(head_v1),
  #     v2_block = shortlog(head_v2)

  return head_v1
