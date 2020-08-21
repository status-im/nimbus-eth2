# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Standard libraries
  std/[algorithm, deques, sequtils, sets, tables, options],
  # Status libraries
  chronicles, stew/[byteutils], json_serialization/std/sets as jsonSets,
  # Internal
  ./spec/[beaconstate, datatypes, crypto, digest, helpers],
  ./block_pools/[spec_cache, chain_dag, clearance], ./beacon_node_types,
  ./fork_choice/fork_choice

export beacon_node_types, sets

logScope: topics = "attpool"

proc init*(T: type AttestationPool, chainDag: ChainDAGRef, quarantine: QuarantineRef): T =
  ## Initialize an AttestationPool from the chainDag `headState`
  ## The `finalized_root` works around the finalized_checkpoint of the genesis block
  ## holding a zero_root.
  # TODO chainDag/quarantine are only used when resolving orphaned attestations - they
  #      should probably be removed as a dependency of AttestationPool (or some other
  #      smart refactoring)

  let
    finalizedEpochRef = chainDag.getEpochRef(
      chainDag.finalizedHead.blck, chainDag.finalizedHead.slot.epoch())

  var forkChoice = ForkChoice.init(
    finalizedEpochRef, chainDag.finalizedHead.blck)

  # Feed fork choice with unfinalized history - during startup, block pool only
  # keeps track of a single history so we just need to follow it
  doAssert chainDag.heads.len == 1, "Init only supports a single history"

  var blocks: seq[BlockRef]
  var cur = chainDag.head
  while cur != chainDag.finalizedHead.blck:
    blocks.add cur
    cur = cur.parent

  debug "Preloading fork choice with blocks", blocks = blocks.len

  for blck in reversed(blocks):
    let
      epochRef = chainDag.getEpochRef(blck, blck.slot.compute_epoch_at_slot)
      status =
        forkChoice.process_block(
          chainDag, epochRef, blck, chainDag.get(blck).data.message, blck.slot)

    doAssert status.isOk(), "Error in preloading the fork choice: " & $status.error

  info "Fork choice initialized",
    justified_epoch = chainDag.headState.data.data.current_justified_checkpoint.epoch,
    finalized_epoch = chainDag.headState.data.data.finalized_checkpoint.epoch,
    finalized_root = shortlog(chainDag.finalizedHead.blck.root)

  T(
    chainDag: chainDag,
    quarantine: quarantine,
    unresolved: initTable[Eth2Digest, UnresolvedAttestation](),
    forkChoice: forkChoice
  )

proc processAttestation(
    pool: var AttestationPool, slot: Slot, participants: HashSet[ValidatorIndex],
    block_root: Eth2Digest, target: Checkpoint, wallSlot: Slot) =
  # Add attestation votes to fork choice
  if (let v = pool.forkChoice.on_attestation(
    pool.chainDag, slot, block_root, toSeq(participants), target, wallSlot);
    v.isErr):
      warn "Couldn't process attestation", err = v.error()

func addUnresolved*(pool: var AttestationPool, attestation: Attestation) =
  pool.unresolved[attestation.data.beacon_block_root] =
    UnresolvedAttestation(
      attestation: attestation,
    )

func candidateIdx(pool: AttestationPool, slot: Slot): Option[uint64] =
  if slot >= pool.startingSlot and
      slot < (pool.startingSlot + pool.candidates.lenu64):
    some(slot mod pool.candidates.lenu64)
  else:
    none(uint64)

proc updateCurrent(pool: var AttestationPool, wallSlot: Slot) =
  if wallSlot + 1 < pool.candidates.lenu64:
    return

  if pool.startingSlot + pool.candidates.lenu64 - 1 > wallSlot:
    error "Current slot older than attestation pool view, clock reset?",
      poolSlot = pool.startingSlot, wallSlot
    return

  # As time passes we'll clear out any old attestations as they are no longer
  # viable to be included in blocks

  let newWallSlot = wallSlot + 1 - pool.candidates.lenu64
  for i in pool.startingSlot..newWallSlot:
    pool.candidates[i.uint64 mod pool.candidates.lenu64] = AttestationsSeen()

  pool.startingSlot = newWallSlot

proc addResolved(
    pool: var AttestationPool, blck: BlockRef, attestation: Attestation,
    wallSlot: Slot) =
  # Add an attestation whose parent we know
  logScope:
    attestation = shortLog(attestation)

  updateCurrent(pool, wallSlot)

  doAssert blck.root == attestation.data.beacon_block_root

  let candidateIdx = pool.candidateIdx(attestation.data.slot)
  if candidateIdx.isNone:
    debug "Attestation slot out of range",
      startingSlot = pool.startingSlot
    return

  let
    epochRef = pool.chainDag.getEpochRef(blck, attestation.data.target.epoch)
    attestationsSeen = addr pool.candidates[candidateIdx.get]
    validation = Validation(
      aggregation_bits: attestation.aggregation_bits,
      aggregate_signature: attestation.signature)
    participants = get_attesting_indices(
      epochRef, attestation.data, validation.aggregation_bits)

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
            newParticipants = participants
          found = true
          break

      if not found:
        # Attestations in the pool that are a subset of the new attestation
        # can now be removed per same logic as above

        trace "Removing subset attestations",
          newParticipants = participants

        a.validations.keepItIf(
          not it.aggregation_bits.isSubsetOf(validation.aggregation_bits))

        a.validations.add(validation)
        pool.processAttestation(
          attestation.data.slot, participants, attestation.data.beacon_block_root,
          attestation.data.target, wallSlot)

        info "Attestation resolved",
          attestation = shortLog(attestation),
          validations = a.validations.len(),
          blockSlot = shortLog(blck.slot)

        found = true

      break

  if not found:
    attestationsSeen.attestations.add(AttestationEntry(
      data: attestation.data,
      blck: blck,
      validations: @[validation]
    ))
    pool.processAttestation(
      attestation.data.slot, participants, attestation.data.beacon_block_root,
      attestation.data.target, wallSlot)

    info "Attestation resolved",
      attestation = shortLog(attestation),
      validations = 1,
      blockSlot = shortLog(blck.slot)

proc addAttestation*(pool: var AttestationPool,
                     attestation: Attestation,
                     wallSlot: Slot) =
  ## Add a verified attestation to the fork choice context
  logScope: pcs = "atp_add_attestation"

  # Fetch the target block or notify the block pool that it's needed
  let blck = pool.chainDag.getOrResolve(
    pool.quarantine,
    attestation.data.beacon_block_root)

  # If the block exist, add it to the fork choice context
  # Otherwise delay until it resolves
  if blck.isNil:
    pool.addUnresolved(attestation)
    return

  pool.addResolved(blck, attestation, wallSlot)

proc addForkChoice*(pool: var AttestationPool,
                    epochRef: EpochRef,
                    blckRef: BlockRef,
                    blck: BeaconBlock,
                    wallSlot: Slot) =
  ## Add a verified block to the fork choice context
  let state = pool.forkChoice.process_block(
    pool.chainDag, epochRef, blckRef, blck, wallSlot)

  if state.isErr:
    # TODO If this happens, it is effectively a bug - the BlockRef structure
    #      guarantees that the DAG is valid and the state transition should
    #      guarantee that the justified and finalized epochs are ok! However,
    #      we'll log it for now to avoid crashes
    error "Unexpected error when applying block",
      blck = shortLog(blck), err = state.error

proc getAttestationsForSlot*(pool: AttestationPool, newBlockSlot: Slot):
    Option[AttestationsSeen] =
  if newBlockSlot < (GENESIS_SLOT + MIN_ATTESTATION_INCLUSION_DELAY):
    debug "Too early for attestations",
      newBlockSlot = shortLog(newBlockSlot)
    return none(AttestationsSeen)

  let
    attestationSlot = newBlockSlot - MIN_ATTESTATION_INCLUSION_DELAY
    candidateIdx = pool.candidateIdx(attestationSlot)

  if candidateIdx.isNone:
    trace "No attestations matching the slot range",
      attestationSlot = shortLog(attestationSlot),
      startingSlot = shortLog(pool.startingSlot)
    return none(AttestationsSeen)

  some(pool.candidates[candidateIdx.get()])

proc getAttestationsForBlock*(pool: AttestationPool,
                              state: BeaconState): seq[Attestation] =
  ## Retrieve attestations that may be added to a new block at the slot of the
  ## given state
  logScope: pcs = "retrieve_attestation"

  # TODO this shouldn't really need state -- it's to recheck/validate, but that
  # should be refactored
  let newBlockSlot = state.slot
  var attestations: seq[AttestationEntry]

  # This potentially creates problems with lots of repeated attestations,
  # as a bunch of synchronized beacon_nodes do almost the opposite of the
  # intended thing -- sure, _blocks_ have to be popular (via attestation)
  # but _attestations_ shouldn't have to be so frequently repeated, as an
  # artifact of this state-free, identical-across-clones choice basis. In
  # addResolved, too, the new attestations get added to the end, while in
  # these functions, it's reading from the beginning, et cetera. This all
  # needs a single unified strategy.
  for i in max(1, newBlockSlot.int64 - ATTESTATION_LOOKBACK.int64) .. newBlockSlot.int64:
    let maybeSlotData = getAttestationsForSlot(pool, i.Slot)
    if maybeSlotData.isSome:
      insert(attestations, maybeSlotData.get.attestations)

  if attestations.len == 0:
    return

  var cache = StateCache()
  for a in attestations:
    var
      # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#construct-attestation
      attestation = Attestation(
        aggregation_bits: a.validations[0].aggregation_bits,
        data: a.data,
        signature: a.validations[0].aggregate_signature
      )

      agg {.noInit.}: AggregateSignature
    agg.init(a.validations[0].aggregate_signature)

    # TODO what's going on here is that when producing a block, we need to
    #      include only such attestations that will not cause block validation
    #      to fail. How this interacts with voting and the acceptance of
    #      attestations into the pool in general is an open question that needs
    #      revisiting - for example, when attestations are added, against which
    #      state should they be validated, if at all?
    # TODO we're checking signatures here every time which is very slow and we don't want
    #      to include a broken attestation
    if (let v = check_attestation(state, attestation, {}, cache); v.isErr):
      warn "Attestation no longer validates...",
        attestation = shortLog(attestation),
        err = v.error

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
        agg.aggregate(v.aggregate_signature)

    attestation.signature = agg.finish()
    result.add(attestation)

    if result.lenu64 >= MAX_ATTESTATIONS:
      debug "getAttestationsForBlock: returning early after hitting MAX_ATTESTATIONS",
        attestationSlot = newBlockSlot - 1
      return

proc getAggregatedAttestation*(pool: AttestationPool,
                               slot: Slot,
                               index: CommitteeIndex): Option[Attestation] =
  let attestations = pool.getAttestationsForSlot(
    slot + MIN_ATTESTATION_INCLUSION_DELAY)
  if attestations.isNone:
    return none(Attestation)

  for a in attestations.get.attestations:
    doAssert a.data.slot == slot
    if index.uint64 != a.data.index:
      continue

    var
      # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#construct-attestation
      attestation = Attestation(
        aggregation_bits: a.validations[0].aggregation_bits,
        data: a.data,
        signature: a.validations[0].aggregate_signature
      )

      agg {.noInit.}: AggregateSignature

    agg.init(a.validations[0].aggregate_signature)
    for v in a.validations[1..^1]:
      if not attestation.aggregation_bits.overlaps(v.aggregation_bits):
        attestation.aggregation_bits.combine(v.aggregation_bits)
        agg.aggregate(v.aggregate_signature)

      attestation.signature = agg.finish()

    return some(attestation)

  none(Attestation)

proc resolve*(pool: var AttestationPool, wallSlot: Slot) =
  ## Check attestations in our unresolved deque
  ## if they can be integrated to the fork choice
  logScope: pcs = "atp_resolve"

  var
    done: seq[Eth2Digest]
    resolved: seq[tuple[blck: BlockRef, attestation: Attestation]]

  for k, v in pool.unresolved.mpairs():
    if (let blck = pool.chainDag.getRef(k); not blck.isNil()):
      resolved.add((blck, v.attestation))
      done.add(k)
    elif v.tries > 8:
      done.add(k)
    else:
      inc v.tries

  for k in done:
    pool.unresolved.del(k)

  for a in resolved:
    pool.addResolved(a.blck, a.attestation, wallSlot)

proc selectHead*(pool: var AttestationPool, wallSlot: Slot): Option[BlockRef] =
  # TODO: using "Option" here leads to high stack usage and stack overflows
  #       visible in test_attestation_pool and test_block_pool.
  #       This is compounded by unittest.check taking a copy
  #       of everything tested on the stack
  #
  #       However an option on a ref type should take the same size
  #       https://github.com/nim-lang/Nim/blob/v1.2.6/lib/pure/options.nim#L68-L75
  #
  #       Do we also need the lent PR?
  #       https://github.com/nim-lang/Nim/pull/14442

  let newHead = pool.forkChoice.get_head(pool.chainDag, wallSlot)

  if newHead.isErr:
    error "Couldn't select head", err = newHead.error
    result = none(BlockRef)
  else:
    result = some(pool.chainDag.getRef(newHead.get()))
    doAssert not result.unsafeGet().isNil

proc prune*(pool: var AttestationPool) =
  if (let v = pool.forkChoice.prune(); v.isErr):
    error "Pruning failed", err = v.error() # TODO should never happen
