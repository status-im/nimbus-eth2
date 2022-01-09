# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Standard libraries
  std/[options, tables, sequtils],
  # Status libraries
  metrics,
  chronicles, stew/byteutils,
  # Internal
  ../spec/[beaconstate, eth2_merkleization, forks, helpers, validator],
  ../spec/datatypes/[phase0, altair, bellatrix],
  "."/[spec_cache, blockchain_dag, block_quarantine],
  ../fork_choice/fork_choice,
  ../beacon_clock

export options, tables, phase0, altair, bellatrix, blockchain_dag, fork_choice

const
  ATTESTATION_LOOKBACK* =
    min(24'u64, SLOTS_PER_EPOCH) + MIN_ATTESTATION_INCLUSION_DELAY
    ## The number of slots we'll keep track of in terms of "free" attestations
    ## that potentially could be added to a newly created block

type
  OnAttestationCallback* = proc(data: Attestation) {.gcsafe, raises: [Defect].}

  Validation* = object
    ## Validations collect a set of signatures for a distict attestation - in
    ## eth2, a single bit is used to keep track of which signatures have been
    ## added to the aggregate meaning that only non-overlapping aggregates may
    ## be further combined.
    aggregation_bits*: CommitteeValidatorsBits
    aggregate_signature*: AggregateSignature

  AttestationEntry* = object
    ## Each entry holds the known signatures for a particular, distinct vote
    data*: AttestationData
    committee_len*: int
    singles*: Table[int, CookedSig] ## \
      ## On the attestation subnets, only attestations with a single vote are
      ## allowed - these can be collected separately to top up aggregates with -
      ## here we collect them by mapping index in committee to a vote
    aggregates*: seq[Validation]

  AttestationTable* = Table[Eth2Digest, AttestationEntry]
    ## Depending on the world view of the various validators, they may have
    ## voted on different states - this map keeps track of each vote keyed by
    ## hash_tree_root(AttestationData)

  AttestationPool* = object
    ## The attestation pool keeps track of all attestations that potentially
    ## could be added to a block during block production.
    ## These attestations also contribute to the fork choice, which combines
    ## "free" attestations with those found in past blocks - these votes
    ## are tracked separately in the fork choice.

    candidates*: array[ATTESTATION_LOOKBACK, AttestationTable] ## \
      ## We keep one item per slot such that indexing matches slot number
      ## together with startingSlot

    startingSlot*: Slot ## \
    ## Generally, we keep attestations only until a slot has been finalized -
    ## after that, they may no longer affect fork choice.

    dag*: ChainDAGRef
    quarantine*: ref Quarantine

    forkChoice*: ForkChoice

    nextAttestationEpoch*: seq[tuple[subnet: Epoch, aggregate: Epoch]] ## \
    ## sequence based on validator indices

    onAttestationAdded*: OnAttestationCallback

logScope: topics = "attpool"

declareGauge attestation_pool_block_attestation_packing_time,
  "Time it took to create list of attestations for block"

proc init*(T: type AttestationPool, dag: ChainDAGRef,
           quarantine: ref Quarantine,
           onAttestation: OnAttestationCallback = nil): T =
  ## Initialize an AttestationPool from the dag `headState`
  ## The `finalized_root` works around the finalized_checkpoint of the genesis block
  ## holding a zero_root.
  let finalizedEpochRef = dag.getFinalizedEpochRef()

  var forkChoice = ForkChoice.init(
    finalizedEpochRef,
    dag.finalizedHead.blck)

  # Feed fork choice with unfinalized history - during startup, block pool only
  # keeps track of a single history so we just need to follow it
  doAssert dag.heads.len == 1, "Init only supports a single history"

  var blocks: seq[BlockRef]
  var cur = dag.head

  # When the chain is finalizing, the votes between the head block and the
  # finalized checkpoint should be enough for a stable fork choice - when the
  # chain is not finalizing, we want to seed it with as many votes as possible
  # since the whole history of each branch might be significant. It is however
  # a game of diminishing returns, and we have to weigh it against the time
  # it takes to replay that many blocks during startup and thus miss _new_
  # votes.
  const ForkChoiceHorizon = 256
  while cur != dag.finalizedHead.blck:
    blocks.add cur
    cur = cur.parent

  info "Initializing fork choice", unfinalized_blocks = blocks.len

  var epochRef = finalizedEpochRef
  for i in 0..<blocks.len:
    let
      blckRef = blocks[blocks.len - i - 1]
      status =
        if i < (blocks.len - ForkChoiceHorizon) and (i mod 1024 != 0):
          # Fork choice needs to know about the full block tree up to the
          # finalization point, but doesn't really need to have overly accurate
          # justification and finalization points until we get close to head -
          # nonetheless, we'll make sure to pass a fresh finalization point now
          # and then to make sure the fork choice data structure doesn't grow
          # too big - getting an EpochRef can be expensive.
          forkChoice.backend.process_block(
            blckRef.root, blckRef.parent.root,
            epochRef.current_justified_checkpoint,
            epochRef.finalized_checkpoint)
        else:
          epochRef = dag.getEpochRef(blckRef, blckRef.slot.epoch, false).expect(
            "Getting an EpochRef should always work for non-finalized blocks")

          withBlck(dag.get(blckRef).data):
            forkChoice.process_block(
              dag, epochRef, blckRef, blck.message, blckRef.slot.start_beacon_time)

    doAssert status.isOk(), "Error in preloading the fork choice: " & $status.error

  info "Fork choice initialized",
    justified_epoch = getStateField(
      dag.headState.data, current_justified_checkpoint).epoch,
    finalized_epoch = getStateField(
      dag.headState.data, finalized_checkpoint).epoch,
    finalized_root = shortlog(dag.finalizedHead.blck.root)

  T(
    dag: dag,
    quarantine: quarantine,
    forkChoice: forkChoice,
    onAttestationAdded: onAttestation
  )

proc addForkChoiceVotes(
    pool: var AttestationPool, slot: Slot,
    attesting_indices: openArray[ValidatorIndex], block_root: Eth2Digest,
    wallTime: BeaconTime) =
  # Add attestation votes to fork choice
  if (let v = pool.forkChoice.on_attestation(
    pool.dag, slot, block_root, attesting_indices, wallTime);
    v.isErr):
      # This indicates that the fork choice and the chain dag are out of sync -
      # this is most likely the result of a bug, but we'll try to keep going -
      # hopefully the fork choice will heal itself over time.
      error "Couldn't add attestation to fork choice, bug?", err = v.error()

func candidateIdx(pool: AttestationPool, slot: Slot): Option[int] =
  if slot >= pool.startingSlot and
      slot < (pool.startingSlot + pool.candidates.lenu64):
    some(int(slot mod pool.candidates.lenu64))
  else:
    none(int)

proc updateCurrent(pool: var AttestationPool, wallSlot: Slot) =
  if wallSlot + 1 < pool.candidates.lenu64:
    return # Genesis

  let
    newStartingSlot = wallSlot + 1 - pool.candidates.lenu64

  if newStartingSlot < pool.startingSlot:
    error "Current slot older than attestation pool view, clock reset?",
      startingSlot = pool.startingSlot, newStartingSlot, wallSlot
    return

  # As time passes we'll clear out any old attestations as they are no longer
  # viable to be included in blocks

  if newStartingSlot - pool.startingSlot >= pool.candidates.lenu64():
    # In case many slots passed since the last update, avoid iterating over
    # the same indices over and over
    pool.candidates = default(type(pool.candidates))
  else:
    for i in pool.startingSlot..newStartingSlot:
      pool.candidates[i.uint64 mod pool.candidates.lenu64] = AttestationTable()

  pool.startingSlot = newStartingSlot

proc oneIndex(bits: CommitteeValidatorsBits): Option[int] =
  # Find the index of the set bit, iff one bit is set
  var res = none(int)
  for idx in 0..<bits.len():
    if bits[idx]:
      if res.isNone():
        res = some(idx)
      else: # More than one bit set!
        return none(int)
  res

func toAttestation(entry: AttestationEntry, validation: Validation): Attestation =
  Attestation(
    aggregation_bits: validation.aggregation_bits,
    data: entry.data,
    signature: validation.aggregate_signature.finish().toValidatorSig()
  )

func updateAggregates(entry: var AttestationEntry) =
  # Upgrade the list of aggregates to ensure that there is at least one
  # aggregate (assuming there are singles) and all aggregates have all
  # singles incorporated
  if entry.singles.len() == 0:
    return

  if entry.aggregates.len() == 0:
    # If there are singles, we can create an aggregate from them that will
    # represent our best knowledge about the current votes
    for index_in_committee, signature in entry.singles:
      if entry.aggregates.len() == 0:
        # Create aggregate on first iteration..
        entry.aggregates.add(
          Validation(
            aggregation_bits: CommitteeValidatorsBits.init(entry.committee_len),
            aggregate_signature: AggregateSignature.init(signature)
          ))
      else:
        entry.aggregates[0].aggregate_signature.aggregate(signature)

      entry.aggregates[0].aggregation_bits.setBit(index_in_committee)
  else:
    # There already exist aggregates - we'll try to top them up by adding
    # singles to them - for example, it may happen that we're being asked to
    # produce a block 4s after creating an aggregate and new information may
    # have arrived by then.
    # In theory, also aggregates could be combined but finding the best
    # combination is hard, so we'll pragmatically use singles only here
    var updated = false
    for index_in_committee, signature in entry.singles:
      for v in entry.aggregates.mitems():
        if not v.aggregation_bits[index_in_committee]:
          v.aggregation_bits.setBit(index_in_committee)
          v.aggregate_signature.aggregate(signature)
          updated = true

    if updated:
      # One or more aggregates were updated - time to remove the ones that are
      # pure subsets of the others. This may lead to quadratic behaviour, but
      # the number of aggregates for the entry is limited by the number of
      # aggregators on the topic which is capped `is_aggregator` and
      # TARGET_AGGREGATORS_PER_COMMITTEE
      var i = 0
      while i < entry.aggregates.len():
        var j = 0
        while j < entry.aggregates.len():
          if i != j and entry.aggregates[i].aggregation_bits.isSubsetOf(
              entry.aggregates[j].aggregation_bits):
            entry.aggregates[i] = entry.aggregates[j]
            entry.aggregates.del(j)
            dec i # Rerun checks on the new `i` item
            break
          else:
            inc j
        inc i

proc addAttestation(entry: var AttestationEntry,
                    attestation: Attestation,
                    signature: CookedSig): bool =
  logScope:
    attestation = shortLog(attestation)

  let
    singleIndex = oneIndex(attestation.aggregation_bits)

  if singleIndex.isSome():
    if singleIndex.get() in entry.singles:
      trace "Attestation already seen",
        singles = entry.singles.len(),
        aggregates = entry.aggregates.len()

      return false

    debug "Attestation resolved",
      singles = entry.singles.len(),
      aggregates = entry.aggregates.len()

    entry.singles[singleIndex.get()] = signature
  else:
    # More than one vote in this attestation
    for i in 0..<entry.aggregates.len():
      if attestation.aggregation_bits.isSubsetOf(entry.aggregates[i].aggregation_bits):
        trace "Aggregate already seen",
          singles = entry.singles.len(),
          aggregates = entry.aggregates.len()
        return false

    # Since we're adding a new aggregate, we can now remove existing
    # aggregates that don't add any new votes
    entry.aggregates.keepItIf(
      not it.aggregation_bits.isSubsetOf(attestation.aggregation_bits))

    entry.aggregates.add(Validation(
      aggregation_bits: attestation.aggregation_bits,
      aggregate_signature: AggregateSignature.init(signature)))

    debug "Aggregate resolved",
      singles = entry.singles.len(),
      aggregates = entry.aggregates.len()

  true

proc addAttestation*(pool: var AttestationPool,
                     attestation: Attestation,
                     attesting_indices: openArray[ValidatorIndex],
                     signature: CookedSig,
                     wallTime: BeaconTime) =
  ## Add an attestation to the pool, assuming it's been validated already.
  ##
  ## Assuming the votes in the attestation have not already been seen, the
  ## attestation will be added to the fork choice and lazily added to a list of
  ## attestations for future aggregation and block production.
  logScope:
    attestation = shortLog(attestation)

  doAssert attestation.signature == signature.toValidatorSig(),
    "Deserialized signature must match the one in the attestation"

  updateCurrent(pool, wallTime.slotOrZero)

  let candidateIdx = pool.candidateIdx(attestation.data.slot)
  if candidateIdx.isNone:
    debug "Skipping old attestation for block production",
      startingSlot = pool.startingSlot
    return

  let attestation_data_root = hash_tree_root(attestation.data)

  # TODO withValue is an abomination but hard to use anything else too without
  #      creating an unnecessary AttestationEntry on the hot path and avoiding
  #      multiple lookups
  pool.candidates[candidateIdx.get()].withValue(attestation_data_root, entry) do:
    if not addAttestation(entry[], attestation, signature):
      return
  do:
    if not addAttestation(
        pool.candidates[candidateIdx.get()].mgetOrPut(
          attestation_data_root,
          AttestationEntry(
            data: attestation.data,
            committee_len: attestation.aggregation_bits.len())),
        attestation, signature):
      return

  pool.addForkChoiceVotes(
    attestation.data.slot, attesting_indices,
    attestation.data.beacon_block_root, wallTime)

  # Send notification about new attestation via callback.
  if not(isNil(pool.onAttestationAdded)):
    pool.onAttestationAdded(attestation)

proc addForkChoice*(pool: var AttestationPool,
                    epochRef: EpochRef,
                    blckRef: BlockRef,
                    blck: ForkyTrustedBeaconBlock,
                    wallTime: BeaconTime) =
  ## Add a verified block to the fork choice context
  let state = pool.forkChoice.process_block(
    pool.dag, epochRef, blckRef, blck, wallTime)

  if state.isErr:
    # This indicates that the fork choice and the chain dag are out of sync -
    # this is most likely the result of a bug, but we'll try to keep going -
    # hopefully the fork choice will heal itself over time.
    error "Couldn't add block to fork choice, bug?",
      blck = shortLog(blck), err = state.error

iterator attestations*(pool: AttestationPool, slot: Option[Slot],
                       committee_index: Option[CommitteeIndex]): Attestation =
  let candidateIndices =
    if slot.isSome():
      let candidateIdx = pool.candidateIdx(slot.get())
      if candidateIdx.isSome():
        candidateIdx.get() .. candidateIdx.get()
      else:
        1 .. 0
    else:
      0 ..< pool.candidates.len()

  for candidateIndex in candidateIndices:
    for _, entry in pool.candidates[candidateIndex]:
      if committee_index.isNone() or entry.data.index == committee_index.get():
        var singleAttestation = Attestation(
          aggregation_bits: CommitteeValidatorsBits.init(entry.committee_len),
          data: entry.data)

        for index, signature in entry.singles:
          singleAttestation.aggregation_bits.setBit(index)
          singleAttestation.signature = signature.toValidatorSig()
          yield singleAttestation
          singleAttestation.aggregation_bits.clearBit(index)

        for v in entry.aggregates:
          yield entry.toAttestation(v)

type
  AttestationCacheKey* = (Slot, uint64)
  AttestationCache = Table[AttestationCacheKey, CommitteeValidatorsBits] ##\
    ## Cache for quick lookup during beacon block construction of attestations
    ## which have already been included, and therefore should be skipped.

func getAttestationCacheKey(ad: AttestationData): AttestationCacheKey =
  # The committee is unique per slot and committee index which means we can use
  # it as key for a participation cache - this is checked in `check_attestation`
  (ad.slot, ad.index)

func add(
    attCache: var AttestationCache, data: AttestationData,
    aggregation_bits: CommitteeValidatorsBits) =
  let key = data.getAttestationCacheKey()
  attCache.withValue(key, v) do:
    v[].incl(aggregation_bits)
  do:
    attCache[key] = aggregation_bits

func init(T: type AttestationCache, state: phase0.HashedBeaconState): T =
  # Load attestations that are scheduled for being given rewards for
  for i in 0..<state.data.previous_epoch_attestations.len():
    result.add(
      state.data.previous_epoch_attestations[i].data,
      state.data.previous_epoch_attestations[i].aggregation_bits)
  for i in 0..<state.data.current_epoch_attestations.len():
    result.add(
      state.data.current_epoch_attestations[i].data,
      state.data.current_epoch_attestations[i].aggregation_bits)

func init(
    T: type AttestationCache,
    state: altair.HashedBeaconState | bellatrix.HashedBeaconState,
    cache: var StateCache): T =
  # Load attestations that are scheduled for being given rewards for
  let
    prev_epoch = state.data.get_previous_epoch()
    cur_epoch = state.data.get_current_epoch()

  template update_attestation_pool_cache(
      epoch: Epoch, participation_bitmap: untyped) =
    for committee_index in get_committee_indices(state.data, epoch, cache):
      for slot in epoch.slots():
        let committee = get_beacon_committee(
            state.data, slot, committee_index, cache)
        var
          validator_bits = CommitteeValidatorsBits.init(committee.len)
        for index_in_committee, validator_index in committee:
          if participation_bitmap[validator_index] != 0:
            # If any flag got set, there was an attestation from this validator.
            validator_bits[index_in_committee] = true
        result.add((slot, committee_index.uint64), validator_bits)

  # This treats all types of rewards as equivalent, which isn't ideal
  update_attestation_pool_cache(
    prev_epoch, state.data.previous_epoch_participation)
  update_attestation_pool_cache(
    cur_epoch, state.data.current_epoch_participation)

proc score(
    attCache: var AttestationCache, data: AttestationData,
    aggregation_bits: CommitteeValidatorsBits): int =
  # The score of an attestation is loosely based on how many new votes it brings
  # to the state - a more accurate score function would also look at inclusion
  # distance and effective balance.
  # TODO cache not var, but `withValue` requires it
  let
    key = data.getAttestationCacheKey()
    bitsScore = aggregation_bits.countOnes()

  attCache.withValue(key, value):
    doAssert aggregation_bits.len() == value[].len(),
      "check_attestation ensures committee length"

    # How many votes were in the attestation minues the votes that are the same
    return bitsScore - aggregation_bits.countOverlap(value[])

  # Not found in cache - fresh vote meaning all attestations count
  bitsScore

proc getAttestationsForBlock*(pool: var AttestationPool,
                              state: ForkyHashedBeaconState,
                              cache: var StateCache): seq[Attestation] =
  ## Retrieve attestations that may be added to a new block at the slot of the
  ## given state
  ## https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/validator.md#attestations
  let newBlockSlot = state.data.slot.uint64

  if newBlockSlot < MIN_ATTESTATION_INCLUSION_DELAY:
    return # Too close to genesis

  let
    # Attestations produced in a particular slot are added to the block
    # at the slot where at least MIN_ATTESTATION_INCLUSION_DELAY have passed
    maxAttestationSlot = newBlockSlot - MIN_ATTESTATION_INCLUSION_DELAY
    startPackingTick = Moment.now()

  var
    candidates: seq[tuple[
      score: int, slot: Slot, entry: ptr AttestationEntry, validation: int]]
    attCache =
      when state is phase0.HashedBeaconState:
        AttestationCache.init(state)
      elif state is altair.HashedBeaconState or state is bellatrix.HashedBeaconState:
        AttestationCache.init(state, cache)
      else:
        static: doAssert false

  for i in 0..<ATTESTATION_LOOKBACK:
    if i > maxAttestationSlot: # Around genesis..
      break

    let
      slot = Slot(maxAttestationSlot - i)
      candidateIdx = pool.candidateIdx(slot)

    if candidateIdx.isNone():
      # Passed the collection horizon - shouldn't happen because it's based on
      # ATTESTATION_LOOKBACK
      break

    for _, entry in pool.candidates[candidateIdx.get()].mpairs():
      entry.updateAggregates()

      for j in 0..<entry.aggregates.len():
        let
          attestation = entry.toAttestation(entry.aggregates[j])

        # Attestations are checked based on the state that we're adding the
        # attestation to - there might have been a fork between when we first
        # saw the attestation and the time that we added it
        if not check_attestation(
              state.data, attestation, {skipBlsValidation}, cache).isOk():
          continue

        let score = attCache.score(
          entry.data, entry.aggregates[j].aggregation_bits)
        if score == 0:
          # 0 score means the attestation would not bring any votes - discard
          # it early
          # Note; this must be done _after_ `check_attestation` as it relies on
          # the committee to match the state that was used to build the cache
          continue

        # Careful, must not update the attestation table for the pointer to
        # remain valid
        candidates.add((score, slot, addr entry, j))

  # Using a greedy algorithm, select as many attestations as possible that will
  # fit in the block.
  #
  # For each round, we'll look for the best attestation and add it to the result
  # then re-score the other candidates.
  #
  # A possible improvement here would be to use a maximum cover algorithm.
  var
    prevEpoch = state.data.get_previous_epoch()
    prevEpochSpace =
      when state is altair.HashedBeaconState or state is bellatrix.HashedBeaconState:
        MAX_ATTESTATIONS
      elif state is phase0.HashedBeaconState:
        state.data.previous_epoch_attestations.maxLen -
          state.data.previous_epoch_attestations.len()
      else:
        raiseAssert "invalid HashedBeaconState fork"

  var res: seq[Attestation]
  let totalCandidates = candidates.len()
  while candidates.len > 0 and res.lenu64() < MAX_ATTESTATIONS:
    block:
      # Find the candidate with the highest score - slot is used as a
      # tie-breaker so that more recent attestations are added first
      let
        candidate =
          # Fast path for when all remaining candidates fit
          if candidates.lenu64 < MAX_ATTESTATIONS: candidates.len - 1
          else: maxIndex(candidates)
        # TODO slot not used; replace with _ when
        # https://github.com/nim-lang/Nim/issues/15972 and
        # https://github.com/nim-lang/Nim/issues/16217 are
        # fixed in Status's Nim.
        (_, slot, entry, j) = candidates[candidate]

      candidates.del(candidate) # careful, `del` reorders candidates

      if entry[].data.target.epoch == prevEpoch:
        if prevEpochSpace < 1:
          continue # No need to rescore since we didn't add the attestation

        prevEpochSpace -= 1

      res.add(entry[].toAttestation(entry[].aggregates[j]))

      # Update cache so that the new votes are taken into account when updating
      # the score below
      attCache.add(entry[].data,  entry[].aggregates[j].aggregation_bits)

    block:
      # Because we added some votes, it's quite possible that some candidates
      # are no longer interesting - update the scores of the existing candidates
      for it in candidates.mitems():
        it.score = attCache.score(
          it.entry[].data,
          it.entry[].aggregates[it.validation].aggregation_bits)

      candidates.keepItIf:
        # Only keep candidates that might add coverage
        it.score > 0

  let
    packingDur = Moment.now() - startPackingTick

  debug "Packed attestations for block",
    newBlockSlot, packingDur, totalCandidates, attestations = res.len()
  attestation_pool_block_attestation_packing_time.set(
    packingDur.toFloatSeconds())

  res

proc getAttestationsForBlock*(pool: var AttestationPool,
                              state: ForkedHashedBeaconState,
                              cache: var StateCache): seq[Attestation] =
  withState(state):
    pool.getAttestationsForBlock(state, cache)

func bestValidation(aggregates: openArray[Validation]): (int, int) =
  # Look for best validation based on number of votes in the aggregate
  doAssert aggregates.len() > 0,
    "updateAggregates should have created at least one aggregate"
  var
    bestIndex = 0
    best = aggregates[bestIndex].aggregation_bits.countOnes()

  for i in 1..<aggregates.len():
    let count = aggregates[i].aggregation_bits.countOnes()
    if count > best:
      best = count
      bestIndex = i
  (bestIndex, best)

func getAggregatedAttestation*(pool: var AttestationPool,
                               slot: Slot,
                               attestation_data_root: Eth2Digest): Option[Attestation] =
  let
    candidateIdx = pool.candidateIdx(slot)
  if candidateIdx.isNone:
    return none(Attestation)

  pool.candidates[candidateIdx.get].withValue(attestation_data_root, entry):
    entry[].updateAggregates()

    let (bestIndex, _) = bestValidation(entry[].aggregates)

    # Found the right hash, no need to look further
    return some(entry[].toAttestation(entry[].aggregates[bestIndex]))

  none(Attestation)

proc getAggregatedAttestation*(pool: var AttestationPool,
                               slot: Slot,
                               index: CommitteeIndex): Option[Attestation] =
  ## Select the attestation that has the most votes going for it in the given
  ## slot/index
  ## https://github.com/ethereum/consensus-specs/blob/v1.1.8/specs/phase0/validator.md#construct-aggregate
  let
    candidateIdx = pool.candidateIdx(slot)
  if candidateIdx.isNone:
    return none(Attestation)

  var res: Option[Attestation]
  for _, entry in pool.candidates[candidateIdx.get].mpairs():
    doAssert entry.data.slot == slot
    if index != entry.data.index:
      continue

    entry.updateAggregates()

    let (bestIndex, best) = bestValidation(entry.aggregates)

    if res.isNone() or best > res.get().aggregation_bits.countOnes():
      res = some(entry.toAttestation(entry.aggregates[bestIndex]))

  res

proc selectHead*(pool: var AttestationPool, wallTime: BeaconTime): BlockRef =
  ## Trigger fork choice and returns the new head block.
  ## Can return `nil`
  let newHead = pool.forkChoice.get_head(pool.dag, wallTime)

  if newHead.isErr:
    error "Couldn't select head", err = newHead.error
    nil
  else:
    let ret = pool.dag.getRef(newHead.get())
    if ret.isNil:
      # This should normally not happen, but if the chain dag and fork choice
      # get out of sync, we'll need to try to download the selected head - in
      # the meantime, return nil to indicate that no new head was chosen
      warn "Fork choice selected unknown head, trying to sync", root = newHead.get()
      pool.quarantine[].addMissing(newHead.get())

    ret

proc prune*(pool: var AttestationPool) =
  if (let v = pool.forkChoice.prune(); v.isErr):
    # If pruning fails, it's likely the result of a bug - this shouldn't happen
    # but we'll keep running hoping that the fork chocie will recover eventually
    error "Couldn't prune fork choice, bug?", err = v.error()
