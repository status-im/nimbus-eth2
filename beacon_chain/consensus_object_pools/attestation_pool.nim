# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  # Status libraries
  metrics,
  chronicles, stew/byteutils,
  # Internal
  ../spec/[eth2_merkleization, forks, validator],
  ./[spec_cache, blockchain_dag, block_quarantine],
  ../fork_choice/fork_choice,
  ../beacon_clock

from std/algorithm import sort
from std/sequtils import anyIt, keepItIf
from ../spec/beaconstate import check_attestation, dependent_root
from ../spec/state_transition_epoch import compute_unrealized_finality

export blockchain_dag, fork_choice

const
  # TODO since deneb, this is looser (whole previous epoch)
  ATTESTATION_LOOKBACK = SLOTS_PER_EPOCH + MIN_ATTESTATION_INCLUSION_DELAY
    ## The number of slots we'll keep track of in terms of "free" attestations
    ## that potentially could be added to a newly created block

type
  OnSingleAttestationCallback =
    proc(data: SingleAttestation) {.gcsafe, raises: [].}

  Validation = object
    ## Validations collect a set of signatures for a distinct attestation - in
    ## eth2, a single bit is used to keep track of which signatures have been
    ## added to the aggregate meaning that only non-overlapping aggregates may
    ## be further combined.
    aggregation_bits: ElectraCommitteeValidatorsBits
    aggregate_signature: AggregateSignature

  AttestationEntry = object
    ## Each entry holds the known signatures of a particular
    ## slot/committee/block root combination, both single votes and aggregates.
    ## Single votes are used to top up (or construct) aggregates.
    slot*: Slot
    index*: uint64
    payloadIndex*: uint64
    beacon_block_root*: Eth2Digest
    source*: Checkpoint
    target*: Checkpoint

    committee_len: int
      ## Size of the committee, for initializing aggregates from singles
    singles: Table[int, CookedSig]
      ## On the attestation subnets, only attestations with a single vote are
      ## allowed - these are collected separately to top up aggregates -
      ## here we collect them by mapping index in committee to a vote
    aggregates: seq[Validation]

  AttestationTable = Table[Eth2Digest, AttestationEntry]
    ## Depending on the world view of the various validators, they may have
    ## voted on different states - this map keeps track of each vote keyed by
    ## getAttestationCandidateKey()

  AttestationPool* = object
    ## The attestation pool keeps track of all attestations that potentially
    ## could be added to a block during block production.
    ## These attestations also contribute to the fork choice, which combines
    ## "free" attestations with those found in past blocks - these votes
    ## are tracked separately in the fork choice.

    candidates: array[ATTESTATION_LOOKBACK.int, AttestationTable] ## \
      ## We keep one item per slot such that indexing matches slot number
      ## together with startingSlot

    startingSlot: Slot
      ## Generally, we keep attestations only until a slot has been finalized -
      ## after that, they may no longer affect fork choice.

    dag*: ChainDAGRef
    quarantine*: ref Quarantine

    forkChoice*: ForkChoice

    nextAttestationEpoch*: seq[tuple[subnet: Epoch, aggregate: Epoch]]
      ## sequence based on validator indices

    onSingleAttestationAdded: OnSingleAttestationCallback

logScope: topics = "attpool"

declareGauge attestation_pool_block_attestation_packing_time,
  "Time it took to create list of attestations for block"

func init(
    T: type AttestationEntry,
    data: AttestationData,
    committee_index: uint64,
    committee_len: int,
): T =
  T(
    slot: data.slot,
    index: committee_index,
    payloadIndex: data.index,
    beacon_block_root: data.beacon_block_root,
    source: data.source,
    target: data.target,
    committee_len: committee_len,
  )

func init(T: type AttestationData, entry: AttestationEntry): T =
  T(
    slot: entry.slot,
    index: entry.payloadIndex,
    beacon_block_root: entry.beacon_block_root,
    source: entry.source,
    target: entry.target,
  )

proc init*(T: type AttestationPool, dag: ChainDAGRef,
           quarantine: ref Quarantine, wallTime = default(BeaconTime),
           onSingleAttestation: OnSingleAttestationCallback = nil): T =
  ## Initialize an AttestationPool from the dag `headState`
  ## The `finalized_root` works around the finalized_checkpoint of the genesis block
  ## holding a zero_root.
  let
    currentSlot = wallTime.slotOrZero(dag.timeParams)
    finalizedEpochRef = dag.getFinalizedEpochRef()
  var forkChoice = ForkChoice.init(
    dag.cfg.CONFIRMATION_BYZANTINE_THRESHOLD,
    finalizedEpochRef, dag.finalizedHead.blck, currentSlot, wallTime)

  # Feed fork choice with unfinalized history - during startup, block pool only
  # keeps track of a single history so we just need to follow it
  doAssert dag.heads.len == 1, "Init only supports a single history"

  var
    blocks: seq[BlockRef]
    cur = dag.head

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
          # Fork choice needs to know about the full block tree back through the
          # finalization point, but doesn't really need to have overly accurate
          # justification and finalization points until we get close to head -
          # nonetheless, we'll make sure to pass a fresh finalization point now
          # and then to make sure the fork choice data structure doesn't grow
          # too big - getting an EpochRef can be expensive.
          forkChoice.backend.process_block(
            blckRef.bid, blckRef.parent.root, epochRef.checkpoints)
        else:
          epochRef = dag.getEpochRef(blckRef, blckRef.slot.epoch, false).expect(
            "Getting an EpochRef should always work for non-finalized blocks")
          let
            blck = dag.getForkedBlock(blckRef.bid).expect(
              "Should be able to load initial fork choice blocks")
            unrealized =
              if blckRef == dag.head:
                withState(dag.headState):
                  when consensusFork >= ConsensusFork.Altair:
                    let (checkpoints, balances) =
                      forkyState.data.compute_unrealized_finality()
                    dag.putParticipatingBalances CachedParticipatingBalances(
                      bid: blckRef.bid, balances: balances)
                    checkpoints
                  else:
                    var cache: StateCache
                    forkyState.data.compute_unrealized_finality(cache)
              else:
                default(FinalityCheckpoints)
          withBlck(blck):
            forkChoice.process_block(
              dag, epochRef, blckRef, unrealized, forkyBlck.message,
              blckRef.slot.start_beacon_time(dag.timeParams))

    doAssert status.isOk(), "Error in preloading the fork choice: " & $status.error

  info "Fork choice initialized",
    justified = shortLog(dag.headState.current_justified_checkpoint),
    finalized = shortLog(dag.headState.finalized_checkpoint)
  T(
    dag: dag,
    quarantine: quarantine,
    forkChoice: forkChoice,
    onSingleAttestationAdded: onSingleAttestation
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

func candidateIdx(pool: AttestationPool, slot: Slot): Opt[int] =
  const poolLength = pool.candidates.lenu64

  if slot >= pool.startingSlot and slot < (pool.startingSlot + poolLength):
    Opt.some(int(slot mod poolLength))
  else:
    Opt.none(int)

proc updateCurrent(pool: var AttestationPool, wallSlot: Slot) =
  if wallSlot + 1 < pool.candidates.lenu64:
    return # Genesis

  let newStartingSlot = wallSlot + 1 - pool.candidates.lenu64

  if newStartingSlot < pool.startingSlot:
    error "Current slot older than attestation pool view, clock reset?",
      startingSlot = pool.startingSlot, newStartingSlot, wallSlot
    return

  # As time passes we'll clear out any old attestations as they are no longer
  # viable to be included in blocks

  if newStartingSlot - pool.startingSlot >= pool.candidates.lenu64():
    # In case many slots passed since the last update, avoid iterating over
    # the same indices over and over
    pool.candidates.reset()
  else:
    for i in pool.startingSlot..newStartingSlot:
      pool.candidates[i.uint64 mod pool.candidates.lenu64].reset()

  pool.startingSlot = newStartingSlot

func oneIndex(bits: ElectraCommitteeValidatorsBits): Opt[int] =
  # Find the index of the set bit, iff one bit is set
  var res = Opt.none(int)
  for idx in 0..<bits.len():
    if bits[idx]:
      if res.isNone():
        res = Opt.some(idx)
      else: # More than one bit set!
        return Opt.none(int)
  res

func toElectraAttestation(
    entry: AttestationEntry, validation: Validation
): electra.Attestation =
  var committee_bits: AttestationCommitteeBits
  committee_bits[int(entry.index)] = true

  electra.Attestation(
    aggregation_bits: validation.aggregation_bits,
    committee_bits: committee_bits,
    data: AttestationData.init(entry),
    signature: validation.aggregate_signature.finish().toValidatorSig(),
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
        entry.aggregates.add Validation(
          aggregation_bits: ElectraCommitteeValidatorsBits.init(entry.committee_len),
          aggregate_signature: AggregateSignature.init(signature),
        )
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

  if entry.aggregates.len == 1 and
      entry.aggregates[0].aggregation_bits.countOnes() ==
      entry.aggregates[0].aggregation_bits.len:
    # All bits are set in the aggregate (ergo all other aggregates should have
    # been removed in the cover check) meaning that the singles are no longer
    # useful - although we reset things here, we have to be careful to not rely
    # on singles remaining empty (more might drop in later) - this is simply a
    # small way to save some memory in the optimistic case that everyone in the
    # committee voted successfully
    entry.singles.reset()

func covers(entry: AttestationEntry, bits: ElectraCommitteeValidatorsBits): bool =
  entry.aggregates.anyIt(bits.isSubsetOf(it.aggregation_bits))

proc addAttestation(
    entry: var AttestationEntry, attestation: SingleAttestation,
    index_in_committee: int, signature: CookedSig): bool =
  logScope:
    attestation = shortLog(attestation)

  if index_in_committee in entry.singles:
    trace "SingleAttestation already seen",
      singles = entry.singles.len(),
      aggregates = entry.aggregates.len()

    return false

  entry.singles[index_in_committee] = signature

  debug "SingleAttestation resolved",
    singles = entry.singles.len(),
    aggregates = entry.aggregates.len()

  true

proc addAttestation(
    entry: var AttestationEntry,
    attestation: electra.Attestation, _: int, signature: CookedSig): bool =
  logScope:
    attestation = shortLog(attestation)

  let singleIndex = oneIndex(attestation.aggregation_bits)

  if singleIndex.isSome():
    # An aggregate that contains only a single vote can be stored as a single
    if singleIndex.get() in entry.singles:
      trace "Aggregate already seen",
        singles = entry.singles.len(),
        aggregates = entry.aggregates.len()

      return false

    entry.singles[singleIndex.get()] = signature
  else:
    # More than one vote in this attestation
    if entry.covers(attestation.aggregation_bits):
      trace "Aggregate already covered",
        singles = entry.singles.len(),
        aggregates = entry.aggregates.len()
      return false

    # Since we're adding a new aggregate, we can now remove existing
    # aggregates that don't add any new votes
    entry.aggregates.keepItIf(
      not it.aggregation_bits.isSubsetOf(attestation.aggregation_bits))

    entry.aggregates.add Validation(
      aggregation_bits: attestation.aggregation_bits,
      aggregate_signature: AggregateSignature.init(signature),
    )

  debug "Aggregate resolved",
    singles = entry.singles.len(),
    aggregates = entry.aggregates.len()

  true

func getAttestationCandidateKey(
    attestationDataRoot: Eth2Digest, committee_index: uint64
): Eth2Digest =
  ## Key that keeps entries separated by committee index - since the votes of
  ## each committee are non-overlapping, this makes it easier to construct an
  ## aggregate or on-chain attestation down the line
  hash_tree_root([attestationDataRoot, hash_tree_root(committee_index)])

func getAttestationCandidateKey(
    attestationData: AttestationData, committee_index: uint64
): Eth2Digest =
  getAttestationCandidateKey(hash_tree_root(attestationData), committee_index)

proc addAttestation*(
    pool: var AttestationPool,
    attestation: SingleAttestation | electra.Attestation,
    attesting_indices: openArray[ValidatorIndex],
    beacon_committee_len: int,
    index_in_committee: int,
    signature: CookedSig,
    wallTime: BeaconTime,
) =
  ## Add an attestation to the pool, assuming it's been validated already.
  ##
  ## Assuming the votes in the attestation have not already been seen, the
  ## attestation will be added to the fork choice and lazily added to a list of
  ## attestations for future aggregation and block production.
  logScope:
    attestation = shortLog(attestation)

  doAssert attestation.signature == signature.toValidatorSig(),
    "Deserialized signature must match the one in the attestation"

  updateCurrent(pool, wallTime.slotOrZero(pool.dag.timeParams))

  let
    candidateIdx = pool.candidateIdx(attestation.data.slot).valueOr:
      debug "Skipping old attestation for block production",
        startingSlot = pool.startingSlot
      return
    committee_index =
      when attestation is SingleAttestation:
        attestation.committee_index
      else:
        uint64 get_committee_index_one(attestation.committee_bits).expect(
          "Gossip validation requires this"
        )
    candidateKey = getAttestationCandidateKey(attestation.data, committee_index)

  # Add or update an attestation entry in the candidate list but return early
  # in case the attestation adds no new votes - uses `withValue` to avoid
  # constructing the entry in case it's already present
  pool.candidates[candidateIdx].withValue(candidateKey, entry):
    if not addAttestation(entry[], attestation, index_in_committee, signature):
      return
  do:
    var entry =
      AttestationEntry.init(attestation.data, committee_index, beacon_committee_len)
    if not addAttestation(entry, attestation, index_in_committee, signature):
      # This can only happen if there are no votes in the attestation which
      # would mean a bug elsewhere..
      return

    pool.candidates[candidateIdx][candidateKey] = move(entry)

  pool.addForkChoiceVotes(
    attestation.data.slot, attesting_indices, attestation.data.beacon_block_root,
    wallTime,
  )

  # There does not seem to be an SSE stream event corresponding to Attestation,
  # because both attestation and single_attestation specifically specify
  # the `beacon_attestation_{subnet_id}` topic and that in not possible,
  # for this type, in Electra because this case is always an aggregate.

  when attestation is SingleAttestation:
    # Send notification about new attestation via callback.
    if not(isNil(pool.onSingleAttestationAdded)):
      pool.onSingleAttestationAdded(attestation)

func covers*(
    pool: var AttestationPool,
    data: AttestationData,
    aggregation_bits: ElectraCommitteeValidatorsBits,
    committee_index: CommitteeIndex,
): bool =
  ## Return true iff the given attestation already is fully covered by one of
  ## the existing aggregates, making it redundant
  ##
  ## `pool` must be `var` to enable the use of `withValue`, else Table becomes
  ## unusably inefficient
  let
    candidateIdx = pool.candidateIdx(data.slot).valueOr:
      return false
    candidateKey = getAttestationCandidateKey(data, uint64 committee_index)

  pool.candidates[candidateIdx].withValue(candidateKey, entry):
    return entry[].covers(aggregation_bits)

  false

proc addForkChoice*(pool: var AttestationPool,
                    epochRef: EpochRef,
                    blckRef: BlockRef,
                    unrealized: FinalityCheckpoints,
                    blck: ForkyTrustedBeaconBlock,
                    wallTime: BeaconTime) =
  ## Add a verified block to the fork choice context
  let state = pool.forkChoice.process_block(
    pool.dag, epochRef, blckRef, unrealized, blck, wallTime)

  if state.isErr:
    # This indicates that the fork choice and the chain dag are out of sync -
    # this is most likely the result of a bug, but we'll try to keep going -
    # hopefully the fork choice will heal itself over time.
    error "Couldn't add block to fork choice, bug?",
      blck = shortLog(blck), err = state.error

iterator electraAttestations*(
    pool: AttestationPool, slot: Opt[Slot],
    committee_index: Opt[CommitteeIndex]): electra.Attestation =
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
      ## data.index field from phase0 is still being used while we have
      ## 2 attestation pools (pre and post electra). Refer to template addAttToPool
      ## at addAttestation proc.
      if committee_index.isNone() or entry.index == committee_index.get().uint64:
        var committee_bits: AttestationCommitteeBits
        committee_bits[int(entry.index)] = true

        var attestation = electra.Attestation(
          aggregation_bits: ElectraCommitteeValidatorsBits.init(entry.committee_len),
          committee_bits: committee_bits,
          data: AttestationData.init(entry),
        )

        for index, signature in entry.singles:
          attestation.aggregation_bits.setBit(index)
          attestation.signature = signature.toValidatorSig()
          yield attestation
          attestation.aggregation_bits.clearBit(index)

        for v in entry.aggregates:
          yield entry.toElectraAttestation(v)

type
  AttestationCacheKey = (Slot, uint64)
  AttestationCache =
    Table[AttestationCacheKey, ElectraCommitteeValidatorsBits]
      ## Cache for quick lookup during beacon block construction of attestations
      ## which have already been included, and therefore should be skipped.

func getAttestationCacheKey(entry: AttestationEntry): AttestationCacheKey =
  # The committee is unique per slot and committee index which means we can use
  # it as key for a participation cache - this is checked in `check_attestation`
  (entry.slot, entry.index)

func add(
    attCache: var AttestationCache, key: AttestationCacheKey,
    aggregation_bits: ElectraCommitteeValidatorsBits) =
  attCache.withValue(key, v) do:
    v[].incl(aggregation_bits)
  do:
    attCache[key] = aggregation_bits

func init(
    T: type AttestationCache,
    state: electra.HashedBeaconState | fulu.HashedBeaconState |
           gloas.HashedBeaconState | heze.HashedBeaconState,
    cache: var StateCache): T =
  # Load attestations that are scheduled for being given rewards for
  let
    prev_epoch = state.data.get_previous_epoch()
    cur_epoch = state.data.get_current_epoch()

  template update_attestation_pool_cache(
      epoch: Epoch, participation_bitmap: untyped) =
    let committees_per_slot = get_committee_count_per_slot(
      state.data, epoch, cache)
    for committee_index in get_committee_indices(committees_per_slot):
      for slot in epoch.slots():
        let committee_len =
          get_beacon_committee_len(state.data, slot, committee_index, cache)
        var validator_bits = ElectraCommitteeValidatorsBits.init(committee_len.int)
        for index_in_committee, validator_index in get_beacon_committee(
          state.data, slot, committee_index, cache
        ):
          if participation_bitmap[validator_index] != 0:
            # If any flag got set, there was an attestation from this validator.
            validator_bits[index_in_committee] = true
        result[(slot, committee_index.uint64)] = validator_bits

  # This treats all types of rewards as equivalent, which isn't ideal
  update_attestation_pool_cache(
    prev_epoch, state.data.previous_epoch_participation)
  update_attestation_pool_cache(
    cur_epoch, state.data.current_epoch_participation)

func score(
    attCache: var AttestationCache, key: AttestationCacheKey,
    aggregation_bits: ElectraCommitteeValidatorsBits): int =
  # The score of an attestation is loosely based on how many new votes it brings
  # to the state - a more accurate score function would also look at inclusion
  # distance and effective balance.
  # TODO cache not var, but `withValue` requires it
  let bitsScore = aggregation_bits.countOnes()

  attCache.withValue(key, xxx):
    doAssert aggregation_bits.len() == xxx[].len(),
      "check_attestation ensures committee length"

    # How many votes were in the attestation minus the votes that are the same
    return bitsScore - aggregation_bits.countOverlap(xxx[])

  # Not found in cache - fresh vote meaning all attestations count
  bitsScore

func check_attestation_compatible*(
    dag: ChainDAGRef,
    state: ForkyHashedBeaconState,
    attestation: electra.Attestation | electra.TrustedAttestation):
    Result[void, cstring] =
  let
    targetEpoch = attestation.data.target.epoch
    compatibleRoot = state.dependent_root(targetEpoch.get_previous_epoch)

    attestedBlck = dag.getBlockRef(attestation.data.target.root).valueOr:
      return err("Unknown `target.root`")
    dependentSlot = targetEpoch.attester_dependent_slot
    dependentBid = dag.atSlot(attestedBlck.bid, dependentSlot).valueOr:
      return err("Dependent root not found")
    dependentRoot = dependentBid.bid.root

  if dependentRoot != compatibleRoot:
    return err("Incompatible shuffling")
  ok()

proc getAttestationsForBlock*(
    pool: var AttestationPool,
    state: electra.HashedBeaconState | fulu.HashedBeaconState |
           gloas.HashedBeaconState | heze.HashedBeaconState,
    cache: var StateCache,
): seq[electra.Attestation] =
  let newBlockSlot = state.data.slot.uint64

  if newBlockSlot < MIN_ATTESTATION_INCLUSION_DELAY:
    return @[] # Too close to genesis

  let
    # Attestations produced in a particular slot are added to the block
    # at the slot where at least MIN_ATTESTATION_INCLUSION_DELAY have passed
    maxAttestationSlot = newBlockSlot - MIN_ATTESTATION_INCLUSION_DELAY
    startPackingTick = Moment.now()

  var
    candidates:
      seq[tuple[score: int, slot: Slot, entry: ptr AttestationEntry, validation: int]]
    attCache = AttestationCache.init(state, cache)

  for i in 0..<ATTESTATION_LOOKBACK:
    if i > maxAttestationSlot: # Around genesis..
      break

    let
      slot = Slot(maxAttestationSlot - i)
      candidateIdx = pool.candidateIdx(slot).valueOr:
        # Passed the collection horizon - shouldn't happen because it's based on
        # ATTESTATION_LOOKBACK
        break

    for _, entry in pool.candidates[candidateIdx].mpairs():
      entry.updateAggregates()

      for j in 0..<entry.aggregates.len():
        let attestation = entry.toElectraAttestation(entry.aggregates[j])

        # Filter out attestations that were created with a different shuffling.
        # As we don't re-check signatures, this needs to be done separately
        if not pool.dag.check_attestation_compatible(state, attestation).isOk():
          continue

        # Attestations are checked based on the state that we're adding the
        # attestation to - there might have been a fork between when we first
        # saw the attestation and the time that we added it
        if not check_attestation(
              state.data, attestation, {skipBlsValidation}, cache).isOk():
          continue

        let score = attCache.score(
          entry.getAttestationCacheKey(), entry.aggregates[j].aggregation_bits)
        if score == 0:
          # 0 score means the attestation would not bring any votes - discard
          # it early
          # Note; this must be done _after_ `check_attestation` as it relies on
          # the committee to match the state that was used to build the cache
          continue

        # Careful, must not update the attestation table for the pointer to
        # remain valid
        candidates.add((score, slot, addr entry, j))

  # Sort candidates by score use slot as a tie-breaker
  candidates.sort()

  # Using a greedy algorithm, select as many attestations as possible that will
  # fit in the block.
  #
  # Effectively https://en.wikipedia.org/wiki/Maximum_coverage_problem which
  # therefore has inapproximability results of greedy algorithm optimality.
  #
  # Some research, also, has been done showing that one can tweak this and do
  # a kind of k-greedy version where each greedy step tries all possible two,
  # three, or higher-order tuples of next elements. These seem promising, but
  # also expensive.
  #
  # For each round, we'll look for the best attestation and add it to the result
  # then re-score the other candidates.
  var candidatesPerBlock: OrderedTable[Eth2Digest, seq[electra.Attestation]]

  let totalCandidates = candidates.len()
  while candidates.len > 0 and candidatesPerBlock.lenu64() <
      MAX_ATTESTATIONS_ELECTRA * MAX_COMMITTEES_PER_SLOT:
    let entryCacheKey = block:
      let (_, _, entry, j) =
        # Fast path for when all remaining candidates fit
        if candidates.lenu64 < MAX_ATTESTATIONS_ELECTRA:
          candidates[candidates.len - 1]
        else:
          # Get the candidate with the highest score
          candidates.pop()

      #TODO: Merge candidates per block structure with the candidates one
      # and score possible on-chain attestations while collecting candidates
      # (previous loop) and reevaluate cache key definition
      let newAtt = entry[].toElectraAttestation(entry[].aggregates[j])
      candidatesPerBlock.mgetOrPut(hash_tree_root(newAtt.data), @[]).add(newAtt)

      # Update cache so that the new votes are taken into account when updating
      # the score below
      let key = entry[].getAttestationCacheKey()
      attCache.add(key, entry[].aggregates[j].aggregation_bits)

      key

    block:
      # Because we added some votes, it's quite possible that some candidates
      # are no longer interesting - update the scores of the existing candidates
      for it in candidates.mitems():
        # Aggregates not on the same (slot, committee) pair don't change scores
        if it.entry[].getAttestationCacheKey() != entryCacheKey:
          continue

        it.score = attCache.score(
          entryCacheKey,
          it.entry[].aggregates[it.validation].aggregation_bits)

      candidates.keepItIf:
        # Only keep candidates that might add coverage
        it.score > 0

      # Sort candidates by score use slot as a tie-breaker
      candidates.sort()

  # Consolidate attestation aggregates with disjoint committee bits into single
  # attestation
  var res: seq[electra.Attestation]
  for a in candidatesPerBlock.values():
    if a.len > 1:
      let att = compute_on_chain_aggregate(a).valueOr:
        continue
      res.add(att)
    # no on-chain candidates
    else:
      res.add(a)

    if res.lenu64 == MAX_ATTESTATIONS_ELECTRA:
      break

  let packingDur = Moment.now() - startPackingTick

  debug "Packed attestations for block",
    newBlockSlot, packingDur, totalCandidates, attestations = res.len()
  attestation_pool_block_attestation_packing_time.set(
    packingDur.toFloatSeconds())

  res

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

func getElectraAggregatedAttestation*(
    pool: var AttestationPool, slot: Slot,
    attestationDataRoot: Eth2Digest, committee_index: CommitteeIndex):
    Opt[electra.Attestation] =
  let
    candidateIdx = ?pool.candidateIdx(slot)
    candidateKey =
      getAttestationCandidateKey(attestationDataRoot, committee_index.uint64)

  pool.candidates[candidateIdx].withValue(candidateKey, entry):
    if entry[].index == committee_index.uint64:
      entry[].updateAggregates()

      let (bestIndex, _) = bestValidation(entry[].aggregates)

      # Found the right hash, no need to look further
      return Opt.some(entry[].toElectraAttestation(entry[].aggregates[bestIndex]))

  Opt.none(electra.Attestation)

func getElectraAggregatedAttestation*(
    pool: var AttestationPool, slot: Slot, index: CommitteeIndex):
    Opt[electra.Attestation] =
  ## Select the attestation that has the most votes going for it in the given
  ## slot/index
  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.8/specs/electra/validator.md#construct-aggregate
  # even though Electra attestations support cross-committee aggregation,
  # "Set `attestation.committee_bits = committee_bits`, where `committee_bits`
  # has the same value as in each individual attestation." implies that cannot
  # be used here, because otherwise they wouldn't have the same value. It thus
  # leaves the cross-committee aggregation for getAttestationsForBlock() which
  # does do this.
  let candidateIdx = ?pool.candidateIdx(slot)

  var res: Opt[electra.Attestation]
  for _, entry in pool.candidates[candidateIdx].mpairs():
    doAssert entry.slot == slot
    if index.uint64 != entry.index:
      continue

    entry.updateAggregates()

    let (bestIndex, best) = bestValidation(entry.aggregates)

    if res.isNone() or best > res.get().aggregation_bits.countOnes():
      res = Opt.some(entry.toElectraAttestation(entry.aggregates[bestIndex]))

  res

type BeaconHead* = object
  blck*: BlockRef
  safeExecutionBlockHash*, finalizedExecutionBlockHash*: Eth2Digest

proc getBeaconHead*(
    pool: AttestationPool, headBlock: BlockRef): BeaconHead =
  let
    finalizedExecutionBlockHash =
      pool.dag.loadExecutionBlockHash(pool.dag.finalizedHead.blck)
        .get(ZERO_HASH)

    # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/fork_choice/safe-block.md#get_safe_execution_block_hash
    safeBlockRoot = pool.forkChoice.retrieve_fast_confirmed_root()
    safeBlock = pool.dag.getBlockRef(safeBlockRoot)
    safeExecutionBlockHash =
      if safeBlock.isErr:
        # If finality already advanced beyond the current safe block,
        # the safe block may end up not having a `BlockRef` anymore.
        # Because a different fork already finalized a later point,
        # report the finalized execution payload hash instead.
        finalizedExecutionBlockHash
      else:
        pool.dag.loadExecutionBlockHash(safeBlock.get)
          .get(finalizedExecutionBlockHash)

  BeaconHead(
    blck: headBlock,
    safeExecutionBlockHash: safeExecutionBlockHash,
    finalizedExecutionBlockHash: finalizedExecutionBlockHash)

proc willSelectNewHead*(
    pool: var AttestationPool,
    headBlock: BlockRef, wallTime: BeaconTime): Opt[void] =
  ## Informs fork choice that a new head will be selected.
  ## This may affect `retrieve_fast_confirmed_root`; must call this before that.
  pool.forkChoice.will_select_head(pool.dag, headBlock, wallTime).isOkOr:
    error "Couldn't store head to fork choice", err = error
    return err()
  ok()

proc selectOptimisticHead*(
    pool: var AttestationPool, wallTime: BeaconTime): Opt[BeaconHead] =
  ## Trigger fork choice and returns the new head block.
  let newHeadRoot = pool.forkChoice.get_head(pool.dag, wallTime).valueOr:
    error "Couldn't select head", err = error
    return Opt.none(BeaconHead)

  let headBlock = pool.dag.getBlockRef(newHeadRoot).valueOr:
    # This should normally not happen, but if the chain dag and fork choice
    # get out of sync, we'll need to try to download the selected head - in
    # the meantime, return nil to indicate that no new head was chosen

    pool.quarantine[].addMissing(newHeadRoot).isOkOr:
      # The newly selected head is unviable for some reason - the only way out
      # here is that fork choice gets information about some other head
      warn "Fork choice selected unviable head - cannot sync",
        newHeadRoot, err = error
      return Opt.none(BeaconHead)

    warn "Fork choice selected unknown head, trying to sync", newHeadRoot
    return Opt.none(BeaconHead)

  ? pool.willSelectNewHead(headBlock, wallTime)
  ok pool.getBeaconHead(headBlock)

proc prune*(pool: var AttestationPool, dag: ChainDAGRef) =
  if (let v = pool.forkChoice.prune(dag); v.isErr):
    # If pruning fails, it's likely the result of a bug - this shouldn't happen
    # but we'll keep running hoping that the fork choice will recover eventually
    error "Couldn't prune fork choice, bug?", err = v.error()

func validatorSeenAtEpoch*(pool: AttestationPool, epoch: Epoch,
                           vindex: ValidatorIndex): bool =
  if uint64(vindex) < lenu64(pool.nextAttestationEpoch):
    let mark = pool.nextAttestationEpoch[vindex]
    (mark.subnet > epoch) or (mark.aggregate > epoch)
  else:
    false
