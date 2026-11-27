# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

## Attestation pool for the PQ fork.
##
## Attestations carry no signature. A `PqSingleAttestation` carries the XMSS
## signature of one attester; an aggregator proves the signatures of its
## committee with a STARK (`AggregateAndProof.proof`), and a proposer merges
## the proofs of the aggregates behind its block's attestations into the
## block's `proof`.
##
## https://github.com/ethereum/consensus-specs/blob/2f43bc0f989f47af81df390a90bc1f78e2436323/specs/_features/pq/validator.md#attestation-aggregation

import
  std/[sets, tables],
  chronicles, chronos,
  ../spec/[beaconstate, forks, pq_stark, signatures],
  ./[blockchain_dag, spec_cache]

from std/algorithm import sort

export pq_stark

logScope: topics = "pq_attpool"

const
  PoolLookbackSlots = 2 * SLOTS_PER_EPOCH
  BuiltLookbackSlots = 2
    ## How long an aggregate made by this node is kept for its aggregators

type
  PqAttestationKey = (Eth2Digest, uint64)
    ## `hash_tree_root(data)` and committee index

  PqSignatures = object
    data: AttestationData
    committee: seq[ValidatorIndex]
    signatures: Table[int, XMSSSignature]
      ## Position in the committee -> signature

  PqAggregate* = object
    attestation*: pq.Attestation
      ## Single committee
    proof*: seq[byte]

  PqAggregateFut = Future[Opt[PqAggregate]].Raising([CancelledError])

  PqBuiltAggregate = object
    slot: Slot
    fut: PqAggregateFut

  PqAttestationPool* = object
    dag: ChainDAGRef
    singles: Table[PqAttestationKey, PqSignatures]
    aggregates: Table[PqAttestationKey, PqAggregate]
    built: Table[PqAttestationKey, PqBuiltAggregate]
      ## Aggregates this node proves or has proved for its aggregators, local
      ## or of a validator client: each is proved once
    remoteAggregators: Table[Slot, HashSet[uint64]]
      ## Committees for which a validator client aggregates, as it said with
      ## its beacon committee subscriptions

func init*(T: type PqAttestationPool, dag: ChainDAGRef): T =
  T(dag: dag)

func committeeIndex(attestation: pq.Attestation): Opt[CommitteeIndex] =
  get_committee_index_one(attestation.committee_bits)

func numBits(attestation: pq.Attestation): int =
  attestation.aggregation_bits.countOnes()

proc addSingleAttestation*(
    pool: var PqAttestationPool, attestation: PqSingleAttestation,
    committee: openArray[ValidatorIndex]) =
  ## Record the (verified) signature of a single attester.
  let
    committee_index = attestation.committee_index
    key = (hash_tree_root(attestation.data), committee_index)
  var position = -1
  for i, vidx in committee:
    if vidx.uint64 == attestation.attester_index:
      position = i
      break
  if position < 0:
    return
  pool.singles.mgetOrPut(key, PqSignatures(
    data: attestation.data, committee: @committee)).signatures[position] =
      attestation.signature

proc addAggregate*(
    pool: var PqAttestationPool, attestation: pq.Attestation,
    proof: openArray[byte]) =
  ## Record a (verified) single-committee aggregate, keeping the one with the
  ## most attesters.
  let committee_index = attestation.committeeIndex.valueOr:
    return
  let key = (hash_tree_root(attestation.data), committee_index.uint64)
  pool.aggregates.withValue(key, existing):
    if existing[].attestation.numBits >= attestation.numBits:
      return
  pool.aggregates[key] = PqAggregate(attestation: attestation, proof: @proof)

# https://github.com/ethereum/consensus-specs/blob/4c296784bb6ff54cbdcf72ebdda2a1057cce8893/specs/_features/pq/validator.md#broadcast-aggregate
func should_broadcast_aggregate*(
    pool: PqAttestationPool, aggregate: pq.Attestation): bool =
  ## Return whether no aggregate received with the same data and committee as
  ## ``aggregate`` includes all of its attesters: the network ignores an
  ## aggregate whose attesters are all in one it has seen. Of the aggregates
  ## received for a committee, the pool keeps the one with the most attesters,
  ## which is the one compared against.
  let committee_index = aggregate.committeeIndex.valueOr:
    return false
  pool.aggregates.withValue(
      (hash_tree_root(aggregate.data), committee_index.uint64), received):
    return not aggregate.aggregation_bits.isSubsetOf(
      received.attestation.aggregation_bits)
  true

proc prune*(pool: var PqAttestationPool, wallSlot: Slot) =
  var toDel: seq[PqAttestationKey]
  for key, entry in pool.singles:
    if entry.data.slot + PoolLookbackSlots < wallSlot:
      toDel.add key
  for key in toDel:
    pool.singles.del key
  toDel.reset()
  for key, entry in pool.aggregates:
    if entry.attestation.data.slot + PoolLookbackSlots < wallSlot:
      toDel.add key
  for key in toDel:
    pool.aggregates.del key
  toDel.reset()
  for key, entry in pool.built:
    if entry.slot + BuiltLookbackSlots < wallSlot:
      toDel.add key
  for key in toDel:
    pool.built.del key
  var slots: seq[Slot]
  for slot in pool.remoteAggregators.keys:
    if slot + BuiltLookbackSlots < wallSlot:
      slots.add slot
  for slot in slots:
    pool.remoteAggregators.del slot

func registerRemoteAggregator*(
    pool: var PqAttestationPool, slot: Slot, committee_index: CommitteeIndex):
    bool =
  ## A validator client has an aggregator of ``committee_index`` at ``slot``:
  ## the aggregate it will ask for is to be proved at the aggregate deadline.
  ## Returns whether it is the first one known for ``slot``.
  let first = slot notin pool.remoteAggregators
  pool.remoteAggregators.mgetOrPut(
    slot, HashSet[uint64].default).incl committee_index.uint64
  first

func remoteAggregatorCommittees*(
    pool: PqAttestationPool, slot: Slot): seq[CommitteeIndex] =
  ## The committees of ``slot`` that validator clients aggregate for.
  var res: seq[CommitteeIndex]
  for committee_index in
      pool.remoteAggregators.getOrDefault(slot, HashSet[uint64].default):
    res.add CommitteeIndex(committee_index)
  res

func attestationData*(
    pool: PqAttestationPool, data_root: Eth2Digest,
    committee_index: CommitteeIndex): Opt[AttestationData] =
  ## The attestation data with root ``data_root`` that members of
  ## ``committee_index`` signed, if any did.
  pool.singles.withValue((data_root, committee_index.uint64), entry):
    return Opt.some entry.data
  Opt.none(AttestationData)

func bestAttestationData*(
    pool: PqAttestationPool, slot: Slot, committee_index: CommitteeIndex):
    Opt[AttestationData] =
  ## The attestation data with the most signatures for ``committee_index`` at
  ## ``slot``.
  var
    best = Opt.none(AttestationData)
    bestCount = 0
  for key, entry in pool.singles:
    if key[1] == committee_index.uint64 and entry.data.slot == slot and
        entry.signatures.len > bestCount:
      best = Opt.some entry.data
      bestCount = entry.signatures.len
  best

proc makeAggregate*(
    pool: ref PqAttestationPool, data: AttestationData,
    committee_index: CommitteeIndex
): Future[Opt[PqAggregate]] {.async: (raises: [CancelledError]).} =
  ## `get_aggregate_stark`: prove the signatures collected for ``data`` and
  ## ``committee_index``.
  let key = (hash_tree_root(data), committee_index.uint64)
  let entry = pool[].singles.getOrDefault(key)
  if entry.signatures.len == 0:
    return Opt.none(PqAggregate)

  var
    attestation = pq.Attestation(
      aggregation_bits: gloas.AggregationBits.init(entry.committee.len),
      data: data)
    pubkeys: seq[XMSSPubkey]
    signatures: seq[XMSSSignature]
  attestation.committee_bits[committee_index.int] = true
  for position in 0 ..< entry.committee.len:
    if position notin entry.signatures:
      continue
    let pubkey = pool.dag.pqValidatorKey(entry.committee[position]).valueOr:
      continue
    attestation.aggregation_bits[position] = true
    pubkeys.add pubkey
    signatures.add entry.signatures.getOrDefault(position)

  let
    statement = XMSSAggregateStatement(
      pubkeys: pubkeys,
      leaf_index: compute_xmss_attestation_leaf_index(data.target.epoch),
      message: compute_attestation_signing_root(
        pool.dag.forkAtEpoch(data.target.epoch),
        pool.dag.genesis_validators_root, data))
    proof = (await proveAggregates(@[statement], @[signatures])).valueOr:
      warn "Cannot prove attestation aggregate", err = error,
        slot = data.slot, committee_index
      return Opt.none(PqAggregate)

  Opt.some PqAggregate(attestation: attestation, proof: proof)

proc getAggregate*(
    pool: ref PqAttestationPool, data: AttestationData,
    committee_index: CommitteeIndex
): Future[Opt[PqAggregate]] {.async: (raises: [CancelledError]).} =
  ## `makeAggregate`, once: the aggregate being proved or already proved for
  ## ``data`` and ``committee_index`` is shared by those that ask for it, such
  ## as the aggregators of one committee, or the node at the aggregate deadline
  ## and the validator client that signs the aggregate.
  let key = (hash_tree_root(data), committee_index.uint64)
  var fut: PqAggregateFut
  pool[].built.withValue(key, entry):
    fut = entry[].fut
  do:
    fut = pool.makeAggregate(data, committee_index)
    pool[].built[key] = PqBuiltAggregate(slot: data.slot, fut: fut)

  # The proof goes on for the others when this caller is cancelled
  await fut.join()

  let res =
    if fut.completed():
      fut.value()
    else:
      Opt.none(PqAggregate)
  if res.isNone:
    # Nothing to aggregate yet, or the prover failed: the next caller tries
    # again
    var current = false
    pool[].built.withValue(key, entry):
      current = entry[].fut == fut
    if current:
      pool[].built.del key
  res

proc getAttestationsForBlock*(
    pool: ref PqAttestationPool, forkedState: ref ForkedHashedBeaconState,
    cache: ref StateCache
): Future[(seq[pq.Attestation], AttestationProof)] {.
    async: (raises: [CancelledError]).} =
  ## Pick the aggregates to include in a block on ``state``, combine those with
  ## equal data into on-chain aggregates (`compute_on_chain_aggregate`) and
  ## merge their proofs, ordered as the attestations and, within each, by
  ## committee index.
  doAssert forkedState[].kind == ConsensusFork.Pq
  template state: untyped = forkedState[].pqData
  var groups: Table[Eth2Digest, seq[PqAggregate]]
  for key, aggregate in pool[].aggregates:
    let data = aggregate.attestation.data
    if data.slot + MIN_ATTESTATION_INCLUSION_DELAY_PQ > state.data.slot:
      continue
    if data.target.epoch notin
        [get_previous_epoch(state.data), get_current_epoch(state.data)]:
      continue
    groups.mgetOrPut(key[0], @[]).add aggregate

  type Candidate = object
    attestation: pq.Attestation
    parts: seq[PqAggregate]
    newVotes: int
      ## Attesters whose vote the state does not count yet

  func countsNewVotes(
      state: pq.BeaconState, attestation: pq.Attestation,
      cache: var StateCache): int =
    ## Attesters of ``attestation`` without the timely target flag for its
    ## target epoch: attestations already included add nothing.
    let current = attestation.data.target.epoch == get_current_epoch(state)
    var res = 0
    for vidx in get_attesting_indices(state, attestation, cache):
      let flags =
        if current:
          state.current_epoch_participation[vidx]
        else:
          state.previous_epoch_participation[vidx]
      if not flags.has_flag(TIMELY_TARGET_FLAG_INDEX):
        inc res
    res

  var candidates: seq[Candidate]
  for _, aggregates in groups.mpairs:
    aggregates.sort(proc(a, b: PqAggregate): int =
      cmp(a.attestation.committeeIndex.get.uint64,
          b.attestation.committeeIndex.get.uint64))
    var
      totalLen = 0
      bits = 0
    for aggregate in aggregates:
      totalLen += aggregate.attestation.aggregation_bits.len
      bits += aggregate.attestation.numBits
    var attestation = pq.Attestation(
      aggregation_bits: gloas.AggregationBits.init(totalLen),
      data: aggregates[0].attestation.data)
    var pos = 0
    for aggregate in aggregates:
      for b in aggregate.attestation.aggregation_bits:
        attestation.aggregation_bits[pos] = b
        inc pos
      attestation.committee_bits[
        aggregate.attestation.committeeIndex.get.int] = true
    if check_attestation(state.data, attestation, {}, cache[]).isErr:
      continue
    let newVotes = countsNewVotes(state.data, attestation, cache[])
    if newVotes == 0:
      continue
    candidates.add Candidate(
      attestation: attestation, parts: aggregates, newVotes: newVotes)

  # Most new votes first, then the most recent
  candidates.sort(proc(a, b: Candidate): int =
    let byVotes = cmp(b.newVotes, a.newVotes)
    if byVotes != 0:
      byVotes
    else:
      cmp(b.attestation.data.slot, a.attestation.data.slot))
  if candidates.lenu64 > MAX_ATTESTATIONS_PQ:
    candidates.setLen(MAX_ATTESTATIONS_PQ.int)

  var
    attestations: seq[pq.Attestation]
    children: seq[(seq[XMSSAggregateStatement], seq[byte])]
  for candidate in candidates:
    attestations.add candidate.attestation
    for part in candidate.parts:
      children.add (
        get_attestation_statements(state.data, part.attestation, cache[]),
        part.proof)

  if attestations.len == 0:
    return (attestations, default(AttestationProof))

  let merged = (await mergeProofs(children)).valueOr:
    warn "Cannot merge attestation proofs, proposing without attestations",
      err = error, slot = state.data.slot
    return (newSeq[pq.Attestation](), default(AttestationProof))
  if merged.lenu64 > MAX_STARK_PROOF_SIZE:
    warn "Merged attestation proof too large", size = merged.len
    return (newSeq[pq.Attestation](), default(AttestationProof))

  (attestations, AttestationProof.init(merged))
