import
  deques,
  tables,
  milagro_crypto,
  spec/[datatypes, digest, crypto, validator, beaconstate]

type
  AttesterIdx* = int

  AttestationCandidate* = object
    validator*: AttesterIdx
    data*: AttestationData
    participation_bitfield*: seq[byte]
    signature*: ValidatorSig

  AttestationPool* = object
    # TODO: check whether still useful/necessary at all;
    # data structures have different tradeoffs, but need
    # for this one questionable given need to identify a
    # ValidatorRecord/index regardless.
    attestations: Deque[seq[AttestationCandidate]]

    # only remember last attestation in given slot for a given attester.
    attestationsPerValidator: Table[AttesterIdx, AttestationCandidate]

    startingSlot: int

proc init*(T: type AttestationPool, startingSlot: int): T =
  result.attestations = initDeque[seq[AttestationCandidate]]()
  result.attestationsPerValidator = initTable[AttesterIdx, AttestationCandidate]()
  result.startingSlot = startingSlot

proc setLen*[T](d: var Deque[T], len: int) =
  # TODO: The upstream `Deque` type should gain a proper resize API
  let delta = len - d.len
  if delta > 0:
    for i in 0 ..< delta:
      var defaultVal: T
      d.addLast(defaultVal)
  else:
    d.shrink(fromLast = delta)

proc bitfieldUnion(accum: var seq[byte], disjunct: seq[byte]) =
  # TODO replace with nim-ranges
  doAssert len(accum) == len(disjunct)
  for i in 0 ..< len(accum):
    accum[i] = accum[i] or disjunct[i]

proc add*(pool: var AttestationPool,
          attestation: AttestationCandidate,
          beaconState: BeaconState) =
  # The caller of this function is responsible for ensuring that
  # the attestations will be given in a strictly slot increasing order:
  doAssert attestation.data.slot.int >= pool.startingSlot

  var curAttestation = pool.attestationsPerValidator.getOrDefault(attestation.validator)
  if attestation.data.slot.int > curAttestation.data.slot.int:
    pool.attestationsPerValidator[attestation.validator] = attestation

  # TODO: aggregation, for get_latest_attestation/get_latest_attestation_target, needs to
  # occur later as far as I can tell.
  # TODO: much more testing
  #elif curAttestation.data == attestation.data:
  #  curAttestation.signature = combine(@[curAttestation.signature, attestation.signature])
  #  curAttestation.participation_bitfield.bitfieldUnion attestation.participation_bitfield
  #  pool.attestationsPerValidator[attestation.validator] =  curAttestation 

  let slotIdxInPool = attestation.data.slot.int - pool.startingSlot
  if slotIdxInPool >= pool.attestations.len:
    pool.attestations.setLen(slotIdxInPool + 1)

  pool.attestations[slotIdxInPool].add attestation

iterator each*(pool: AttestationPool,
               firstSlot, lastSlot: int): AttestationCandidate =
  ## Both indices are treated inclusively
  ## TODO: this should return a lent value
  doAssert firstSlot <= lastSlot
  for idx in countup(max(0, firstSlot - pool.startingSlot),
                     min(pool.attestations.len - 1, lastSlot - pool.startingSlot)):
    for attestation in pool.attestations[idx]:
      yield attestation

proc discardHistoryToSlot*(pool: var AttestationPool, slot: int) =
  ## The index is treated inclusively
  if slot < pool.startingSlot:
    return
  let slotIdx = int(slot - pool.startingSlot)
  pool.attestations.shrink(fromFirst = slotIdx + 1)

  var rmKeys : seq[AttesterIdx] = @[]
  for k, ac in pool.attestationsPerValidator.pairs:
    if ac.data.slot.int < slot:
      rmKeys.add k

  for k in rmKeys:
    pool.attestationsPerValidator.del(k)

func getAttestationCandidate*(attestation: Attestation, state: BeaconState): AttestationCandidate =
  # TODO generalize to already-aggreagated attestations, but indications that's not
  # in initial approach.
  let participants = get_attestation_participants(state, attestation.data, attestation.participation_bitfield)
  if participants.len == 0:
    return
  result.validator = participants[0]

  result.participation_bitfield = attestation.participation_bitfield
  result.data = attestation.data
  result.signature = attestation.aggregate_signature

func forkChoice*(pool: AttestationPool, oldHead, newBlock: BeaconBlock): bool =
  # This will return true if the new block is accepted over the old head block
  discard

# Functions from spec
func get_latest_attestation*(pool: AttestationPool, validator: ValidatorRecord) : AttestationCandidate =
  let idxs = get_active_validator_indices(@[validator])
  if idxs.len > 0:
    return pool.attestationsPerValidator.getOrDefault(idxs[0])

  # TODO error handling, probably with e.g., Some[AttestationCandidate]

func get_latest_attestation_target*(pool: AttestationPool, validator: ValidatorRecord) : Eth2Digest =
  # TODO verify whether it's this or shard_root
  get_latest_attestation(pool, validator).data.beacon_block_root
