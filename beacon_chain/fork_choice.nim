import
  deques, options,
  milagro_crypto,
  spec/[datatypes, crypto, helpers], extras

type
  AttestationCandidate* = object
    validator*: int
    data*: AttestationData
    signature*: ValidatorSig

  AttestationPool* = object
    # The Deque below stores all outstanding attestations per slot.
    # In each slot, we have an array of all attestations indexed by their
    # shard number. When we haven't received an attestation for a particular
    # shard yet, the Option value will be `none`
    attestations: Deque[array[SHARD_COUNT, Option[Attestation]]]
    startingSlot: int

  # TODO:
  # The compilicated Deque above is not needed.
  #
  # In fact, we can use a simple array with length SHARD_COUNT because
  # in each epoch, each shard is going to receive attestations exactly once.
  # Once the epoch is over, we can discard all attestations and start all
  # over again (no need for `discardHistoryToSlot` too).

proc init*(T: type AttestationPool, startingSlot: int): T =
  result.attestations = initDeque[array[SHARD_COUNT, Option[Attestation]]]()
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

proc combine*(tgt: var Attestation, src: Attestation, flags: UpdateFlags) =
  # Combine the signature and participation bitfield, with the assumption that
  # the same data is being signed!
  # TODO similar code in work_pool, clean up

  assert tgt.data == src.data

  for i in 0 ..< tgt.participation_bitfield.len:
    # TODO:
    # when BLS signatures are combined, we must ensure that
    # the same participant key is not included on both sides
    tgt.participation_bitfield[i] =
      tgt.participation_bitfield[i] or
      src.participation_bitfield[i]

  if skipValidation notin flags:
    tgt.aggregate_signature.combine(src.aggregate_signature)

proc add*(pool: var AttestationPool,
          attestation: Attestation,
          beaconState: BeaconState) =
  # The caller of this function is responsible for ensuring that
  # the attestations will be given in a strictly slot increasing order:
  doAssert attestation.data.slot.int >= pool.startingSlot

  # TODO:
  # Validate that the attestation is authentic (it's properly signed)
  # and make sure that the validator is supposed to make an attestation
  # for the specific shard/slot

  let slotIdxInPool = attestation.data.slot.int - pool.startingSlot
  if slotIdxInPool >= pool.attestations.len:
    pool.attestations.setLen(slotIdxInPool + 1)

  let shard = attestation.data.shard

  if pool.attestations[slotIdxInPool][shard].isSome:
    combine(pool.attestations[slotIdxInPool][shard].get, attestation, {})
  else:
    pool.attestations[slotIdxInPool][shard] = some(attestation)

proc getAttestationsForBlock*(pool: AttestationPool,
                              lastState: BeaconState,
                              newBlockSlot: uint64): seq[Attestation] =
  if newBlockSlot < MIN_ATTESTATION_INCLUSION_DELAY or pool.attestations.len == 0:
    return

  doAssert newBlockSlot > lastState.slot

  var
    firstSlot = 0.uint64
    lastSlot = newBlockSlot - MIN_ATTESTATION_INCLUSION_DELAY

  if pool.startingSlot.uint64 + MIN_ATTESTATION_INCLUSION_DELAY <= lastState.slot:
    firstSlot = lastState.slot - MIN_ATTESTATION_INCLUSION_DELAY

  for slot in firstSlot .. lastSlot:
    let slotDequeIdx = slot.int - pool.startingSlot
    if slotDequeIdx >= pool.attestations.len: return
    let shardAndComittees = get_shard_committees_at_slot(lastState, slot)
    for s in shardAndComittees:
      if pool.attestations[slotDequeIdx][s.shard].isSome:
        result.add pool.attestations[slotDequeIdx][s.shard].get

proc discardHistoryToSlot*(pool: var AttestationPool, slot: int) =
  ## The index is treated inclusively
  let slot = slot - MIN_ATTESTATION_INCLUSION_DELAY.int
  if slot < pool.startingSlot:
    return
  let slotIdx = int(slot - pool.startingSlot)
  pool.attestations.shrink(fromFirst = slotIdx + 1)

func getAttestationCandidate*(attestation: Attestation): AttestationCandidate =
  # TODO: not complete AttestationCandidate object
  result.data = attestation.data
  result.signature = attestation.aggregate_signature

func getLatestAttestation*(pool: AttestationPool, validator: ValidatorRecord) =
  discard

func getLatestAttestationTarget*() =
  discard

func forkChoice*(pool: AttestationPool, oldHead, newBlock: BeaconBlock): bool =
  # This will return true if the new block is accepted over the old head block
  discard

