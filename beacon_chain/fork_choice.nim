import
  deques,
  spec/[datatypes, crypto]

type
  Attestation* = object
    validator*: int
    data*: AttestationData
    signature*: ValidatorSig

  AttestationPool* = object
    attestations: Deque[seq[Attestation]]
    startingSlot: int

proc init*(T: type AttestationPool, startingSlot: int): T =
  result.attestationsPerSlot = initDeque[seq[Attestation]]()
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

proc add*(pool: var AttestationPool,
          attestation: Attestation,
          beaconState: BeaconState) =
  # The caller of this function is responsible for ensuring that
  # the attestations will be given in a strictly slot increasing order:
  doAssert attestation.data.slot.int >= pool.startingSlot

  let slotIdxInPool = attestation.data.slot.int - pool.startingSlot
  if slotIdxInPool >= pool.attestations.len:
    pool.attestations.setLen(slotIdxInPool + 1)

  pool.attestations[slotIdxInPool].add attestation

iterator each*(pool: AttestationPool,
               firstSlot, lastSlot: int): Attestation =
  ## Both indices are treated inclusively
  ## TODO: this should return a lent value
  doAssert firstSlot <= lastSlot
  for idx in countup(max(0, firstSlot - pool.startingSlot),
                     min(pool.attestations.len - 1, lastSlot - pool.startingSlot)):
    for attestation in pool.attestations[idx]:
      yield attestation

proc discardHistoryToSlot*(pool: var AttestationPool, slot: int) =
  ## The index is treated inclusively
  let slotIdx = slot - pool.startingSlot
  if slotIdx < 0: return
  pool.attestations.shrink(fromFirst = slotIdx + 1)

proc getLatestAttestation*(pool: AttestationPool, validator: ValidatorRecord) =
  discard

proc getLatestAttestationTarget*() =
  discard

proc forkChoice*(pool: AttestationPool, oldHead, newBlock: BeaconBlock): bool =
  # This will return true if the new block is accepted over the old head block
  discard

