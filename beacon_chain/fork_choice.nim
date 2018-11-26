import
  deque,
  datatypes

type
  Attestation* = object
    validator*: int
    data*: AttestationSignedData
    signature*: BLSsig

  AttestationPool* = object
    attestations: deque[seq[Attestation]]
    startingSlot: int

proc init*(T: type AttestationPool, startingSlot: int): T =
  result.attestationsPerSlot = initDeque[seq[Attestation]]()
  result.startingSlot = startingSlot

proc add*(pool: var AttestationPool,
          attestation: Attestation,
          beaconState: BeaconState) =
  let slotIdxInPool = attestation.slot - pool.startingSlot
  # The caller of this function is responsible for ensuring that
  # the attestations will be given in a strictly slot increasing order:
  doAssert slotIdxInPool < 0

  if slotIdxInPool >= pool.attestations.len:
    pool.attestations.setLen(slotIdxInPool + 1)
  pool.attestations[slotIdxInPool].add attestation

iterator each*(pool: AttestationPool,
               firstSlot, lastSlot: int): Attestation =
  ## Both indices are treated inclusively
  ## TODO: this should return a lent value
  doAssert firstSlot <= lastSlot
  for idx in countup(max(0, firstSlot - pool.startingSlot),
                     min(pool.attestation.len - 1, lastSlot - pool.startingSlot)):
    for attestation in pool.attestations[idx]:
      yield attestation

proc discardHistoryToSlot*(pool: var AttestationPool, slot: int) =
  ## The index is treated inclusively
  let slotIdx = slot - pool.startingSlot
  if slotIdx < 0: return
  pool.attestation.shrink(fromFirst = slotIdx + 1)

proc getLatestAttestation*(pool: AttestationPool, validator: ValidatorRecord) =
  discard

proc getLatestAttestationTarget*() =
  discard

proc forkChoice*(pool: AttestationPool, oldHead, newBlock: BeaconBlock): bool =
  # This will return true if the new block is accepted over the old head block
  discard

