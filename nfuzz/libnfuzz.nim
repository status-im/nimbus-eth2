import
  endians, stew/ptrops, stew/ranges/ptr_arith,
  ../beacon_chain/[ssz, state_transition],
  ../beacon_chain/spec/[datatypes, helpers, digest, validator, beaconstate],
# Required for deserialisation of ValidatorSig in Attestation due to
# https://github.com/nim-lang/Nim/issues/11225
  ../beacon_chain/spec/crypto

type
  BlockInput = object
    state: BeaconState
    beaconBlock: BeaconBlock
  AttestationInput = object
    state: BeaconState
    attestation: Attestation

proc copyState(state: BeaconState, output: ptr byte,
    output_size: ptr csize): bool {.raises:[IOError, Defect].} =
  # Not catching any errors as it is assumed that a state object will always be
  # in a shape that it is serializable. Can raise IOError and Defects though.
  let resultState = SSZ.encode(state)
  if resultState.len <= output_size[]:
    output_size[] = resultState.len
    # Note: improvement might be to write directly to buffer with OutputStream
    # and SszWriter
    copyMem(output, unsafeAddr resultState[0], output_size[])
    result = true

proc nfuzz_block(input: openArray[byte], output: ptr byte,
    output_size: ptr csize): bool {.exportc.} =
  var data: BlockInput

  try:
    data = SSZ.decode(input, BlockInput)
  except MalformedSszError, SszSizeMismatchError, RangeError:
    return false

  try:
    result = state_transition(data.state, data.beaconBlock, flags = {})
  except ValueError: # Not catching Defect, IOError and ... Exception! :(
    discard

  if result:
    result = copyState(data.state, output, output_size)

proc nfuzz_attestation(input: openArray[byte], output: ptr byte,
    output_size: ptr csize): bool {.exportc.} =
  var
    data: AttestationInput
    cache = get_empty_per_epoch_cache()

  try:
    data = SSZ.decode(input, AttestationInput)
  except MalformedSszError, SszSizeMismatchError, RangeError:
    return false

  try:
    result = process_attestation(data.state, data.attestation,
      flags = {}, cache)
  except ValueError: # Not catching Defect and IOError
    discard

  if result:
    result = copyState(data.state, output, output_size)

# Note: Could also accept raw input pointer and access list_size + seed here.
# However, list_size needs to be known also outside this proc to allocate output.
# TODO: rework to copy immediatly in an uint8 openArray, considering we have to
# go over the list anyhow?
proc nfuzz_shuffle(input_seed: ptr byte, output: var openArray[uint64])
    {.exportc.} =
  var seed: Eth2Digest
  let list_size = output.len.uint64 # should be OK as max 2 bytes are passed.

  copyMem(addr(seed.data), input_seed, 32)

  # TODO: is RangeError a valid error here that needs to be catched?
  let shuffled_seq =  get_shuffled_seq(seed, list_size)

  doAssert(list_size == shuffled_seq.len.uint64)

  for i in 0..<list_size:
    # ValidatorIndex is currently wrongly uint32 so we copy this 1 by 1,
    # assumes passed output is zeroed.
    copyMem(offset(addr output, i.int), shuffled_seq[i.int].unsafeAddr,
      sizeof(ValidatorIndex))
