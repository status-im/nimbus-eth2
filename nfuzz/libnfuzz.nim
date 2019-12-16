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
  # This and AssertionError are raised to indicate programming bugs
  # Used as a wrapper to allow exception tracking to identify unexpected exceptions
  FuzzCrashError* = object of Exception

# TODO: change ptr uint to ptr csize_t when available in newer Nim version.
proc copyState(state: BeaconState, output: ptr byte,
    output_size: ptr uint): bool {.raises:[].} =
  var resultState: seq[byte]

  try:
    resultState = SSZ.encode(state)
  except IOError, Defect:
    return false

  if resultState.len.uint <= output_size[]:
    output_size[] = resultState.len.uint
    # TODO: improvement might be to write directly to buffer with OutputStream
    # and SszWriter
    copyMem(output, unsafeAddr resultState[0], output_size[])
    result = true

proc nfuzz_block(input: openArray[byte], output: ptr byte,
    output_size: ptr uint): bool {.exportc, raises:[FuzzCrashError].} =
  var data: BlockInput

  try:
    data = SSZ.decode(input, BlockInput)
  except MalformedSszError, SszSizeMismatchError, RangeError:
      raise newException(FuzzCrashError, "SSZ deserialisation failed, likely bug in preprocessing.")

  try:
    result = state_transition(data.state, data.beaconBlock, flags = {})
  except ValueError, RangeError, Exception:
    discard

  if result:
    result = copyState(data.state, output, output_size)

proc nfuzz_attestation(input: openArray[byte], output: ptr byte,
    output_size: ptr uint): bool {.exportc, raises:[FuzzCrashError].} =
  var
    data: AttestationInput
    cache = get_empty_per_epoch_cache()

  try:
    data = SSZ.decode(input, AttestationInput)
  except MalformedSszError, SszSizeMismatchError, RangeError:
    raise newException(FuzzCrashError, "SSZ deserialisation failed, likely bug in preprocessing.")

  try:
    result = process_attestation(data.state, data.attestation,
      flags = {}, cache)
  except ValueError, RangeError:
    discard

  if result:
    result = copyState(data.state, output, output_size)

# Note: Could also accept raw input pointer and access list_size + seed here.
# However, list_size needs to be known also outside this proc to allocate output.
# TODO: rework to copy immediatly in an uint8 openArray, considering we have to
# go over the list anyhow?
proc nfuzz_shuffle(input_seed: ptr byte, output: var openArray[uint64]): bool
    {.exportc, raises:[].} =
  var seed: Eth2Digest
  # Should be OK as max 2 bytes are passed by the framework.
  let list_size = output.len.uint64

  copyMem(addr(seed.data), input_seed, sizeof(seed.data))

  var shuffled_seq: seq[ValidatorIndex]
  try:
    shuffled_seq = get_shuffled_seq(seed, list_size)
  except RangeError:
    return false

  # TODO: Hah! AssertionError doesn't get picked up by raises. Do we let them
  # slip or shall we wrap one big try/except AssertionError around the calls?
  doAssert(list_size == shuffled_seq.len.uint64)

  for i in 0..<list_size:
    # ValidatorIndex is currently wrongly uint32 so we copy this 1 by 1,
    # assumes passed output is zeroed.
    copyMem(offset(addr output, i.int), shuffled_seq[i.int].unsafeAddr,
      sizeof(ValidatorIndex))

  result = true
