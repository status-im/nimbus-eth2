import
  endians, stew/ptrops, stew/ranges/ptr_arith,
  ../beacon_chain/[ssz, state_transition],
  ../beacon_chain/spec/[datatypes, helpers, digest, validator, beaconstate, state_transition_block],
# Required for deserialisation of ValidatorSig in Attestation due to
# https://github.com/nim-lang/Nim/issues/11225
  ../beacon_chain/spec/crypto,
  ../beacon_chain/extras

type
  BlockInput = object
    state: BeaconState
    beaconBlock: BeaconBlock
  BlockHeaderInput = BlockInput
  AttesterSlashingInput = object
    state: BeaconState
    attesterSlashing: AttesterSlashing
  AttestationInput = object
    state: BeaconState
    attestation: Attestation
  # This and AssertionError are raised to indicate programming bugs
  # Used as a wrapper to allow exception tracking to identify unexpected exceptions
  FuzzCrashError = object of Exception

# TODO: change ptr uint to ptr csize_t when available in newer Nim version.
proc copyState(state: BeaconState, output: ptr byte,
    output_size: ptr uint): bool {.raises:[FuzzCrashError, Defect].} =
  var resultState: seq[byte]

  try:
    resultState = SSZ.encode(state)
  except IOError as e:
    # TODO is an IOError indicative of a bug? e.g. any state passed to it after processing should be valid and serializable?
    # How can this raise an IOError (as the writer isn't to a file?)?
    raise newException(FuzzCrashError, "Unexpected failure to serialize.", e)

  if unlikely(resultState.len.uint > output_size[]):
      let msg = (
        "Not enough output buffer provided to nimbus harness. Provided: " &
        $(output_size[]) &
        "Required: " &
        $resultState.len.uint
      )
      raise newException(FuzzCrashError, msg)
  output_size[] = resultState.len.uint
  # TODO: improvement might be to write directly to buffer with OutputStream
  # and SszWriter (but then need to ensure length doesn't overflow)
  copyMem(output, unsafeAddr resultState[0], output_size[])
  result = true


proc nfuzz_attestation(input: openArray[byte], output: ptr byte,
    output_size: ptr uint): bool {.exportc, raises:[FuzzCrashError, Defect].} =
  var
    data: AttestationInput
    cache = get_empty_per_epoch_cache()

  try:
    data = SSZ.decode(input, AttestationInput)
  except MalformedSszError, SszSizeMismatchError:
    let e = getCurrentException()
    raise newException(FuzzCrashError, "SSZ deserialisation failed, likely bug in preprocessing.", e)

  try:
    result = process_attestation(data.state, data.attestation,
      {skipValidation}, cache)
  except ValueError:
    # TODO is a ValueError indicative of correct or incorrect processing code?
    # If correct (but given invalid input), we should return false
    # If incorrect, we should allow it to crash
    result = false

  if result:
    result = copyState(data.state, output, output_size)


proc nfuzz_attester_slashing(input: openArray[byte], output: ptr byte,
    output_size: ptr uint): bool {.exportc, raises:[FuzzCrashError, Defect].} =
  var
    data: AttesterSlashingInput
    cache = get_empty_per_epoch_cache()

  try:
    data = SSZ.decode(input, AttesterSlashingInput)
  except MalformedSszError, SszSizeMismatchError:
    let e = getCurrentException()
    raise newException(FuzzCrashError, "SSZ deserialisation failed, likely bug in preprocessing.", e)

  try:
    result = process_attester_slashing(data.state, data.attesterSlashing, cache)
  except ValueError:
    # TODO is a ValueError indicative of correct or incorrect processing code?
    # If correct (but given invalid input), we should return false
    # If incorrect, we should allow it to crash
    result = false

  if result:
    result = copyState(data.state, output, output_size)


proc nfuzz_block(input: openArray[byte], output: ptr byte,
    output_size: ptr uint): bool {.exportc, raises:[FuzzCrashError, Defect].} =
  var data: BlockInput

  try:
    data = SSZ.decode(input, BlockInput)
  except MalformedSszError, SszSizeMismatchError:
    let e = getCurrentException()
    raise newException(FuzzCrashError, "SSZ deserialisation failed, likely bug in preprocessing.", e)

  try:
    result = state_transition(data.state, data.beaconBlock, {skipValidation})
  except IOError as e:
    # TODO why an IOError?
    raise newException(FuzzCrashError, "Unexpected IOError in state transition", e)
  except Exception as e:
    # TODO why an Exception?
    # Lots of vendor code looks like it might raise a bare exception type
    raise newException(FuzzCrashError, "Unexpected IOError in state transition", e)
  except ValueError:
    # TODO is a ValueError indicative of correct or incorrect processing code?
    # If correct (but given invalid input), we should return false
    # If incorrect, we should allow it to crash
    result = false

  if result:
    result = copyState(data.state, output, output_size)


proc nfuzz_block_header(input: openArray[byte], output: ptr byte,
    output_size: ptr uint): bool {.exportc, raises:[FuzzCrashError, Defect].} =
  var
    data: BlockHeaderInput
    cache = get_empty_per_epoch_cache()

  try:
    data = SSZ.decode(input, BlockHeaderInput)
  except MalformedSszError, SszSizeMismatchError:
    let e = getCurrentException()
    raise newException(FuzzCrashError, "SSZ deserialisation failed, likely bug in preprocessing.", e)

  try:
    result = process_block_header(data.state, data.beaconBlock, {skipValidation}, cache)
  except IOError as e:
    # TODO why an IOError? - is this expected/should we return false?
    raise newException(FuzzCrashError, "Unexpected IOError in block header processing", e)
  except ValueError:
    # TODO is a ValueError indicative of correct or incorrect processing code?
    # If correct (but given invalid input), we should return false
    # If incorrect, we should allow it to crash
    result = false

  if result:
    result = copyState(data.state, output, output_size)


# Note: Could also accept raw input pointer and access list_size + seed here.
# However, list_size needs to be known also outside this proc to allocate output.
# TODO: rework to copy immediatly in an uint8 openArray, considering we have to
# go over the list anyhow?
proc nfuzz_shuffle(input_seed: ptr byte, output: var openArray[uint64]): bool
    {.exportc, raises:[Defect].} =
  var seed: Eth2Digest
  # Should be OK as max 2 bytes are passed by the framework.
  let list_size = output.len.uint64

  copyMem(addr(seed.data), input_seed, sizeof(seed.data))

  var shuffled_seq: seq[ValidatorIndex]
  shuffled_seq = get_shuffled_seq(seed, list_size)

  doAssert(list_size == shuffled_seq.len.uint64, "Shuffled list should be of requested size.")

  for i in 0..<list_size:
    # ValidatorIndex is currently wrongly uint32 so we copy this 1 by 1,
    # assumes passed output is zeroed.
    copyMem(offset(addr output, i.int), shuffled_seq[i.int].unsafeAddr,
      sizeof(ValidatorIndex))

  result = true
