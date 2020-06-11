# Required for deserialisation of ValidatorSig in Attestation due to
# https://github.com/nim-lang/Nim/issues/11225

import
  stew/ptrops, stew/ranges/ptr_arith,
  ../beacon_chain/[extras, state_transition],
  ../beacon_chain/spec/[crypto, datatypes, digest, validator, beaconstate,
      state_transition_block],
  ../beacon_chain/ssz/[merkleization, ssz_serialization]

type
  AttestationInput = object
    state: BeaconState
    attestation: Attestation
  AttesterSlashingInput = object
    state: BeaconState
    attesterSlashing: AttesterSlashing
  BlockInput = object
    state: BeaconState
    beaconBlock: SignedBeaconBlock
  BlockHeaderInput = BlockInput
  DepositInput = object
    state: BeaconState
    deposit: Deposit
  ProposerSlashingInput = object
    state: BeaconState
    proposerSlashing: ProposerSlashing
  VoluntaryExitInput = object
    state: BeaconState
    exit: SignedVoluntaryExit
  # This and AssertionError are raised to indicate programming bugs
  # A wrapper to allow exception tracking to identify unexpected exceptions
  FuzzCrashError = object of CatchableError

# TODO: change ptr uint to ptr csize_t when available in newer Nim version.
proc copyState(state: BeaconState, output: ptr byte,
    output_size: ptr uint): bool {.raises: [FuzzCrashError, Defect].} =
  var resultState =
    try:
      SSZ.encode(state)
    except IOError as e:
      # Shouldn't occur as the writer isn't a file
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

template decodeAndProcess(typ, process: untyped): bool =
  let flags {.inject.} = if disable_bls: {skipBlsValidation} else: {}

  var
    cache {.used, inject.} = get_empty_per_epoch_cache()
    data {.inject.} = newClone(
      try:
        SSZ.decode(input, typ)
      except MalformedSszError as e:
        raise newException(
          FuzzCrashError,
          "Malformed SSZ, likely bug in preprocessing.", e)
      except SszSizeMismatchError as e:
        raise newException(
          FuzzCrashError,
          "SSZ size mismatch, likely bug in preprocessing.", e)
    )
  let processOk =
    try:
      process
    except IOError as e:
      raise newException(
        FuzzCrashError, "Unexpected  (logging?) IOError in state transition", e,
      )
    except ValueError as e:
      raise newException(
        FuzzCrashError,
        "Unexpected  (logging?) IOError in state transition", e)
    except Exception as e:
      # TODO why an Exception?
      # Lots of vendor code looks like it might raise a bare exception type
      raise newException(FuzzCrashError, "Unexpected Exception in state transition", e)

  if processOk:
    copyState(data.state, output, output_size)
  else:
    false

proc nfuzz_attestation(input: openArray[byte], output: ptr byte,
    output_size: ptr uint, disable_bls: bool): bool {.exportc, raises: [FuzzCrashError, Defect].} =
  decodeAndProcess(AttestationInput):
    process_attestation(data.state, data.attestation, flags, cache)

proc nfuzz_attester_slashing(input: openArray[byte], output: ptr byte,
    output_size: ptr uint, disable_bls: bool): bool {.exportc, raises: [FuzzCrashError, Defect].} =
  decodeAndProcess(AttesterSlashingInput):
    process_attester_slashing(data.state, data.attesterSlashing, flags, cache)

proc nfuzz_block(input: openArray[byte], output: ptr byte,
    output_size: ptr uint, disable_bls: bool): bool {.exportc, raises: [FuzzCrashError, Defect].} =
  # There's not a perfect approach here, but it's not worth switching the rest
  # and requiring HashedBeaconState (yet). So to keep consistent, puts wrapper
  # only in one function.
  proc state_transition(
      data: auto, blck: auto, flags: auto, rollback: RollbackHashedProc):
      auto =
    var hashedState =
      HashedBeaconState(data: data.state, root: hash_tree_root(data.state))
    result = state_transition(hashedState, blck, flags, rollback)
    data.state = hashedState.data

  decodeAndProcess(BlockInput):
    state_transition(data, data.beaconBlock, flags, noRollback)

proc nfuzz_block_header(input: openArray[byte], output: ptr byte,
    output_size: ptr uint, disable_bls: bool): bool {.exportc, raises: [FuzzCrashError, Defect].} =
  decodeAndProcess(BlockHeaderInput):
    process_block_header(data.state, data.beaconBlock.message, flags, cache)

proc nfuzz_deposit(input: openArray[byte], output: ptr byte,
    output_size: ptr uint, disable_bls: bool): bool {.exportc, raises: [FuzzCrashError, Defect].} =
  decodeAndProcess(DepositInput):
    process_deposit(data.state, data.deposit, flags)

proc nfuzz_proposer_slashing(input: openArray[byte], output: ptr byte,
    output_size: ptr uint, disable_bls: bool): bool {.exportc, raises: [FuzzCrashError, Defect].} =
  decodeAndProcess(ProposerSlashingInput):
    process_proposer_slashing(data.state, data.proposerSlashing, flags, cache)

proc nfuzz_voluntary_exit(input: openArray[byte], output: ptr byte,
    output_size: ptr uint, disable_bls: bool): bool {.exportc, raises: [FuzzCrashError, Defect].} =
  decodeAndProcess(VoluntaryExitInput):
    process_voluntary_exit(data.state, data.exit, flags)

# Note: Could also accept raw input pointer and access list_size + seed here.
# However, list_size needs to be known also outside this proc to allocate output.
# TODO: rework to copy immediatly in an uint8 openArray, considering we have to
# go over the list anyhow?
proc nfuzz_shuffle(input_seed: ptr byte, output: var openArray[uint64]): bool
    {.exportc, raises: [Defect].} =
  var seed: Eth2Digest
  # Should be OK as max 2 bytes are passed by the framework.
  let list_size = output.len.uint64

  copyMem(addr(seed.data), input_seed, sizeof(seed.data))

  var shuffled_seq: seq[ValidatorIndex]
  shuffled_seq = get_shuffled_seq(seed, list_size)

  doAssert(
    list_size == shuffled_seq.len.uint64,
    "Shuffled list should be of requested size."
  )

  for i in 0..<list_size:
    # ValidatorIndex is currently wrongly uint32 so we copy this 1 by 1,
    # assumes passed output is zeroed.
    copyMem(offset(addr output, i.int), shuffled_seq[i.int].unsafeAddr,
      sizeof(ValidatorIndex))

  result = true
