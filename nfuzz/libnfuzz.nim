# Required for deserialisation of ValidatorSig in Attestation due to
# https://github.com/nim-lang/Nim/issues/11225

import
  stew/ptrops, stew/ranges/ptr_arith, chronicles,
  ../beacon_chain/networking/network_metadata,
  ../beacon_chain/spec/datatypes/phase0,
  ../beacon_chain/spec/[
    beaconstate, eth2_ssz_serialization, forks, validator, state_transition,
    state_transition_block]

type
  AttestationInput = object
    state: phase0.BeaconState
    attestation: Attestation
  AttesterSlashingInput = object
    state: phase0.BeaconState
    attesterSlashing: AttesterSlashing
  BlockInput = object
    state: phase0.BeaconState
    beaconBlock: phase0.SignedBeaconBlock
  BlockHeaderInput = BlockInput
  DepositInput = object
    state: phase0.BeaconState
    deposit: Deposit
  ProposerSlashingInput = object
    state: phase0.BeaconState
    proposerSlashing: ProposerSlashing
  VoluntaryExitInput = object
    state: phase0.BeaconState
    exit: SignedVoluntaryExit
  # This and AssertionError are raised to indicate programming bugs
  # A wrapper to allow exception tracking to identify unexpected exceptions
  FuzzCrashError = object of CatchableError

# TODO: change ptr uint to ptr csize_t when available in newer Nim version.
proc copyState(state: phase0.BeaconState, xoutput: ptr byte,
    xoutput_size: ptr uint): bool {.raises: [FuzzCrashError, Defect].} =
  var resultState =
    try:
      SSZ.encode(state)
    except IOError as e:
      # Shouldn't occur as the writer isn't a file
      raise newException(FuzzCrashError, "Unexpected failure to serialize.", e)

  if unlikely(resultState.len.uint > xoutput_size[]):
    let msg = (
      "Not enough xoutput buffer provided to nimbus harness. Provided: " &
      $(xoutput_size[]) &
      "Required: " &
      $resultState.len.uint
    )
    raise newException(FuzzCrashError, msg)
  xoutput_size[] = resultState.len.uint
  # TODO: improvement might be to write directly to buffer with xoutputStream
  # and SszWriter (but then need to ensure length doesn't overflow)
  copyMem(xoutput, unsafeAddr resultState[0], xoutput_size[])
  result = true

template decodeAndProcess(typ, process: untyped): bool =
  let flags {.inject.} = if disable_bls: {skipBlsValidation} else: {}

  var
    cache {.used, inject.} = StateCache()
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
    copyState(data.state, xoutput, xoutput_size)
  else:
    false

proc nfuzz_attestation(input: openArray[byte], xoutput: ptr byte,
    xoutput_size: ptr uint, disable_bls: bool): bool {.exportc, raises: [FuzzCrashError, Defect].} =
  decodeAndProcess(AttestationInput):
    process_attestation(data.state, data.attestation, flags, 0.Gwei, cache).isOk

proc nfuzz_attester_slashing(input: openArray[byte], xoutput: ptr byte,
    xoutput_size: ptr uint, disable_bls: bool): bool {.exportc, raises: [FuzzCrashError, Defect].} =
  decodeAndProcess(AttesterSlashingInput):
    process_attester_slashing(mainnetMetadata.cfg, data.state, data.attesterSlashing, flags, cache).isOk

proc nfuzz_block(input: openArray[byte], xoutput: ptr byte,
    xoutput_size: ptr uint, disable_bls: bool): bool {.exportc, raises: [FuzzCrashError, Defect].} =
  # There's not a perfect approach here, but it's not worth switching the rest
  # and requiring HashedBeaconState (yet). So to keep consistent, puts wrapper
  # only in one function.
  proc state_transition(
      cfg: RuntimeConfig, data: auto, blck: auto, flags: auto,
      rollback: RollbackForkedHashedProc): auto =
    var
      fhState = (ref ForkedHashedBeaconState)(
        phase0Data: phase0.HashedBeaconState(
          data: data.state, root: hash_tree_root(data.state)),
        kind: ConsensusFork.Phase0)
      cache = StateCache()
      info = ForkedEpochInfo()
    result =
      state_transition(
        cfg, fhState[], blck, cache, info, flags, rollback)
    data.state = fhState.phase0Data.data

  decodeAndProcess(BlockInput):
    state_transition(
      mainnetMetadata.cfg, data, data.beaconBlock, flags, noRollback).isOk

proc nfuzz_block_header(input: openArray[byte], xoutput: ptr byte,
    xoutput_size: ptr uint, disable_bls: bool): bool {.exportc, raises: [FuzzCrashError, Defect].} =
  decodeAndProcess(BlockHeaderInput):
    process_block_header(data.state, data.beaconBlock.message, flags, cache).isOk

proc nfuzz_deposit(input: openArray[byte], xoutput: ptr byte,
    xoutput_size: ptr uint, disable_bls: bool): bool {.exportc, raises: [FuzzCrashError, Defect].} =
  decodeAndProcess(DepositInput):
    process_deposit(mainnetMetadata.cfg, data.state, data.deposit, flags).isOk

proc nfuzz_proposer_slashing(input: openArray[byte], xoutput: ptr byte,
    xoutput_size: ptr uint, disable_bls: bool): bool {.exportc, raises: [FuzzCrashError, Defect].} =
  decodeAndProcess(ProposerSlashingInput):
    process_proposer_slashing(mainnetMetadata.cfg, data.state, data.proposerSlashing, flags, cache).isOk

proc nfuzz_voluntary_exit(input: openArray[byte], xoutput: ptr byte,
    xoutput_size: ptr uint, disable_bls: bool): bool {.exportc, raises: [FuzzCrashError, Defect].} =
  decodeAndProcess(VoluntaryExitInput):
    process_voluntary_exit(mainnetMetadata.cfg, data.state, data.exit, flags, cache).isOk

# Note: Could also accept raw input pointer and access list_size + seed here.
# However, list_size needs to be known also outside this proc to allocate xoutput.
# TODO: rework to copy immediatly in an uint8 openArray, considering we have to
# go over the list anyhow?
proc nfuzz_shuffle(input_seed: ptr byte, xoutput: var openArray[uint64]): bool
    {.exportc, raises: [Defect].} =
  var seed: Eth2Digest
  # Should be OK as max 2 bytes are passed by the framework.
  let list_size = xoutput.len

  copyMem(addr(seed.data), input_seed, sizeof(seed.data))

  var shuffled_seq: seq[ValidatorIndex]
  for i in 0..<list_size:
    shuffled_seq.add i.ValidatorIndex
  shuffle_list(shuffled_seq, seed)

  for i in 0..<list_size:
    # ValidatorIndex is currently wrongly uint32 so we copy this 1 by 1,
    # assumes passed xoutput is zeroed.
    copyMem(offset(addr xoutput, i), shuffled_seq[i].unsafeAddr,
      sizeof(ValidatorIndex))

  true
