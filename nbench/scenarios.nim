# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  os, tables,
  # Status libraries
  confutils/defs, serialization,
  # Beacon-chain
  ../beacon_chain/spec/[
      datatypes, crypto, helpers, beaconstate, validator,
      state_transition_block, state_transition_epoch],
  ../beacon_chain/[state_transition, extras],
  ../beacon_chain/ssz/[merkleization, ssz_serialization]

# Nimbus Bench - Scenario configuration
# --------------------------------------------------

type
  StartupCommand* = enum
    noCommand
    cmdFullStateTransition
    cmdSlotProcessing
    cmdBlockProcessing
    cmdEpochProcessing

  BlockProcessingCat* = enum
    catBlockHeader
    catRANDAO
    catEth1Data
    catProposerSlashings
    catAttesterSlashings
    catAttestations
    catDeposits
    catVoluntaryExits

  EpochProcessingCat* = enum
    catFinalUpdates
    catJustificationFinalization
    catRegistryUpdates
    catSlashings
    # catRewardsPenalties  # no upstream tests

  ScenarioConf* = object
    scenarioDir* {.
      desc: "The directory of your benchmark scenario"
      name: "scenario-dir"
      abbr: "d"
      required .}: InputDir
    preState* {.
      desc: "The name of your pre-state (without .ssz)"
      name: "pre"
      abbr: "p"
      defaultValue: "pre".}: string
    blocksPrefix* {.
      desc: "The prefix of your blocks file, for exemple \"blocks_\" for blocks in the form \"blocks_XX.ssz\""
      name: "blocks-prefix"
      abbr: "b"
      defaultValue: "blocks_".}: string
    blocksQty* {.
      desc: "The number of blocks to process for this transition. Blocks should start at 0."
      name: "block-quantity"
      abbr: "q"
      defaultValue: 1.}: int
    skipBLS*{.
      desc: "Skip BLS public keys and signature verification"
      name: "skip-bls"
      defaultValue: true.}: bool
    case cmd*{.
      command
      defaultValue: noCommand }: StartupCommand
    of noCommand:
      discard
    of cmdFullStateTransition:
      discard
    of cmdSlotProcessing:
      numSlots* {.
        desc: "The number of slots the pre-state will be advanced by"
        name: "num-slots"
        abbr: "s"
        defaultValue: 1.}: uint64
    of cmdBlockProcessing:
      case blockProcessingCat* {.
        desc: "block transitions"
        # name: "process-blocks" # Pending https://github.com/status-im/nim-confutils/issues/10
        implicitlySelectable
        required .}: BlockProcessingCat
      of catBlockHeader:
        blockHeader*{.
          desc: "Block header filename (without .ssz)"
          name: "block-header"
          defaultValue: "block".}: string
      of catRANDAO:
          discard
      of catEth1Data:
         discard
      of catProposerSlashings:
        proposerSlashing*{.
          desc: "Proposer slashing filename (without .ssz)"
          name: "proposer-slashing"
          defaultValue: "proposer_slashing".}: string
      of catAttesterSlashings:
        attesterSlashing*{.
          desc: "Attester slashing filename (without .ssz)"
          name: "attester-slashing"
          defaultValue: "attester_slashing".}: string
      of catAttestations:
        attestation*{.
          desc: "Attestation filename (without .ssz)"
          name: "attestation"
          defaultValue: "attestation".}: string
      of catDeposits:
        deposit*{.
          desc: "Deposit filename (without .ssz)"
          name: "deposit"
          defaultValue: "deposit".}: string
      of catVoluntaryExits:
        voluntaryExit*{.
          desc: "Voluntary Exit filename (without .ssz)"
          name: "voluntary_exit"
          defaultValue: "voluntary_exit".}: string
    of cmdEpochProcessing:
      epochProcessingCat*: EpochProcessingCat

proc parseSSZ(path: string, T: typedesc): T =
  try:
    when T is ref:
      result = newClone(SSZ.loadFile(path, typeof(default(T)[])))
    else:
      result = SSZ.loadFile(path, T)
  except SerializationError as err:
    writeStackTrace()
    stderr.write "SSZ load issue for file \"", path, "\"\n"
    stderr.write err.formatMsg(path), "\n"
    quit 1
  except CatchableError:
    writeStackTrace()
    stderr.write "SSZ load issue for file \"", path, "\"\n"
    quit 1

proc runFullTransition*(dir, preState, blocksPrefix: string, blocksQty: int, skipBLS: bool) =
  let prePath = dir / preState & ".ssz"

  echo "Running: ", prePath
  let state = (ref HashedBeaconState)(
    data: parseSSZ(prePath, BeaconState)
  )
  state.root = hash_tree_root(state.data)

  for i in 0 ..< blocksQty:
    let blockPath = dir / blocksPrefix & $i & ".ssz"
    echo "Processing: ", blockPath

    let signedBlock = parseSSZ(blockPath, SignedBeaconBlock)
    let flags = if skipBLS: {skipBlsValidation}
                else: {}
    let success = state_transition(
      state[], signedBlock, flags, noRollback)
    echo "State transition status: ", if success: "SUCCESS ✓" else: "FAILURE ⚠️"

proc runProcessSlots*(dir, preState: string, numSlots: uint64) =
  let prePath = dir / preState & ".ssz"

  echo "Running: ", prePath
  let state = (ref HashedBeaconState)(
    data: parseSSZ(prePath, BeaconState)
  )
  state.root = hash_tree_root(state.data)

  # Shouldn't necessarily assert, because nbench can run test suite
  discard process_slots(state[], state.data.slot + numSlots)

template processEpochScenarioImpl(
           dir, preState: string,
           transitionFn: untyped,
           needCache: static bool): untyped =
  let prePath = dir/preState & ".ssz"

  echo "Running: ", prePath
  let state = (ref HashedBeaconState)(
    data: parseSSZ(prePath, BeaconState)
  )
  state.root = hash_tree_root(state.data)

  when needCache:
    var cache = get_empty_per_epoch_cache()
    let epoch = state.data.slot.compute_epoch_at_slot
    cache.shuffled_active_validator_indices[epoch] =
      get_shuffled_active_validator_indices(state.data, epoch)

  # Epoch transitions can't fail (TODO is this true?)
  when needCache:
    transitionFn(state.data, cache)
  else:
    transitionFn(state.data)

  echo astToStr(transitionFn) & " status: ", "Done" # if success: "SUCCESS ✓" else: "FAILURE ⚠️"

template genProcessEpochScenario(name, transitionFn: untyped, needCache: static bool): untyped =
  proc `name`*(dir, preState: string) =
    processEpochScenarioImpl(dir, preState, transitionFn, needCache)

template processBlockScenarioImpl(
           dir, preState: string, skipBLS: bool,
           transitionFn, paramName: untyped,
           ConsensusObjectRefType: typedesc,
           needFlags, needCache: static bool): untyped =
  let prePath = dir/preState & ".ssz"

  echo "Running: ", prePath
  let state = (ref HashedBeaconState)(
    data: parseSSZ(prePath, BeaconState)
  )
  state.root = hash_tree_root(state.data)

  when needCache:
    var cache = get_empty_per_epoch_cache()
  when needFlags:
    let flags = if skipBLS: {skipBlsValidation}
                else: {}

  let consObjPath = dir/paramName & ".ssz"
  echo "Processing: ", consObjPath
  var consObj = parseSSZ(consObjPath, ConsensusObjectRefType)

  when needFlags and needCache:
    let success = transitionFn(state.data, consObj[], flags, cache)
  elif needFlags:
    let success = transitionFn(state.data, consObj[], flags)
  elif needCache:
    let success = transitionFn(state, consObj[], flags, cache)
  else:
    let success = transitionFn(state, consObj[])

  echo astToStr(transitionFn) & " status: ", if success: "SUCCESS ✓" else: "FAILURE ⚠️"

template genProcessBlockScenario(name, transitionFn,
                                 paramName: untyped,
                                 ConsensusObjectType: typedesc,
                                 needFlags,
                                 needCache: static bool): untyped =
  when needFlags:
    proc `name`*(dir, preState, `paramName`: string, skipBLS: bool) =
      processBlockScenarioImpl(dir, preState, skipBLS, transitionFn, paramName, ref ConsensusObjectType, needFlags, needCache)
  else:
    proc `name`*(dir, preState, `paramName`: string) =
      # skipBLS is a dummy to avoid undeclared identifier
      processBlockScenarioImpl(dir, preState, skipBLS = false, transitionFn, paramName, ref ConsensusObjectType, needFlags, needCache)

genProcessEpochScenario(runProcessJustificationFinalization,
                        process_justification_and_finalization,
                        needCache = true)

genProcessEpochScenario(runProcessRegistryUpdates,
                        process_registry_updates,
                        needCache = true)

genProcessEpochScenario(runProcessSlashings,
                        process_slashings,
                        needCache = true)

genProcessEpochScenario(runProcessFinalUpdates,
                        process_final_updates,
                        needCache = false)

genProcessBlockScenario(runProcessBlockHeader,
                        process_block_header,
                        block_header,
                        BeaconBlock,
                        needFlags = true,
                        needCache = true)

genProcessBlockScenario(runProcessProposerSlashing,
                        process_proposer_slashing,
                        proposer_slashing,
                        ProposerSlashing,
                        needFlags = true,
                        needCache = true)

genProcessBlockScenario(runProcessAttestation,
                        process_attestation,
                        attestation,
                        Attestation,
                        needFlags = true,
                        needCache = true)

genProcessBlockScenario(runProcessAttesterSlashing,
                        process_attester_slashing,
                        att_slash,
                        AttesterSlashing,
                        needFlags = true,
                        needCache = true)

genProcessBlockScenario(runProcessDeposit,
                        process_deposit,
                        deposit,
                        Deposit,
                        needFlags = true,
                        needCache = false)

genProcessBlockScenario(runProcessVoluntaryExits,
                        process_voluntary_exit,
                        deposit,
                        SignedVoluntaryExit,
                        needFlags = true,
                        needCache = false)
