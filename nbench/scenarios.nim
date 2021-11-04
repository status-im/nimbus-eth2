# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  os, tables,
  # Status libraries
  confutils/defs, serialization, chronicles,
  # Beacon-chain
  ../beacon_chain/spec/datatypes/[phase0],
  ../beacon_chain/spec/[
      beaconstate, forks, helpers, state_transition, state_transition_block,
      state_transition_epoch],
  ../tests/consensus_spec/fixtures_utils

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
  var
    cache = StateCache()
    info = ForkedEpochInfo()

  echo "Running: ", prePath
  let state = (ref ForkedHashedBeaconState)(
    phase0Data: phase0.HashedBeaconState(data: parseSSZ(prePath, phase0.BeaconState)),
    kind: BeaconStateFork.Phase0
  )
  setStateRoot(state[], hash_tree_root(state[].phase0Data.data))

  for i in 0 ..< blocksQty:
    let blockPath = dir / blocksPrefix & $i & ".ssz"
    echo "Processing: ", blockPath

    let signedBlock = parseSSZ(blockPath, phase0.SignedBeaconBlock)
    let flags = if skipBLS: {skipBlsValidation}
                else: {}
    let success = state_transition(
      defaultRuntimeConfig, state[], signedBlock, cache, info, flags,
      noRollback)
    echo "State transition status: ", if success: "SUCCESS ✓" else: "FAILURE ⚠️"

proc runProcessSlots*(dir, preState: string, numSlots: uint64) =
  var
    cache = StateCache()
    info = ForkedEpochInfo()
  let prePath = dir / preState & ".ssz"

  echo "Running: ", prePath
  let state = (ref ForkedHashedBeaconState)(
    phase0Data: phase0.HashedBeaconState(
      data: parseSSZ(prePath, phase0.BeaconState)),
    kind: BeaconStateFork.Phase0)
  setStateRoot(state[], hash_tree_root(state[].phase0Data.data))

  # Shouldn't necessarily assert, because nbench can run test suite
  discard process_slots(
    defaultRuntimeConfig, state[], getStateField(state[], slot) + numSlots,
    cache, info, {})

template processEpochScenarioImpl(
           dir, preState: string,
           transitionFn: untyped): untyped =
  let prePath = dir/preState & ".ssz"

  echo "Running: ", prePath
  type T = phase0.BeaconState
  let state = (ref phase0.HashedBeaconState)(
    data: parseSSZ(prePath, T)
  )
  state.root = hash_tree_root(state.data)

  var cache {.used.} = StateCache()
  when compiles(transitionFn(defaultRuntimeConfig, state.data, cache)):
    transitionFn(defaultRuntimeConfig, state.data, cache)
  elif compiles(transitionFn(state.data, cache)):
    transitionFn(state.data, cache)
  elif compiles(transitionFn(state.data)):
    transitionFn(state.data)
  else:
    transitionFn(defaultRuntimeConfig, state.data)

  echo astToStr(transitionFn) & " status: ", "Done" # if success: "SUCCESS ✓" else: "FAILURE ⚠️"

template genProcessEpochScenario(name, transitionFn: untyped): untyped =
  proc `name`*(dir, preState: string) =
    processEpochScenarioImpl(dir, preState, transitionFn)

proc process_deposit(state: var phase0.BeaconState;
                     deposit: Deposit;
                     flags: UpdateFlags = {}): Result[void, cstring] =
  process_deposit(defaultRuntimeConfig, state, deposit, flags)

proc bench_process_justification_and_finalization(state: var phase0.BeaconState) =
  var
    cache: StateCache
    info: phase0.EpochInfo
  info.init(state)
  info.process_attestations(state, cache)
  process_justification_and_finalization(state, info.total_balances)

func bench_process_slashings(state: var phase0.BeaconState) =
  var
    cache: StateCache
    info: phase0.EpochInfo
  info.init(state)
  info.process_attestations(state, cache)
  process_slashings(state, info.total_balances.current_epoch)

template processBlockScenarioImpl(
           dir, preState: string, skipBLS: bool,
           transitionFn, paramName: untyped,
           ConsensusObjectRefType: typedesc): untyped =
  let prePath = dir/preState & ".ssz"

  echo "Running: ", prePath
  type T = phase0.BeaconState
  let state = (ref phase0.HashedBeaconState)(
    data: parseSSZ(prePath, T)
  )
  state.root = hash_tree_root(state.data)

  var cache {.used.} = StateCache()
  let flags {.used.} = if skipBLS: {skipBlsValidation}
                       else: {}

  let consObjPath = dir/paramName & ".ssz"
  echo "Processing: ", consObjPath
  var consObj = parseSSZ(consObjPath, ConsensusObjectRefType)

  when compiles(transitionFn(state.data, consObj[], flags, cache)):
    let success = transitionFn(state.data, consObj[], flags, cache).isOk
  elif compiles(transitionFn(defaultRuntimeConfig, state.data, consObj[], flags, cache)):
    let success = transitionFn(defaultRuntimeConfig, state.data, consObj[], flags, cache).isOk
  elif compiles(transitionFn(state.data, consObj[], flags)):
    let success = transitionFn(state.data, consObj[], flags).isOk
  elif compiles(transitionFn(state, consObj[], flags, cache)):
    let success = transitionFn(state, consObj[], flags, cache).isOk
  else:
    let success = transitionFn(state, consObj[]).isOk

  echo astToStr(transitionFn) & " status: ", if success: "SUCCESS ✓" else: "FAILURE ⚠️"

template genProcessBlockScenario(name, transitionFn,
                                 paramName: untyped,
                                 ConsensusObjectType: typedesc): untyped =
  proc `name`*(dir, preState, `paramName`: string, skipBLS: bool) =
    processBlockScenarioImpl(dir, preState, skipBLS, transitionFn, paramName, ref ConsensusObjectType)

genProcessEpochScenario(runProcessJustificationFinalization,
                        bench_process_justification_and_finalization)

genProcessEpochScenario(runProcessRegistryUpdates,
                        process_registry_updates)

genProcessEpochScenario(runProcessSlashings,
                        bench_process_slashings)

genProcessBlockScenario(runProcessBlockHeader,
                        process_block_header,
                        block_header,
                        phase0.BeaconBlock)

genProcessBlockScenario(runProcessProposerSlashing,
                        process_proposer_slashing,
                        proposer_slashing,
                        ProposerSlashing)

template do_process_attestation(state, operation, flags, cache: untyped):
    untyped =
  process_attestation(state, operation, flags, 0.Gwei, cache)
genProcessBlockScenario(runProcessAttestation,
                        do_process_attestation,
                        attestation,
                        Attestation)

genProcessBlockScenario(runProcessAttesterSlashing,
                        process_attester_slashing,
                        att_slash,
                        AttesterSlashing)

genProcessBlockScenario(runProcessDeposit,
                        process_deposit,
                        deposit,
                        Deposit)

genProcessBlockScenario(runProcessVoluntaryExits,
                        process_voluntary_exit,
                        deposit,
                        SignedVoluntaryExit)
