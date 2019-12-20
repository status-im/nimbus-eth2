# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  os,
  # Status libraries
  confutils/defs, serialization,
  # Beacon-chain
  ../beacon_chain/spec/[datatypes, crypto, beaconstate, validator],
  ../beacon_chain/[ssz, state_transition, extras]

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
        discard
      of catRANDAO:
        discard
      of catEth1Data:
        discard
      of catProposerSlashings:
        discard
      of catAttesterSlashings:
        discard
      of catAttestations:
        attestation*{.
          desc: "Attestation filename (without .ssz)"
          name: "attestation"
          defaultValue: "attestation".}: string
      of catDeposits:
        discard
      of catVoluntaryExits:
        discard
    of cmdEpochProcessing:
      discard

proc runFullTransition*(dir, preState, blocksPrefix: string, blocksQty: int, skipBLS: bool) =
  let prePath = dir / preState & ".ssz"

  var state: ref BeaconState
  new state
  echo "Running: ", prePath
  state[] = SSZ.loadFile(prePath, BeaconState)

  for i in 0 ..< blocksQty:
    let blockPath = dir / blocksPrefix & $i & ".ssz"
    echo "Processing: ", blockPath

    let blck = SSZ.loadFile(blockPath, SignedBeaconBlock)
    let flags = if skipBLS: {skipValidation} # TODO: this also skips state root verification
                else: {}
    let success = state_transition(state[], blck.message, flags)
    echo "State transition status: ", if success: "SUCCESS ✓" else: "FAILURE ⚠️"

proc runProcessSlots*(dir, preState: string, numSlots: uint64) =
  let prePath = dir / preState & ".ssz"

  var state: ref BeaconState
  new state
  echo "Running: ", prePath
  state[] = SSZ.loadFile(prePath, BeaconState)

  process_slots(state[], state.slot + numSlots)

template processScenarioImpl(
           dir, preState: string, skipBLS: bool,
           transitionFn, paramName: untyped,
           ConsensusObject: typedesc,
           needFlags, needCache: static bool): untyped =
  let prePath = dir/preState & ".ssz"

  var state: ref BeaconState
  new state
  echo "Running: ", prePath
  state[] = SSZ.loadFile(prePath, BeaconState)

  var consObj: ref `ConsensusObject`
  new consObj
  when needCache:
    var cache = get_empty_per_epoch_cache()
  when needCache:
    let flags = if skipBLS: {skipValidation} # TODO: this also skips state root verification
                else: {}

  let consObjPath = dir/paramName & ".ssz"
  echo "Processing: ", consObjPath
  consObj[] = SSZ.loadFile(consObjPath, ConsensusObject)

  when needFlags and needCache:
    let success = transitionFn(state[], consObj[], flags, cache)
  elif needFlags:
    let success = transitionFn(state[], consObj[], flags)
  elif needCache:
    let success = transitionFn(state[], consObj[], cache)
  else:
    let success = transitionFn(state[], consObj[])

  echo astToStr(transitionFn) & " status: ", if success: "SUCCESS ✓" else: "FAILURE ⚠️"

template genProcessScenario(name, transitionFn, paramName: untyped, ConsensusObject: typedesc, needFlags, needCache: static bool): untyped =
  when needFlags:
    proc `name`*(dir, preState, `paramName`: string, skipBLS: bool) =
      processScenarioImpl(dir, preState, skipBLS, transitionFn, paramName, ConsensusObject, needFlags, needCache)
  else:
    proc `name`*(dir, preState, `paramName`: string) =
      # skipBLS is a dummy to avoid undeclared identifier
      processScenarioImpl(dir, preState, skipBLS = false, transitionFn, paramName, ConsensusObject, needFlags, needCache)

genProcessScenario(runProcessAttestation, process_attestation, attestation, Attestation, needFlags = true, needCache = true)
