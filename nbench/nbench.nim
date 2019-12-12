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
  confutils, serialization,
  # Beacon-chain
  ../beacon_chain/spec/[datatypes, crypto],
  ../beacon_chain/[ssz, state_transition, extras],
  # Bench specific
  scenarios, bench_lab, reports

# Example:
# build/nbench cmdFullStateTransition -d

# Nimbus Bench
# --------------------------------------------------
#
# Run select scenarios and get statistics on Nimbus runtime behaviour

when not defined(nbench):
  {.error: "`nbench` requires `-d:nbench` flag to enable tracing on procedures.".}

proc runFullTransition(dir, preState, blocksPrefix: string, blocksQty: int, skipBLS: bool) =
  let prePath = dir / preState & ".ssz"

  var state: ref BeaconState
  new state
  echo "Running: ", prePath
  state[] = SSZ.loadFile(prePath, BeaconState)

  for i in 0 ..< blocksQty:
    let blockPath = dir / blocksPrefix & $i & ".ssz"
    echo "Processing: ", blockPath

    let blck = SSZ.loadFile(blockPath, BeaconBlock)
    let flags = if skipBLS: {skipValidation} # TODO: this also skips state root verification
                else: {}
    let success = state_transition(state[], blck, flags)
    doAssert success, "Failure when applying block " & blockPath

proc runProcessSlots(dir, preState: string, numSlots: uint64) =
  let prePath = dir / preState & ".ssz"

  var state: ref BeaconState
  new state
  echo "Running: ", prePath
  state[] = SSZ.loadFile(prePath, BeaconState)

  process_slots(state[], state.slot + numSlots)

proc main() =
  # TODO versioning
  echo "Nimbus bench, preset \"", const_preset, '\"'

  BenchMetrics = static(ctBenchMetrics) # Make compile-time data available at runtime
  let scenario = ScenarioConf.load()

  case scenario.cmd
  of cmdFullStateTransition:
    runFullTransition(
      scenario.scenarioDir.string,
      scenario.preState,
      scenario.blocksPrefix,
      scenario.blocksQty,
      scenario.skipBLS
    )
  of cmdSlotProcessing:
    runProcessSlots(
      scenario.scenarioDir.string,
      scenario.preState,
      scenario.numSlots
    )
  else:
    quit "Unsupported"

  reportCli(BenchMetrics)

when isMainModule:
  main()
