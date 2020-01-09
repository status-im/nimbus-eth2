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
  ../beacon_chain/spec/datatypes,
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
  of cmdBlockProcessing:
    case scenario.blockProcessingCat
    of catBlockHeader:
      runProcessBlockHeader(
        scenario.scenarioDir.string,
        scenario.preState,
        "block", # Pending https://github.com/status-im/nim-confutils/issues/11
        # scenario.attesterSlashing
        scenario.skipBLS
      )
    of catProposerSlashings:
      runProcessProposerSlashing(
        scenario.scenarioDir.string,
        scenario.preState,
        "proposer_slashing", # Pending https://github.com/status-im/nim-confutils/issues/11
        # scenario.attesterSlashing
        scenario.skipBLS
      )
    of catAttesterSlashings:
      runProcessAttesterSlashing(
        scenario.scenarioDir.string,
        scenario.preState,
        "attester_slashing" # Pending https://github.com/status-im/nim-confutils/issues/11
        # scenario.attesterSlashing
      )
    of catAttestations:
      runProcessAttestation(
        scenario.scenarioDir.string,
        scenario.preState,
        "attestation", # Pending https://github.com/status-im/nim-confutils/issues/11
        # scenario.attestation,
        scenario.skipBLS
      )
    of catDeposits:
      runProcessDeposit(
        scenario.scenarioDir.string,
        scenario.preState,
        "deposit", # Pending https://github.com/status-im/nim-confutils/issues/11
        # scenario.deposit,
        scenario.skipBLS
      )
    of catVoluntaryExits:
      runProcessVoluntaryExits(
        scenario.scenarioDir.string,
        scenario.preState,
        "voluntary_exit", # Pending https://github.com/status-im/nim-confutils/issues/11
        # scenario.voluntary_exit,
        scenario.skipBLS
      )
    else:
      quit "Unsupported"
  of cmdEpochProcessing:
    case scenario.epochProcessingCat
    of catJustificationFinalization:
      runProcessJustificationFinalization(
        scenario.scenarioDir.string,
        scenario.preState
      )
    of catRegistryUpdates:
      runProcessRegistryUpdates(
        scenario.scenarioDir.string,
        scenario.preState
      )
    of catSlashings:
      runProcessSlashings(
        scenario.scenarioDir.string,
        scenario.preState
      )
    of catFinalUpdates:
      runProcessFinalUpdates(
        scenario.scenarioDir.string,
        scenario.preState
      )
  else:
    quit "Unsupported"

  # TODO: Nimbus not fine-grained enough in UpdateFlags
  let flags = if scenario.skipBLS: "[skipBLS, skipStateRootVerification]"
              else: "[withBLS, withStateRootVerification]"
  reportCli(BenchMetrics, const_preset, flags)

when isMainModule:
  main()
