# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  os, osproc, strformat,
  # Status libraries
  confutils

# Nimbus Bench Batch
# --------------------------------------------------
# This script calls Nimbus bench in parallel batch
# to run a series of benchmarks from the official SSZ tests

type
  CmdLists = seq[string]

proc collectTarget(cmds: var CmdLists, nbench, name, cmd, cat, path: string) =
  echo "----------------------------------------"
  echo "Collecting ", name, " transitions"
  echo "----------------------------------------"
  for folder in walkDirRec(path, yieldFilter = {pcDir}, relative = true):
    echo "Found: ", folder
    var cat = cat
    if cmd == "cmdBlockProcessing":
      cat = "--blockProcessingCat=" & cat
    cmds.add &"{nbench} {cmd} {cat} -d={path/folder}"

proc collectBenchTargets(nbench, basePath: string): CmdLists =
  block: # Full state transitions
    echo "----------------------------------------"
    echo "Collecting full state transitions"
    echo "----------------------------------------"
    let path = basePath/"phase0"/"sanity"/"blocks"/"pyspec_tests"
    for folder in walkDirRec(path, yieldFilter = {pcDir}, relative = true):
      var countBlocks = 0
      for _ in walkFiles(path/folder/"blocks_*.ssz"):
        inc countBlocks
      echo "Found: ", folder, " with ", countBlocks, " blocks"
      result.add &"{nbench} cmdFullStateTransition -d={path/folder} -q={$countBlocks}"
  block: # Slot processing
    let path = basePath/"phase0"/"sanity"/"slots"/"pyspec_tests"
    result.collectTarget(nbench, "slot", "cmdSlotProcessing", "", path)
  block: # Attestation
    let path = basePath/"phase0"/"operations"/"attestation"/"pyspec_tests"
    result.collectTarget(nbench, "attestation", "cmdBlockProcessing", "catAttestations", path)
  block: # Attester_slashing
    let path = basePath/"phase0"/"operations"/"attester_slashing"/"pyspec_tests"
    result.collectTarget(nbench, "attester_slashing", "cmdBlockProcessing", "catAttesterSlashings", path)
  block: # block_header
    let path = basePath/"phase0"/"operations"/"block_header"/"pyspec_tests"
    result.collectTarget(nbench, "block_header", "cmdBlockProcessing", "catBlockHeader", path)
  block: # deposit
    let path = basePath/"phase0"/"operations"/"deposit"/"pyspec_tests"
    result.collectTarget(nbench, "deposit", "cmdBlockProcessing", "catDeposits", path)
  block: # proposer_slashing
    let path = basePath/"phase0"/"operations"/"proposer_slashing"/"pyspec_tests"
    result.collectTarget(nbench, "proposer_slashing", "cmdBlockProcessing", "catProposerSlashings", path)
  block: # voluntary_exit
    let path = basePath/"phase0"/"operations"/"voluntary_exit"/"pyspec_tests"
    result.collectTarget(nbench, "voluntary_exit", "cmdBlockProcessing", "catVoluntaryExits", path)

cli do(nbench: string, tests: string):
  let cmdLists = collectBenchTargets(nbench, tests)
  let err = execProcesses(cmdLists)
  quit err
