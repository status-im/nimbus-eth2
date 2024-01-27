# beacon_chain
# Copyright (c) 2020-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  stew/io2,
  ../tests/testblockutil, ../tests/consensus_spec/os_ops,
  ../beacon_chain/spec/[beaconstate, forks]

from std/stats import RunningStat, mean, push, standardDeviationS
from std/strformat import `&`
from std/times import cpuTime
from ../beacon_chain/filepath import secureCreatePath
from ../beacon_chain/spec/deposit_snapshots import DepositTreeSnapshot

template withTimer*(stats: var RunningStat, body: untyped) =
  # TODO unify timing somehow
  let start = cpuTime()

  block:
    body

  let stop = cpuTime()
  stats.push stop - start

template withTimerRet*(stats: var RunningStat, body: untyped): untyped =
  let start = cpuTime()
  let tmp = block:
    body
  let stop = cpuTime()
  stats.push stop - start

  tmp

func verifyConsensus*(state: ForkedHashedBeaconState, attesterRatio: float) =
  if attesterRatio < 0.63:
    doAssert getStateField(state, current_justified_checkpoint).epoch == 0
    doAssert getStateField(state, finalized_checkpoint).epoch == 0

  # Quorum is 2/3 of validators, and at low numbers, quantization effects
  # can dominate, so allow for play above/below attesterRatio of 2/3.
  if attesterRatio < 0.72:
    return

  let current_epoch = get_current_epoch(state)
  if current_epoch >= 3:
    doAssert getStateField(
      state, current_justified_checkpoint).epoch + 1 >= current_epoch
  if current_epoch >= 4:
    doAssert getStateField(
      state, finalized_checkpoint).epoch + 2 >= current_epoch

func getSimulationConfig*(): RuntimeConfig {.compileTime.} =
  var cfg = defaultRuntimeConfig
  cfg.ALTAIR_FORK_EPOCH = 0.Epoch
  cfg.BELLATRIX_FORK_EPOCH = 0.Epoch
  cfg.CAPELLA_FORK_EPOCH = 0.Epoch
  cfg.DENEB_FORK_EPOCH = 2.Epoch
  cfg

proc loadGenesis*(validators: Natural, validate: bool):
                 (ref ForkedHashedBeaconState, DepositTreeSnapshot) =
  const genesisDir = "test_sim"
  if (let res = secureCreatePath(genesisDir); res.isErr):
    fatal "Could not create directory",
      path = genesisDir, err = ioErrorMsg(res.error)
    quit 1

  let
    genesisFn = genesisDir /
      &"genesis_{const_preset}_{validators}_{SPEC_VERSION}.ssz"
    contractSnapshotFn = genesisDir /
      &"deposit_contract_snapshot_{const_preset}_{validators}_{SPEC_VERSION}.ssz"
  const cfg = getSimulationConfig()

  if fileExists(genesisFn) and fileExists(contractSnapshotFn):
    let res = newClone(readSszForkedHashedBeaconState(
      cfg, readAllBytes(genesisFn).tryGet()))

    withState(res[]):
      if forkyState.data.slot != GENESIS_SLOT:
        echo "Can only start from genesis state"
        quit 1

      if forkyState.data.validators.len != validators:
        echo &"Supplied genesis file has {forkyState.data.validators.len} validators, while {validators} where requested, running anyway"

      echo &"Loaded {genesisFn}..."

      # TODO check that the private keys are EF test keys

      let contractSnapshot = SSZ.loadFile(contractSnapshotFn,
                                          DepositTreeSnapshot)
      (res, contractSnapshot)
  else:
    echo "Genesis file not found, making one up (use nimbus_beacon_node createTestnet to make one)"

    echo "Preparing validators..."
    let
      flags = if validate: {} else: {skipBlsValidation}
      deposits = makeInitialDeposits(validators.uint64, flags)

    echo "Generating Genesis..."
    var merkleizer = init DepositsMerkleizer
    for d in deposits:
      merkleizer.addChunk hash_tree_root(d).data
    let contractSnapshot = DepositTreeSnapshot(
      depositContractState: merkleizer.toDepositContractState)

    let res = (ref ForkedHashedBeaconState)(
      kind: ConsensusFork.Capella,
      capellaData: capella.HashedBeaconState(
        data: initialize_beacon_state_from_eth1(
          cfg, ZERO_HASH, 0, deposits,
          default(capella.ExecutionPayloadHeader), {skipBlsValidation})))

    echo &"Saving to {genesisFn}..."
    SSZ.saveFile(genesisFn, res.capellaData.data)
    echo &"Saving to {contractSnapshotFn}..."
    SSZ.saveFile(contractSnapshotFn, contractSnapshot)

    (res, contractSnapshot)

proc printTimers*[Timers: enum](
  validate: bool,
  timers: array[Timers, RunningStat]
) =
  func fmtTime(t: float): string = &"{t * 1000 :>12.3f}, "

  echo "All time are ms"
  echo &"{\"Average\" :>12}, {\"StdDev\" :>12}, {\"Min\" :>12}, " &
    &"{\"Max\" :>12}, {\"Samples\" :>12}, {\"Test\" :>12}"

  if not validate:
    echo "Validation is turned off meaning that no BLS operations are performed"

  for t in Timers:
    echo fmtTime(timers[t].mean), fmtTime(timers[t].standardDeviationS),
      fmtTime(timers[t].min), fmtTime(timers[t].max), &"{timers[t].n :>12}, ",
      $t

proc printTimers*[Timers: enum](
    state: ForkedHashedBeaconState, attesters: RunningStat, validate: bool,
    timers: array[Timers, RunningStat]) =
  echo "Validators: ", getStateField(state, validators).len, ", epoch length: ", SLOTS_PER_EPOCH
  echo "Validators per attestation (mean): ", attesters.mean
  printTimers(validate, timers)
