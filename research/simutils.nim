# beacon_chain
# Copyright (c) 2020-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  stew/io2,
  ../tests/testblockutil, ../tests/consensus_spec/os_ops,
  ../beacon_chain/spec/[beaconstate, forks]

from std/stats import RunningStat, mean, push, standardDeviationS
from std/strformat import `&`
from std/times import cpuTime
from ../beacon_chain/filepath import secureCreatePath
from ../beacon_chain/spec/deposit_snapshots import DepositContractSnapshot

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
  cfg.DENEB_FORK_EPOCH = 1.Epoch
  debugRaiseAssert "set ELECTRA_FORK_EPOCH to 3.Epoch"
  cfg.ELECTRA_FORK_EPOCH = FAR_FUTURE_EPOCH
  cfg

proc loadGenesis*(
    validators: Natural,
    validate: bool): (ref ForkedHashedBeaconState, DepositContractSnapshot) =
  const genesisDir = "test_sim"
  if (let res = secureCreatePath(genesisDir); res.isErr):
    fatal "Could not create directory",
      path = genesisDir, err = ioErrorMsg(res.error)
    quit 1

  let
    suffix = const_preset & "_" & $validators & "_" & SPEC_VERSION
    genesisFn = genesisDir /
      "genesis_" & suffix & ".ssz"
    contractSnapshotFn = genesisDir /
      "deposit_contract_snapshot_" & suffix & ".ssz"
  const cfg = getSimulationConfig()

  if fileExists(genesisFn) and fileExists(contractSnapshotFn):
    let res =
      try:
        newClone(readSszForkedHashedBeaconState(
          cfg, readAllBytes(genesisFn).tryGet()))
      except ResultError[IoErrorCode] as exc:
        fatal "Genesis file failed to load",
          fileName = genesisFn, exc = exc.msg
        quit 1
      except SerializationError as exc:
        fatal "Genesis file malformed",
          fileName = genesisFn, exc = exc.msg
        quit 1

    withState(res[]):
      if forkyState.data.slot != GENESIS_SLOT:
        fatal "Can only start from genesis state"
        quit 1

      if forkyState.data.validators.len != validators:
        fatal "Supplied genesis file has unexpected number of validators",
          numExpectedValidators = validators,
          numActualValidators = forkyState.data.validators.len
        quit 1

      info "Loaded genesis file", fileName = genesisFn

      # TODO check that the private keys are EF test keys

      let contractSnapshot =
        try:
          SSZ.loadFile(contractSnapshotFn, DepositContractSnapshot)
        except IOError as exc:
          fatal "Deposit contract snapshot failed to load",
            fileName = contractSnapshotFn, exc = exc.msg
          quit 1
        except SerializationError as exc:
          fatal "Deposit contract snapshot malformed",
            fileName = contractSnapshotFn, exc = exc.msg
          quit 1
      (res, contractSnapshot)
  else:
    warn "Genesis file not found, making one up",
      hint = "use nimbus_beacon_node createTestnet to make one"

    info "Preparing validators..."
    let
      flags = if validate: {} else: {skipBlsValidation}
      deposits = makeInitialDeposits(validators.uint64, flags)

    info "Generating Genesis..."
    var merkleizer = init DepositsMerkleizer
    for d in deposits:
      merkleizer.addChunk hash_tree_root(d).data
    let contractSnapshot = DepositContractSnapshot(
      depositContractState: merkleizer.toDepositContractState)

    let res = (ref ForkedHashedBeaconState)(
      kind: ConsensusFork.Capella,
      capellaData: capella.HashedBeaconState(
        data: initialize_beacon_state_from_eth1(
          cfg, ZERO_HASH, 0, deposits,
          default(capella.ExecutionPayloadHeader), {skipBlsValidation})))

    info "Saving genesis file", fileName = genesisFn
    try:
      SSZ.saveFile(genesisFn, res.capellaData.data)
    except IOError as exc:
      fatal "Genesis file failed to save",
        fileName = genesisFn, exc = exc.msg
      quit 1
    info "Saving deposit contract snapshot", fileName = contractSnapshotFn
    try:
      SSZ.saveFile(contractSnapshotFn, contractSnapshot)
    except IOError as exc:
      fatal "Deposit contract snapshot failed to save",
        fileName = contractSnapshotFn, exc = exc.msg
      quit 1

    (res, contractSnapshot)

proc printTimers*[Timers: enum](
    validate: bool,
    timers: array[Timers, RunningStat]) =
  func fmtTime(t: float): string =
    try:
      &"{t * 1000 :>12.3f}, "
    except ValueError as exc:
      raiseAssert "formatValue failed unexpectedly: " & $exc.msg

  try:
    echo "All time are ms"
    echo &"{\"Average\" :>12}, {\"StdDev\" :>12}, {\"Min\" :>12}, " &
      &"{\"Max\" :>12}, {\"Samples\" :>12}, {\"Test\" :>12}"

    if not validate:
      echo "Validation is turned off; no BLS operations are performed"

    for t in Timers:
      echo fmtTime(timers[t].mean), fmtTime(timers[t].standardDeviationS),
        fmtTime(timers[t].min), fmtTime(timers[t].max), &"{timers[t].n :>12}, ",
        $t
  except ValueError as exc:
    raiseAssert "formatValue failed unexpectedly: " & $exc.msg

proc printTimers*[Timers: enum](
    state: ForkedHashedBeaconState, attesters: RunningStat, validate: bool,
    timers: array[Timers, RunningStat]) =
  echo "Validators: ", getStateField(state, validators).len,
    ", epoch length: ", SLOTS_PER_EPOCH
  echo "Validators per attestation (mean): ", attesters.mean
  printTimers(validate, timers)