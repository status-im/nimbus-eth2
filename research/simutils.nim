import
  stats, os, strformat, times,
  ../tests/[testblockutil],
  ../beacon_chain/[extras],
  ../beacon_chain/ssz/[merkleization, ssz_serialization],
  ../beacon_chain/spec/[beaconstate, datatypes, digest, helpers]

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

func verifyConsensus*(state: BeaconState, attesterRatio: auto) =
  if attesterRatio < 0.63:
    doAssert state.current_justified_checkpoint.epoch == 0
    doAssert state.finalized_checkpoint.epoch == 0

  # Quorum is 2/3 of validators, and at low numbers, quantization effects
  # can dominate, so allow for play above/below attesterRatio of 2/3.
  if attesterRatio < 0.72:
    return

  let current_epoch = get_current_epoch(state)
  if current_epoch >= 3:
    doAssert state.current_justified_checkpoint.epoch + 1 >= current_epoch
  if current_epoch >= 4:
    doAssert state.finalized_checkpoint.epoch + 2 >= current_epoch

proc loadGenesis*(validators: int, validate: bool): ref HashedBeaconState =
  let fn = &"genesim_{const_preset}_{validators}.ssz"
  let res = (ref HashedBeaconState)()
  if fileExists(fn):
    res.data = SSZ.loadFile(fn, BeaconState)
    res.root = hash_tree_root(res.data)
    if res.data.slot != GENESIS_SLOT:
      echo "Can only start from genesis state"
      quit 1

    if res.data.validators.len != validators:
      echo &"Supplied genesis file has {res.data.validators.len} validators, while {validators} where requested, running anyway"

    echo &"Loaded {fn}..."
    # TODO check that the private keys are interop keys
    res
  else:
    echo "Genesis file not found, making one up (use beacon_node createTestnet to make one)"

    echo "Preparing validators..."
    let
      flags = if validate: {} else: {skipBlsValidation}
      deposits = makeInitialDeposits(validators, flags)

    echo "Generating Genesis..."

    res.data =
      initialize_beacon_state_from_eth1(Eth2Digest(), 0, deposits, flags)[]
    res.root = hash_tree_root(res.data)

    echo &"Saving to {fn}..."
    SSZ.saveFile(fn, res.data)
    res

proc printTimers*[Timers: enum](
  validate: bool,
  timers: array[Timers, RunningStat]
) =
  proc fmtTime(t: float): string = &"{t * 1000 :>12.3f}, "

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
    state: BeaconState, attesters: RunningStat, validate: bool,
    timers: array[Timers, RunningStat]) =
  echo "Validators: ", state.validators.len, ", epoch length: ", SLOTS_PER_EPOCH
  echo "Validators per attestation (mean): ", attesters.mean
  printTimers(validate, timers)
