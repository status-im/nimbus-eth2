import
  confutils, stats, times,
  json, strformat,
  options, sequtils, random,
  ../tests/[testutil],
  ../beacon_chain/spec/[beaconstate, crypto, datatypes, digest, helpers, validator],
  ../beacon_chain/[attestation_pool, extras, ssz, state_transition, fork_choice]

proc `%`(v: uint64): JsonNode =
  if v > uint64(high(BiggestInt)): newJString($v) else: newJInt(BiggestInt(v))
proc `%`(v: Eth2Digest): JsonNode = newJString($v)
proc `%`(v: ValidatorSig|ValidatorPubKey): JsonNode = newJString($v)

type Timers = enum
  tBlock = "Process non-epoch slot with block"
  tEpoch = "Proces epoch slot with block"
  tHashBlock = "Tree-hash block"
  tShuffle = "Retrieve committe once using get_crosslink_committees_at_slot"
  tAttest = "Combine committee attestations"

template withTimer(stats: var RunningStat, body: untyped) =
  let start = cpuTime()

  block:
    body

  let stop = cpuTime()
  stats.push stop - start

template withTimerRet(stats: var RunningStat, body: untyped): untyped =
  let start = cpuTime()
  let tmp = block:
    body
  let stop = cpuTime()
  stats.push stop - start

  tmp

proc writeJson*(prefix, slot, v: auto) =
  var f: File
  defer: close(f)
  discard open(f, fmt"{prefix:04}-{humaneSlotNum(slot):08}.json", fmWrite)
  write(f, pretty(%*(v)))

cli do(slots = 1945,
       validators = SLOTS_PER_EPOCH, # One per shard is minimum
       json_interval = SLOTS_PER_EPOCH,
       prefix = 0,
       attesterRatio {.desc: "ratio of validators that attest in each round"} = 0.9,
       validate = false):
  let
    flags = if validate: {} else: {skipValidation}
    genesisState = get_genesis_beacon_state(
      makeInitialDeposits(validators, flags), 0, Eth1Data(), flags)
    genesisBlock = get_initial_beacon_block(genesisState)

  var
    attestations: array[MIN_ATTESTATION_INCLUSION_DELAY, seq[Attestation]]
    state = genesisState
    latest_block_root = hash_tree_root_final(genesisBlock)
    timers: array[Timers, RunningStat]
    attesters: RunningStat
    r: Rand
    blck: BeaconBlock

  proc maybeWrite() =
    if state.slot mod json_interval.uint64 == 0:
      writeJson(prefix, state.slot, state)
      write(stdout, ":")
    else:
      write(stdout, ".")

  for i in 0..<slots:
    maybeWrite()

    let
      attestations_idx = state.slot mod MIN_ATTESTATION_INCLUSION_DELAY
      body = BeaconBlockBody(attestations: attestations[attestations_idx])

    attestations[attestations_idx] = @[]

    let t =
      if (state.slot + 2.Slot) mod SLOTS_PER_EPOCH == 0: tEpoch
      else: tBlock

    withTimer(timers[t]):
      blck = addBlock(state, latest_block_root, body, flags)
    latest_block_root = withTimerRet(timers[tHashBlock]):
      hash_tree_root_final(blck)

    if attesterRatio > 0.0:
      # attesterRatio is the fraction of attesters that actually do their
      # work for every slot - we'll randomize it deterministically to give
      # some variation
      let scass = withTimerRet(timers[tShuffle]):
        get_crosslink_committees_at_slot(state, state.slot)

      for scas in scass:
        var
          attestation: Attestation
          first = true

        attesters.push scas.committee.len()

        withTimer(timers[tAttest]):
          for v in scas.committee:
            if (rand(r, high(int)).float * attesterRatio).int <= high(int):
              if first:
                attestation = makeAttestation(state, latest_block_root, v, flags)
                first = false
              else:
                attestation.combine(
                  makeAttestation(state, latest_block_root, v, flags), flags)

        if not first:
          # add the attestation if any of the validators attested, as given
          # by the randomness. We have to delay when the attestation is
          # actually added to the block per the attestation delay rule!
          attestations[
            (state.slot + MIN_ATTESTATION_INCLUSION_DELAY - 1) mod
              MIN_ATTESTATION_INCLUSION_DELAY].add attestation

    flushFile(stdout)

    if (state.slot) mod SLOTS_PER_EPOCH == 0:
      echo &" slot: {humaneSlotNum(state.slot)} ",
        &"epoch: {humaneEpochNum(state.slot.slot_to_epoch)}"

  maybeWrite() # catch that last state as well..

  echo "done!"

  echo "Validators: ", validators, ", epoch length: ", SLOTS_PER_EPOCH
  echo "Validators per attestation (mean): ", attesters.mean

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
