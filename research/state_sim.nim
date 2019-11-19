import
  confutils, stats, times,
  strformat,
  options, sequtils, random, tables,
  ../tests/[testutil],
  ../beacon_chain/spec/[beaconstate, crypto, datatypes, digest, helpers, validator],
  ../beacon_chain/[attestation_pool, extras, ssz]

type Timers = enum
  tBlock = "Process non-epoch slot with block"
  tEpoch = "Process epoch slot with block"
  tHashBlock = "Tree-hash block"
  tShuffle = "Retrieve committee once using get_crosslink_committee"
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
  let fileName = fmt"{prefix:04}-{shortLog(slot):08}.json"
  Json.saveFile(fileName, v, pretty = true)

func verifyConsensus(state: BeaconState, attesterRatio: auto) =
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

cli do(slots = SLOTS_PER_EPOCH * 6,
       validators = SLOTS_PER_EPOCH * 11, # One per shard is minimum
       json_interval = SLOTS_PER_EPOCH,
       prefix = 0,
       attesterRatio {.desc: "ratio of validators that attest in each round"} = 0.75,
       validate = true):
  let
    flags = if validate: {} else: {skipValidation}
    genesisState = initialize_beacon_state_from_eth1(
      Eth2Digest(), 0,
      makeInitialDeposits(validators, flags), flags)
    genesisBlock = get_initial_beacon_block(genesisState)

  var
    attestations = initTable[Slot, seq[Attestation]]()
    state = genesisState
    latest_block_root = signing_root(genesisBlock)
    timers: array[Timers, RunningStat]
    attesters: RunningStat
    r: Rand
    blck: BeaconBlock
    cache = get_empty_per_epoch_cache()

  proc maybeWrite() =
    if state.slot mod json_interval.uint64 == 0:
      writeJson(prefix, state.slot, state)
      write(stdout, ":")
    else:
      write(stdout, ".")

  for i in 0..<slots:
    maybeWrite()
    verifyConsensus(state, attesterRatio)

    let
      attestations_idx = state.slot
      body = BeaconBlockBody(
        attestations: attestations.getOrDefault(attestations_idx))

    attestations.del attestations_idx
    doAssert len(attestations) <=
      (SLOTS_PER_EPOCH.int + MIN_ATTESTATION_INCLUSION_DELAY.int)

    let t =
      if (state.slot > GENESIS_SLOT and
        (state.slot + 1) mod SLOTS_PER_EPOCH == 0): tEpoch
      else: tBlock

    withTimer(timers[t]):
      blck = addBlock(state, latest_block_root, body, flags)
    latest_block_root = withTimerRet(timers[tHashBlock]):
      signing_root(blck)

    if attesterRatio > 0.0:
      # attesterRatio is the fraction of attesters that actually do their
      # work for every slot - we'll randomize it deterministically to give
      # some variation
      let
        epoch = compute_epoch_at_slot(state.slot)
        scass = withTimerRet(timers[tShuffle]):
          mapIt(
            0'u64 .. (get_committee_count_at_slot(state, state.slot) *
              SLOTS_PER_EPOCH - 1),
            get_beacon_committee(state, epoch.compute_start_slot_at_epoch + (it mod SLOTS_PER_EPOCH),
              it div SLOTS_PER_EPOCH, cache))

      for scas in scass:
        var
          attestation: Attestation
          first = true

        attesters.push scas.len()

        withTimer(timers[tAttest]):
          for v in scas:
            if (rand(r, high(int)).float * attesterRatio).int <= high(int):
              if first:
                attestation =
                  makeAttestation(state, latest_block_root, v, cache, flags)
                first = false
              else:
                attestation.combine(
                  makeAttestation(state, latest_block_root, v, cache, flags),
                  flags)

        if not first:
          # add the attestation if any of the validators attested, as given
          # by the randomness. We have to delay when the attestation is
          # actually added to the block per the attestation delay rule!
          let target_slot =
            attestation.data.slot + MIN_ATTESTATION_INCLUSION_DELAY - 1

          ## In principle, should enumerate possible shard/slot combinations by
          ## inverting get_attestation_data_slot(...), but this works. Could be
          ## filtering earlier if we know that this attestation's being created
          ## too late to be useful, as well.
          if target_slot > attestations_idx:
            var target_slot_attestations =
              getOrDefault(attestations, target_slot)
            target_slot_attestations.add attestation
            attestations[target_slot] = target_slot_attestations

    flushFile(stdout)

    if (state.slot) mod SLOTS_PER_EPOCH == 0:
      echo &" slot: {shortLog(state.slot)} ",
        &"epoch: {shortLog(state.slot.compute_epoch_at_slot)}"

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
