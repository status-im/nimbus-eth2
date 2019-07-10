import
  confutils, stats, times,
  json, strformat,
  options, sequtils, random, tables,
  ../tests/[testutil],
  ../beacon_chain/spec/[beaconstate, crypto, datatypes, digest, helpers, validator],
  ../beacon_chain/[attestation_pool, extras, ssz, state_transition, fork_choice]

proc `%`(v: uint64): JsonNode =
  if v > uint64(high(BiggestInt)): newJString($v) else: newJInt(BiggestInt(v))
proc `%`(v: Eth2Digest): JsonNode = newJString($v)
proc `%`(v: ValidatorSig|ValidatorPubKey): JsonNode = newJString($v)

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

proc `%`*(x: Slot): JsonNode {.borrow.}
proc `%`*(x: Epoch): JsonNode {.borrow.}

proc writeJson*(prefix, slot, v: auto) =
  var f: File
  defer: close(f)
  discard open(f, fmt"{prefix:04}-{humaneSlotNum(slot):08}.json", fmWrite)
  write(f, pretty(%*(v)))

cli do(slots = 448,
       validators = SLOTS_PER_EPOCH * 9, # One per shard is minimum
       json_interval = SLOTS_PER_EPOCH,
       prefix = 0,
       attesterRatio {.desc: "ratio of validators that attest in each round"} = 0.9,
       validate = true):
  let
    flags = if validate: {} else: {skipValidation}
    genesisState = initialize_beacon_state_from_eth1(
      makeInitialDeposits(validators, flags), 0, Eth1Data(), flags)
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
        epoch = compute_epoch_of_slot(state.slot)
        scass = withTimerRet(timers[tShuffle]):
          mapIt(
            0'u64 .. (get_committee_count(state, epoch) - 1),
            get_crosslink_committee(state, epoch,
              (it + get_start_shard(state, epoch)) mod SHARD_COUNT,
              cache))

      for scas in scass:
        var
          attestation: Attestation
          first = true

        attesters.push scas.len()

        withTimer(timers[tAttest]):
          for v in scas:
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
          let target_slot =
            get_attestation_data_slot(state, attestation.data) +
            MIN_ATTESTATION_INCLUSION_DELAY - 1

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
      echo &" slot: {humaneSlotNum(state.slot)} ",
        &"epoch: {humaneEpochNum(state.slot.compute_epoch_of_slot)}"

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
