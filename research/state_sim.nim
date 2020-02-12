# beacon_chain
# Copyright (c) 2019-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  confutils, stats, times, std/monotimes,
  strformat,
  options, sequtils, random, tables,
  ../tests/[testblockutil],
  ../beacon_chain/spec/[beaconstate, crypto, datatypes, digest, helpers, validator],
  ../beacon_chain/[attestation_pool, extras, ssz]

type Timers = enum
  tBlock = "Process non-epoch slot with block"
  tEpoch = "Process epoch slot with block"
  tHashBlock = "Tree-hash block"
  tShuffle = "Retrieve committee once using get_beacon_committee"
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

proc jsonName(prefix, slot: auto): string =
  fmt"{prefix:04}-{shortLog(slot):08}.json"

proc writeJson*(fn, v: auto) =
  var f: File
  defer: close(f)
  Json.saveFile(fn, v, pretty = true)

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
       validators = SLOTS_PER_EPOCH * 30, # One per shard is minimum
       json_interval = SLOTS_PER_EPOCH,
       write_last_json = false,
       prefix = 0,
       attesterRatio {.desc: "ratio of validators that attest in each round"} = 0.73,
       validate = true):
  echo "Preparing validators..."
  let
    flags = if validate: {} else: {skipValidation}
    deposits = makeInitialDeposits(validators, flags)

  echo "Generating Genesis..."

  let
    genesisState =
      initialize_beacon_state_from_eth1(
        Eth2Digest(), 0, deposits, {skipMerkleValidation})
    genesisBlock = get_initial_beacon_block(genesisState)

  echo "Starting simulation..."

  var
    attestations = initTable[Slot, seq[Attestation]]()
    state = genesisState
    latest_block_root = hash_tree_root(genesisBlock.message)
    timers: array[Timers, RunningStat]
    attesters: RunningStat
    r: Rand
    blck: SignedBeaconBlock
    cache = get_empty_per_epoch_cache()

  proc maybeWrite(last: bool) =
    if write_last_json:
      if state.slot mod json_interval.uint64 == 0:
        write(stdout, ":")
      else:
        write(stdout, ".")

      if last:
        writeJson("state.json", state)
    else:
      if state.slot mod json_interval.uint64 == 0:
        writeJson(jsonName(prefix, state.slot), state)
        write(stdout, ":")
      else:
        write(stdout, ".")

  # TODO doAssert against this up-front
  # indexed attestation: validator index beyond max validators per committee
  # len(indices) <= MAX_VALIDATORS_PER_COMMITTEE

  for i in 0..<slots:
    maybeWrite(false)
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
      hash_tree_root(blck.message)

    if attesterRatio > 0.0:
      # attesterRatio is the fraction of attesters that actually do their
      # work for every slot - we'll randomize it deterministically to give
      # some variation
      let
        target_slot = state.slot + MIN_ATTESTATION_INCLUSION_DELAY - 1
        scass = withTimerRet(timers[tShuffle]):
          mapIt(
            0'u64 ..< get_committee_count_at_slot(state, target_slot),
            get_beacon_committee(state, target_slot, it, cache))

      for i, scas in scass:
        var
          attestation: Attestation
          first = true

        attesters.push scas.len()

        withTimer(timers[tAttest]):
          for v in scas:
            if (rand(r, high(int)).float * attesterRatio).int <= high(int):
              if first:
                attestation =
                  makeAttestation(state, latest_block_root, scas, target_slot,
                    i.uint64, v, cache, flags)
                first = false
              else:
                attestation.combine(
                  makeAttestation(state, latest_block_root, scas, target_slot,
                    i.uint64, v, cache, flags),
                  flags)

        if not first:
          # add the attestation if any of the validators attested, as given
          # by the randomness. We have to delay when the attestation is
          # actually added to the block per the attestation delay rule!
          let target_slot =
            attestation.data.slot + MIN_ATTESTATION_INCLUSION_DELAY - 1

          doAssert target_slot > attestations_idx
          var target_slot_attestations =
            getOrDefault(attestations, target_slot)
          target_slot_attestations.add attestation
          attestations[target_slot] = target_slot_attestations

    flushFile(stdout)

    if (state.slot) mod SLOTS_PER_EPOCH == 0:
      echo &" slot: {shortLog(state.slot)} ",
        &"epoch: {shortLog(state.slot.compute_epoch_at_slot)}"


  maybeWrite(true) # catch that last state as well..

  echo "Done!"

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
