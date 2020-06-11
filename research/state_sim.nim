# beacon_chain
# Copyright (c) 2019-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# `state_sim` runs the state transition function in isolation, creating blocks
# and attesting to them as if the network was running as a whole.

import
  confutils, stats, times,
  strformat,
  options, sequtils, random, tables,
  ../tests/[testblockutil],
  ../beacon_chain/spec/[beaconstate, crypto, datatypes, digest, helpers, validator],
  ../beacon_chain/[attestation_pool, extras],
  ../beacon_chain/ssz/[merkleization, ssz_serialization],
  ./simutils

type Timers = enum
  tBlock = "Process non-epoch slot with block"
  tEpoch = "Process epoch slot with block"
  tHashBlock = "Tree-hash block"
  tShuffle = "Retrieve committee once using get_beacon_committee"
  tAttest = "Combine committee attestations"

proc jsonName(prefix, slot: auto): string =
  fmt"{prefix:04}-{shortLog(slot):08}.json"

proc writeJson*(fn, v: auto) =
  var f: File
  defer: close(f)
  Json.saveFile(fn, v, pretty = true)

cli do(slots = SLOTS_PER_EPOCH * 6,
       validators = SLOTS_PER_EPOCH * 100, # One per shard is minimum
       json_interval = SLOTS_PER_EPOCH,
       write_last_json = false,
       prefix = 0,
       attesterRatio {.desc: "ratio of validators that attest in each round"} = 0.73,
       validate = true):
  let
    flags = if validate: {} else: {skipBlsValidation}
    state = loadGenesis(validators, validate)
    genesisBlock = get_initial_beacon_block(state.data)

  echo "Starting simulation..."

  var
    attestations = initTable[Slot, seq[Attestation]]()
    latest_block_root = hash_tree_root(genesisBlock.message)
    timers: array[Timers, RunningStat]
    attesters: RunningStat
    r = initRand(1)
    signedBlock: SignedBeaconBlock
    cache = get_empty_per_epoch_cache()

  proc maybeWrite(last: bool) =
    if write_last_json:
      if state[].data.slot mod json_interval.uint64 == 0:
        write(stdout, ":")
      else:
        write(stdout, ".")

      if last:
        writeJson("state.json", state[])
    else:
      if state[].data.slot mod json_interval.uint64 == 0:
        writeJson(jsonName(prefix, state[].data.slot), state[].data)
        write(stdout, ":")
      else:
        write(stdout, ".")

  # TODO doAssert against this up-front
  # indexed attestation: validator index beyond max validators per committee
  # len(indices) <= MAX_VALIDATORS_PER_COMMITTEE

  for i in 0..<slots:
    maybeWrite(false)
    verifyConsensus(state[].data, attesterRatio)

    let
      attestations_idx = state[].data.slot
      blockAttestations = attestations.getOrDefault(attestations_idx)

    attestations.del attestations_idx
    doAssert len(attestations) <=
      (SLOTS_PER_EPOCH.int + MIN_ATTESTATION_INCLUSION_DELAY.int)

    let t =
      if (state[].data.slot > GENESIS_SLOT and
        (state[].data.slot + 1).isEpoch): tEpoch
      else: tBlock

    withTimer(timers[t]):
      signedBlock = addTestBlock(
        state[], latest_block_root, cache, attestations = blockAttestations,
        flags = flags)
    latest_block_root = withTimerRet(timers[tHashBlock]):
      hash_tree_root(signedBlock.message)

    if attesterRatio > 0.0:
      # attesterRatio is the fraction of attesters that actually do their
      # work for every slot - we'll randomize it deterministically to give
      # some variation
      let
        target_slot = state[].data.slot + MIN_ATTESTATION_INCLUSION_DELAY - 1
        scass = withTimerRet(timers[tShuffle]):
          mapIt(
            0'u64 ..< get_committee_count_at_slot(state[].data, target_slot),
            get_beacon_committee(state[].data, target_slot, it.CommitteeIndex, cache))

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
                  makeAttestation(state[].data, latest_block_root, scas, target_slot,
                    i.uint64, v, cache, flags)
                first = false
              else:
                attestation.combine(
                  makeAttestation(state[].data, latest_block_root, scas, target_slot,
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

    if (state[].data.slot) mod SLOTS_PER_EPOCH == 0:
      echo &" slot: {shortLog(state[].data.slot)} ",
        &"epoch: {shortLog(state[].data.slot.compute_epoch_at_slot)}"


  maybeWrite(true) # catch that last state as well..

  echo "Done!"

  printTimers(state[].data, attesters, validate, timers)
