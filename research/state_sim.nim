# beacon_chain
# Copyright (c) 2019-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# `state_sim` runs the state transition function in isolation, creating blocks
# and attesting to them as if the network was running as a whole.

import
  std/[stats, times, strformat, random, tables],
  confutils,
  ../tests/testblockutil,
  ../beacon_chain/spec/datatypes/phase0,
  ../beacon_chain/spec/eth2_apis/eth2_rest_serialization,
  ../beacon_chain/spec/[beaconstate, forks, helpers, signatures],
  ./simutils

type Timers = enum
  tBlock = "Process non-epoch slot with block"
  tEpoch = "Process epoch slot with block"
  tHashBlock = "Tree-hash block"
  tAttest = "Combine committee attestations"

func jsonName(prefix, slot: auto): string =
  fmt"{prefix:04}-{shortLog(slot):08}.json"

proc writeJson*(fn, v: auto) =
  var f: File
  defer: close(f)
  RestJson.saveFile(fn, v, pretty = true)

cli do(slots = SLOTS_PER_EPOCH * 5,
       validators = SLOTS_PER_EPOCH * 400, # One per shard is minimum
       json_interval = SLOTS_PER_EPOCH,
       write_last_json = false,
       prefix: int = 0,
       attesterRatio {.desc: "ratio of validators that attest in each round"} = 0.82,
       validate = true):
  let
    flags = if validate: {} else: {skipBlsValidation}
    (state, _) = loadGenesis(validators, validate)
    genesisBlock = get_initial_beacon_block(state[])
    genesis_validators_root = getStateField(state[], genesis_validators_root)

  echo "Starting simulation..."

  var
    attestations = initTable[Slot, seq[Attestation]]()
    latest_block_root = withBlck(genesisBlock): blck.root
    timers: array[Timers, RunningStat]
    attesters: RunningStat
    r = initRand(1)
    signedBlock: ForkedSignedBeaconBlock
    cache = StateCache()

  proc maybeWrite(last: bool) =
    if write_last_json:
      if getStateField(state[], slot) mod json_interval.uint64 == 0:
        write(stdout, ":")
      else:
        write(stdout, ".")

      if last:
        withState(state[]): writeJson("state.json", forkyState.data)
    else:
      withState(state[]):
        if forkyState.data.slot mod json_interval.uint64 == 0:
          writeJson(jsonName(prefix, forkyState.data.slot), forkyState.data)
          write(stdout, ":")
        else:
          write(stdout, ".")

  # TODO doAssert against this up-front
  # indexed attestation: validator index beyond max validators per committee
  # len(indices) <= MAX_VALIDATORS_PER_COMMITTEE

  for i in 0..<slots:
    maybeWrite(false)
    verifyConsensus(state[].phase0Data.data, attesterRatio)

    let
      attestations_idx = getStateField(state[], slot)
      blockAttestations = attestations.getOrDefault(attestations_idx)

    attestations.del attestations_idx
    doAssert attestations.lenu64 <=
      SLOTS_PER_EPOCH + MIN_ATTESTATION_INCLUSION_DELAY

    let t =
      if (getStateField(state[], slot) > GENESIS_SLOT and
        (getStateField(state[], slot) + 1).is_epoch): tEpoch
      else: tBlock

    withTimer(timers[t]):
      signedBlock = addTestBlock(
        state[], cache, attestations = blockAttestations,
        flags = flags)
    latest_block_root = withTimerRet(timers[tHashBlock]):
      withBlck(signedBlock): hash_tree_root(blck.message)

    if attesterRatio > 0.0:
      # attesterRatio is the fraction of attesters that actually do their
      # work for every slot - we'll randomize it deterministically to give
      # some variation

      withState(state[]):
        let
          slot = forkyState.data.slot
          epoch = slot.epoch
          committees_per_slot =
            get_committee_count_per_slot(forkyState.data, epoch, cache)
        for committee_index in get_committee_indices(committees_per_slot):
          let committee = get_beacon_committee(
            forkyState.data, slot, committee_index, cache)
          var
            attestation = Attestation(
              aggregation_bits: CommitteeValidatorsBits.init(committee.len),
              data: makeAttestationData(
                forkyState.data, slot, committee_index, latest_block_root),
            )
            first = true

          attesters.push committee.len()

          withTimer(timers[tAttest]):
            for index_in_committee, validator_index in committee:
              if (rand(r, high(int)).float * attesterRatio).int <= high(int):
                attestation.aggregation_bits.setBit index_in_committee

            if not attestation.aggregation_bits.isZeros:
              if validate:
                attestation.signature = makeAttestationSig(
                  forkyState.data.fork, genesis_validators_root,
                  attestation.data, committee, attestation.aggregation_bits)

              # add the attestation if any of the validators attested, as given
              # by the randomness. We have to delay when the attestation is
              # actually added to the block per the attestation delay rule!
              let
                target_slot = slot + MIN_ATTESTATION_INCLUSION_DELAY - 1
              attestations.mgetOrPut(target_slot, default(seq[Attestation])).add(
                attestation)

    flushFile(stdout)

    if getStateField(state[], slot).is_epoch:
      echo &" slot: {shortLog(getStateField(state[], slot))} ",
        &"epoch: {shortLog(state[].get_current_epoch())}"


  maybeWrite(true) # catch that last state as well..

  echo "Done!"

  printTimers(state[], attesters, true, timers)
