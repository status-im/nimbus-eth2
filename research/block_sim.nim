# beacon_chain
# Copyright (c) 2019-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# `block_sim` is a block and attestation simulator similar to `state_sim` whose
# task is to run the beacon chain without considering the network or the
# wall clock. Functionally, it achieves the same as the distributed beacon chain
# by producing blocks and attestations as if they were created by separate
# nodes, just like a set of `beacon_node` instances would.
#
# Similar to `state_sim`, but uses the block and attestation pools along with
# a database, as if a real node was running.

import
  confutils, chronicles, stats, times,
  strformat,
  options, random, tables,
  ../tests/[testblockutil],
  ../beacon_chain/spec/[
    beaconstate, crypto, datatypes, digest, helpers, validator,
    state_transition_block],
  ../beacon_chain/[
    attestation_pool, block_pool, beacon_node_types, beacon_chain_db,
    interop, ssz, validator_pool],
  eth/db/[kvstore, kvstore_sqlite3],
  ./simutils

type Timers = enum
  tBlock = "Process non-epoch slot with block"
  tEpoch = "Process epoch slot with block"
  tHashBlock = "Tree-hash block"
  tSignBlock = "Sign block"
  tShuffle = "Retrieve committee once using get_beacon_committee"
  tAttest = "Combine committee attestations"

# TODO confutils is an impenetrable black box. how can a help text be added here?
cli do(slots = SLOTS_PER_EPOCH * 6,
       validators = SLOTS_PER_EPOCH * 100, # One per shard is minimum
       attesterRatio {.desc: "ratio of validators that attest in each round"} = 0.73):
  let
    state = loadGenesis(validators, true)
    genesisBlock = get_initial_beacon_block(state[])

  echo "Starting simulation..."

  let
    db = BeaconChainDB.init(kvStore SqStoreRef.init(".", "block_sim").tryGet())

  BlockPool.preInit(db, state[], genesisBlock)

  var
    blockPool = BlockPool.init(db)
    attPool = AttestationPool.init(blockPool)
    timers: array[Timers, RunningStat]
    attesters: RunningStat
    r: Rand

  proc handleAttestations() =
    let
      slot = blockPool.head.blck.slot
      attestationHead = blockPool.head.blck.atSlot(slot)

    blockPool.withState(blockPool.tmpState, attestationHead):
      var cache = get_empty_per_epoch_cache()
      let committees_per_slot = get_committee_count_at_slot(state, slot)

      for committee_index in 0'u64..<committees_per_slot:
        let committee = get_beacon_committee(
          state, slot, committee_index.CommitteeIndex, cache)

        for index_in_committee, validatorIdx in committee:
          if (rand(r, high(int)).float * attesterRatio).int <= high(int):
            let
              data = makeAttestationData(state, slot, committee_index, blck.root)
              sig =
                get_attestation_signature(state.fork,
                  state.genesis_validators_root,
                  data, hackPrivKey(state.validators[validatorIdx]))
            var aggregation_bits = CommitteeValidatorsBits.init(committee.len)
            aggregation_bits.setBit index_in_committee

            attPool.add(
              Attestation(
                data: data,
                aggregation_bits: aggregation_bits,
                signature: sig
              ))

  proc proposeBlock() =
    let
      head = blockPool.head.blck
      slot = blockPool.head.blck.slot + 1

    blockPool.withState(blockPool.tmpState, head.atSlot(slot)):
      var cache = get_empty_per_epoch_cache()

      let
        proposerIdx = get_beacon_proposer_index(state, cache).get()
        privKey = hackPrivKey(state.validators[proposerIdx])
        eth1data = get_eth1data_stub(
          state.eth1_deposit_index, slot.compute_epoch_at_slot())
        message = makeBeaconBlock(
          state,
          head.root,
          privKey.genRandaoReveal(state.fork, state.genesis_validators_root, slot),
          eth1data,
          Eth2Digest(),
          attPool.getAttestationsForBlock(state),
          @[])

      var
        newBlock = SignedBeaconBlock(
          message: message.get()
        )

      let blockRoot = withTimerRet(timers[tHashBlock]):
        hash_tree_root(newBlock.message)

      # Careful, state no longer valid after here because of the await..
      newBlock.signature = withTimerRet(timers[tSignBlock]):
        get_block_signature(
          state.fork, state.genesis_validators_root, newBlock.message.slot,
          blockRoot, privKey)

      let added = blockPool.add(blockRoot, newBlock)
      blockPool.updateHead(added)

  for i in 0..<slots:
    let
      slot = blockPool.headState.data.data.slot + 1
      t =
        if slot mod SLOTS_PER_EPOCH == 0: tEpoch
        else: tBlock

    withTimer(timers[t]):
      proposeBlock()
    if attesterRatio > 0.0:
      withTimer(timers[tAttest]):
        handleAttestations()

    verifyConsensus(blockPool.headState.data.data, attesterRatio)

    if t == tEpoch:
      echo &". slot: {shortLog(slot)} ",
        &"epoch: {shortLog(slot.compute_epoch_at_slot)}"
    else:
      write(stdout, ".")
      flushFile(stdout)

  echo "Done!"

  printTimers(blockPool.headState.data.data, attesters, true, timers)
