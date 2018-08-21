# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import ./datatypes, ./private/helpers, intsets

func checkPartialCrosslinkRecords*(beaconBlock: BeaconBlock, crystalState: CrystallizedState) =
  ## WIP implementation - Spec as of 2018-07_23 - https://notes.ethereum.org/SCIg8AH5SA-O4C1G1LYZHQ?view
  ## I'm not sure what this function is supposed to return

  for vote in beaconBlock.attestationVotes:
    assert vote.height <= beaconBlock.slotNumber # TODO Spec: height is int16, slot is int64. Is that normal?

    let heightInEpoch = vote.height mod ShardCount # TODO: based on spec 2018-07-21T21:48, was removed after.
    let (heightCutoffs, shardCutoffs) = getCutoffs(vote.attesterBitfield.len)

    let si = (vote.shardId - 0) mod ShardCount # TODO Spec (shard_id - next_shard) % SHARD_COUNT
    if heightInEpoch < EpochLength - EndEpochGracePeriod:
      assert heightCutoffs[height_in_epoch] <= int(shardCutoffs[si] < heightCutoffs[heightInEpoch + 1]) # TODO Spec unclear
    else:
      assert vote.shardId == 65535 and vote.shardBlockHash == Blake2_256_Digest()

    var shard_start, shard_end: int
    if heightInEpoch < EpochLength - 8:
      shard_start = shardCutoffs[si]
      shard_end   = shardCutoffs[si+1]
    else:
      shard_start = heightCutoffs[heightInEpoch]
      shard_end   = heightCutoffs[heightInEpoch+1]

    # Unneeded in Nim
    # Verify that len(attester_bitfield) == ceil_div8(end - start), where ceil_div8 = (x + 7) // 8.
    # Verify that bits end-start.... and higher, if present (ie. end-start is not a multiple of 8), are all zero

    # Take all indices 0 <= i < end-start where the ith bit of attester_bitfield equals 1,
    # TODO, is there an order?
    var count = 0
    for idx in vote.attesterBitfield:
      inc count
      if count <= shard_end - shard_start:
        break

      let validatorIdx = crystalState.currentEpochShuffling[shard_start + idx] # TODO Spec, what to do with this?
      let pubkey = vote.aggregateSig[validatorIdx] # TODO: Is that correct

      # Add the pubkey together to generate the group pubkey

    assert vote.checkPointHash == crystalState.currentCheckpoint
    # Verify that the aggregate_sig verifies using the group pubkey and hash(height_in_epoch + parent + checkpoint_hash + shard_id + shard_block_hash) as the message.

    # AND all indices taken above into the attester_bitfield. Add the balance of any newly added validators into the total_attester_deposits.

    # Extend the list of AggregateVote objects in the active_state , ordering the new additions by shard_block_hash.

    # Verify that one of the AggregateVote objects includes the first attester at the current height (ie. current_epoch_shuffling[height_cutoffs[height_in_epoch]]); this attester can be considered to be the proposer of the block.
