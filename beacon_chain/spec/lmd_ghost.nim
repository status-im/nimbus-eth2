# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# This file contains the implementation of the beacon chain fork choice rule.
# The chosen rule is a hybrid that combines justification and finality
# with Latest Message Driven (LMD) Greediest Heaviest Observed SubTree (GHOST)
#
# The latest version can be seen here:
# https://github.com/ethereum/eth2.0-specs/blob/master/specs/beacon-chain.md
#
# How wrong the code is:
# https://github.com/ethereum/eth2.0-specs/compare/126a7abfa86448091a0e037f52966b6a9531a857...master
#

# A standalone research implementation can be found here:
#   - https://github.com/ethereum/research/blob/94ac4e2100a808a7097715003d8ad1964df4dbd9/clock_disparity/lmd_node.py
# A minispec in mathematical notation including proofs can be found here:
#   - https://ethresear.ch/t/beacon-chain-casper-ffg-rpj-mini-spec/2760
# Note that it might be out-of-sync with the official spec.

import
  tables, hashes,
  milagro_crypto,
  ./datatypes, ./helpers, ./digest,
  ../ssz

type
  AttesterIdx = int
  BlockHash = Eth2Digest

  Store = object
    # This is private to each validator.
    # It holds the set of attestations and blocks that a validator
    # has observed and verified.
    #
    # We uniquely identify each block via it's block hash
    # and each attester via it's attester index (from AttestationRecord object)
    # TODO/Question: Should we use the public key? That would defeat the pubkey aggregation purpose

    verified_attestations: Table[AttesterIdx, ref seq[AttestationData]]
      # TODO: We assume that ref seq[AttestationData] is queue, ordered by
      #       a pair (slot, observation time).
    verified_blocks: Table[BlockHash, BeaconBlock]
    finalized_head: BeaconBlock
    justified_head: BeaconBlock

func hash(x: BlockHash): Hash =
  ## Hash for Keccak digests for Nim hash tables
  # We just slice the first 4 or 8 bytes of the block hash
  # depending of if we are on a 32 or 64-bit platform
  const size = x.sizeof
  const num_hashes = size div sizeof(int)
  result = cast[array[num_hashes, Hash]](x)[0]

func get_parent(store: Store, blck: BeaconBlock): BeaconBlock =
  store.verified_blocks[blck.parent_root]

func get_ancestor(store: Store, blck: BeaconBlock, slot: uint64): BeaconBlock =
  ## Find the ancestor with a specific slot number
  if blck.slot == slot:
    return blck
  else:
    return store.get_ancestor(store.get_parent(blck), slot)
  # TODO: what if the slot was never observed/verified?

func get_latest_attestation(store: Store, validatorIdx: AttesterIdx): AttestationData =
  ## Search for the attestation with the highest slot number
  ## If multiple attestation have the same slot number, keep the first one.

  # We assume that in `verified_attestations: Table[AttesterIdx, seq[AttestationData]]`
  # `seq[AttestationSignedData]` is a queue ordered by (slot, observation time)

  let attestations = store.verified_attestations[validatorIdx]
  result = attestations[^1]                        # Pick the last attestation
  for idx in countdown(attestations[].len - 2, 0): # From the second to last attestation to 0, check if they have the same slot.
    if attestations[idx].slot == result.slot:      # if yes it was observed earlier
      result = attestations[idx]
    else:                                          # otherwise we are at the first observed attestation with the highest slot
      return

func get_latest_attestation_target(store: Store, validatorIdx: AttesterIdx): BlockHash =
  store.get_latest_attestation(validatorIdx).beacon_block_root
