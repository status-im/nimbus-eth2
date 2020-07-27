# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/[algorithm, sequtils, sets],
  extras, beacon_chain_db,
  stew/results,
  spec/[beaconstate, crypto, datatypes, digest, presets, validator],
  block_pools/[block_pools_types, clearance, candidate_chains, quarantine]

export results, block_pools_types

# Block_Pools
# --------------------------------------------
#
# Compatibility shims to minimize PR breakage
# during block_pool refactor

type
  BlockPool* = object
    quarantine: Quarantine
    dag*: CandidateChains

{.push raises: [Defect], inline.}

# Quarantine dispatch
# --------------------------------------------

func checkMissing*(pool: var BlockPool): seq[FetchRecord] =
  checkMissing(pool.quarantine)

# CandidateChains
# --------------------------------------------

template tail*(pool: BlockPool): BlockRef =
  pool.dag.tail

template heads*(pool: BlockPool): seq[Head] =
  pool.dag.heads

template head*(pool: BlockPool): Head =
  pool.dag.head

template finalizedHead*(pool: BlockPool): BlockSlot =
  pool.dag.finalizedHead

proc addRawBlock*(pool: var BlockPool, signedBlock: SignedBeaconBlock,
          onBlockAdded: OnBlockAdded
        ): Result[BlockRef, BlockError] =
  ## Add a raw block to the blockpool
  ## Trigger "callback" on success
  ## Adding a rawblock might unlock a consequent amount of blocks in quarantine
  # TODO: `addRawBlock` is accumulating significant cruft
  # and is in dire need of refactoring
  # - the ugly `inAdd` field
  # - the callback
  # - callback may be problematic as it's called in async validator duties
  result = addRawBlock(pool.dag, pool.quarantine, signedBlock, onBlockAdded)

export parent        # func parent*(bs: BlockSlot): BlockSlot
export isAncestorOf  # func isAncestorOf*(a, b: BlockRef): bool
export getAncestorAt # func isAncestorOf*(a, b: BlockRef): bool
export get_ancestor  # func get_ancestor*(blck: BlockRef, slot: Slot): BlockRef
export atSlot        # func atSlot*(blck: BlockRef, slot: Slot): BlockSlot


proc init*(T: type BlockPool,
           preset: RuntimePreset,
           db: BeaconChainDB,
           updateFlags: UpdateFlags = {}): BlockPool =
  result.dag = init(CandidateChains, preset, db, updateFlags)

func addFlags*(pool: BlockPool, flags: UpdateFlags) =
  ## Add a flag to the block processing
  ## This is destined for testing to add skipBLSValidation flag
  pool.dag.updateFlags.incl flags

export init          # func init*(T: type BlockRef, root: Eth2Digest, blck: BeaconBlock): BlockRef
export addFlags

func getRef*(pool: BlockPool, root: Eth2Digest): BlockRef =
  ## Retrieve a resolved block reference, if available
  pool.dag.getRef(root)

func getBlockRange*(
    pool: BlockPool, startSlot: Slot, skipStep: Natural,
    output: var openArray[BlockRef]): Natural =
  ## This function populates an `output` buffer of blocks
  ## with a slots ranging from `startSlot` up to, but not including,
  ## `startSlot + skipStep * output.len`, skipping any slots that don't have
  ## a block.
  ##
  ## Blocks will be written to `output` from the end without gaps, even if
  ## a block is missing in a particular slot. The return value shows how
  ## many slots were missing blocks - to iterate over the result, start
  ## at this index.
  ##
  ## If there were no blocks in the range, `output.len` will be returned.
  pool.dag.getBlockRange(startSlot, skipStep, output)

func getBlockBySlot*(pool: BlockPool, slot: Slot): BlockRef =
  ## Retrieves the first block in the current canonical chain
  ## with slot number less or equal to `slot`.
  pool.dag.getBlockBySlot(slot)

func getBlockByPreciseSlot*(pool: BlockPool, slot: Slot): BlockRef =
  ## Retrieves a block from the canonical chain with a slot
  ## number equal to `slot`.
  pool.dag.getBlockByPreciseSlot(slot)

proc get*(pool: BlockPool, blck: BlockRef): BlockData =
  ## Retrieve the associated block body of a block reference
  pool.dag.get(blck)

proc get*(pool: BlockPool, root: Eth2Digest): Option[BlockData] =
  ## Retrieve a resolved block reference and its associated body, if available
  pool.dag.get(root)

func getOrResolve*(pool: var BlockPool, root: Eth2Digest): BlockRef =
  ## Fetch a block ref, or nil if not found (will be added to list of
  ## blocks-to-resolve)
  getOrResolve(pool.dag, pool.quarantine, root)

proc updateHead*(pool: BlockPool, newHead: BlockRef) =
  ## Update what we consider to be the current head, as given by the fork
  ## choice.
  ## The choice of head affects the choice of finalization point - the order
  ## of operations naturally becomes important here - after updating the head,
  ## blocks that were once considered potential candidates for a tree will
  ## now fall from grace, or no longer be considered resolved.
  updateHead(pool.dag, newHead)

proc latestJustifiedBlock*(pool: BlockPool): BlockSlot =
  ## Return the most recent block that is justified and at least as recent
  ## as the latest finalized block
  latestJustifiedBlock(pool.dag)

proc addMissing*(pool: var BlockPool, broot: Eth2Digest) {.inline.} =
  pool.quarantine.addMissing(broot)

proc isInitialized*(T: type BlockPool, db: BeaconChainDB): bool =
  isInitialized(CandidateChains, db)

proc preInit*(
    T: type BlockPool, db: BeaconChainDB, state: BeaconState,
    signedBlock: SignedBeaconBlock) =
  preInit(CandidateChains, db, state, signedBlock)

proc getProposer*(pool: BlockPool, head: BlockRef, slot: Slot):
    Option[(ValidatorIndex, ValidatorPubKey)] =
  getProposer(pool.dag, head, slot)

# Rewinder / State transitions
# --------------------------------------------

template headState*(pool: BlockPool): StateData =
  pool.dag.headState

template tmpState*(pool: BlockPool): StateData =
  pool.dag.tmpState

template balanceState*(pool: BlockPool): StateData =
  pool.dag.balanceState

template withState*(
    pool: BlockPool, cache: var StateData, blockSlot: BlockSlot, body: untyped):
    untyped =
  ## Helper template that updates state to a particular BlockSlot - usage of
  ## cache is unsafe outside of block.
  ## TODO async transformations will lead to a race where cache gets updated
  ##      while waiting for future to complete - catch this here somehow?

  withState(pool.dag, cache, blockSlot, body)

template withEpochState*(
    pool: BlockPool, cache: var StateData, blockSlot: BlockSlot, body: untyped):
    untyped =
  ## Helper template that updates state to a state with an epoch matching the
  ## epoch of blockSlot. This aims to be at least as fast as withState, quick
  ## enough to expose to unautheticated, remote use, but trades off that it's
  ## possible for it to decide that finding a state from a matching epoch may
  ## provide too expensive for such use cases.
  ##
  ## cache is unsafe outside of block.

  withEpochState(pool.dag, cache, blockSlot, body)

proc updateStateData*(
    pool: BlockPool, state: var StateData, bs: BlockSlot,
    matchEpoch: bool = false) =
  ## Rewind or advance state such that it matches the given block and slot -
  ## this may include replaying from an earlier snapshot if blck is on a
  ## different branch or has advanced to a higher slot number than slot
  ## If slot is higher than blck.slot, replay will fill in with empty/non-block
  ## slots, else it is ignored
  updateStateData(pool.dag, state, bs)

proc loadTailState*(pool: BlockPool): StateData =
  loadTailState(pool.dag)

proc isValidBeaconBlock*(
    pool: var BlockPool, signed_beacon_block: SignedBeaconBlock,
    current_slot: Slot, flags: UpdateFlags): Result[void, BlockError] =
  isValidBeaconBlock(
    pool.dag, pool.quarantine, signed_beacon_block, current_slot, flags)

func count_active_validators*(epochInfo: EpochRef): uint64 =
  epochInfo.shuffled_active_validator_indices.lenu64

func get_committee_count_per_slot*(epochInfo: EpochRef): uint64 =
  get_committee_count_per_slot(count_active_validators(epochInfo))

func get_beacon_committee*(
    epochRef: EpochRef, slot: Slot, index: CommitteeIndex): seq[ValidatorIndex] =
  # Return the beacon committee at ``slot`` for ``index``.
  let
    committees_per_slot = get_committee_count_per_slot(epochRef)
  compute_committee(
    epochRef.shuffled_active_validator_indices,
    (slot mod SLOTS_PER_EPOCH) * committees_per_slot +
      index.uint64,
    committees_per_slot * SLOTS_PER_EPOCH
  )

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#get_attesting_indices
func get_attesting_indices*(epochRef: EpochRef,
                            data: AttestationData,
                            bits: CommitteeValidatorsBits):
                            HashSet[ValidatorIndex] =
  get_attesting_indices(
    bits,
    get_beacon_committee(epochRef, data.slot, data.index.CommitteeIndex))

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#get_indexed_attestation
func get_indexed_attestation*(epochRef: EpochRef, attestation: Attestation): IndexedAttestation =
  # Return the indexed attestation corresponding to ``attestation``.
  let
    attesting_indices =
      get_attesting_indices(
        epochRef, attestation.data, attestation.aggregation_bits)

  IndexedAttestation(
    attesting_indices:
      List[uint64, Limit MAX_VALIDATORS_PER_COMMITTEE].init(
        sorted(mapIt(attesting_indices, it.uint64), system.cmp)),
    data: attestation.data,
    signature: attestation.signature
  )
