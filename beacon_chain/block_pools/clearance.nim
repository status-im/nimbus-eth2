# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/tables,
  chronicles,
  stew/results,
  ../extras, ../time,
  ../spec/[crypto, datatypes, digest, helpers, signatures, state_transition],
  ./block_pools_types, ./chain_dag, ./quarantine

export results

# Clearance
# ---------------------------------------------
#
# This module is in charge of making the
# "quarantined" network blocks
# pass the firewall and be stored in the chain DAG

logScope:
  topics = "clearance"

func getOrResolve*(dag: ChainDAGRef, quarantine: var QuarantineRef, root: Eth2Digest): BlockRef =
  ## Fetch a block ref, or nil if not found (will be added to list of
  ## blocks-to-resolve)
  result = dag.getRef(root)

  if result.isNil:
    quarantine.addMissing(root)

proc addRawBlock*(
      dag: var ChainDAGRef, quarantine: var QuarantineRef,
      signedBlock: SignedBeaconBlock, onBlockAdded: OnBlockAdded
     ): Result[BlockRef, (ValidationResult, BlockError)] {.gcsafe.}

proc addResolvedBlock(
       dag: var ChainDAGRef, quarantine: var QuarantineRef,
       state: var StateData, signedBlock: SignedBeaconBlock,
       parent: BlockRef, cache: var StateCache,
       onBlockAdded: OnBlockAdded
     ) =
  # TODO move quarantine processing out of here
  doAssert state.data.data.slot == signedBlock.message.slot,
    "state must match block"
  doAssert state.blck.root == signedBlock.message.parent_root,
    "the StateData passed into the addResolved function not yet updated!"

  let
    blockRoot = signedBlock.root
    blockRef = BlockRef.init(blockRoot, signedBlock.message)
    blockEpoch = blockRef.slot.compute_epoch_at_slot()

  link(parent, blockRef)

  var epochRef = blockRef.findEpochRef(blockEpoch)
  if epochRef == nil:
    let prevEpochRef = blockRef.findEpochRef(blockEpoch - 1)

    epochRef = EpochRef.init(state.data.data, cache, prevEpochRef)
    let ancestor = blockRef.epochAncestor(blockEpoch)
    epochRef.updateKeyStores(ancestor.blck.parent, dag.finalizedHead.blck)

    ancestor.blck.epochRefs.add epochRef

  dag.blocks[blockRoot] = blockRef
  trace "Populating block dag", key = blockRoot, val = blockRef

  # Resolved blocks should be stored in database
  dag.putBlock(signedBlock)

  var foundHead: BlockRef
  for head in dag.heads.mitems():
    if head.isAncestorOf(blockRef):

      head = blockRef

      foundHead = head
      break

  if foundHead.isNil:
    foundHead = blockRef
    dag.heads.add(foundHead)

  debug "Block resolved",
    blck = shortLog(signedBlock.message),
    blockRoot = shortLog(blockRoot),
    heads = dag.heads.len()

  state.blck = blockRef

  # Notify others of the new block before processing the quarantine, such that
  # notifications for parents happens before those of the children
  if onBlockAdded != nil:
    onBlockAdded(blockRef, signedBlock, epochRef, state.data)

  # Now that we have the new block, we should see if any of the previously
  # unresolved blocks magically become resolved
  # TODO This code is convoluted because when there are more than ~1.5k
  #      blocks being synced, there's a stack overflow as `add` gets called
  #      for the whole chain of blocks. Instead we use this ugly field in `dag`
  #      which could be avoided by refactoring the code
  # TODO unit test the logic, in particular interaction with fork choice block parents
  if not quarantine.inAdd:
    quarantine.inAdd = true
    defer: quarantine.inAdd = false
    var entries = 0
    while entries != quarantine.orphans.len:
      entries = quarantine.orphans.len # keep going while quarantine is shrinking
      var resolved: seq[SignedBeaconBlock]
      for _, v in quarantine.orphans:
        if v.message.parent_root in dag.blocks: resolved.add(v)

      for v in resolved:
        discard addRawBlock(dag, quarantine, v, onBlockAdded)

proc addRawBlock*(
       dag: var ChainDAGRef, quarantine: var QuarantineRef,
       signedBlock: SignedBeaconBlock,
       onBlockAdded: OnBlockAdded
     ): Result[BlockRef, (ValidationResult, BlockError)] =
  ## Try adding a block to the chain, verifying first that it passes the state
  ## transition function.

  logScope:
    blck = shortLog(signedBlock.message)
    blockRoot = shortLog(signedBlock.root)

  template blck(): untyped = signedBlock.message # shortcuts without copy
  template blockRoot(): untyped = signedBlock.root

  if blockRoot in dag.blocks:
    debug "Block already exists"

    # We should not call the block added callback for blocks that already
    # existed in the pool, as that may confuse consumers such as the fork
    # choice. While the validation result won't be accessed, it's IGNORE,
    # according to the spec.
    return err((ValidationResult.Ignore, Duplicate))

  quarantine.missing.del(blockRoot)

  # If the block we get is older than what we finalized already, we drop it.
  # One way this can happen is that we start resolving a block and finalization
  # happens in the meantime - the block we requested will then be stale
  # by the time it gets here.
  if blck.slot <= dag.finalizedHead.slot:
    debug "Old block, dropping",
      finalizedHead = shortLog(dag.finalizedHead),
      tail = shortLog(dag.tail)

    # Doesn't correspond to any specific validation condition, and still won't
    # be used, but certainly would be IGNORE.
    return err((ValidationResult.Ignore, Unviable))

  let parent = dag.blocks.getOrDefault(blck.parent_root)

  if parent != nil:
    if parent.slot >= blck.slot:
      # A block whose parent is newer than the block itself is clearly invalid -
      # discard it immediately
      debug "Invalid block slot",
        parentBlock = shortLog(parent)

      return err((ValidationResult.Reject, Invalid))

    if (parent.slot < dag.finalizedHead.slot) or
        (parent.slot == dag.finalizedHead.slot and
          parent != dag.finalizedHead.blck):
      # We finalized a block that's newer than the parent of this block - this
      # block, although recent, is thus building on a history we're no longer
      # interested in pursuing. This can happen if a client produces a block
      # while syncing - ie it's own head block will be old, but it'll create
      # a block according to the wall clock, in its own little world - this is
      # correct - from their point of view, the head block they have is the
      # latest thing that happened on the chain and they're performing their
      # duty correctly.
      debug "Unviable block, dropping",
        finalizedHead = shortLog(dag.finalizedHead),
        tail = shortLog(dag.tail)

      return err((ValidationResult.Ignore, Unviable))

    # The block might have been in either of `orphans` or `missing` - we don't
    # want any more work done on its behalf
    quarantine.removeOrphan(signedBlock)

    # The block is resolved, now it's time to validate it to ensure that the
    # blocks we add to the database are clean for the given state

    # TODO if the block is from the future, we should not be resolving it (yet),
    #      but maybe we should use it as a hint that our clock is wrong?
    var cache = getStateCache(parent, blck.slot.epoch)
    updateStateData(
      dag, dag.clearanceState, parent.atSlot(blck.slot), true, cache)

    let
      poolPtr = unsafeAddr dag # safe because restore is short-lived
    func restore(v: var HashedBeaconState) =
      # TODO address this ugly workaround - there should probably be a
      #      `state_transition` that takes a `StateData` instead and updates
      #      the block as well
      doAssert v.addr == addr poolPtr.clearanceState.data
      assign(poolPtr.clearanceState, poolPtr.headState)

    if not state_transition(dag.runtimePreset, dag.clearanceState.data, signedBlock,
                            cache, dag.updateFlags + {slotProcessed}, restore):
      info "Invalid block"

      return err((ValidationResult.Reject, Invalid))

    # Careful, clearanceState.data has been updated but not blck - we need to
    # create the BlockRef first!
    addResolvedBlock(
      dag, quarantine, dag.clearanceState, signedBlock, parent, cache,
      onBlockAdded)

    return ok dag.clearanceState.blck

  # This is an unresolved block - add it to the quarantine, which will cause its
  # parent to be scheduled for downloading
  if not quarantine.add(dag, signedBlock):
    debug "Block quarantine full"

  if blck.parent_root in quarantine.missing or
      containsOrphan(quarantine, signedBlock):
    debug "Unresolved block (parent missing or orphaned)",
      orphans = quarantine.orphans.len,
      missing = quarantine.missing.len

    return err((ValidationResult.Ignore, MissingParent))

  # TODO if we receive spam blocks, one heurestic to implement might be to wait
  #      for a couple of attestations to appear before fetching parents - this
  #      would help prevent using up network resources for spam - this serves
  #      two purposes: one is that attestations are likely to appear for the
  #      block only if it's valid / not spam - the other is that malicious
  #      validators that are not proposers can sign invalid blocks and send
  #      them out without penalty - but signing invalid attestations carries
  #      a risk of being slashed, making attestations a more valuable spam
  #      filter.
  debug "Unresolved block (parent missing)",
    orphans = quarantine.orphans.len,
    missing = quarantine.missing.len

  return err((ValidationResult.Ignore, MissingParent))

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/p2p-interface.md#beacon_block
proc isValidBeaconBlock*(
       dag: ChainDAGRef, quarantine: var QuarantineRef,
       signed_beacon_block: SignedBeaconBlock, wallTime: BeaconTime,
       flags: UpdateFlags):
       Result[void, (ValidationResult, BlockError)] =
  logScope:
    topics = "clearance valid_blck"
    received_block = shortLog(signed_beacon_block.message)
    blockRoot = shortLog(signed_beacon_block.root)

  # In general, checks are ordered from cheap to expensive. Especially, crypto
  # verification could be quite a bit more expensive than the rest. This is an
  # externally easy-to-invoke function by tossing network packets at the node.

  # [IGNORE] The block is not from a future slot (with a
  # MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance) -- i.e. validate that
  # signed_beacon_block.message.slot <= current_slot (a client MAY queue future
  # blocks for processing at the appropriate slot).
  if not (signed_beacon_block.message.slot <=
      (wallTime + MAXIMUM_GOSSIP_CLOCK_DISPARITY).slotOrZero):
    debug "block is from a future slot",
      wallSlot = wallTime.toSlot()
    return err((ValidationResult.Ignore, Invalid))

  # [IGNORE] The block is from a slot greater than the latest finalized slot --
  # i.e. validate that signed_beacon_block.message.slot >
  # compute_start_slot_at_epoch(state.finalized_checkpoint.epoch)
  if not (signed_beacon_block.message.slot > dag.finalizedHead.slot):
    debug "block is not from a slot greater than the latest finalized slot"
    return err((ValidationResult.Ignore, Invalid))

  # [IGNORE] The block is the first block with valid signature received for the
  # proposer for the slot, signed_beacon_block.message.slot.
  #
  # While this condition is similar to the proposer slashing condition at
  # https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/validator.md#proposer-slashing
  # it's not identical, and this check does not address slashing:
  #
  # (1) The beacon blocks must be conflicting, i.e. different, for the same
  #     slot and proposer. This check also catches identical blocks.
  #
  # (2) By this point in the function, it's not been checked whether they're
  #     signed yet. As in general, expensive checks should be deferred, this
  #     would add complexity not directly relevant this function.
  #
  # (3) As evidenced by point (1), the similarity in the validation condition
  #     and slashing condition, while not coincidental, aren't similar enough
  #     to combine, as one or the other might drift.
  #
  # (4) Furthermore, this function, as much as possible, simply returns a yes
  #     or no answer, without modifying other state for p2p network interface
  #     validation. Complicating this interface, for the sake of sharing only
  #     couple lines of code, wouldn't be worthwhile.
  #
  # TODO might check unresolved/orphaned blocks too, and this might not see all
  # blocks at a given slot (though, in theory, those get checked elsewhere), or
  # adding metrics that count how often these conditions occur.
  let
    slotBlockRef = getBlockBySlot(dag, signed_beacon_block.message.slot)

  if not slotBlockRef.isNil:
    let blck = dag.get(slotBlockRef).data
    if blck.message.proposer_index ==
          signed_beacon_block.message.proposer_index and
        blck.message.slot == signed_beacon_block.message.slot and
        blck.signature.toRaw() != signed_beacon_block.signature.toRaw():
      notice "block isn't first block with valid signature received for the proposer",
        blckRef = slotBlockRef,
        existing_block = shortLog(blck.message)
      return err((ValidationResult.Ignore, Invalid))

  # [IGNORE] The block's parent (defined by block.parent_root) has been seen
  # (via both gossip and non-gossip sources) (a client MAY queue blocks for
  # processing once the parent block is retrieved).
  #
  # And implicitly:
  # [REJECT] The block's parent (defined by block.parent_root) passes validation.
  let parent_ref = dag.getRef(signed_beacon_block.message.parent_root)
  if parent_ref.isNil:
    # Pending dag gets checked via `ChainDAGRef.add(...)` later, and relevant
    # checks are performed there. In usual paths beacon_node adds blocks via
    # ChainDAGRef.add(...) directly, with no additional validity checks.
    debug "parent unknown, putting block in quarantine",
      current_slot = wallTime.toSlot()
    if not quarantine.add(dag, signed_beacon_block):
      debug "Block quarantine full"
    return err((ValidationResult.Ignore, MissingParent))

  # [REJECT] The current finalized_checkpoint is an ancestor of block -- i.e.
  # get_ancestor(store, block.parent_root,
  # compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)) ==
  # store.finalized_checkpoint.root
  let
    finalized_checkpoint = dag.headState.data.data.finalized_checkpoint
    ancestor = get_ancestor(
      parent_ref, compute_start_slot_at_epoch(finalized_checkpoint.epoch))

  if ancestor.isNil:
    debug "couldn't find ancestor block"
    return err((ValidationResult.Ignore, Invalid)) # might not've received block

  if not (finalized_checkpoint.root in [ancestor.root, Eth2Digest()]):
    debug "block not descendent of finalized block"
    return err((ValidationResult.Reject, Invalid))

  # [REJECT] The block is proposed by the expected proposer_index for the
  # block's slot in the context of the current shuffling (defined by
  # parent_root/slot). If the proposer_index cannot immediately be verified
  # against the expected shuffling, the block MAY be queued for later
  # processing while proposers for the block's branch are calculated -- in such
  # a case do not REJECT, instead IGNORE this message.
  let
    proposer = getProposer(dag, parent_ref, signed_beacon_block.message.slot)

  if proposer.isNone:
    warn "cannot compute proposer for message"
    return err((ValidationResult.Ignore, Invalid)) # internal issue

  if proposer.get()[0] !=
      ValidatorIndex(signed_beacon_block.message.proposer_index):
    notice "block had unexpected proposer",
      expected_proposer = proposer.get()[0]
    return err((ValidationResult.Reject, Invalid))

  # [REJECT] The proposer signature, signed_beacon_block.signature, is valid
  # with respect to the proposer_index pubkey.
  if not verify_block_signature(
      dag.headState.data.data.fork,
      dag.headState.data.data.genesis_validators_root,
      signed_beacon_block.message.slot,
      signed_beacon_block.message,
      proposer.get()[1],
      signed_beacon_block.signature):
    debug "block failed signature verification",
      signature = shortLog(signed_beacon_block.signature)

    return err((ValidationResult.Reject, Invalid))

  ok()
