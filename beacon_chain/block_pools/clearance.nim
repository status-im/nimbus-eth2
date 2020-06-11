# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  chronicles, sequtils, tables,
  metrics, stew/results,
  ../ssz/merkleization, ../state_transition, ../extras,
  ../spec/[crypto, datatypes, digest, helpers],

  block_pools_types, candidate_chains

export results

# Clearance
# ---------------------------------------------
#
# This module is in charge of making the
# "quarantined" network blocks
# pass the firewall and be stored in the blockpool

logScope: topics = "clearblk"
{.push raises: [Defect].}

func getOrResolve*(dag: CandidateChains, quarantine: var Quarantine, root: Eth2Digest): BlockRef =
  ## Fetch a block ref, or nil if not found (will be added to list of
  ## blocks-to-resolve)
  result = dag.getRef(root)

  if result.isNil:
    quarantine.missing[root] = MissingBlock(slots: 1)

proc add*(
    dag: var CandidateChains, quarantine: var Quarantine,
    blockRoot: Eth2Digest,
    signedBlock: SignedBeaconBlock): Result[BlockRef, BlockError] {.gcsafe.}

proc addResolvedBlock(
    dag: var CandidateChains, quarantine: var Quarantine,
    state: BeaconState, blockRoot: Eth2Digest,
    signedBlock: SignedBeaconBlock, parent: BlockRef): BlockRef =
  logScope: pcs = "block_resolution"
  doAssert state.slot == signedBlock.message.slot, "state must match block"

  let blockRef = BlockRef.init(blockRoot, signedBlock.message)
  blockRef.epochsInfo = filterIt(parent.epochsInfo,
    it.epoch + 1 >= state.slot.compute_epoch_at_slot)
  link(parent, blockRef)

  dag.blocks[blockRoot] = blockRef
  trace "Populating block dag", key = blockRoot, val = blockRef

  # Resolved blocks should be stored in database
  dag.putBlock(blockRoot, signedBlock)

  # This block *might* have caused a justification - make sure we stow away
  # that information:
  let justifiedSlot =
    state.current_justified_checkpoint.epoch.compute_start_slot_at_epoch()

  var foundHead: Option[Head]
  for head in dag.heads.mitems():
    if head.blck.isAncestorOf(blockRef):
      if head.justified.slot != justifiedSlot:
        head.justified = blockRef.atSlot(justifiedSlot)

      head.blck = blockRef

      foundHead = some(head)
      break

  if foundHead.isNone():
    foundHead = some(Head(
      blck: blockRef,
      justified: blockRef.atSlot(justifiedSlot)))
    dag.heads.add(foundHead.get())

  info "Block resolved",
    blck = shortLog(signedBlock.message),
    blockRoot = shortLog(blockRoot),
    justifiedHead = foundHead.get().justified,
    heads = dag.heads.len(),
    cat = "filtering"

  # Now that we have the new block, we should see if any of the previously
  # unresolved blocks magically become resolved
  # TODO there are more efficient ways of doing this that don't risk
  #      running out of stack etc
  # TODO This code is convoluted because when there are more than ~1.5k
  #      blocks being synced, there's a stack overflow as `add` gets called
  #      for the whole chain of blocks. Instead we use this ugly field in `dag`
  #      which could be avoided by refactoring the code
  if not quarantine.inAdd:
    quarantine.inAdd = true
    defer: quarantine.inAdd = false
    var keepGoing = true
    while keepGoing:
      let retries = quarantine.pending
      for k, v in retries:
        discard add(dag, quarantine, k, v)
      # Keep going for as long as the pending dag is shrinking
      # TODO inefficient! so what?
      keepGoing = quarantine.pending.len < retries.len
  blockRef

proc add*(
    dag: var CandidateChains, quarantine: var Quarantine,
    blockRoot: Eth2Digest,
    signedBlock: SignedBeaconBlock): Result[BlockRef, BlockError] {.gcsafe.} =
  ## return the block, if resolved...
  ## the state parameter may be updated to include the given block, if
  ## everything checks out
  # TODO reevaluate passing the state in like this
  let blck = signedBlock.message
  doAssert blockRoot == hash_tree_root(blck)

  logScope: pcs = "block_addition"

  # Already seen this block??
  dag.blocks.withValue(blockRoot, blockRef):
    debug "Block already exists",
      blck = shortLog(blck),
      blockRoot = shortLog(blockRoot),
      cat = "filtering"

    return ok blockRef[]

  quarantine.missing.del(blockRoot)

  # If the block we get is older than what we finalized already, we drop it.
  # One way this can happen is that we start resolving a block and finalization
  # happens in the meantime - the block we requested will then be stale
  # by the time it gets here.
  if blck.slot <= dag.finalizedHead.slot:
    debug "Old block, dropping",
      blck = shortLog(blck),
      finalizedHead = shortLog(dag.finalizedHead),
      tail = shortLog(dag.tail),
      blockRoot = shortLog(blockRoot),
      cat = "filtering"

    return err Old

  let parent = dag.blocks.getOrDefault(blck.parent_root)

  if parent != nil:
    if parent.slot >= blck.slot:
      # TODO Malicious block? inform peer dag?
      notice "Invalid block slot",
        blck = shortLog(blck),
        blockRoot = shortLog(blockRoot),
        parentBlock = shortLog(parent)

      return err Invalid

    # The block might have been in either of pending or missing - we don't want
    # any more work done on its behalf
    quarantine.pending.del(blockRoot)

    # The block is resolved, now it's time to validate it to ensure that the
    # blocks we add to the database are clean for the given state

    # TODO if the block is from the future, we should not be resolving it (yet),
    #      but maybe we should use it as a hint that our clock is wrong?
    updateStateData(
      dag, dag.tmpState, BlockSlot(blck: parent, slot: blck.slot - 1))

    let
      poolPtr = unsafeAddr dag # safe because restore is short-lived
    func restore(v: var HashedBeaconState) =
      # TODO address this ugly workaround - there should probably be a
      #      `state_transition` that takes a `StateData` instead and updates
      #      the block as well
      doAssert v.addr == addr poolPtr.tmpState.data
      poolPtr.tmpState = poolPtr.headState

    var stateCache = getEpochCache(parent, dag.tmpState.data.data)
    if not state_transition(
        dag.tmpState.data, signedBlock, stateCache, dag.updateFlags, restore):
      # TODO find a better way to log all this block data
      notice "Invalid block",
        blck = shortLog(blck),
        blockRoot = shortLog(blockRoot),
        cat = "filtering"

      return err Invalid
    # Careful, tmpState.data has been updated but not blck - we need to create
    # the BlockRef first!
    dag.tmpState.blck = addResolvedBlock(
      dag, quarantine,
      dag.tmpState.data.data, blockRoot, signedBlock, parent)
    dag.putState(dag.tmpState.data, dag.tmpState.blck)

    return ok dag.tmpState.blck

  # TODO already checked hash though? main reason to keep this is because
  # the pending dag calls this function back later in a loop, so as long
  # as dag.add(...) requires a SignedBeaconBlock, easier to keep them in
  # pending too.
  quarantine.pending[blockRoot] = signedBlock

  # TODO possibly, it makes sense to check the database - that would allow sync
  #      to simply fill up the database with random blocks the other clients
  #      think are useful - but, it would also risk filling the database with
  #      junk that's not part of the block graph

  if blck.parent_root in quarantine.missing or
      blck.parent_root in quarantine.pending:
    return err MissingParent

  # This is an unresolved block - put its parent on the missing list for now...
  # TODO if we receive spam blocks, one heurestic to implement might be to wait
  #      for a couple of attestations to appear before fetching parents - this
  #      would help prevent using up network resources for spam - this serves
  #      two purposes: one is that attestations are likely to appear for the
  #      block only if it's valid / not spam - the other is that malicious
  #      validators that are not proposers can sign invalid blocks and send
  #      them out without penalty - but signing invalid attestations carries
  #      a risk of being slashed, making attestations a more valuable spam
  #      filter.
  # TODO when we receive the block, we don't know how many others we're missing
  #      from that branch, so right now, we'll just do a blind guess
  let parentSlot = blck.slot - 1

  quarantine.missing[blck.parent_root] = MissingBlock(
    slots:
      # The block is at least two slots ahead - try to grab whole history
      if parentSlot > dag.head.blck.slot:
        parentSlot - dag.head.blck.slot
      else:
        # It's a sibling block from a branch that we're missing - fetch one
        # epoch at a time
        max(1.uint64, SLOTS_PER_EPOCH.uint64 -
          (parentSlot.uint64 mod SLOTS_PER_EPOCH.uint64))
  )

  debug "Unresolved block (parent missing)",
    blck = shortLog(blck),
    blockRoot = shortLog(blockRoot),
    pending = quarantine.pending.len,
    missing = quarantine.missing.len,
    cat = "filtering"

  return err MissingParent

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/p2p-interface.md#global-topics
proc isValidBeaconBlock*(
       dag: CandidateChains, quarantine: var Quarantine,
       signed_beacon_block: SignedBeaconBlock, current_slot: Slot,
       flags: UpdateFlags): bool =
  # In general, checks are ordered from cheap to expensive. Especially, crypto
  # verification could be quite a bit more expensive than the rest. This is an
  # externally easy-to-invoke function by tossing network packets at the node.

  # The block is not from a future slot
  # TODO allow `MAXIMUM_GOSSIP_CLOCK_DISPARITY` leniency, especially towards
  # seemingly future slots.
  if not (signed_beacon_block.message.slot <= current_slot):
    debug "isValidBeaconBlock: block is from a future slot",
      signed_beacon_block_message_slot = signed_beacon_block.message.slot,
      current_slot = current_slot
    return false

  # The block is from a slot greater than the latest finalized slot (with a
  # MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance) -- i.e. validate that
  # signed_beacon_block.message.slot >
  # compute_start_slot_at_epoch(state.finalized_checkpoint.epoch)
  if not (signed_beacon_block.message.slot > dag.finalizedHead.slot):
    debug "isValidBeaconBlock: block is not from a slot greater than the latest finalized slot"
    return false

  # The block is the first block with valid signature received for the proposer
  # for the slot, signed_beacon_block.message.slot.
  #
  # While this condition is similar to the proposer slashing condition at
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/validator.md#proposer-slashing
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
      debug "isValidBeaconBlock: block isn't first block with valid signature received for the proposer",
        signed_beacon_block_message_slot = signed_beacon_block.message.slot,
        blckRef = slotBlockRef,
        received_block = shortLog(signed_beacon_block.message),
        existing_block = shortLog(dag.get(slotBlockRef).data.message)
      return false

  # If this block doesn't have a parent we know about, we can't/don't really
  # trace it back to a known-good state/checkpoint to verify its prevenance;
  # while one could getOrResolve to queue up searching for missing parent it
  # might not be the best place. As much as feasible, this function aims for
  # answering yes/no, not queuing other action or otherwise altering state.
  let parent_ref = dag.getRef(signed_beacon_block.message.parent_root)
  if parent_ref.isNil:
    # This doesn't mean a block is forever invalid, only that we haven't seen
    # its ancestor blocks yet. While that means for now it should be blocked,
    # at least, from libp2p propagation, it shouldn't be ignored. TODO, if in
    # the future this block moves from pending to being resolved, consider if
    # it's worth broadcasting it then.

    # Pending dag gets checked via `CandidateChains.add(...)` later, and relevant
    # checks are performed there. In usual paths beacon_node adds blocks via
    # CandidateChains.add(...) directly, with no additional validity checks. TODO,
    # not specific to this, but by the pending dag keying on the htr of the
    # BeaconBlock, not SignedBeaconBlock, opens up certain spoofing attacks.
    quarantine.pending[hash_tree_root(signed_beacon_block.message)] =
      signed_beacon_block
    return false

  # The proposer signature, signed_beacon_block.signature, is valid with
  # respect to the proposer_index pubkey.
  let bs =
    BlockSlot(blck: parent_ref, slot: dag.get(parent_ref).data.message.slot)
  dag.withState(dag.tmpState, bs):
    let
      blockRoot = hash_tree_root(signed_beacon_block.message)
      domain = get_domain(dag.headState.data.data, DOMAIN_BEACON_PROPOSER,
        compute_epoch_at_slot(signed_beacon_block.message.slot))
      signing_root = compute_signing_root(blockRoot, domain)
      proposer_index = signed_beacon_block.message.proposer_index

    if proposer_index >= dag.headState.data.data.validators.len.uint64:
      return false
    if not blsVerify(dag.headState.data.data.validators[proposer_index].pubkey,
        signing_root.data, signed_beacon_block.signature):
      debug "isValidBeaconBlock: block failed signature verification"
      return false

  true
