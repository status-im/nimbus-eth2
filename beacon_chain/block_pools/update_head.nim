# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  chronicles, tables,
  metrics,
  ../ssz, ../state_transition, ../extras,
  ../spec/[crypto, datatypes, digest, helpers],

  block_pools_types, candidate_chains, rewinder

# Clearance
# ---------------------------------------------
#
# This module is in charge of
# - making the "quarantined" network blocks
#   pass the firewall and be stored in the blockpool
# - Update the head block

logScope: topics = "updhead"
{.push raises: [Defect].}

declareCounter beacon_reorgs_total, "Total occurrences of reorganizations of the chain" # On fork choice

proc updateHead*(dag: var CandidateChains, rewinder: var Rewinder, newHead: BlockRef) =
  ## Update what we consider to be the current head, as given by the fork
  ## choice.
  ## The choice of head affects the choice of finalization point - the order
  ## of operations naturally becomes important here - after updating the head,
  ## blocks that were once considered potential candidates for a tree will
  ## now fall from grace, or no longer be considered resolved.
  doAssert newHead.parent != nil or newHead.slot == 0
  logScope: pcs = "fork_choice"

  if dag.head.blck == newHead:
    info "No head block update",
      head = shortLog(newHead),
      cat = "fork_choice"

    return

  let
    lastHead = dag.head
  dag.putHeadBlock(newHead.root)

  # Start off by making sure we have the right state
  updateStateData(
    rewinder, rewinder.headState, BlockSlot(blck: newHead, slot: newHead.slot))

  let
    justifiedSlot = rewinder.headState.data.data
                      .current_justified_checkpoint
                      .epoch
                      .compute_start_slot_at_epoch()
    justifiedBS = newHead.atSlot(justifiedSlot)

  dag.head = Head(blck: newHead, justified: justifiedBS)
  updateStateData(rewinder, rewinder.justifiedState, justifiedBS)

  # TODO isAncestorOf may be expensive - too expensive?
  if not lastHead.blck.isAncestorOf(newHead):
    info "Updated head block (new parent)",
      lastHead = shortLog(lastHead.blck),
      headParent = shortLog(newHead.parent),
      stateRoot = shortLog(rewinder.headState.data.root),
      headBlock = shortLog(rewinder.headState.blck),
      stateSlot = shortLog(rewinder.headState.data.data.slot),
      justifiedEpoch = shortLog(rewinder.headState.data.data.current_justified_checkpoint.epoch),
      finalizedEpoch = shortLog(rewinder.headState.data.data.finalized_checkpoint.epoch),
      cat = "fork_choice"

    # A reasonable criterion for "reorganizations of the chain"
    beacon_reorgs_total.inc()
  else:
    info "Updated head block",
      stateRoot = shortLog(rewinder.headState.data.root),
      headBlock = shortLog(rewinder.headState.blck),
      stateSlot = shortLog(rewinder.headState.data.data.slot),
      justifiedEpoch = shortLog(rewinder.headState.data.data.current_justified_checkpoint.epoch),
      finalizedEpoch = shortLog(rewinder.headState.data.data.finalized_checkpoint.epoch),
      cat = "fork_choice"

  let
    finalizedEpochStartSlot =
      rewinder.headState.data.data.finalized_checkpoint.epoch.
      compute_start_slot_at_epoch()
    # TODO there might not be a block at the epoch boundary - what then?
    finalizedHead = newHead.atSlot(finalizedEpochStartSlot)

  doAssert (not finalizedHead.blck.isNil),
    "Block graph should always lead to a finalized block"

  if finalizedHead != dag.finalizedHead:
    block: # Remove states, walking slot by slot
      discard
      # TODO this is very aggressive - in theory all our operations start at
      #      the finalized block so all states before that can be wiped..
      # TODO this is disabled for now because the logic for initializing the
      #      block dag and potentially a few other places depend on certain
      #      states (like the tail state) being present. It's also problematic
      #      because it is not clear what happens when tail and finalized states
      #      happen on an empty slot..
      # var cur = finalizedHead
      # while cur != dag.finalizedHead:
      #  cur = cur.parent
      #  dag.delState(cur)

    block: # Clean up block refs, walking block by block
      var cur = finalizedHead.blck
      while cur != dag.finalizedHead.blck:
        # Finalization means that we choose a single chain as the canonical one -
        # it also means we're no longer interested in any branches from that chain
        # up to the finalization point.
        # The new finalized head should not be cleaned! We start at its parent and
        # clean everything including the old finalized head.
        cur = cur.parent

        # TODO what about attestations? we need to drop those too, though they
        #      *should* be pretty harmless
        if cur.parent != nil: # This happens for the genesis / tail block
          for child in cur.parent.children:
            if child != cur:
              # TODO also remove states associated with the unviable forks!
              # TODO the easiest thing to do here would probably be to use
              #      dag.heads to find unviable heads, then walk those chains
              #      and remove everything.. currently, if there's a child with
              #      children of its own, those children will not be pruned
              #      correctly from the database
              dag.blocks.del(child.root)
              dag.delBlock(child.root)
          cur.parent.children = @[cur]

    dag.finalizedHead = finalizedHead

    let hlen = dag.heads.len
    for i in 0..<hlen:
      let n = hlen - i - 1
      if not dag.finalizedHead.blck.isAncestorOf(dag.heads[n].blck):
        # Any heads that are not derived from the newly finalized block are no
        # longer viable candidates for future head selection
        dag.heads.del(n)

    info "Finalized block",
      finalizedHead = shortLog(finalizedHead),
      head = shortLog(newHead),
      heads = dag.heads.len,
      cat = "fork_choice"

    # TODO prune everything before weak subjectivity period
