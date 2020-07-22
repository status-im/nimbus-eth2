# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Standard library
  std/tables, std/options, std/typetraits,
  # Status libraries
  chronicles,
  # Internal
  ../spec/[datatypes, digest],
  # Fork choice
  ./fork_choice_types

logScope:
  topics = "fork_choice"

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/fork-choice.md
# This is a port of https://github.com/sigp/lighthouse/pull/804
# which is a port of "Proto-Array": https://github.com/protolambda/lmd-ghost
# See also:
# - Protolambda port of Lighthouse: https://github.com/protolambda/eth2-py-hacks/blob/ae286567/proto_array.py
# - Prysmatic writeup: https://hackmd.io/bABJiht3Q9SyV3Ga4FT9lQ#High-level-concept
# - Gasper Whitepaper: https://arxiv.org/abs/2003.03052

# Helper
# ----------------------------------------------------------------------

func tiebreak(a, b: Eth2Digest): bool =
  ## Fork-Choice tie-break between 2 digests
  ## Currently implemented as `>=` (greater or equal)
  ## on the binary representation
  for i in 0 ..< a.data.len:
    if a.data[i] < b.data[i]:
      return false
    elif a.data[i] > b.data[i]:
      return true
    # else we have equality so far
  return true

template getOrFailcase*[K, V](table: Table[K, V], key: K, failcase: untyped): V =
  ## Get a value from a Nim Table, turning KeyError into
  ## the "failcase"
  block:
    # TODO: try/except expression with Nim v1.2.0:
    #       https://github.com/status-im/nim-beacon-chain/pull/865#discussion_r404856551
    var value: V
    try:
      value = table[key]
    except KeyError:
      failcase
    value

template unsafeGet*[K, V](table: Table[K, V], key: K): V =
  ## Get a value from a Nim Table, turning KeyError into
  ## an AssertionError defect
  getOrFailcase(table, key):
    doAssert false, "The " & astToStr(table) & " table shouldn't miss a key"

# Forward declarations
# ----------------------------------------------------------------------

func maybe_update_best_child_and_descendant(self: var ProtoArray, parent_index: Index, child_index: Index): ForkChoiceError
func node_is_viable_for_head(self: ProtoArray, node: ProtoNode): bool
func node_leads_to_viable_head(self: ProtoArray, node: ProtoNode): tuple[viable: bool, err: ForkChoiceError]

# ProtoArray routines
# ----------------------------------------------------------------------

func apply_score_changes*(
       self: var ProtoArray,
       deltas: var openarray[Delta],
       justified_epoch: Epoch,
       finalized_epoch: Epoch
     ): ForkChoiceError =
  ## Iterate backwards through the array, touching all nodes and their parents
  ## and potentially the best-child of each parent.
  ##
  ## The structure of `self.nodes` array ensures that the child of each node
  ## is always touched before it's aprent.
  ##
  ## For each node the following is done:
  ##
  ## 1. Update the node's weight with the corresponding delta.
  ## 2. Backpropagate each node's delta to its parent's delta.
  ## 3. Compare the current node with the parent's best-child,
  ##    updating if the current node should become the best-child
  ## 4. If required, update the parent's best-descendant with the current node or its best-descendant
  if deltas.len != self.indices.len:
    return ForkChoiceError(
             kind: fcErrInvalidDeltaLen,
             deltasLen: deltas.len,
             indicesLen: self.indices.len
           )

  self.justified_epoch = justified_epoch
  self.finalized_epoch = finalized_epoch

  # Iterate backwards through all the indices in `self.nodes`
  for node_index in countdown(self.nodes.len - 1, 0):
    template node: untyped {.dirty.}= self.nodes[node_index]
      ## Alias
      # This cannot raise the IndexError exception, how to tell compiler?

    if node.root == default(Eth2Digest):
      continue

    if node_index notin {0..deltas.len-1}:
      # TODO: Here `deltas.len == self.indices.len` from the previous check
      #       and we can probably assume that
      #       `self.indices.len == self.nodes.len` by construction
      #       and avoid this check in a loop or altogether
      return ForkChoiceError(
        kind: fcErrInvalidNodeDelta,
        index: node_index
      )
    let node_delta = deltas[node_index]

    # Apply the delta to the node
    # We fail fast if underflow, which shouldn't happen.
    # Note that delta can be negative but weight cannot
    let weight = node.weight + node_delta
    if weight < 0:
      return ForkChoiceError(
        kind: fcErrDeltaUnderflow,
        index: node_index
      )
    node.weight = weight

    # If the node has a parent, try to update its best-child and best-descendant
    if node.parent.isSome():
      # TODO: Nim `options` module could use some {.inline.}
      #       and a mutable overload for unsafeGet
      #       and a "no exceptions" (only panics) implementation.
      let parent_index = node.parent.unsafeGet()
      if parent_index notin {0..deltas.len-1}:
        return ForkChoiceError(
          kind: fcErrInvalidParentDelta,
          index: parent_index
        )

      # Back-propagate the nodes delta to its parent.
      deltas[parent_index] += node_delta

      let err = self.maybe_update_best_child_and_descendant(parent_index, node_index)
      if err.kind != fcSuccess:
        return err

  return ForkChoiceSuccess


func on_block*(
       self: var ProtoArray,
       root: Eth2Digest,
       hasParentInForkChoice: bool,
       parent: Eth2Digest,
       justified_epoch: Epoch,
       finalized_epoch: Epoch
     ): ForkChoiceError =
  ## Register a block with the fork choice
  ## A block `hasParentInForkChoice` may be false
  ## on fork choice initialization:
  ## - either from Genesis
  ## - or from a finalized state loaded from database

  # Note: if parent is an "Option" type, we can run out of stack space.

  # If the block is already known, ignore it
  if root in self.indices:
    return ForkChoiceSuccess

  var parent_index: Option[int]
  if not hasParentInForkChoice:
      # Genesis (but Genesis might not be default(Eth2Digest))
    parent_index = none(int)
  elif parent notin self.indices:
    {.noSideEffect.}:
      error "Trying to add block with unknown parent",
        child_root = shortLog(root),
        parent_root = shortLog(parent),
        justified_epoch = justified_epoch,
        finalized_epoch = finalized_epoch

    return ForkChoiceError(
      kind: fcErrUnknownParent,
      child_root: root,
      parent_root: parent
    )
  else:
    parent_index = some(self.indices.unsafeGet(parent))

  let node_index = self.nodes.len

  let node = ProtoNode(
    root: root,
    parent: parent_index,
    justified_epoch: justified_epoch,
    finalized_epoch: finalized_epoch,
    weight: 0,
    best_child: none(int),
    best_descendant: none(int)
  )

  self.indices[node.root] = node_index
  self.nodes.add node # TODO: if this is costly, we can setLen + construct the node in-place

  if parent_index.isSome(): # parent_index is always valid except for Genesis
    let err = self.maybe_update_best_child_and_descendant(parent_index.unsafeGet(), node_index)
    if err.kind != fcSuccess:
      return err

  return ForkChoiceSuccess

func find_head*(
        self: var ProtoArray,
        head: var Eth2Digest,
        justified_root: Eth2Digest
     ): ForkChoiceError =
  ## Follows the best-descendant links to find the best-block (i.e. head-block)
  ##
  ## ⚠️ Warning
  ## The result may not be accurate if `on_new_block`
  ## is not followed by `apply_score_changes` as `on_new_block` does not
  ## update the whole tree.

  let justified_index = self.indices.getOrFailcase(justified_root):
    return ForkChoiceError(
      kind: fcErrJustifiedNodeUnknown,
      block_root: justified_root
    )

  if justified_index notin {0..self.nodes.len-1}:
    return ForkChoiceError(
      kind: fcErrInvalidJustifiedIndex,
      index: justified_index
    )

  template justified_node: untyped {.dirty.} = self.nodes[justified_index]
    # Alias, IndexError are defects

  let best_descendant_index = block:
    if justified_node.best_descendant.isSome():
      justified_node.best_descendant.unsafeGet()
    else:
      justified_index

  if best_descendant_index notin {0..self.nodes.len-1}:
    return ForkChoiceError(
      kind: fcErrInvalidBestDescendant,
      index: best_descendant_index
    )
  template best_node: untyped {.dirty.} = self.nodes[best_descendant_index]
    # Alias, IndexError are defects

  # Perform a sanity check to ensure the node can be head
  if not self.node_is_viable_for_head(best_node):
    return ForkChoiceError(
      kind: fcErrInvalidBestNode,
      start_root: justified_root,
      justified_epoch: self.justified_epoch,
      finalized_epoch: self.finalized_epoch,
      head_root: justified_node.root,
      head_justified_epoch: justified_node.justified_epoch,
      head_finalized_epoch: justified_node.finalized_epoch
    )

  head = best_node.root
  return ForkChoiceSuccess

# TODO: pruning can be made cheaper by keeping the new offset as a field
#       in proto_array instead of scanning the table to substract the offset.
#       In that case pruning can always be done and does not need a threshold for efficiency.
#       https://github.com/protolambda/eth2-py-hacks/blob/ae286567/proto_array.py
func maybe_prune*(
       self: var ProtoArray,
       finalized_root: Eth2Digest
     ): ForkChoiceError =
  ## Update the tree with new finalization information.
  ## The tree is pruned if and only if:
  ## - The `finalized_root` and finalized epoch are different from current
  ## - The number of nodes in `self` is at least `self.prune_threshold`
  ##
  ## Returns error if:
  ## - The finalized epoch is less than the current one
  ## - The finalized epoch matches the current one but the finalized root is different
  ## - Internal error due to invalid indices in `self`
  let finalized_index = self.indices.getOrFailcase(finalized_root):
    return ForkChoiceError(
      kind: fcErrFinalizedNodeUnknown,
      block_root: finalized_root
    )

  if finalized_index < self.prune_threshold:
    # Pruning small numbers of nodes incurs more overhead than leaving them as is
    return ForkChoiceSuccess

  # Remove the `self.indices` key/values for the nodes slated for deletion
  if finalized_index notin {0..self.nodes.len-1}:
    return ForkChoiceError(
      kind: fcErrInvalidNodeIndex,
      index: finalized_index
    )

  {.noSideEffect.}:
    debug "Pruning blocks from fork choice",
      finalizedRoot = shortlog(finalized_root),
      pcs = "prune"

  for node_index in 0 ..< finalized_index:
    self.indices.del(self.nodes[node_index].root)

  # Drop all nodes prior to finalization.
  # This is done in-place with `moveMem` to avoid costly reallocations.
  static: doAssert ProtoNode.supportsCopyMem(), "ProtoNode must be a trivial type"
  let tail = self.nodes.len - finalized_index
  # TODO: can we have an unallocated `self.nodes`? i.e. self.nodes[0] is nil
  moveMem(self.nodes[0].addr, self.nodes[finalized_index].addr, tail * sizeof(ProtoNode))
  self.nodes.setLen(tail)

  # Adjust the indices map
  for index in self.indices.mvalues():
    index -= finalized_index
    if index < 0:
      return ForkChoiceError(
        kind: fcErrIndexUnderflow,
        underflowKind: fcUnderflowIndices
      )

  # Iterate through all the existing nodes and adjust their indices to match
  # the new layout of `self.nodes`
  for node in self.nodes.mitems():
    # If `node.parent` is less than `finalized_index`, set it to None
    if node.parent.isSome():
      let new_parent = node.parent.unsafeGet() - finalized_index
      if new_parent < 0:
        node.parent = none(Index)
      else:
        node.parent = some(new_parent)

    if node.best_child.isSome():
      let new_best_child = node.best_child.unsafeGet() - finalized_index
      if new_best_child < 0:
        return ForkChoiceError(
          kind: fcErrIndexUnderflow,
          underflowKind: fcUnderflowBestChild
        )
      node.best_child = some(new_best_child)

    if node.best_descendant.isSome():
      let new_best_descendant = node.best_descendant.unsafeGet() - finalized_index
      if new_best_descendant < 0:
        return ForkChoiceError(
          kind: fcErrIndexUnderflow,
          underflowKind: fcUnderflowBestDescendant
        )
      node.best_descendant = some(new_best_descendant)

  return ForkChoiceSuccess


func maybe_update_best_child_and_descendant(
       self: var ProtoArray,
       parent_index: Index,
       child_index: Index): ForkChoiceError =
  ## Observe the parent at `parent_index` with respect to the child at `child_index` and
  ## potentiatlly modify the `parent.best_child` and `parent.best_descendant` values
  ##
  ## There are four scenarios:
  ##
  ## 1. The child is already the best child
  ##    but it's now invalid due to a FFG change and should be removed.
  ## 2. The child is already the best child
  ##    and the parent is updated with the new best descendant
  ## 3. The child is not the best child but becomes the best child
  ## 4. The child is not the best child and does not become the best child

  if child_index notin {0..self.nodes.len-1}:
    return ForkChoiceError(
      kind: fcErrInvalidNodeIndex,
      index: child_index
    )
  if parent_index notin {0..self.nodes.len-1}:
    return ForkChoiceError(
      kind: fcErrInvalidNodeIndex,
      index: parent_index
    )

  # Aliases
  template child: untyped {.dirty.} = self.nodes[child_index]
  template parent: untyped {.dirty.} = self.nodes[parent_index]

  let (child_leads_to_viable_head, err) = self.node_leads_to_viable_head(child)
  if err.kind != fcSuccess:
    return err

  let # Aliases to the 3 possible (best_child, best_descendant) tuples
    change_to_none = (none(Index), none(Index))
    change_to_child = (
        some(child_index),
        # Nim `options` module doesn't implement option `or`
        if child.best_descendant.isSome(): child.best_descendant
        else: some(child_index)
      )
    no_change = (parent.best_child, parent.best_descendant)

  # TODO: state-machine? The control-flow is messy
  let (new_best_child, new_best_descendant) = block:
    if parent.best_child.isSome:
      let best_child_index = parent.best_child.unsafeGet()
      if best_child_index == child_index and not child_leads_to_viable_head:
        # The child is already the best-child of the parent
        # but it's not viable to be the head block => remove it
        change_to_none
      elif best_child_index == child_index:
        # If the child is the best-child already, set it again to ensure
        # that the best-descendant of the parent is up-to-date.
        change_to_child
      else:
        if best_child_index notin {0..self.nodes.len-1}:
          return ForkChoiceError(
            kind: fcErrInvalidBestDescendant,
            index: best_child_index
          )
        let best_child = self.nodes[best_child_index]

        let (best_child_leads_to_viable_head, err) = self.node_leads_to_viable_head(best_child)
        if err.kind != fcSuccess:
          return err

        if child_leads_to_viable_head and not best_child_leads_to_viable_head:
          # The child leads to a viable head, but the current best-child doesn't
          change_to_child
        elif not child_leads_to_viable_head and best_child_leads_to_viable_head:
          # The best child leads to a viable head, but the child doesn't
          no_change
        elif child.weight == best_child.weight:
          # Tie-breaker of equal weights by root
          if child.root.tiebreak(best_child.root):
            change_to_child
          else:
            no_change
        else: # Choose winner by weight
          if child.weight >= best_child.weight:
            change_to_child
          else:
            no_change
    else:
      if child_leads_to_viable_head:
        # There is no current best-child and the child is viable
        change_to_child
      else:
        # There is no current best-child but the child is not viable
        no_change

  self.nodes[parent_index].best_child = new_best_child
  self.nodes[parent_index].best_descendant = new_best_descendant

  return ForkChoiceSuccess

func node_leads_to_viable_head(
       self: ProtoArray, node: ProtoNode
     ): tuple[viable: bool, err: ForkChoiceError] =
  ## Indicates if the node itself or its best-descendant are viable
  ## for blockchain head
  let best_descendant_is_viable_for_head = block:
    if node.best_descendant.isSome():
      let best_descendant_index = node.best_descendant.unsafeGet()
      if best_descendant_index notin {0..self.nodes.len-1}:
        return (
          false,
          ForkChoiceError(
            kind: fcErrInvalidBestDescendant,
            index: best_descendant_index
          )
        )
      let best_descendant = self.nodes[best_descendant_index]
      self.node_is_viable_for_head(best_descendant)
    else:
      false

  return (
    best_descendant_is_viable_for_head or
      self.node_is_viable_for_head(node),
    ForkChoiceSuccess
  )

func node_is_viable_for_head(self: ProtoArray, node: ProtoNode): bool =
  ## This is the equivalent of `filter_block_tree` function in eth2 spec
  ## https://github.com/ethereum/eth2.0-specs/blob/v0.10.0/specs/phase0/fork-choice.md#filter_block_tree
  ##
  ## Any node that has a different finalized or justified epoch
  ## should not be viable for the head.
  (
    (node.justified_epoch == self.justified_epoch) or
    (self.justified_epoch == Epoch(0))
  ) and (
    (node.finalized_epoch == self.finalized_epoch) or
    (self.finalized_epoch == Epoch(0))
  )

# Sanity checks
# ----------------------------------------------------------------------
# Sanity checks on internal private procedures

when isMainModule:
  import nimcrypto/hash

  echo "Sanity checks on fork choice tiebreaks"

  block:
    let a = Eth2Digest.fromHex("0x0000000000000001000000000000000000000000000000000000000000000000")
    let b = Eth2Digest.fromHex("0x0000000000000000000000000000000000000000000000000000000000000000") # sha256(1)

    doAssert tiebreak(a, b)


  block:
    let a = Eth2Digest.fromHex("0x0000000000000002000000000000000000000000000000000000000000000000")
    let b = Eth2Digest.fromHex("0x0000000000000001000000000000000000000000000000000000000000000000") # sha256(1)

    doAssert tiebreak(a, b)


  block:
    let a = Eth2Digest.fromHex("0xD86E8112F3C4C4442126F8E9F44F16867DA487F29052BF91B810457DB34209A4") # sha256(2)
    let b = Eth2Digest.fromHex("0x7C9FA136D4413FA6173637E883B6998D32E1D675F88CDDFF9DCBCF331820F4B8") # sha256(1)

    doAssert tiebreak(a, b)
