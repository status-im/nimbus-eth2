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
  stew/results,
  # Internal
  ../spec/[datatypes, digest],
  # Fork choice
  ./fork_choice_types

logScope:
  topics = "fork_choice"

export results

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/fork-choice.md
# This is a port of https://github.com/sigp/lighthouse/pull/804
# which is a port of "Proto-Array": https://github.com/protolambda/lmd-ghost
# See also:
# - Protolambda port of Lighthouse: https://github.com/protolambda/eth2-py-hacks/blob/ae286567/proto_array.py
# - Prysmatic writeup: https://hackmd.io/bABJiht3Q9SyV3Ga4FT9lQ#High-level-concept
# - Gasper Whitepaper: https://arxiv.org/abs/2003.03052

# Helpers
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

template unsafeGet*[K, V](table: Table[K, V], key: K): V =
  ## Get a value from a Nim Table, turning KeyError into
  ## an AssertionError defect
  # Pointer is used to work around the lack of a `var` withValue
  try:
    table[key]
  except KeyError as exc:
    raiseAssert(exc.msg)

func `[]`(nodes: ProtoNodes, idx: Index): Option[ProtoNode] {.inline.} =
  ## Retrieve a ProtoNode at "Index"
  if idx < nodes.offset:
    return none(ProtoNode)
  let i = idx - nodes.offset
  if i >= nodes.buf.len:
    return none(ProtoNode)
  return some(nodes.buf[i])

func len*(nodes: ProtoNodes): int {.inline.} =
  nodes.buf.len

func add(nodes: var ProtoNodes, node: ProtoNode) {.inline.} =
  nodes.buf.add node

# Forward declarations
# ----------------------------------------------------------------------

func maybe_update_best_child_and_descendant(
  self: var ProtoArray, parent_index: Index, child_index: Index): FcResult[void]
func node_is_viable_for_head(self: ProtoArray, node: ProtoNode): bool
func node_leads_to_viable_head(self: ProtoArray, node: ProtoNode): FcResult[bool]

# ProtoArray routines
# ----------------------------------------------------------------------

func init*(T: type ProtoArray,
           justified_epoch: Epoch,
           finalized_root: Eth2Digest,
           finalized_epoch: Epoch): T =
  let node = ProtoNode(
    root: finalized_root,
    parent: none(int),
    justified_epoch: justified_epoch,
    finalized_epoch: finalized_epoch,
    weight: 0,
    best_child: none(int),
    best_descendant: none(int)
  )

  T(
    justified_epoch: justified_epoch,
    finalized_epoch: finalized_epoch,
    nodes: ProtoNodes(buf: @[node], offset: 0),
    indices: {node.root: 0}.toTable()
  )

func apply_score_changes*(
       self: var ProtoArray,
       deltas: var openarray[Delta],
       justified_epoch: Epoch,
       finalized_epoch: Epoch
     ): FcResult[void] =
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
  doAssert self.indices.len == self.nodes.len # By construction
  if deltas.len != self.indices.len:
    return err ForkChoiceError(
             kind: fcInvalidDeltaLen,
             deltasLen: deltas.len,
             indicesLen: self.indices.len
           )

  self.justified_epoch = justified_epoch
  self.finalized_epoch = finalized_epoch

  # Iterate backwards through all the indices in `self.nodes`
  for node_physical_index in countdown(self.nodes.len - 1, 0):
    template node: untyped {.dirty.}= self.nodes.buf[node_physical_index]
      ## Alias
      # This cannot raise the IndexError exception, how to tell compiler?

    if node.root == default(Eth2Digest):
      continue

    let node_delta = deltas[node_physical_index]

    # Apply the delta to the node
    # We fail fast if underflow, which shouldn't happen.
    # Note that delta can be negative but weight cannot
    let weight = node.weight + node_delta
    if weight < 0:
      return err ForkChoiceError(
        kind: fcDeltaUnderflow,
        index: node_physical_index
      )
    node.weight = weight

    # If the node has a parent, try to update its best-child and best-descendant
    if node.parent.isSome():
      let parent_logical_index = node.parent.unsafeGet()
      let parent_physical_index = parent_logical_index - self.nodes.offset
      if parent_physical_index < 0:
        # Orphan, for example
        #          0
        #         / \
        #        2   1
        #            |
        #            3
        #            |
        #            4
        # -------pruned here ------
        #          5   6
        #          |
        #          7
        #          |
        #          8
        #         / \
        #        9  10
        #
        # with 5 the canonical chain and 6 a discarded fork
        # that will be pruned next.
        break

      if parent_physical_index >= deltas.len:
        return err ForkChoiceError(
          kind: fcInvalidParentDelta,
          index: parent_physical_index
        )

      # Back-propagate the nodes delta to its parent.
      deltas[parent_physical_index] += node_delta

      let node_logical_index = node_physical_index + self.nodes.offset
      ? self.maybe_update_best_child_and_descendant(parent_logical_index, node_logical_index)

  return ok()

func on_block*(
       self: var ProtoArray,
       root: Eth2Digest,
       parent: Eth2Digest,
       justified_epoch: Epoch,
       finalized_epoch: Epoch
     ): FcResult[void] =
  ## Register a block with the fork choice
  ## A block `hasParentInForkChoice` may be false
  ## on fork choice initialization:
  ## - either from Genesis
  ## - or from a finalized state loaded from database

  # Note: if parent is an "Option" type, we can run out of stack space.

  # If the block is already known, ignore it
  if root in self.indices:
    return ok()

  var parent_index: Index
  self.indices.withValue(parent, index) do:
    parent_index = index[]
  do:
    return err ForkChoiceError(
      kind: fcUnknownParent,
      child_root: root,
      parent_root: parent
    )

  let node_logical_index = self.nodes.offset + self.nodes.buf.len

  let node = ProtoNode(
    root: root,
    parent: some(parent_index),
    justified_epoch: justified_epoch,
    finalized_epoch: finalized_epoch,
    weight: 0,
    best_child: none(int),
    best_descendant: none(int)
  )

  self.indices[node.root] = node_logical_index
  self.nodes.add node

  ? self.maybe_update_best_child_and_descendant(parent_index, node_logical_index)

  return ok()

func find_head*(
        self: var ProtoArray,
        head: var Eth2Digest,
        justified_root: Eth2Digest
     ): FcResult[void] =
  ## Follows the best-descendant links to find the best-block (i.e. head-block)
  ##
  ## ⚠️ Warning
  ## The result may not be accurate if `on_new_block`
  ## is not followed by `apply_score_changes` as `on_new_block` does not
  ## update the whole tree.

  var justified_index: Index
  self.indices.withValue(justified_root, value) do:
    justified_index = value[]
  do:
    return err ForkChoiceError(
      kind: fcJustifiedNodeUnknown,
      block_root: justified_root
    )

  let justified_node = self.nodes[justified_index]
  if justified_node.isNone():
    return err ForkChoiceError(
      kind: fcInvalidJustifiedIndex,
      index: justified_index
    )

  let best_descendant_index = justified_node.get().best_descendant.get(justified_index)
  let best_node = self.nodes[best_descendant_index]
  if best_node.isNone():
    return err ForkChoiceError(
      kind: fcInvalidBestDescendant,
      index: best_descendant_index
    )

  # Perform a sanity check to ensure the node can be head
  if not self.node_is_viable_for_head(best_node.get()):
    return err ForkChoiceError(
      kind: fcInvalidBestNode,
      start_root: justified_root,
      justified_epoch: self.justified_epoch,
      finalized_epoch: self.finalized_epoch,
      head_root: justified_node.get().root,
      head_justified_epoch: justified_node.get().justified_epoch,
      head_finalized_epoch: justified_node.get().finalized_epoch
    )

  head = best_node.get().root
  return ok()

func prune*(
       self: var ProtoArray,
       finalized_root: Eth2Digest
     ): FcResult[void] =
  ## Update the tree with new finalization information.
  ## The tree is pruned if and only if:
  ## - The `finalized_root` and finalized epoch are different from current
  ##
  ## Returns error if:
  ## - The finalized epoch is less than the current one
  ## - The finalized epoch matches the current one but the finalized root is different
  ## - Internal error due to invalid indices in `self`

  var finalized_index: int
  self.indices.withValue(finalized_root, value) do:
    finalized_index = value[]
  do:
    return err ForkChoiceError(
      kind: fcFinalizedNodeUnknown,
      block_root: finalized_root
    )

  if finalized_index == self.nodes.offset:
    # Nothing to do
    return ok()

  if finalized_index < self.nodes.offset:
    return err ForkChoiceError(
      kind: fcPruningFromOutdatedFinalizedRoot,
      finalizedRoot: finalized_root
    )

  trace "Pruning blocks from fork choice",
    finalizedRoot = shortlog(finalized_root),
    pcs = "prune"

  let final_phys_index = finalized_index-self.nodes.offset
  for node_index in 0 ..< final_phys_index:
    self.indices.del(self.nodes.buf[node_index].root)

  # Drop all nodes prior to finalization.
  # This is done in-place with `moveMem` to avoid costly reallocations.
  static: doAssert ProtoNode.supportsCopyMem(), "ProtoNode must be a trivial type"
  let tail = self.nodes.len - final_phys_index
  # TODO: can we have an unallocated `self.nodes`? i.e. self.nodes[0] is nil
  moveMem(self.nodes.buf[0].addr, self.nodes.buf[final_phys_index].addr, tail * sizeof(ProtoNode))
  self.nodes.buf.setLen(tail)

  # update offset
  self.nodes.offset = finalized_index

  return ok()


func maybe_update_best_child_and_descendant(
       self: var ProtoArray,
       parent_index: Index,
       child_index: Index): Result[void, ForkChoiceError] =
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

  let child = self.nodes[child_index]
  if child.isNone():
    return err ForkChoiceError(
      kind: fcInvalidNodeIndex,
      index: child_index
    )

  let parent = self.nodes[parent_index]
  if parent.isNone():
    return err ForkChoiceError(
      kind: fcInvalidNodeIndex,
      index: parent_index
    )

  let child_leads_to_viable_head = ? self.node_leads_to_viable_head(child.get())

  let # Aliases to the 3 possible (best_child, best_descendant) tuples
    change_to_none = (none(Index), none(Index))
    change_to_child = (
        some(child_index),
        # Nim `options` module doesn't implement option `or`
        if child.get().best_descendant.isSome(): child.get().best_descendant
        else: some(child_index)
      )
    no_change = (parent.get().best_child, parent.get().best_descendant)

  # TODO: state-machine? The control-flow is messy
  let (new_best_child, new_best_descendant) = block:
    if parent.get().best_child.isSome:
      let best_child_index = parent.get().best_child.unsafeGet()
      if best_child_index == child_index and not child_leads_to_viable_head:
        # The child is already the best-child of the parent
        # but it's not viable to be the head block => remove it
        change_to_none
      elif best_child_index == child_index:
        # If the child is the best-child already, set it again to ensure
        # that the best-descendant of the parent is up-to-date.
        change_to_child
      else:
        let best_child = self.nodes[best_child_index]
        if best_child.isNone():
          return err ForkChoiceError(
            kind: fcInvalidBestDescendant,
            index: best_child_index
          )

        let best_child_leads_to_viable_head =
          ? self.node_leads_to_viable_head(best_child.get())

        if child_leads_to_viable_head and not best_child_leads_to_viable_head:
          # The child leads to a viable head, but the current best-child doesn't
          change_to_child
        elif not child_leads_to_viable_head and best_child_leads_to_viable_head:
          # The best child leads to a viable head, but the child doesn't
          no_change
        elif child.get().weight == best_child.get().weight:
          # Tie-breaker of equal weights by root
          if child.get().root.tiebreak(best_child.get().root):
            change_to_child
          else:
            no_change
        else: # Choose winner by weight
          let cw = child.get().weight
          let bw = best_child.get().weight
          if cw >= bw:
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

  self.nodes.buf[parent_index - self.nodes.offset].best_child = new_best_child
  self.nodes.buf[parent_index - self.nodes.offset].best_descendant = new_best_descendant

  return ok()

func node_leads_to_viable_head(
       self: ProtoArray, node: ProtoNode
     ): FcResult[bool] =
  ## Indicates if the node itself or its best-descendant are viable
  ## for blockchain head
  let best_descendant_is_viable_for_head = block:
    if node.best_descendant.isSome():
      let best_descendant_index = node.best_descendant.unsafeGet()
      let best_descendant = self.nodes[best_descendant_index]
      if best_descendant.isNone:
        return err ForkChoiceError(
            kind: fcInvalidBestDescendant,
            index: best_descendant_index
          )
      self.node_is_viable_for_head(best_descendant.get())
    else:
      false

  return ok(best_descendant_is_viable_for_head or
      self.node_is_viable_for_head(node))

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
