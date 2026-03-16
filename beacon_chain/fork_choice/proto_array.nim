# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  # Standard library
  std/[tables, typetraits],
  # Status libraries
  chronicles,
  results,
  # Internal
  ../spec/datatypes/base,
  ../spec/helpers,
  # Fork choice
  ./fork_choice_types

logScope:
  topics = "fork_choice"

export results

# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md
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
  true

template unsafeGet*[K, V](table: Table[K, V], key: K): V =
  ## Get a value from a Nim Table, turning KeyError into
  ## an AssertionError defect
  try:
    table[key]
  except KeyError as exc:
    raiseAssert(exc.msg)

func `[]`(nodes: ProtoNodes, idx: Index): Opt[ProtoNode] =
  ## Retrieve a ProtoNode at "Index"
  if idx < nodes.offset:
    return Opt.none(ProtoNode)
  let i = idx - nodes.offset
  if i >= nodes.buf.len:
    return Opt.none(ProtoNode)
  Opt.some(nodes.buf[i])

func len*(nodes: ProtoNodes): int =
  nodes.buf.len

func add(nodes: var ProtoNodes, node: ProtoNode) =
  nodes.buf.add node

func find(self: ProtoArray, root: Eth2Digest): Index =
  self.indices.getOrDefault(root, -1)

# Forward declarations
# ----------------------------------------------------------------------

func maybeUpdateBestChildAndDescendant(self: var ProtoArray,
                                       parentIdx: Index,
                                       childIdx: Index): FcResult[void]

func nodeIsViableForHead(
    self: var ProtoArray, node: ProtoNode, nodeIdx: Index): bool
func nodeLeadsToViableHead(
    self: var ProtoArray, node: ProtoNode, nodeIdx: Index): FcResult[bool]

# ProtoArray routines
# ----------------------------------------------------------------------

func init*(T: type ProtoArray, finalized: Checkpoint, currentSlot: Slot): T =
  let node = ProtoNode(
    bid: BlockId(
      slot: finalized.epoch.start_slot,
      root: finalized.root),
    parent: Opt.none(int),
    checkpoints: FinalityCheckpoints(
      justified: finalized,
      finalized: finalized))

  T(currentSlot: currentSlot,
    checkpoints: node.checkpoints,
    nodes: ProtoNodes(buf: @[node], offset: 0),
    indices: {node.bid.root: 0}.toTable())

func unrealized_justified*(
    self: ProtoArray, justified: Checkpoint): Checkpoint =
  result = justified
  for unrealized in self.currentEpochTips.values:
    if unrealized.justified.epoch > result.epoch:
      result = unrealized.justified

iterator realizePendingCheckpoints*(
    self: var ProtoArray): FinalityCheckpoints =
  # Pull-up chain tips from previous epoch
  for idx, unrealized in self.currentEpochTips:
    let physicalIdx = idx - self.nodes.offset
    if unrealized != self.nodes.buf[physicalIdx].checkpoints:
      trace "Pulling up chain tip",
        blck = self.nodes.buf[physicalIdx].bid.root,
        checkpoints = self.nodes.buf[physicalIdx].checkpoints,
        unrealized
      self.nodes.buf[physicalIdx].checkpoints = unrealized

    yield unrealized

  # Reset tip tracking for new epoch
  self.currentEpochTips.clear()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.3/specs/phase0/fork-choice.md#get_weight
func calculateProposerBoost(justifiedTotalActiveBalance: Gwei): Gwei =
  let committee_weight = justifiedTotalActiveBalance div SLOTS_PER_EPOCH
  (committee_weight * PROPOSER_SCORE_BOOST) div 100

func applyScoreChanges*(
    self: var ProtoArray,
    deltas: var openArray[Delta],
    currentSlot: Slot,
    checkpoints: FinalityCheckpoints,
    justifiedTotalActiveBalance: Gwei,
    proposerBoostRoot: Eth2Digest): FcResult[void] =
  ## Iterate backwards through the array, touching all nodes and their parents
  ## and potentially the best-child of each parent.
  #
  # The structure of `self.nodes` array ensures that the child of each node
  # is always touched before its parent.
  #
  # For each node the following is done:
  #
  # 1. Update the node's weight with the corresponding delta.
  # 2. Backpropagate each node's delta to its parent's delta.
  # 3. Compare the current node with the parent's best-child,
  #    updating if the current node should become the best-child
  # 4. If required, update the parent's best-descendant with the current node
  #    or its best-descendant
  doAssert self.indices.len == self.nodes.len # By construction
  if deltas.len != self.indices.len:
    return err ForkChoiceError(
      kind: fcInvalidDeltaLen,
      deltasLen: deltas.len,
      indicesLen: self.indices.len)

  doAssert currentSlot >= self.currentSlot
  self.currentSlot = currentSlot

  doAssert checkpoints.finalized.epoch >= self.checkpoints.finalized.epoch
  doAssert checkpoints.finalized.epoch > self.checkpoints.finalized.epoch or
    checkpoints.finalized.root == self.checkpoints.finalized.root or
    self.checkpoints.finalized.epoch == GENESIS_EPOCH
  self.checkpoints = checkpoints

  ## Alias
  # This cannot raise the IndexError exception, how to tell compiler?
  template node: untyped {.dirty.} =
    self.nodes.buf[nodePhysicalIdx]

  # Default value, if not otherwise set in first node loop
  var proposerBoostScore: Gwei

  # Iterate backwards through all the indices in `self.nodes`
  for nodePhysicalIdx in countdown(self.nodes.len - 1, 0):
    if node.bid.root.isZero:
      continue

    var nodeDelta = deltas[nodePhysicalIdx]

    # If we find the node for which the proposer boost was previously applied,
    # decrease the delta by the previous score amount.
    if  (not self.previousProposerBoostRoot.isZero) and
        self.previousProposerBoostRoot == node.bid.root:
          if  nodeDelta < 0 and
              nodeDelta - low(Delta) < self.previousProposerBoostScore.int64:
            return err ForkChoiceError(
                kind: fcDeltaUnderflow,
                index: nodePhysicalIdx)
          nodeDelta -= self.previousProposerBoostScore.int64

    # If we find the node matching the current proposer boost root, increase
    # the delta by the new score amount.
    #
    # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.3/specs/phase0/fork-choice.md#get_weight
    if (not proposerBoostRoot.isZero) and proposerBoostRoot == node.bid.root:
      proposerBoostScore = calculateProposerBoost(justifiedTotalActiveBalance)
      if  nodeDelta >= 0 and
          high(Delta) - nodeDelta < proposerBoostScore.int64:
        return err ForkChoiceError(
            kind: fcDeltaOverflow,
            index: nodePhysicalIdx)
      nodeDelta += proposerBoostScore.int64

    # Apply the delta to the node
    # We fail fast if underflow, which shouldn't happen.
    # Note that delta can be negative but weight cannot
    let weight = node.weight + nodeDelta
    if weight < 0:
      return err ForkChoiceError(
        kind: fcDeltaUnderflow,
        index: nodePhysicalIdx)
    node.weight = weight

    # If the node has a parent, try to update its best-child and best-descendent
    if node.parent.isSome():
      let
        parentLogicalIdx = node.parent.unsafeGet()
        parentPhysicalIdx = parentLogicalIdx - self.nodes.offset
      if parentPhysicalIdx < 0:
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
        continue

      if parentPhysicalIdx >= deltas.len:
        return err ForkChoiceError(
          kind: fcInvalidParentDelta,
          index: parentPhysicalIdx)

      # Back-propagate the nodes delta to its parent.
      deltas[parentPhysicalIdx] += nodeDelta

  # After applying all deltas, update the `previous_proposer_boost`.
  self.previousProposerBoostRoot = proposerBoostRoot
  self.previousProposerBoostScore = proposerBoostScore

  for nodePhysicalIdx in countdown(self.nodes.len - 1, 0):
    if node.bid.root.isZero:
      continue

    if node.parent.isSome():
      let parentLogicalIdx = node.parent.unsafeGet()
      let parentPhysicalIdx = parentLogicalIdx - self.nodes.offset
      if parentPhysicalIdx < 0:
        # Orphan
        continue

      let nodeLogicalIdx = nodePhysicalIdx + self.nodes.offset
      ? self.maybeUpdateBestChildAndDescendant(parentLogicalIdx, nodeLogicalIdx)

  ok()

func onBlock*(
    self: var ProtoArray,
    bid: BlockId,
    parent: Eth2Digest,
    checkpoints: FinalityCheckpoints,
    unrealized = Opt.none(FinalityCheckpoints)): FcResult[void] =
  ## Register a block with the fork choice
  ## A block `hasParentInForkChoice` may be false
  ## on fork choice initialization:
  ## - either from Genesis
  ## - or from a finalized state loaded from database

  # Note: if parent is an "Opt" type, we can run out of stack space.

  # If the block is already known, ignore it
  if bid.root in self.indices:
    return ok()

  let parentIdx = self.find(parent)
  if parentIdx < 0:
    return err ForkChoiceError(
      kind: fcUnknownParent,
      childRoot: bid.root,
      parentRoot: parent)

  let nodeLogicalIdx = self.nodes.offset + self.nodes.buf.len

  let node = ProtoNode(
    bid: bid,
    parent: Opt.some(parentIdx),
    checkpoints: checkpoints)

  self.indices[node.bid.root] = nodeLogicalIdx
  self.nodes.add node

  self.currentEpochTips.del parentIdx
  if unrealized.isSome:
    self.currentEpochTips[nodeLogicalIdx] = unrealized.get

  ? self.maybeUpdateBestChildAndDescendant(parentIdx, nodeLogicalIdx)

  ok()

func findHead*(self: var ProtoArray, head: var Eth2Digest): FcResult[void] =
  ## Follows the best-descendant links to find the best-block (i.e. head-block)
  ##
  ## ️ Warning
  ## The result may not be accurate if `onBlock` is not followed by
  ## `applyScoreChanges` as `onBlock` does not update the whole tree.
  template justifiedRoot: Eth2Digest = self.checkpoints.justified.root
  let justifiedIdx = self.find(justifiedRoot)
  if justifiedIdx < 0:
    return err ForkChoiceError(
      kind: fcJustifiedNodeUnknown,
      blockRoot: justifiedRoot)
  let
    justifiedNode = self.nodes[justifiedIdx].valueOr:
      return err ForkChoiceError(
        kind: fcInvalidJustifiedIndex,
        index: justifiedIdx)
    bestDescendantIdx = justifiedNode.bestDescendant.get(justifiedIdx)
    bestNode = self.nodes[bestDescendantIdx].valueOr:
      return err ForkChoiceError(
        kind: fcInvalidBestDescendant,
        index: bestDescendantIdx)

  # Perform a sanity check to ensure the node can be head
  if not self.nodeIsViableForHead(bestNode, bestDescendantIdx):
    return err ForkChoiceError(
      kind: fcInvalidBestNode,
      startRoot: justifiedRoot,
      fkChoiceCheckpoints: self.checkpoints,
      headRoot: justifiedNode.bid.root,
      headCheckpoints: justifiedNode.checkpoints)

  head = bestNode.bid.root
  ok()

func prune*(
    self: var ProtoArray,
    checkpoints: FinalityCheckpoints): FcResult[void] =
  ## Update the tree with new finalization information.
  ## The tree is pruned if and only if:
  ## - `checkpoints.finalized.root` and finalized epoch
  ##   are different from current
  ##
  ## Returns error if:
  ## - The finalized epoch is less than the current one
  ## - The finalized epoch matches the current one but the f
  ##   inalized root is different
  ## - Internal error due to invalid indices in `self`

  let finalizedIdx = self.find(checkpoints.finalized.root)
  if finalizedIdx < 0:
    return err ForkChoiceError(
      kind: fcFinalizedNodeUnknown,
      blockRoot: checkpoints.finalized.root)

  if finalizedIdx == self.nodes.offset:
    # Nothing to do
    return ok()

  if finalizedIdx < self.nodes.offset:
    return err ForkChoiceError(
      kind: fcPruningFromOutdatedFinalizedRoot,
      finalizedRoot: checkpoints.finalized.root)

  trace "Pruning blocks from fork choice", checkpoints

  let finalPhysicalIdx = finalizedIdx - self.nodes.offset
  for nodePhysicalIdx in 0 ..< finalPhysicalIdx:
    let nodeLogicalIdx = nodePhysicalIdx + self.nodes.offset
    self.currentEpochTips.del nodeLogicalIdx
    self.indices.del(self.nodes.buf[nodePhysicalIdx].bid.root)

  # Drop all nodes prior to finalization.
  # This is done in-place with `moveMem` to avoid costly reallocations.
  static: doAssert ProtoNode.supportsCopyMem(), "ProtoNode must be a trivial type"
  let tail = self.nodes.len - finalPhysicalIdx
  # TODO: can we have an unallocated `self.nodes`? i.e. self.nodes[0] is nil
  moveMem(self.nodes.buf[0].addr, self.nodes.buf[finalPhysicalIdx].addr, tail * sizeof(ProtoNode))
  self.nodes.buf.setLen(tail)

  # update offset
  self.nodes.offset = finalizedIdx

  ok()

func maybeUpdateBestChildAndDescendant(
    self: var ProtoArray, parentIdx: Index, childIdx: Index): FcResult[void] =
  ## Observe the parent at `parentIdx` with respect to the child at `childIdx` and
  ## potentially modify the `parent.bestChild` and `parent.bestDescendant` values
  ##
  ## There are four scenarios:
  ##
  ## 1. The child is already the best child
  ##    but it's now invalid due to a FFG change and should be removed.
  ## 2. The child is already the best child
  ##    and the parent is updated with the new best descendant
  ## 3. The child is not the best child but becomes the best child
  ## 4. The child is not the best child and does not become the best child

  let
    child = self.nodes[childIdx].valueOr:
      return err ForkChoiceError(
        kind: fcInvalidNodeIndex,
        index: childIdx)
    parent = self.nodes[parentIdx].valueOr:
      return err ForkChoiceError(
        kind: fcInvalidNodeIndex,
        index: parentIdx)
    childLeadsToViableHead =
      ? self.nodeLeadsToViableHead(child, childIdx)

    # Aliases to the 3 possible (bestChild, bestDescendant) tuples
    changeToNone = (Opt.none(Index), Opt.none(Index))
    changeToChild = (
        Opt.some(childIdx),
        # Nim `options` module doesn't implement option `or`
        if child.bestDescendant.isSome(): child.bestDescendant
        else: Opt.some(childIdx)
      )
    noChange = (parent.bestChild, parent.bestDescendant)

    # TODO: state-machine? The control-flow is messy
    (newBestChild, newBestDescendant) = block:
      if parent.bestChild.isSome:
        let bestChildIdx = parent.bestChild.unsafeGet()
        if bestChildIdx == childIdx and not childLeadsToViableHead:
          # The child is already the best-child of the parent
          # but it's not viable to be the head block => remove it
          changeToNone
        elif bestChildIdx == childIdx:
          # If the child is the best-child already, set it again to ensure
          # that the best-descendant of the parent is up-to-date.
          changeToChild
        else:
          let
            bestChild = self.nodes[bestChildIdx].valueOr:
              return err ForkChoiceError(
                kind: fcInvalidBestDescendant,
                index: bestChildIdx)
            bestChildLeadsToViableHead =
              ? self.nodeLeadsToViableHead(bestChild, bestChildIdx)
          if childLeadsToViableHead and not bestChildLeadsToViableHead:
            # The child leads to a viable head, but the current best-child doesn't
            changeToChild
          elif not childLeadsToViableHead and bestChildLeadsToViableHead:
            # The best child leads to a viable head, but the child doesn't
            noChange
          elif child.weight == bestChild.weight:
            # Tie-breaker of equal weights by root
            if child.bid.root.tiebreak(bestChild.bid.root):
              changeToChild
            else:
              noChange
          else: # Choose winner by weight
            let
              cw = child.weight
              bw = bestChild.weight
            if cw >= bw:
              changeToChild
            else:
              noChange
      else:
        if childLeadsToViableHead:
          # There is no current best-child and the child is viable
          changeToChild
        else:
          # There is no current best-child but the child is not viable
          noChange

  self.nodes.buf[parentIdx - self.nodes.offset]
    .bestChild = newBestChild
  self.nodes.buf[parentIdx - self.nodes.offset]
    .bestDescendant = newBestDescendant
  ok()

func nodeLeadsToViableHead(
    self: var ProtoArray, node: ProtoNode, nodeIdx: Index): FcResult[bool] =
  ## Indicates if the node itself or its best-descendant are viable
  ## for blockchain head
  let bestDescendantIsViableForHead = block:
    if node.bestDescendant.isSome():
      let
        bestDescendantIdx = node.bestDescendant.unsafeGet()
        bestDescendant = self.nodes[bestDescendantIdx].valueOr:
          return err ForkChoiceError(
            kind: fcInvalidBestDescendant,
            index: bestDescendantIdx)
      self.nodeIsViableForHead(bestDescendant, bestDescendantIdx)
    else:
      false

  ok(bestDescendantIsViableForHead or self.nodeIsViableForHead(node, nodeIdx))

func nodeIsViableForHead(
    self: var ProtoArray, node: ProtoNode, nodeIdx: Index): bool =
  ## This is the equivalent of `filter_block_tree` function in consensus specs
  ## https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#filter_block_tree

  if node.invalid:
    return false

  # The voting source should be at the same height as the store's
  # justified checkpoint
  var correctJustified =
    self.checkpoints.justified.epoch == GENESIS_EPOCH or
    node.checkpoints.justified.epoch == self.checkpoints.justified.epoch

  if not correctJustified:
    # The voting source should be either at the same height as the store's
    # justified checkpoint or not more than two epochs ago
    correctJustified =
      node.checkpoints.justified.epoch + 2 >= self.currentSlot.epoch

  if not correctJustified:
    false
  elif self.checkpoints.finalized.epoch == GENESIS_EPOCH:
    true
  elif node.sharedFinalizedEpoch == self.checkpoints.finalized.epoch:
    # Already checked to share history with `self.checkpoints.finalized`.
    # `self.checkpoints.finalized` cannot reorg, see `applyScoreChanges`
    true
  else:
    # Check that this node is not going to be pruned
    let
      finalizedEpoch = self.checkpoints.finalized.epoch
      finalizedSlot = finalizedEpoch.start_slot
    var ancestor = Opt.some node
    while ancestor.isSome and ancestor.unsafeGet.bid.slot > finalizedSlot and
        ancestor.unsafeGet.sharedFinalizedEpoch != finalizedEpoch:
      if ancestor.unsafeGet.parent.isSome:
        ancestor = self.nodes[ancestor.unsafeGet.parent.unsafeGet]
      else:
        ancestor.reset()
    if ancestor.isNone:
      false
    elif ancestor.unsafeGet.sharedFinalizedEpoch != finalizedEpoch and
        ancestor.unsafeGet.bid.root != self.checkpoints.finalized.root:
      false
    else:
      # An ancestor was already checked to share canonical history,
      # or we reached the `finalizedSlot` and the root matches expectations
      let ancestorSlot = ancestor.unsafeGet.bid.slot
      var idx = nodeIdx
      template mutableNode: untyped = self.nodes.buf[idx - self.nodes.offset]
      while mutableNode.bid.slot > ancestorSlot:
        mutableNode.sharedFinalizedEpoch = finalizedEpoch
        idx = mutableNode.parent.unsafeGet
      mutableNode.sharedFinalizedEpoch = finalizedEpoch
      true

func propagateInvalidity*(
    self: var ProtoArray, startPhysicalIdx: Index) =
  # Called when startPhysicalIdx is updated in a parent role, so the pairs of
  # indices generated of (parent, child) where both >= startPhysicalIdx, mean
  # the loop in general from the child's perspective starts one index higher.
  for nodePhysicalIdx in startPhysicalIdx + 1 ..< self.nodes.len:
    let nodeParent = self.nodes.buf[nodePhysicalIdx].parent
    if nodeParent.isNone:
      continue

    let
      parentLogicalIdx = nodeParent.unsafeGet()
      parentPhysicalIdx = parentLogicalIdx - self.nodes.offset

    # Former case is orphaned, latter is invalid, but caught in score updates
    if parentPhysicalIdx < 0 or parentPhysicalIdx >= self.nodes.len:
      continue

    # Invalidity transmits to all descendants
    if self.nodes.buf[parentPhysicalIdx].invalid:
      self.nodes.buf[nodePhysicalIdx].invalid = true

# Diagnostics
# ----------------------------------------------------------------------
# Helpers to dump internal state

type ProtoArrayItem* = object
  bid*: BlockId
  parent*: Eth2Digest
  checkpoints*: FinalityCheckpoints
  unrealized*: Opt[FinalityCheckpoints]
  weight*: uint64
  invalid*: bool
  bestChild*: Eth2Digest
  bestDescendant*: Eth2Digest

func root(self: ProtoNodes, logicalIdx: Opt[Index]): Eth2Digest =
  if logicalIdx.isNone:
    return ZERO_HASH
  let node = self[logicalIdx.unsafeGet]
  if node.isNone:
    return ZERO_HASH
  node.unsafeGet.bid.root

iterator items*(self: ProtoArray): ProtoArrayItem =
  ## Iterate over all nodes known by fork choice.
  doAssert self.indices.len == self.nodes.len
  for nodePhysicalIdx, node in self.nodes.buf:
    if node.bid.root.isZero:
      continue

    let unrealized = block:
      let nodeLogicalIdx = nodePhysicalIdx + self.nodes.offset
      if self.currentEpochTips.hasKey(nodeLogicalIdx):
        Opt.some self.currentEpochTips.unsafeGet(nodeLogicalIdx)
      else:
        Opt.none(FinalityCheckpoints)

    yield ProtoArrayItem(
      bid: node.bid,
      parent: self.nodes.root(node.parent),
      checkpoints: node.checkpoints,
      unrealized: unrealized,
      weight: cast[uint64](node.weight),
      invalid: node.invalid,
      bestChild: self.nodes.root(node.bestChild),
      bestDescendant: self.nodes.root(node.bestDescendant))

# Sanity checks
# ----------------------------------------------------------------------
# Sanity checks on internal private procedures

when isMainModule:
  import nimcrypto/hash

  echo "Sanity checks on fork choice tiebreaks"

  block:
    const a = Eth2Digest.fromHex("0x0000000000000001000000000000000000000000000000000000000000000000")
    const b = Eth2Digest.fromHex("0x0000000000000000000000000000000000000000000000000000000000000000") # sha256(1)

    doAssert tiebreak(a, b)

  block:
    const a = Eth2Digest.fromHex("0x0000000000000002000000000000000000000000000000000000000000000000")
    const b = Eth2Digest.fromHex("0x0000000000000001000000000000000000000000000000000000000000000000") # sha256(1)

    doAssert tiebreak(a, b)

  block:
    const a = Eth2Digest.fromHex("0xD86E8112F3C4C4442126F8E9F44F16867DA487F29052BF91B810457DB34209A4") # sha256(2)
    const b = Eth2Digest.fromHex("0x7C9FA136D4413FA6173637E883B6998D32E1D675F88CDDFF9DCBCF331820F4B8") # sha256(1)

    doAssert tiebreak(a, b)
