# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  # Standard library
  std/[tables, sets],
  # Status libraries
  results, chronicles,
  # Internal
  ../spec/[beaconstate, helpers, state_transition_block],
  ../spec/datatypes/[phase0, altair, bellatrix],
  # Fork choice
  ../consensus_object_pools/[spec_cache, blockchain_dag],
  "."/[fork_choice_types, proto_array]

func isGloasEnabled*(dag: ChainDAGRef, slot: Slot): bool =
  slot.epoch >= dag.cfg.GLOAS_FORK_EPOCH

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.3/specs/gloas/fork-choice.md#new-on_payload_attestation_message
proc on_payload_attestation_message*(
   self: var ForkChoice,
   dag: ChainDAGRef,
   validator_index: ValidatorIndex,
   beacon_block_root: Eth2Digest,
   slot: Slot,
   payload_present: bool,
   blob_data_available: bool,
   is_from_block: bool = false): FcResult[void] =
  ## Run ``on_payload_attestation_message`` upon receiving
  ## a new ``ptc_message`` directly on the wire.

  if not dag.isGloasEnabled(slot):
    return ok()

  # The beacon block root must be known
  if beacon_block_root notin self.backend.proto_array.indices:
    return ok()

  # PTC attestation must be for a known block.
  # If block is unknown, delay consideration until the block is found
  discard self.backend.ptc_vote.mgetOrPut(
    beacon_block_root, default(PtcVotes))

  withState(dag.headState):
    when consensusFork >= ConsensusFork.Gloas:
      # check that its for the current slot if it is coming from the wire
      if not is_from_block:
        if slot != self.checkpoints.time.slotOrZero(dag.timeParams):
          return ok()

      var
        ptc_index = -1
        i = 0

      for vidx in get_ptc(forkyState.data, slot):
        if vidx == validator_index:
          ptc_index = i
          break
        inc i

      # Check that the attester is from the PTC
      if ptc_index >= 0:
        var votes =
          self.backend.ptc_vote.mgetOrPut(
            beacon_block_root, default(PtcVotes))
        votes.voted.setBit(ptc_index)
        if payload_present:
          votes.value.setBit(ptc_index)
        else:
          votes.value.clearBit(ptc_index)
        self.backend.ptc_vote[beacon_block_root] = votes

        var da_votes =
          self.backend.ptc_data_availability_vote.mgetOrPut(
            beacon_block_root, default(PtcVotes))
        da_votes.voted.setBit(ptc_index)
        if blob_data_available:
          da_votes.value.setBit(ptc_index)
        else:
          da_votes.value.clearBit(ptc_index)
        self.backend.ptc_data_availability_vote[beacon_block_root] = da_votes

        trace "Recorded PTC vote",
          validator_index, payload_present, blob_data_available
  ok()

# Block timeliness and proposer boost
# ----------------------------------------------------------------------

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.3/specs/gloas/fork-choice.md#modified-record_block_timeliness
proc record_block_timeliness*(
    self: var ForkChoice, dag: ChainDAGRef,
    blck_slot: Slot, root: Eth2Digest,
    consensusFork: ConsensusFork) =
  let
    current_slot = self.checkpoints.time.slotOrZero(dag.timeParams)
    is_current_slot = current_slot == blck_slot

  self.backend.block_timeliness[root] = [
    is_current_slot and self.checkpoints.time <
      current_slot.attestation_deadline(dag.timeParams, consensusFork),
    is_current_slot and self.checkpoints.time <
      current_slot.payload_attestation_deadline(dag.timeParams)]

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/phase0/fork-choice.md#update_proposer_boost_root
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.3/specs/gloas/fork-choice.md#modified-update_proposer_boost_root
proc update_proposer_boost_root*(
    self: var ForkChoice, dag: ChainDAGRef,
    blckRef: BlockRef, blck: ForkyTrustedBeaconBlock, current_slot: Slot) =

  template is_first_block: bool =
    self.checkpoints.proposer_boost_root == ZERO_HASH

  let is_timely = self.backend.block_timeliness.getOrDefault(
    blckRef.root, [false, false])[ATTESTATION_TIMELINESS_INDEX]

  # Add proposer score boost if the block is the first timely block
  # for this slot, with the same proposer as the canonical chain.
  if is_timely and is_first_block:
    # Only apply boost if the block's proposer matches the expected proposer
    # on the canonical chain (head advanced to current slot).
    let expectedProposer = dag.getProposer(dag.head, current_slot)
    if expectedProposer.isSome and
        blck.proposer_index == expectedProposer.get().uint64:
      self.checkpoints.proposer_boost_root = blckRef.root

# Payload timeliness and data availability
# ----------------------------------------------------------------------

func ptcVoteAboveThreshold(
    self: ForkChoiceBackend, root: Eth2Digest,
    votes: Table[Eth2Digest, PtcVotes], threshold: uint64): bool =
  # The beacon block root must be known AND payload loacally available
  root in votes and root in self.execution_payload_states and
    votes.getOrDefault(root, default(PtcVotes)).value.countOnes().uint64 >
      threshold

# https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/gloas/fork-choice.md#new-is_payload_timely
func is_payload_timely*(self: ForkChoiceBackend, root: Eth2Digest): bool =
  ## Return whether the execution payload for the beacon block with root ``root``
  ## was voted as present by the PTC, and was locally determined to be available.
  self.ptcVoteAboveThreshold(root, self.ptc_vote, PAYLOAD_TIMELY_THRESHOLD)

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.3/specs/gloas/fork-choice.md#new-is_payload_data_available
func is_payload_data_available(
    self: ForkChoiceBackend, root: Eth2Digest): bool =
  ## Return whether the blob data for the beacon block with root ``root``
  ## was voted as present by the PTC, and was locally determined to be available.
  self.ptcVoteAboveThreshold(
    root, self.ptc_vote, DATA_AVAILABILITY_TIMELY_THRESHOLD)

# Tree navigation helpers
# ----------------------------------------------------------------------

template getPhysicalNode*(
    self: var ForkChoice, logicalIdx: int): ptr ProtoNode =
  let physicalIdx = logicalIdx - self.backend.proto_array.nodes.offset
  if physicalIdx >= 0 and
      physicalIdx < self.backend.proto_array.nodes.buf.len:
    addr self.backend.proto_array.nodes.buf[physicalIdx]
  else: nil

template getNode*(
    self: var ForkChoice, root: Eth2Digest): ptr ProtoNode =
  let idx = self.backend.proto_array.indices.getOrDefault(root, -1)
  if idx < 0: nil
  else:
    self.getPhysicalNode(idx)

#https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.3/specs/gloas/fork-choice.md#new-should_extend_payload
func should_extend_payload*(
    self: var ForkChoice, root: Eth2Digest): bool =
  if self.backend.is_payload_timely(root) and
      self.backend.is_payload_data_available(root):
    return true

  let proposer_root = self.checkpoints.proposer_boost_root
  if proposer_root.isZero:
    return true

  let proposer_node = self.getNode(proposer_root)
  if proposer_node == nil or proposer_node.parent.isNone:
    return true

  let parent_node = self.getPhysicalNode(proposer_node.parent.get())
  if parent_node == nil or parent_node.bid.root != root:
    return true

  proposer_node.parentPayloadStatus == PAYLOAD_STATUS_FULL

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.0/specs/gloas/fork-choice.md#new-get_payload_status_tiebreaker
func get_payload_status_tiebreaker*(
    self: var ForkChoice, node: ForkChoiceNode,
    current_slot: Slot, dag: ChainDAGRef): uint8 =
  if not dag.isGloasEnabled(current_slot):
    return node.payloadStatus

  let proto_node = self.getNode(node.root)
  if proto_node == nil:
    return node.payloadStatus

  if node.payloadStatus == PAYLOAD_STATUS_PENDING or
      not (proto_node.bid.slot + 1 == current_slot):
    return node.payloadStatus

  if node.payloadStatus == PAYLOAD_STATUS_EMPTY:
    1'u8
  elif node.payloadStatus == PAYLOAD_STATUS_FULL:
    if self.should_extend_payload(node.root):
      2'u8
    else:
      0'u8
  else:
    0'u8  # We shouldn't get here ideally

# Parent root --> child (root, logical index) mapping
type ChildrenIndex* =
  Table[Eth2Digest, seq[(Eth2Digest, fork_choice_types.Index)]]


# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.4/specs/gloas/fork-choice.md#modified-get_head
# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#filter_block_tree
func filter_block_tree*(
    self: var ForkChoice,
    block_root: Eth2Digest,
    childrenIdx: ChildrenIndex,
    filtered: var HashSet[Eth2Digest]): bool =
  ## Recursively filter the block tree to only include blocks on branches
  ## where at least one leaf has compatible justified/finalized checkpoints.
  let idx = self.backend.proto_array.indices.getOrDefault(block_root, -1)
  if idx < 0: return false
  let node = self.getPhysicalNode(idx)
  if node == nil or node.invalid: return false

  let children = childrenIdx.getOrDefault(block_root)
  if children.len > 0:
    var anyViable = false
    for (childRoot, _) in children:
      if self.filter_block_tree(childRoot, childrenIdx, filtered):
        anyViable = true
    if anyViable:
      filtered.incl(block_root)
    return anyViable
  else:
    # Leaf: reuse proto_array's viability check
    if self.backend.proto_array.nodeIsViableForHead(node[], idx):
      filtered.incl(block_root)
      return true
    return false

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.3/specs/gloas/fork-choice.md#new-get_node_children
func get_node_children*(
    self: var ForkChoice, node: ForkChoiceNode,
    dag: ChainDAGRef, childrenIdx: ChildrenIndex,
    filtered: HashSet[Eth2Digest]): seq[ForkChoiceNode] =
  if not dag.isGloasEnabled(dag.head.slot):
    for (root, idx) in childrenIdx.getOrDefault(node.root):
      result.add(ForkChoiceNode(
        root: root, payloadStatus: PAYLOAD_STATUS_PENDING))
    return

  if node.payloadStatus == PAYLOAD_STATUS_PENDING:
    result.add(ForkChoiceNode(
      root: node.root, payloadStatus: PAYLOAD_STATUS_EMPTY))

    if node.root in self.backend.execution_payload_states:
      result.add(ForkChoiceNode(
        root: node.root, payloadStatus: PAYLOAD_STATUS_FULL))

      trace "PENDING expanded to EMPTY + FULL",
        has_payload = true
    else:
      trace "PENDING expanded to EMPTY ONLY",
        has_payload = false
  else:
    for (root, idx) in childrenIdx.getOrDefault(node.root):
      if root notin filtered:
        continue

      let child = self.getPhysicalNode(idx)
      if child == nil:
        continue

      if child.parentPayloadStatus != node.payloadStatus:
        continue

      result.add(ForkChoiceNode(
        root: root, payloadStatus: PAYLOAD_STATUS_PENDING))
    trace "EMPTY/FULL expanded to child blocks",
      children = result.len

func get_ancestor_at_slot(
    self: var ForkChoice, root: Eth2Digest,
    target_slot: Slot): Option[(Eth2Digest, PayloadStatus)] =
  var
    current_root = root
    child_root = root
    iterations = 0

  while iterations < 1000:
    inc iterations
    let idx = self.backend.proto_array.indices.getOrDefault(current_root, -1)
    if idx < 0: return none((Eth2Digest, PayloadStatus))

    let node = self.getPhysicalNode(idx)
    if node == nil: return none((Eth2Digest, PayloadStatus))

    if node.bid.slot < target_slot:
      return none((Eth2Digest, PayloadStatus))

    if node.bid.slot == target_slot:
      # We already know `child_root` is the child of `current_root`
      let child_idx =
        self.backend.proto_array.indices.getOrDefault(child_root, -1)
      if child_idx < 0: return none((Eth2Digest, PayloadStatus))

      let child_node = self.getPhysicalNode(child_idx)
      if child_node == nil: return none((Eth2Digest, PayloadStatus))

      return some((current_root, child_node.parentPayloadStatus))

    if node.parent.isNone: return none((Eth2Digest, PayloadStatus))

    let
      parent_idx = node.parent.get()
      parent_node = self.getPhysicalNode(parent_idx)
    if parent_node == nil: return none((Eth2Digest, PayloadStatus))

    child_root = current_root
    current_root = parent_node.bid.root

  none((Eth2Digest, PayloadStatus))

# Vote support and weight calculations
# ----------------------------------------------------------------------

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.2/specs/gloas/fork-choice.md#new-is_supporting_vote
func is_supporting_vote(
    self: var ForkChoice, node: ForkChoiceNode,
    vote: VoteTracker, dag: ChainDAGRef): bool =
  ## Returns whether a vote for ``message.root`` supports the chain
  ## containing the beacon block ``node.root`` with the payload
  ## contents indicated by ``node.payload_status`` as head during
  ## slot ``node.slot`

  if vote.next_root.isZero: return false

  let proto_node = self.getNode(node.root)
  if proto_node == nil:
    return false

  # Pre Gloas, conventional root matching
  if proto_node.bid.slot.epoch < dag.cfg.GLOAS_FORK_EPOCH:
    return node.root == vote.next_root

  # Direct vote for this block
  if node.root == vote.next_root:
    if node.payloadStatus == PAYLOAD_STATUS_PENDING:
      return true
    if vote.next_slot <= proto_node.bid.slot:
      return false
    return if vote.payload_present:
      node.payloadStatus == PAYLOAD_STATUS_FULL
    else:
      node.payloadStatus == PAYLOAD_STATUS_EMPTY

  # Vote for a descendant
  let ancestor =
    self.get_ancestor_at_slot(vote.next_root, proto_node.bid.slot)
  if ancestor.isNone: return false

  let (ancestor_root, ancestor_payload_status) = ancestor.get()
  if ancestor_root != node.root: return false

  if node.payloadStatus == PAYLOAD_STATUS_PENDING:
    return true

  node.payloadStatus == ancestor_payload_status

func sumSupportingWeight(
    self: var ForkChoice, node: ForkChoiceNode, dag: ChainDAGRef): Gwei =
  let justified_balances = self.checkpoints.justified.balances
  for i in 0..<self.backend.votes.len:
    if i >= justified_balances.len:
      break
    let vote = self.backend.votes[i]
    if vote.next_root.isZero:
      continue
    if self.is_supporting_vote(node, vote, dag):
      result += justified_balances[i].unslashed_balance

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.3/specs/gloas/fork-choice.md#modified-is_head_weak
func is_head_weak(
    self: var ForkChoice, head_root: Eth2Digest,
    dag: ChainDAGRef): bool =
  let
    total = self.checkpoints.justified.total_active_balance
    reorg_threshold =
      (total div SLOTS_PER_EPOCH) * dag.cfg.REORG_HEAD_WEIGHT_THRESHOLD div 100
    head_node = ForkChoiceNode(
      root: head_root, payloadStatus: PAYLOAD_STATUS_PENDING)

  var head_weight = self.sumSupportingWeight(head_node, dag)

  let proto_node = self.getNode(head_root)
  if proto_node != nil:
    withState(dag.headState):
      when consensusFork >= ConsensusFork.Gloas:
        var cache: StateCache
        let
          justified_balances = self.checkpoints.justified.balances
          head_slot = proto_node.bid.slot
          epoch = head_slot.epoch
          committee_count = get_committee_count_per_slot(
            forkyState.data, epoch, cache)
        for index in 0..<committee_count:
          for _, vidx in get_beacon_committee(
              forkyState.data, head_slot, index.CommitteeIndex, cache):
            if vidx.int < self.backend.votes.len and
              self.backend.votes[vidx].slot == FAR_FUTURE_SLOT:
                if vidx.int < justified_balances.len:
                  head_weight += justified_balances[vidx.int].unslashed_balance

  head_weight < reorg_threshold

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.3/specs/gloas/fork-choice.md#new-should_apply_proposer_boost
proc should_apply_proposer_boost*(
    self: var ForkChoice, dag: ChainDAGRef): bool =
  let proposer_root = self.checkpoints.proposer_boost_root
  if proposer_root.isZero:
    return false

  let idx = self.backend.proto_array.indices.getOrDefault(proposer_root, -1)
  if idx < 0: return false
  let block_node = self.getPhysicalNode(idx)
  if block_node == nil: return false

  if block_node.parent.isNone: return true
  let parent_node = self.getPhysicalNode(block_node.parent.get())
  if parent_node == nil: return true

  let slot = block_node.bid.slot

  if parent_node.bid.slot + 1 < slot:
    return true

  if not self.is_head_weak(parent_node.bid.root, dag):
    return true

  # If parent is weak and from the previous slot, apply
  # proposer boost if there are no early equivocations
  for i in 0 ..< self.backend.proto_array.nodes.buf.len:
    let blk = addr self.backend.proto_array.nodes.buf[i]
    if blk.bid.root == parent_node.bid.root: continue
    if blk.bid.slot + 1 != slot: continue
    if blk.proposerIndex != parent_node.proposerIndex: continue
    let timeliness = self.backend.block_timeliness.getOrDefault(
      blk.bid.root, [false, false])
    if not timeliness[PTC_TIMELINESS_INDEX]: continue
    return false

  true

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.2/specs/gloas/fork-choice.md#modified-get_weight
func get_weight*(
    self: var ForkChoice, node: ForkChoiceNode,
    current_slot: Slot, dag: ChainDAGRef,
    applyProposerBoost: bool): Gwei =
  let proto_node = self.getNode(node.root)
  if proto_node == nil:
    return 0.Gwei

  if proto_node[].bid.slot.epoch < dag.cfg.GLOAS_FORK_EPOCH:
    return proto_node[].weight.Gwei

  if node.payloadStatus != PAYLOAD_STATUS_PENDING and
      proto_node[].bid.slot + 1 == current_slot:
    return 0.Gwei

  var
    attestation_score = self.sumSupportingWeight(node, dag)
    proposer_score = 0.Gwei

  if applyProposerBoost:
    let boost_vote = VoteTracker(
      next_root: self.checkpoints.proposer_boost_root,
      next_slot: current_slot,
      next_epoch: current_slot.epoch,
      payload_present: false)

    if self.is_supporting_vote(node, boost_vote, dag):
      proposer_score = compute_proposer_score(
        self.checkpoints.justified.total_active_balance)

      trace "Applied proposer boost",
        boost = proposer_score

  attestation_score + proposer_score

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.5/specs/gloas/fork-choice.md#new-on_execution_payload_envelope
proc on_execution_payload*(
    self: var ForkChoice, dag: ChainDAGRef,
    signedEnvelope: SignedExecutionPayloadEnvelope): FcResult[void] =
  template envelope: auto = signedEnvelope.message
  let
    beacon_block_root = envelope.beacon_block_root
    current_slot = self.checkpoints.time.slotOrZero(dag.timeParams)

  if not dag.isGloasEnabled(current_slot):
    return ok()

  if beacon_block_root notin self.backend.proto_array.indices:
    return err ForkChoiceError(kind: fcFinalizedNodeUnknown,
                                blockRoot: beacon_block_root)

  # Verify the execution payload envelope
  withState(dag.headState):
    when consensusFork >= ConsensusFork.Gloas:
      let verifyResult = dag.timeParams.verify_execution_payload_envelope(
          dag.forkAtEpoch(envelope.payload.slot_number.epoch),
          forkyState, signedEnvelope,
          dag.genesis_validators_root)
      if verifyResult.isErr:
        debug "Execution payload envelope verification failed",
          error = verifyResult.error,
          beacon_block_root = shortLog(beacon_block_root),
          headSlot = forkyState.data.slot
        return err ForkChoiceError(kind: fcFinalizedNodeUnknown,
                                    blockRoot: beacon_block_root)

  self.backend.execution_payload_states.incl(beacon_block_root)
  ok()
