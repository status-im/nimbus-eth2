# beacon_chain
# Copyright (c) 2018-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  # Standard library
  std/tables,
  # Status libraries
  results, chronicles,
  # Internal
  ../spec/[beaconstate, helpers, state_transition_block],
  ../spec/datatypes/[phase0, altair, bellatrix],
  # Fork choice
  ./fork_choice_types, ./proto_array,
  ../consensus_object_pools/[spec_cache, blockchain_dag]

from std/sequtils import keepItIf
export results, fork_choice_types
export proto_array.len

# This is a port of https://github.com/sigp/lighthouse/pull/804
# which is a port of "Proto-Array": https://github.com/protolambda/lmd-ghost
# See also:
# - Protolambda port of Lighthouse: https://github.com/protolambda/eth2-py-hacks/blob/ae286567/proto_array.py
# - Prysmatic writeup: https://hackmd.io/bABJiht3Q9SyV3Ga4FT9lQ#High-level-concept
# - Gasper Whitepaper: https://arxiv.org/abs/2003.03052

# Forward declarations
# ----------------------------------------------------------------------

type Index = fork_choice_types.Index

func compute_deltas(
       deltas: var openArray[Delta],
       indices: Table[Eth2Digest, Index],
       indices_offset: Index,
       votes: var openArray[VoteTracker],
       old_balances: openArray[Gwei],
       new_balances: openArray[Gwei]
     ): FcResult[void]

func isGloasEnabled(dag: ChainDAGRef, slot: Slot): bool =
  slot.epoch >= dag.cfg.GLOAS_FORK_EPOCH

# Fork choice routines
# ----------------------------------------------------------------------

logScope: topics = "fork_choice"

func init*(
    T: type ForkChoiceBackend, checkpoints: FinalityCheckpoints): T =
  T(proto_array: ProtoArray.init(checkpoints))

proc init*(
    T: type ForkChoice, epochRef: EpochRef, blck: BlockRef): T =
  ## Initialize a fork choice context for a finalized state - in the finalized
  ## state, the justified and finalized checkpoints are the same, so only one
  ## is used here
  debug "Initializing fork choice",
    epoch = epochRef.epoch, blck = shortLog(blck)

  let checkpoint = Checkpoint(root: blck.root, epoch: epochRef.epoch)
  ForkChoice(
    backend: ForkChoiceBackend.init(
      FinalityCheckpoints(
        justified: checkpoint,
        finalized: checkpoint)),
    checkpoints: Checkpoints(
      justified: BalanceCheckpoint(
        checkpoint: checkpoint,
        total_active_balance: epochRef.total_active_balance,
        balances: epochRef.effective_balances),
      finalized: checkpoint,
      best_justified: checkpoint))

func extend[T](s: var seq[T], minLen: int) =
  ## Extend a sequence so that it can contains at least `minLen` elements.
  ## If it's already bigger, the sequence is unmodified.
  ## The extension is zero-initialized
  if s.len < minLen:
    s.setLen(minLen)

proc update_justified(
    self: var Checkpoints, dag: ChainDAGRef, blck: BlockRef, epoch: Epoch) =
  let
    epochRef = dag.getEpochRef(blck, epoch, false).valueOr:
      # Shouldn't happen for justified data unless out of sync with ChainDAG
      warn "Skipping justified checkpoint update, no EpochRef - report bug",
        blck, epoch, error
      return
    justified = Checkpoint(root: blck.root, epoch: epochRef.epoch)

  trace "Updating justified",
    store = self.justified.checkpoint, state = justified
  self.justified = BalanceCheckpoint(
    checkpoint: justified,
    total_active_balance: epochRef.total_active_balance,
    balances: epochRef.effective_balances)

proc update_justified(
    self: var Checkpoints, dag: ChainDAGRef,
    justified: Checkpoint): FcResult[void] =
  let blck = dag.getBlockRef(justified.root).valueOr:
    return err ForkChoiceError(
      kind: fcJustifiedNodeUnknown,
      blockRoot: justified.root)

  self.update_justified(dag, blck, justified.epoch)
  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.0/specs/phase0/fork-choice.md#update_checkpoints
proc update_checkpoints(
    self: var Checkpoints, dag: ChainDAGRef,
    checkpoints: FinalityCheckpoints): FcResult[void] =
  ## Update checkpoints in store if necessary
  # Update justified checkpoint
  if checkpoints.justified.epoch > self.justified.checkpoint.epoch:
    ? self.update_justified(dag, checkpoints.justified)

  # Update finalized checkpoint
  if checkpoints.finalized.epoch > self.finalized.epoch:
    trace "Updating finalized",
      store = self.finalized, state = checkpoints.finalized
    self.finalized = checkpoints.finalized

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.1/specs/phase0/fork-choice.md#on_tick_per_slot
proc on_tick(
    self: var ForkChoice, dag: ChainDAGRef, time: BeaconTime): FcResult[void] =
  ## Must be called at least once per slot.
  let previous_time = self.checkpoints.time

  # Update store time
  if time < previous_time:
    return err ForkChoiceError(kind: fcInconsistentTick)
  self.checkpoints.time = time

  let
    current_slot = time.slotOrZero(dag.timeParams)
    previous_slot = previous_time.slotOrZero(dag.timeParams)

  # If this is a new slot, reset store.proposer_boost_root
  if current_slot > previous_slot:
    self.checkpoints.proposer_boost_root = ZERO_HASH

  # If a new epoch, pull-up justification and finalization from previous epoch
  if current_slot > previous_slot and current_slot.is_epoch:
    for realized in self.backend.proto_array.realizePendingCheckpoints():
      ? self.checkpoints.update_checkpoints(dag, realized)

  ok()

func process_attestation*(
       self: var ForkChoiceBackend,
       validator_index: ValidatorIndex,
       block_root: Eth2Digest,
       target_epoch: Epoch,
       attestation_slot: Slot,
       payload_present: bool,
       cfg: RuntimeConfig
     ) =
  ## Add an attestation to the fork choice context
  self.votes.extend(validator_index.int + 1)

  template vote: untyped = self.votes[validator_index]

  if attestation_slot.epoch >= cfg.GLOAS_FORK_EPOCH:
    # slot based tracking with payload preference
    if attestation_slot > vote.next_slot or vote.next_root.isZero:
      vote.next_root = block_root
      vote.next_slot = attestation_slot
      vote.next_epoch = target_epoch
      vote.payload_present = payload_present

      trace "Integrating Gloas vote in fork choice",
        validator_index = validator_index,
        slot = attestation_slot,
        payload_present = payload_present,
        new_vote = shortLog(vote)
  else:
    if target_epoch > vote.next_epoch or vote.next_root.isZero:
      vote.next_root = block_root
      vote.next_epoch = target_epoch

    trace "Integrating vote in fork choice",
      validator_index = validator_index,
      new_vote = shortLog(vote)

proc process_attestation_queue(
    self: var ForkChoice, slot: Slot, dag: ChainDAGRef) =
  # Spec:
  # Attestations can only affect the fork choice of subsequent slots.
  # Delay consideration in the fork choice until their slot is in the past.
  let startTick = Moment.now()
  self.queuedAttestations.keepItIf:
    if it.slot < slot:
      for validator_index in it.attesting_indices:
        self.backend.process_attestation(
          validator_index, it.block_root, it.slot.epoch(), it.slot,
          it.committee_index == 1, dag.cfg)
      false
    else:
      true
  let endTick = Moment.now()
  debug "Processed attestation queue", processDur = endTick - startTick

func contains*(self: ForkChoiceBackend, block_root: Eth2Digest): bool =
  ## Returns `true` if a block is known to the fork choice
  ## and `false` otherwise.
  ##
  ## In particular, before adding a block, its parent must be known to the fork choice
  self.proto_array.indices.contains(block_root)

proc update_time*(
    self: var ForkChoice, dag: ChainDAGRef, time: BeaconTime): FcResult[void] =
  # `time` is the wall time, meaning it changes on every call typically
  let step_size = dag.timeParams.SLOT_DURATION
  if time > self.checkpoints.time:
    let
      preSlot = self.checkpoints.time.slotOrZero(dag.timeParams)
      postSlot = time.slotOrZero(dag.timeParams)
    # Call on_tick at least once per slot.
    while time >= self.checkpoints.time + step_size:
      ? self.on_tick(dag, self.checkpoints.time + step_size)

    if time > self.checkpoints.time:
      # Might create two ticks for the last slot.
      ? self.on_tick(dag, time)

    if preSlot != postSlot:
      self.process_attestation_queue(postSlot, dag)

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/fork-choice.md#on_attestation
proc on_attestation*(
       self: var ForkChoice,
       dag: ChainDAGRef,
       attestation_slot: Slot,
       beacon_block_root: Eth2Digest,
       attesting_indices: openArray[ValidatorIndex],
       attestation_committee_index: CommitteeIndex,
       wallTime: BeaconTime
     ): FcResult[void] =
  ? self.update_time(dag,
    max(wallTime, attestation_slot.start_beacon_time(dag.timeParams)))

  if attestation_slot < self.checkpoints.time.slotOrZero(dag.timeParams):
    for validator_index in attesting_indices:
      # attestation_slot and target epoch must match, per attestation rules
      self.backend.process_attestation(
        validator_index, beacon_block_root, attestation_slot.epoch, attestation_slot,
        attestation_committee_index == 1, dag.cfg)
  else:
    # Spec:
    # Attestations can only affect the fork choice of subsequent slots.
    # Delay consideration in the fork choice until their slot is in the past.
    self.queuedAttestations.add(QueuedAttestation(
      slot: attestation_slot,
      attesting_indices: @attesting_indices,
      block_root: beacon_block_root,
      committee_index: attestation_committee_index))
  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.1/specs/phase0/fork-choice.md#on_attester_slashing
func process_equivocation*(
       self: var ForkChoice,
       validator_index: ValidatorIndex
     ) =
  self.backend.votes.extend(validator_index.int + 1)

  # Disallow future votes
  template vote: untyped = self.backend.votes[validator_index]
  if vote.next_epoch != FAR_FUTURE_EPOCH or not vote.next_root.isZero:
    vote.next_epoch = FAR_FUTURE_EPOCH
    vote.next_root.reset()

    trace "Integrating equivocation in fork choice",
      validator_index

# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#on_block
func process_block*(self: var ForkChoiceBackend,
                    bid: BlockId,
                    parent_root: Eth2Digest,
                    checkpoints: FinalityCheckpoints,
                    unrealized = none(FinalityCheckpoints)): FcResult[void] =
  self.proto_array.onBlock(bid, parent_root, checkpoints, unrealized)

proc process_block*(self: var ForkChoice,
                    dag: ChainDAGRef,
                    epochRef: EpochRef,
                    blckRef: BlockRef,
                    unrealized: FinalityCheckpoints,
                    blck: ForkyTrustedBeaconBlock,
                    wallTime: BeaconTime): FcResult[void] =
  ? update_time(self, dag,
    max(wallTime, blckRef.slot.start_beacon_time(dag.timeParams)))

  for attester_slashing in blck.body.attester_slashings:
    for idx in getValidatorIndices(attester_slashing):
      let i = ValidatorIndex.init(idx).valueOr:
        continue
      self.process_equivocation(i)

  for attestation in blck.body.attestations:
    if attestation.data.beacon_block_root in self.backend:
      for validator_index in dag.get_attesting_indices(attestation, true):
        self.backend.process_attestation(
          validator_index,
          attestation.data.beacon_block_root,
          attestation.data.target.epoch,
          attestation.data.slot,
          attestation.data.index == 1,
          dag.cfg)
  
  # Process payload attestations
  when consensusFork >= ConsensusFork.Gloas:
    if dag.isGloasEnabled(blckRef.slot):
      for payload_attestation in blck.body.payload_attestations:
        withState(dag.headState):
          when consensusFork >= ConsensusFork.Gloas:
            let indexed = get_indexed_payload_attestation(
              forkyState.data, blck.slot - 1, payload_attestation)
          
          for validator_idx in indexed.attesting_indices:
            discard self.on_payload_attestation_message(
              dag,
              validator_idx,
              payload_attestation.data.beacon_block_root,
              payload_attestation.data.slot,
              payload_attestation.data.payload_present,
              is_from_block = true)

  trace "Integrating block in fork choice",
    block_root = shortLog(blckRef)

  # Add proposer score boost if the block is timely
  let slot = self.checkpoints.time.slotOrZero(dag.timeParams)
  if slot == blck.slot and
      self.checkpoints.time <= slot.attestation_deadline(
        dag.timeParams, typeof(blck).kind) and
      self.checkpoints.proposer_boost_root == ZERO_HASH:
    self.checkpoints.proposer_boost_root = blckRef.root
  
  debug "Applied proposer boost",
    block_root = shortLog(blckRef)

  # Update checkpoints in store if necessary
  ? update_checkpoints(self.checkpoints, dag, epochRef.checkpoints)

  # If block is from a prior epoch, pull up the post-state to next epoch to
  # realize new finality info
  let unrealized_is_better =
    unrealized.justified.epoch > epochRef.checkpoints.justified.epoch or
    unrealized.finalized.epoch > epochRef.checkpoints.finalized.epoch
  if unrealized_is_better:
    if epochRef.epoch < slot.epoch:
      trace "Pulling up chain tip",
        blck = shortLog(blckRef), checkpoints = epochRef.checkpoints, unrealized
      ? update_checkpoints(self.checkpoints, dag, unrealized)
      ? process_block(
        self.backend, blckRef.bid, blck.parent_root, unrealized)
    else:
      ? process_block(
        self.backend, blckRef.bid, blck.parent_root,
        epochRef.checkpoints, some unrealized)  # Realized in `on_tick`
  else:
    ? process_block(
      self.backend, blckRef.bid, blck.parent_root, epochRef.checkpoints)

  ok()

#https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/gloas/fork-choice.md#new-get_node_children
func get_node_children*(
    self: var ForkChoice, node: ForkChoiceNode,
    dag: ChainDAGRef): seq[ForkChoiceNode] =
  var children: seq[ForkChoiceNode]
  
  if not dag.isGloasEnabled(dag.head.slot):
    for root, idx in self.backend.proto_array.indices:
      let child = self.backend.proto_array.nodes.buf[idx]
      if child.parent.isNone: continue

      # Check if this child's parent is our node
      let
        parent_idx = child.parent.get()
        parent = self.backend.proto_array.nodes.buf[parent_idx]

      if parent.bid.root == node.root:
        children.add(ForkChoiceNode(
          root: root, payloadStatus: PAYLOAD_STATUS_PENDING))
      
    return children

  if node.payloadStatus == PAYLOAD_STATUS_PENDING:
    children.add(ForkChoiceNode(
      root: node.root, payload_status: PAYLOAD_STATUS_EMPTY))
    
    if node.root in self.backend.execution_payload_states:
      children.add(ForkChoiceNode(
        root: node.root, payload_status: PAYLOAD_STATUS_FULL))
      
      trace "PENDING expanded to EMPTY + FULL",
        node = shortLog(node), has_payload = true
    else:
      trace "PENDING expanded to EMPTY ONLY",
        node = shortLog(node), has_payload = false
  else:
    for root, idx in self.backend.proto_array.indices:
      let child = self.backend.proto_array.nodes.buf[idx]
      if child.parent.isNone: continue

      let
        parent_idx = child.parent.get()
        parent = self.backend.proto_array.nodes.buf[parent_idx]

      if parent.bid.root != node.root:
        continue
      # TODO: Verify child's parent_payload_status matches node status

      children.add(ForkChoiceNode(
        root: root, payload_status: PAYLOAD_STATUS_PENDING))
    trace "EMPTY/FULL expanded to child blocks",
      node = shortLog(node), children = children.len
  
  children

# https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/gloas/fork-choice.md#new-is_supporting_vote
func is_supporting_vote*(
    self: var ForkChoice, node: ForkChoiceNode,
    vote: VoteTracker, dag: ChainDAGRef): bool =
  ## Returns whether a vote for ``message.root`` supports the chain 
  ## containing the beacon block ``node.root`` with the payload
  ## contents indicated by ``node.payload_status`` as head during
  ## slot ``node.slot``

  let node_idx = self.backend.proto_array.indices.getOrDefault(node.root, -1)
  if node_idx < 0:
    return false

  let proto_node = self.backend.proto_array.nodes.buf[node_idx]

  # Pre gloas, conventional root matching
  if proto_node.bid.slot.epoch < dag.cfg.GLOAS_FORK_EPOCH:
    return node.root == vote.next_root

  if node.root == vote.next_root:
    # case 1: Vote is for this exact block
    # then check for payload status comapatibility

    # Rule 1: Pending always gets support
    if node.payloadStatus == PAYLOAD_STATUS_PENDING:
      trace "Vote supports pending node",
        node = shortLog(node), vote_root = shortLog(vote.next_root)
      return true

    # Rule 2: Same-slot votes don't support empty or full
    if vote.next_slot <= proto_node.bid.slot:
      trace "Vote from same/earlier slot - neither support empty nor full",
        node = shortLog(node),
        vote_slot = vote.next_slot,
        block_slot = proto_node.bid.slot
      return false

    # Rule 3: Next slot votes distinguish empty from full
    if vote.payload_present:
      let supports = (node.payloadStatus == PAYLOAD_STATUS_FULL)
      trace "Vote with payload present checks full",
        node = shortLog(node), supports = supports
      return supports
    else:
      let supports = (node.payloadStatus == PAYLOAD_STATUS_EMPTY)
      trace "Vote with payload present checks empty",
        node = shortLog(node), supports = supports
      return supports
  else:
    # Case 2: Vote is for a descendant block
    trace "Vote is for descendant",
      node = shortLog(node),
      vote_root = shortLog(vote.next_root)
    
    # Rule 4: Ancestor matching with the payload status
    var
      current_root = vote.next_root
      iterations = 0
    const MAX_ITERATIONS = 1000

    while iterations < MAX_ITERATIONS:
      inc iterations

      if current_root == node.root:
        if node.payloadStatus == PAYLOAD_STATUS_PENDING:
          trace "Ancestor match, Pending accepts all",
            node = shortLog(node)
          return true

        # For empty/full, we should check if the descendant chain
        # is building on the correct payload status.
        # 
        # TODO: This requires tracking parent_payload_status through
        # the chain

        # JUst accept if ancestor was found
        trace "Ancestor match",
          node = shortLog(node), iterations = iterations
        return true

      let current_idx = self.backend.proto_array.indices.getOrDefault(
        current_root, -1)
      if current_idx < 0:
        break

      let current_node = self.backend.proto_array.nodes.buf[current_idx]

      # Check if we have already gone past the target slot
      if current_node.bid.slot < proto_node.bid.slot:
        trace "Past target slot, not an ancestor",
          current_slot = current_node.bid.slot,
          target_slot = proto_node.bid.slot
        break

      if current_node.parent.isNone:
        break

      let 
        parent_idx = current_node.parent.get()
        parent_node = self.backend.proto_array.nodes.buf[parent_idx]

      current_root = parent_node.bid.root

    trace "No ancestor match found",
      node = shortLog(node), iterations = iterations
    return false

# https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/gloas/fork-choice.md#modified-get_weight
func get_weight*(
    self: var ForkChoice, node: ForkChoiceNode,
    current_slot: Slot, dag: ChainDAGRef): Gwei =
  let node_idx = self.backend.proto_array.indices.getOrDefault(node.root, -1)
  if node_idx < 0:
    return 0.Gwei

  let proto_node = self.backend.proto_array.nodes.buf[node_idx]

  # Weight calculation is handled by proto_array pre-Gloas
  if proto_node.bid.slot.epoch < dag.cfg.GLOAS_FORK_EPOCH:
    return proto_node.weight.Gwei

  let is_deciding_previous = (node.payloadStatus != PAYLOAD_STATUS_PENDING and
                              proto_node.bid.slot + 1 == current_slot)
  
  if is_deciding_previous:
    trace "Zero weight: deciding on previous slot's payload",
      node = shortLog(node),
      current_slot = current_slot,
      block_slot = proto_node.bid.slot
    return 0.Gwei

  var attestation_score = 0.Gwei
  for i in 0..<self.backend.votes.len:
    if i >= self.checkpoints.justified.balances.len:
      break

    let vote = self.backend.votes[i]
    if vote.next_root.isZero:
      continue

    # Check if this vote supports our node
    if self.is_supporting_vote(node, vote, dag):
      attestation_score += self.checkpoints.justified.balances[i]

  var proposer_score = 0.Gwei
  if not self.checkpoints.proposer_boost_root.isZero:
    var boost_vote = VoteTracker(
      next_root: self.checkpoints.proposer_boost_root,
      next_slot: current_slot,
      next_epoch: current_slot.epoch,
      payload_present: false)

    if self.is_supporting_vote(node, boost_vote, dag):
      proposer_score =
        calculateProposerBoost(self.checkpoints.justified.total_active_balance)

      trace "Applied proposer boost",
        node = shortLog(node), boost = proposer_score

  attestation_score + proposer_score

# https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/gloas/fork-choice.md#new-is_payload_timely
func is_payload_timely*(self: ForkChoiceBackend, root: Eth2Digest): bool =
  ## Return whether the execution payload for the beacon block with root ``root``
  ## was voted as present by the PTC, and was locally determined to be available.

  # The beacon block root must be known
  if root notin self.ptc_vote:
    return false

  # If the payload is not locally available, the payload
  # is not considered available regardless of the PTC vote
  if root notin self.execution_payload_states:
    return false

  let votes = self.ptc_vote.getOrDefault(root, @[])
  var vote_count = 0
  for vote in votes:
    if vote:
      inc vote_count

  if vote_count.uint64 > PAYLOAD_TIMELY_THRESHOLD:
    trace "Payload crossed timeliness threshhold",
      root = shortLog(root),
      votes = vote_count,
      threshhold = PAYLOAD_TIMELY_THRESHOLD
    return true
  false

func should_extend_payload*(
    self: var ForkChoice, root: Eth2Digest): bool =
  # Slot N:   Block B (PENDING) produced
  #         Payload commitment in block
  #         Builder should reveal payload

  # Slot N+1: Fork choice deciding:
  #         Should we extend EMPTY or FULL branch of Block B?

  # Case 1: if payload is timely
  if self.backend.is_payload_timely(root):
    trace "Extending payload: timely according to PTC",
      root = shortLog(root)
    return true

  # Case 2: No proposer boost for block
  # Optimistic, default to full and assume payload will arrive
  let proposer_root = self.checkpoints.proposer_boost_root
  if proposer_root.isZero:
    trace "Extending payload: no proposer boost",
      root = shortLog(root)
    return true

  # Does proposer boost conflict with this block?
  let proposer_idx = self.backend.proto_array.indices.getOrDefault(
    proposer_root, -1)
  if proposer_idx < 0:
    trace "Extending payload: proposer boost block not found",
      root = shortLog(root)
    return true

  # Use the proto_array's node accessor
  let proposer_node = self.backend.proto_array.nodes.buf[proposer_idx]

  # Check if parent exists
  if proposer_node.parent.isNone:
    trace "Extending payload: proposer boost at genesis",
      root = shortLog(root)
    return true

  let
    parent_idx = proposer_node.parent.get()
    parent_node = self.backend.proto_array.nodes.buf[parent_idx]

    parent_root = parent_node.bid.root

  # Case 3: proposer boost is on a different chain than `root`
  if parent_root != root:
    trace "Extending payload: proposer boost on different chain",
      root = shortLog(root),
      proposer_boost_parent = shortLog(parent_root)
    return true

  # Case 4: Proposer boost on our chain (conservative approach)
  trace "Not extending payload: proposer boost on our chain",
    root = shortLog(root),
    proposer_boost_root = shortLog(proposer_root)
  false

func get_payload_status_tiebreaker*(
    self: var ForkChoice, node: ForkChoiceNode,
    current_slot: Slot, dag: ChainDAGRef): uint8 =
  if not dag.isGloasEnabled(current_slot):
    return node.payloadStatus

  let node_idx = self.backend.proto_array.indices.getOrDefault(node.root, -1)
  if node_idx < 0:
    return node.payloadStatus
  let
    proto_node = self.backend.proto_array.nodes.buf[node_idx]

    # Are we deciding on previous slot's payload
    is_deciding_on_previous = (proto_node.bid.slot + 1 == current_slot)

  if node.payloadStatus == PAYLOAD_STATUS_PENDING or not is_deciding_on_previous:
    return node.payloadStatus

  # Deciding on previous slot's payload
  if node.payloadStatus == PAYLOAD_STATUS_EMPTY:
    return 1'u8
  elif node.payloadStatus == PAYLOAD_STATUS_FULL:
    if self.should_extend_payload(node.root):
      return 2'u8
    else:
      return 0'u8
  else:
    return 0'u8  # We shouldn't get here ideally

func find_head(
       self: var ForkChoiceBackend,
       current_epoch: Epoch,
       checkpoints: FinalityCheckpoints,
       justified_total_active_balance: Gwei,
       justified_state_balances: seq[Gwei],
       proposer_boost_root: Eth2Digest
     ): FcResult[Eth2Digest] =
  ## Returns the new blockchain head

  # Compute deltas with previous call
  #   we might want to reuse the `deltas` buffer across calls
  var deltas = newSeq[Delta](self.proto_array.indices.len)
  ? deltas.compute_deltas(
    indices = self.proto_array.indices,
    indices_offset = self.proto_array.nodes.offset,
    votes = self.votes,
    old_balances = self.balances,
    new_balances = justified_state_balances)

  # Apply score changes
  ? self.proto_array.applyScoreChanges(
    deltas, current_epoch, checkpoints,
    justified_total_active_balance, proposer_boost_root)

  self.balances = justified_state_balances

  # Find the best block
  var new_head{.noinit.}: Eth2Digest
  ? self.proto_array.findHead(new_head, checkpoints.justified.root)

  trace "Fork choice requested",
    checkpoints, fork_choice_head = shortLog(new_head)

  return ok(new_head)

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/phase0/fork-choice.md#get_head
proc get_head*(self: var ForkChoice,
               dag: ChainDAGRef,
               wallTime: BeaconTime): FcResult[Eth2Digest] =
  ? self.update_time(dag, wallTime)

  if dag.head.slot.epoch < dag.cfg.GLOAS_FORK_EPOCH:
    return self.backend.find_head(
      self.checkpoints.time.slotOrZero(dag.timeParams).epoch,
      FinalityCheckpoints(
        justified: self.checkpoints.justified.checkpoint,
        finalized: self.checkpoints.finalized),
      self.checkpoints.justified.total_active_balance,
      self.checkpoints.justified.balances,
      self.checkpoints.proposer_boost_root)
  
  # Extended LMD-GHOST with (weight, root, tiebreaker) comparison for gloas
  let current_slot = self.checkpoints.time.slotOrZero(dag.timeParams)
  var head = ForkChoiceNode(
    root: self.checkpoints.justified.checkpoint.root,
    payloadStatus: PAYLOAD_STATUS_PENDING)
  
  var iterations = 0
  const MAX_ITERATIONS = 1000

  while iterations < MAX_ITERATIONS:
    inc iterations
    let children = self.get_node_children(head, dag)

    if children.len == 0:
      debug "Found head",
        iterations = iterations
      return ok(head.root)

    var
      best = children[0]
      best_weight = self.get_weight(best, current_slot, dag)
      best_tiebreaker = self.get_payload_status_tiebreaker(
        best, current_slot, dag)
    
    trace "Initial candidate",
      children = children.len, first_child = shortLog(best),
      first_weight = best_weight, first_tiebreaker = best_tiebreaker

    for i in 1..<children.len:
      let
        child = children[i]
        child_weight = self.get_weight(child, current_slot, dag)
        child_tiebreaker = self.get_payload_status_tiebreaker(
          child, current_slot, dag)

      var should_update = false
      # Higher weight
      if child_weight > best_weight:
        should_update = true
      elif child_weight == best_weight:
        var root_cmp = 0 # Lexicographic comparison
        for j in 0..<32:
          if child.root.data[j] > best.root.data[j]:
            root_cmp = 1
            break
          elif child.root.data[j] < best.root.data[j]:
            root_cmp = -1
            break
        
        if root_cmp > 0:
          should_update = true
        elif root_cmp == 0:
          # Both nodes represent the same block with different payload status
          if child_tiebreaker > best_tiebreaker:
            should_update = true

      if should_update:
        best = child
        best_weight = child_weight
        best_tiebreaker = child_tiebreaker
  
    # Move to best child and continue descent
    head = best

  error "Fork choice iteration limit reached",
    iterations = iterations
  
  ok(head.root)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.0/fork_choice/safe-block.md#get_safe_beacon_block_root
func get_safe_beacon_block_root*(self: ForkChoice): Eth2Digest =
  # Use most recent justified block as a stopgap
  self.checkpoints.justified.checkpoint.root

func prune*(
       self: var ForkChoiceBackend, checkpoints: FinalityCheckpoints
     ): FcResult[void] =
  ## Prune blocks preceding the finalized root as they are now unneeded.
  self.proto_array.prune(checkpoints)

func prune*(self: var ForkChoice): FcResult[void] =
  self.backend.prune(
    FinalityCheckpoints(
      justified: self.checkpoints.justified.checkpoint,
      finalized: self.checkpoints.finalized))

func mark_root_invalid*(self: var ForkChoice, root: Eth2Digest) =
  try:
    let nodePhysicalIdx =
      self.backend.proto_array.indices[root] -
        self.backend.proto_array.nodes.offset
    if nodePhysicalIdx < self.backend.proto_array.nodes.buf.len:
      self.backend.proto_array.nodes.buf[nodePhysicalIdx].invalid = true
    self.backend.proto_array.propagateInvalidity(nodePhysicalIdx)
  # Best-effort; attempts to mark unknown roots invalid harmlessly ignored
  except KeyError:
    discard

func compute_deltas(
       deltas: var openArray[Delta],
       indices: Table[Eth2Digest, Index],
       indices_offset: Index,
       votes: var openArray[VoteTracker],
       old_balances: openArray[Gwei],
       new_balances: openArray[Gwei]
     ): FcResult[void] =
  ## Update `deltas`
  ##   between old and new balances
  ##   between votes
  ##
  ## `deltas.len` must match `indices.len` (length match)
  ##
  ## Error:
  ## - If a value in indices is greater than `indices.len`
  ## - If a `Eth2Digest` in `votes` does not exist in `indices`
  ##   except for the `default(Eth2Digest)` (i.e. zero hash)

  for val_index, vote in votes.mpairs():
    # No need to create a score change if the validator has never voted
    # or if votes are for the zero hash (alias to the genesis block)
    if vote.current_root.isZero and vote.next_root.isZero:
      continue

    # If the validator was not included in `old_balances` (i.e. did not exist)
    # its balance is zero
    let old_balance = if val_index < old_balances.len: old_balances[val_index]
                      else: 0.Gwei

    # If the validator is not known in the `new_balances` then use balance of zero
    #
    # It is possible that there is a vote for an unknown validator if we change our
    # justified state to a new state with a higher epoch on a different fork
    # because that fork may have on-boarded less validators than the previous fork.
    #
    # Note that attesters are not different as they are activated only under finality
    let new_balance = if val_index < new_balances.len: new_balances[val_index]
                      else: 0.Gwei

    if vote.current_root != vote.next_root or old_balance != new_balance:
      # Ignore the current or next vote if it is not known in `indices`.
      # We assume that it is outside of our tree (i.e., pre-finalization) and therefore not interesting.
      if vote.current_root in indices:
        let index = indices.unsafeGet(vote.current_root) - indices_offset
        if index >= deltas.len:
          return err ForkChoiceError(
            kind: fcInvalidNodeDelta,
            index: index)
        deltas[index] -= Delta old_balance
          # Note that delta can be negative
          # TODO: is int64 big enough?

      if vote.next_epoch != FAR_FUTURE_EPOCH or not vote.next_root.isZero:
        if vote.next_root in indices:
          let index = indices.unsafeGet(vote.next_root) - indices_offset
          if index >= deltas.len:
            return err ForkChoiceError(
              kind: fcInvalidNodeDelta,
              index: index)
          deltas[index] += Delta new_balance
            # Note that delta can be negative
            # TODO: is int64 big enough?

      vote.current_root = vote.next_root
  return ok()

# https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/gloas/fork-choice.md#new-on_payload_attestation_message
proc on_payload_attestation_message*(
   self: var ForkChoice,
   dag: ChainDAGRef,
   validator_index: ValidatorIndex,
   beacon_block_root: Eth2Digest,
   slot: Slot,
   payload_present: bool,
   is_from_block: bool = false): FcResult[void] =
  ## Run ``on_payload_attestation_message`` upon receiving
  ## a new ``ptc_message`` directly on the wire.

  if not dag.isGloasEnabled(slot):
    return ok()

  # The beacon block root must be known
  if beacon_block_root notin self.backend.proto_array.indices:
    return ok()

  # PTC attestation must be for a known block. If block is unknown, delay consideration until the block is found
  if beacon_block_root notin self.backend.ptc_vote:
    self.backend.ptc_vote[beacon_block_root] = newSeq[bool](PTC_SIZE)

  withState(dag.headState):
    when consensusFork >= ConsensusFork.Gloas:
      var
        cache: StateCache
        ptc_index = -1
        i = 0

      for vidx in get_ptc(forkyState.data, slot, cache):
        if vidx == validator_index:
          ptc_index = i
          break
        inc i

      if ptc_index >= 0:
        var votes =
          self.backend.ptc_vote.mgetOrPut(
            beacon_block_root, newSeq[bool](PTC_SIZE))

        votes[ptc_index] = payload_present

        trace "Recorded PTC vote",
          validator_index = validator_index,
          beacon_block_root = shortLog(beacon_block_root),
          slot = slot,
          payload_present = payload_present,
          ptc_index = ptc_index,
          is_from_block = is_from_block
      else:
        debug "PTC vote from unknown validator index",
          validator_index = validator_index,
          slot = slot
    else:
      debug "Attempted to record PTC vote before GLOAS fork"
  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/gloas/fork-choice.md#new-on_execution_payload
proc on_execution_payload*(
    self: var ForkChoice,
    dag: ChainDAGRef,
    beacon_block_root: Eth2Digest,
    execution_payload_state_root: Eth2Digest): FcResult[void] =
  ## Run ``on_execution_payload`` upon receiving a new execution payload.

  let current_slot = self.checkpoints.time.slotOrZero(dag.timeParams)
  if not dag.isGloasEnabled(current_slot):
    return ok()

  # The corresponding beacon block root needs to be known
  if beacon_block_root notin self.backend.proto_array.indices:
    debug "Execution payload for unknown block",
      beacon_block_root = shortLog(beacon_block_root)
    return ok()

  self.backend.execution_payload_states[beacon_block_root] =
    execution_payload_state_root

  debug "Recorded execution payload availability",
    beacon_block_root = shortLog(beacon_block_root),
    state_root = shortLog(execution_payload_state_root)
  ok()
  
# Sanity checks
# ----------------------------------------------------------------------
# Sanity checks on internal private procedures

when isMainModule:
  import stew/endians2

  func fakeHash(index: SomeInteger): Eth2Digest =
    ## Create fake hashes
    ## Those are just the value serialized in big-endian
    ## We add 16x16 to avoid having a zero hash are those are special cased
    ## We store them in the first 8 bytes
    ## as those are the one used in hash tables Table[Eth2Digest, T]
    result.data[0 ..< 8] = (16*16+index).uint64.toBytesBE()

  proc tZeroHash() =
    echo "    fork_choice compute_deltas - test zero votes"

    const validator_count = 16
    var deltas = newSeqUninit[Delta](validator_count)

    var indices: Table[Eth2Digest, Index]
    var votes: seq[VoteTracker]
    var old_balances: seq[Gwei]
    var new_balances: seq[Gwei]

    for i in 0 ..< validator_count:
      indices[fakeHash(i)] = i
      votes.add default(VoteTracker)
      old_balances.add 0.Gwei
      new_balances.add 0.Gwei

    let err = deltas.compute_deltas(
      indices, indices_offset = 0, votes, old_balances, new_balances
    )

    doAssert err.isOk, "compute_deltas finished with error: " & $err

    doAssert deltas == newSeq[Delta](validator_count), "deltas should be zeros"

    for vote in votes:
      doAssert vote.current_root == vote.next_root, "The vote should have been updated"


  proc tAll_voted_the_same() =
    echo "    fork_choice compute_deltas - test all same votes"

    const
      Balance = Gwei(42)
      validator_count = 16
    var deltas = newSeqUninit[Delta](validator_count)

    var indices: Table[Eth2Digest, Index]
    var votes: seq[VoteTracker]
    var old_balances: seq[Gwei]
    var new_balances: seq[Gwei]

    for i in 0 ..< validator_count:
      indices[fakeHash(i)] = i
      votes.add VoteTracker(
        current_root: default(Eth2Digest),
        next_root: fakeHash(0), # Get a non-zero hash
        next_epoch: Epoch(0)
      )
      old_balances.add Balance
      new_balances.add Balance

    let err = deltas.compute_deltas(
      indices, indices_offset = 0, votes, old_balances, new_balances
    )

    doAssert err.isOk, "compute_deltas finished with error: " & $err

    for i, delta in deltas:
      if i == 0:
        doAssert delta == Delta(Balance * validator_count), "The 0th root should have a delta"
      else:
        doAssert delta == 0, "The non-0 indexes should have a zero delta"

    for vote in votes:
      doAssert vote.current_root == vote.next_root, "The vote should have been updated"


  proc tDifferent_votes() =
    echo "    fork_choice compute_deltas - test all different votes"

    const
      Balance = Gwei(42)
      validator_count = 16
    var deltas = newSeqUninit[Delta](validator_count)

    var indices: Table[Eth2Digest, Index]
    var votes: seq[VoteTracker]
    var old_balances: seq[Gwei]
    var new_balances: seq[Gwei]

    for i in 0 ..< validator_count:
      indices[fakeHash(i)] = i
      votes.add VoteTracker(
        current_root: default(Eth2Digest),
        next_root: fakeHash(i), # Each vote for a different root
        next_epoch: Epoch(0)
      )
      old_balances.add Balance
      new_balances.add Balance

    let err = deltas.compute_deltas(
      indices, indices_offset = 0, votes, old_balances, new_balances
    )

    doAssert err.isOk, "compute_deltas finished with error: " & $err

    for i, delta in deltas:
      doAssert delta == Delta(Balance), "Each root should have a delta"

    for vote in votes:
      doAssert vote.current_root == vote.next_root, "The vote should have been updated"


  proc tMoving_votes() =
    echo "    fork_choice compute_deltas - test moving votes"

    const
      Balance = Gwei(42)
      validator_count = 16
      TotalDeltas = Delta(Balance * validator_count)
    var deltas = newSeqUninit[Delta](validator_count)

    var indices: Table[Eth2Digest, Index]
    var votes: seq[VoteTracker]
    var old_balances: seq[Gwei]
    var new_balances: seq[Gwei]

    for i in 0 ..< validator_count:
      indices[fakeHash(i)] = i
      votes.add VoteTracker(
        # Move vote from root 0 to root 1
        current_root: fakeHash(0),
        next_root: fakeHash(1),
        next_epoch: Epoch(0)
      )
      old_balances.add Balance
      new_balances.add Balance

    let err = deltas.compute_deltas(
      indices, indices_offset = 0, votes, old_balances, new_balances
    )

    doAssert err.isOk, "compute_deltas finished with error: " & $err

    for i, delta in deltas:
      if i == 0:
        doAssert delta == -TotalDeltas, "0th root should have a negative delta"
      elif i == 1:
        doAssert delta == TotalDeltas, "1st root should have a positive delta"
      else:
        doAssert delta == 0, "The non-0 and non-1 indexes should have a zero delta"

    for vote in votes:
      doAssert vote.current_root == vote.next_root, "The vote should have been updated"


  proc tMove_out_of_tree() =
    echo "    fork_choice compute_deltas - test votes for unknown subtree"

    const Balance = Gwei(42)

    var indices: Table[Eth2Digest, Index]
    var votes: seq[VoteTracker]

    # Add a block
    indices[fakeHash(1)] = 0

    # 2 validators
    var deltas = newSeqUninit[Delta](2)
    let old_balances = @[Balance, Balance]
    let new_balances = @[Balance, Balance]

    # One validator moves their vote from the block to the zero hash
    votes.add VoteTracker(
      current_root: fakeHash(1),
      next_root: default(Eth2Digest),
      next_epoch: Epoch(0)
    )

    # One validator moves their vote from the block to something outside of the tree
    votes.add VoteTracker(
      current_root: fakeHash(1),
      next_root: fakeHash(1337),
      next_epoch: Epoch(0)
    )

    let err = deltas.compute_deltas(
      indices, indices_offset = 0, votes, old_balances, new_balances
    )

    doAssert err.isOk, "compute_deltas finished with error: " & $err

    doAssert deltas[0] == -Delta(Balance)*2, "The 0th block should have lost both balances."

    for vote in votes:
      doAssert vote.current_root == vote.next_root, "The vote should have been updated"


  proc tChanging_balances() =
    echo "    fork_choice compute_deltas - test changing balances"

    const
      OldBalance = Gwei(42)
      NewBalance = OldBalance * 2
      validator_count = 16
      TotalOldDeltas = Delta(OldBalance * validator_count)
      TotalNewDeltas = Delta(NewBalance * validator_count)
    var deltas = newSeqUninit[Delta](validator_count)

    var indices: Table[Eth2Digest, Index]
    var votes: seq[VoteTracker]
    var old_balances: seq[Gwei]
    var new_balances: seq[Gwei]

    for i in 0 ..< validator_count:
      indices[fakeHash(i)] = i
      votes.add VoteTracker(
        # Move vote from root 0 to root 1
        current_root: fakeHash(0),
        next_root: fakeHash(1),
        next_epoch: Epoch(0)
      )
      old_balances.add OldBalance
      new_balances.add NewBalance

    let err = deltas.compute_deltas(
      indices, indices_offset = 0, votes, old_balances, new_balances
    )

    doAssert err.isOk, "compute_deltas finished with error: " & $err

    for i, delta in deltas:
      if i == 0:
        doAssert delta == -TotalOldDeltas, "0th root should have a negative delta"
      elif i == 1:
        doAssert delta == TotalNewDeltas, "1st root should have a positive delta"
      else:
        doAssert delta == 0, "The non-0 and non-1 indexes should have a zero delta"

    for vote in votes:
      doAssert vote.current_root == vote.next_root, "The vote should have been updated"


  proc tValidator_appears() =
    echo "    fork_choice compute_deltas - test validator appears"

    const Balance = Gwei(42)

    var indices: Table[Eth2Digest, Index]
    var votes: seq[VoteTracker]

    # Add 2 blocks
    indices[fakeHash(1)] = 0
    indices[fakeHash(2)] = 1

    # 1 validator at the start, 2 at the end
    var deltas = newSeqUninit[Delta](2)
    let old_balances = @[Balance]
    let new_balances = @[Balance, Balance]

    # Both moves vote from Block 1 to 2
    for _ in 0 ..< 2:
      votes.add VoteTracker(
        current_root: fakeHash(1),
        next_root: fakeHash(2),
        next_epoch: Epoch(0)
      )


    let err = deltas.compute_deltas(
      indices, indices_offset = 0, votes, old_balances, new_balances
    )

    doAssert err.isOk, "compute_deltas finished with error: " & $err

    doAssert deltas[0] == -Delta(Balance), "Block 1 should have lost only 1 balance"
    doAssert deltas[1] == Delta(Balance)*2, "Block 2 should have gained 2 balances"

    for vote in votes:
      doAssert vote.current_root == vote.next_root, "The vote should have been updated"


  proc tValidator_disappears() =
    echo "    fork_choice compute_deltas - test validator disappears"

    const Balance = Gwei(42)

    var indices: Table[Eth2Digest, Index]
    var votes: seq[VoteTracker]

    # Add 2 blocks
    indices[fakeHash(1)] = 0
    indices[fakeHash(2)] = 1

    # 2 validator at the start, 1 at the end
    var deltas = newSeqUninit[Delta](2)
    let old_balances = @[Balance, Balance]
    let new_balances = @[Balance]

    # Both moves vote from Block 1 to 2
    for _ in 0 ..< 2:
      votes.add VoteTracker(
        current_root: fakeHash(1),
        next_root: fakeHash(2),
        next_epoch: Epoch(0)
      )


    let err = deltas.compute_deltas(
      indices, indices_offset = 0, votes, old_balances, new_balances
    )

    doAssert err.isOk, "compute_deltas finished with error: " & $err

    doAssert deltas[0] == -Delta(Balance)*2, "Block 1 should have lost 2 balances"
    doAssert deltas[1] == Delta(Balance), "Block 2 should have gained 1 balance"

    for vote in votes:
      doAssert vote.current_root == vote.next_root, "The vote should have been updated"


  # ----------------------------------------------------------------------

  echo "fork_choice internal tests for compute_deltas"
  tZeroHash()
  tAll_voted_the_same()
  tDifferent_votes()
  tMoving_votes()
  tChanging_balances()
  tValidator_appears()
  tValidator_disappears()
