# beacon_chain
# Copyright (c) 2020-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import
  # Standard libraries
  std/[deques, sets],
  # Status libraries
  chronicles,
  # Internal
  ../spec/datatypes/base,
  ../spec/[helpers, state_transition_block],
  "."/[attestation_pool, blockchain_dag]

export base, deques, sets, blockchain_dag

logScope: topics = "exitpool"

const
  ATTESTER_SLASHINGS_BOUND* = MAX_ATTESTER_SLASHINGS * 4
  PROPOSER_SLASHINGS_BOUND* = MAX_PROPOSER_SLASHINGS * 4
  VOLUNTARY_EXITS_BOUND* = MAX_VOLUNTARY_EXITS * 4

type
  OnVoluntaryExitCallback* =
    proc(data: SignedVoluntaryExit) {.gcsafe, raises: [Defect].}

  ExitPool* = object
    ## The exit pool tracks attester slashings, proposer slashings, and
    ## voluntary exits that could be added to a proposed block.

    attester_slashings*: Deque[AttesterSlashing]  ## \
    ## Not a function of chain DAG branch; just used as a FIFO queue for blocks

    proposer_slashings*: Deque[ProposerSlashing]  ## \
    ## Not a function of chain DAG branch; just used as a FIFO queue for blocks

    voluntary_exits*: Deque[SignedVoluntaryExit]  ## \
    ## Not a function of chain DAG branch; just used as a FIFO queue for blocks

    prior_seen_attester_slashed_indices*: HashSet[uint64] ## \
    ## Records attester-slashed indices seen.

    prior_seen_proposer_slashed_indices*: HashSet[uint64] ## \
    ## Records proposer-slashed indices seen.

    prior_seen_voluntary_exit_indices*: HashSet[uint64] ##\
    ## Records voluntary exit indices seen.

    dag*: ChainDAGRef
    attestationPool*: ref AttestationPool
    onVoluntaryExitReceived*: OnVoluntaryExitCallback

func init*(T: type ExitPool, dag: ChainDAGRef,
           attestationPool: ref AttestationPool = nil,
           onVoluntaryExit: OnVoluntaryExitCallback = nil): T =
  ## Initialize an ExitPool from the dag `headState`
  T(
    # Allow for filtering out some exit messages during block production
    attester_slashings:
      initDeque[AttesterSlashing](initialSize = ATTESTER_SLASHINGS_BOUND.int),
    proposer_slashings:
      initDeque[ProposerSlashing](initialSize = PROPOSER_SLASHINGS_BOUND.int),
    voluntary_exits:
      initDeque[SignedVoluntaryExit](initialSize = VOLUNTARY_EXITS_BOUND.int),
    dag: dag,
    attestationPool: attestationPool,
    onVoluntaryExitReceived: onVoluntaryExit
   )

func addExitMessage(subpool: var auto, exitMessage, bound: auto) =
  # Prefer newer to older exit messages
  while subpool.lenu64 >= bound:
    discard subpool.popFirst()

  subpool.addLast(exitMessage)
  doAssert subpool.lenu64 <= bound

iterator getValidatorIndices(proposer_slashing: ProposerSlashing): uint64 =
  yield proposer_slashing.signed_header_1.message.proposer_index

iterator getValidatorIndices(voluntary_exit: SignedVoluntaryExit): uint64 =
  yield voluntary_exit.message.validator_index

func isSeen*(pool: ExitPool, msg: AttesterSlashing): bool =
  for idx in getValidatorIndices(msg):
    # One index is enough!
    if idx notin pool.prior_seen_attester_slashed_indices:
      return false
  true

func isSeen*(pool: ExitPool, msg: ProposerSlashing): bool =
  msg.signed_header_1.message.proposer_index in
    pool.prior_seen_proposer_slashed_indices

func isSeen*(pool: ExitPool, msg: SignedVoluntaryExit): bool =
  msg.message.validator_index in
    pool.prior_seen_voluntary_exit_indices

func addMessage*(pool: var ExitPool, msg: AttesterSlashing) =
  for idx in getValidatorIndices(msg):
    pool.prior_seen_attester_slashed_indices.incl idx
    if pool.attestationPool != nil:
      let i = ValidatorIndex.init(idx).valueOr:
        continue
      pool.attestationPool.forkChoice.process_equivocation(i)

  pool.attester_slashings.addExitMessage(msg, ATTESTER_SLASHINGS_BOUND)

func addMessage*(pool: var ExitPool, msg: ProposerSlashing) =
  pool.prior_seen_proposer_slashed_indices.incl(
    msg.signed_header_1.message.proposer_index)
  pool.proposer_slashings.addExitMessage(msg, PROPOSER_SLASHINGS_BOUND)

func addMessage*(pool: var ExitPool, msg: SignedVoluntaryExit) =
  pool.prior_seen_voluntary_exit_indices.incl(
    msg.message.validator_index)
  pool.voluntary_exits.addExitMessage(msg, VOLUNTARY_EXITS_BOUND)

proc validateExitMessage(
    cfg: RuntimeConfig, state: ForkyBeaconState, msg: ProposerSlashing): bool =
  check_proposer_slashing(state, msg, {}).isOk
proc validateExitMessage(
    cfg: RuntimeConfig, state: ForkyBeaconState, msg: AttesterSlashing): bool =
  check_attester_slashing(state, msg, {}).isOk
proc validateExitMessage(
    cfg: RuntimeConfig, state: ForkyBeaconState, msg: SignedVoluntaryExit):
    bool =
  check_voluntary_exit(cfg, state, msg, {}).isOk

proc getExitMessagesForBlock(
    subpool: var Deque, cfg: RuntimeConfig, state: ForkyBeaconState,
    seen: var HashSet, output: var List) =
  # Approach taken here is to simply collect messages, effectively, a circular
  # buffer and only re-validate that they haven't already found themselves out
  # of the network eventually via some exit message at block construction time
  # at which point we use exit_epoch. It doesn't matter which of these message
  # types has triggered that exit, as the validation on incoming messages will
  # find it to either be IGNORE (if it's the same type of exit message) or, if
  # it's a different type, REJECT. Neither is worth packaging into BeaconBlock
  # messages we broadcast.
  #
  # Beyond that, it may happen that messages were signed in an epoch pre-dating
  # the current state by two or more forks - such messages can no longer be
  # validated in the context of the given state and are therefore dropped.
  #
  # This overall approach handles a scenario wherein we receive an exit message
  # over gossip and put it in the pool; receive a block X, with that message in
  # it, and select it as head; then orphan block X and build instead on X-1. If
  # this occurs, only validating after the fact ensures that we still broadcast
  # out those exit messages that were in orphaned block X by not having eagerly
  # removed them, if we have the chance.
  while subpool.len > 0 and output.len < output.maxLen:
    # Prefer recent messages
    let exit_message = subpool.popLast()
    # Re-check that message is still valid in the state that we're proposing
    if not validateExitMessage(cfg, state, exit_message):
      continue

    var skip = false
    for slashed_index in getValidatorIndices(exit_message):
      if seen.containsOrIncl(slashed_index):
        skip = true
        break
    if skip:
      continue

    if not output.add exit_message:
      break

  subpool.clear()

proc getBeaconBlockExits*(
    pool: var ExitPool, cfg: RuntimeConfig, state: ForkyBeaconState):
    BeaconBlockExits =
  var
    indices: HashSet[uint64]
    res: BeaconBlockExits

  getExitMessagesForBlock(
    pool.attester_slashings, cfg, state, indices, res.attester_slashings)
  getExitMessagesForBlock(
    pool.proposer_slashings, cfg, state, indices, res.proposer_slashings)
  getExitMessagesForBlock(
    pool.voluntary_exits, cfg, state, indices, res.voluntary_exits)

  res
