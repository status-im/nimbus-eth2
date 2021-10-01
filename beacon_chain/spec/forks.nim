# beacon_chain
# Copyright (c) 2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/macros,
  chronicles,
  stew/[assign2, results],
  ../extras,
  ../spec/[
    beaconstate, eth2_merkleization, helpers, state_transition_block, validator],
  ./datatypes/[phase0, altair, merge]

export extras, phase0, altair, eth2_merkleization

type
  BeaconStateFork* = enum
    forkPhase0,
    forkAltair,
    forkMerge

  ForkedHashedBeaconState* = object
    case beaconStateFork*: BeaconStateFork
    of forkPhase0: hbsPhase0*: phase0.HashedBeaconState
    of forkAltair: hbsAltair*: altair.HashedBeaconState
    of forkMerge:  hbsMerge*:  merge.HashedBeaconState

  ForkedBeaconState* = object
    case beaconStateFork*: BeaconStateFork
    of forkPhase0: bsPhase0*: phase0.BeaconState
    of forkAltair: bsAltair*: altair.BeaconState
    of forkMerge:  bsMerge*:  merge.BeaconState

  BeaconBlockFork* {.pure.} = enum
    Phase0
    Altair
    Merge

  ForkedBeaconBlock* = object
    case kind*: BeaconBlockFork
    of BeaconBlockFork.Phase0:
      phase0Block*: phase0.BeaconBlock
    of BeaconBlockFork.Altair:
      altairBlock*: altair.BeaconBlock
    of BeaconBlockFork.Merge:
      mergeBlock*:  merge.BeaconBlock

  ForkedSignedBeaconBlock* = object
    case kind*: BeaconBlockFork
    of BeaconBlockFork.Phase0:
      phase0Block*: phase0.SignedBeaconBlock
    of BeaconBlockFork.Altair:
      altairBlock*: altair.SignedBeaconBlock
    of BeaconBlockFork.Merge:
      mergeBlock*:  merge.SignedBeaconBlock

  ForkedTrustedSignedBeaconBlock* = object
    case kind*: BeaconBlockFork
    of BeaconBlockFork.Phase0:
      phase0Block*: phase0.TrustedSignedBeaconBlock
    of BeaconBlockFork.Altair:
      altairBlock*: altair.TrustedSignedBeaconBlock
    of BeaconBlockFork.Merge:
      mergeBlock*:  merge.TrustedSignedBeaconBlock

  ForkDigests* = object
    phase0*: ForkDigest
    altair*: ForkDigest
    merge*:  ForkDigest  # TODO where does this get filled
    altairTopicPrefix*: string # Used by isAltairTopic

  ForkDigestsRef* = ref ForkDigests

template init*(T: type ForkedBeaconBlock, blck: phase0.BeaconBlock): T =
  T(kind: BeaconBlockFork.Phase0, phase0Block: blck)
template init*(T: type ForkedBeaconBlock, blck: altair.BeaconBlock): T =
  T(kind: BeaconBlockFork.Altair, altairBlock: blck)
template init*(T: type ForkedBeaconBlock, blck: merge.BeaconBlock): T =
  T(kind: BeaconBlockFork.Merge, mergeBlock: blck)

template init*(T: type ForkedSignedBeaconBlock, blck: phase0.SignedBeaconBlock): T =
  T(kind: BeaconBlockFork.Phase0, phase0Block: blck)
template init*(T: type ForkedSignedBeaconBlock, blck: altair.SignedBeaconBlock): T =
  T(kind: BeaconBlockFork.Altair, altairBlock: blck)
template init*(T: type ForkedSignedBeaconBlock, blck: merge.SignedBeaconBlock): T =
  T(kind: BeaconBlockFork.Merge, mergeBlock: blck)

template init*(T: type ForkedBeaconState, state: phase0.BeaconState): T =
  T(beaconStateFork: BeaconStateFork.forkPhase0, bsPhase0: state)
template init*(T: type ForkedBeaconState, state: altair.BeaconState): T =
  T(beaconStateFork: BeaconStateFork.forkAltair, bsAltair: state)
template init*(T: type ForkedBeaconState, state: merge.BeaconState): T =
  T(beaconStateFork: BeaconStateFork.forkMerge, bsMerge: state)
template init*(T: type ForkedBeaconState, state: ForkedHashedBeaconState): T =
  case state.beaconStateFork
  of BeaconStateFork.forkPhase0:
    T(beaconStateFork: BeaconStateFork.forkPhase0,
      bsPhase0: state.hbsPhase0.data)
  of BeaconStateFork.forkAltair:
    T(beaconStateFork: BeaconStateFork.forkAltair,
      bsAltair: state.hbsAltair.data)
  of BeaconStateFork.forkMerge:
    T(beaconStateFork: BeaconStateFork.forkMerge,
      bsMerge: state.hbsMerge.data)

template init*(T: type ForkedSignedBeaconBlock, forked: ForkedBeaconBlock,
               blockRoot: Eth2Digest, signature: ValidatorSig): T =
  case forked.kind
  of BeaconBlockFork.Phase0:
    T(kind: BeaconBlockFork.Phase0,
      phase0Block: phase0.SignedBeaconBlock(message: forked.phase0Block,
                                            root: blockRoot,
                                            signature: signature))
  of BeaconBlockFork.Altair:
    T(kind: BeaconBlockFork.Altair,
      altairBlock: altair.SignedBeaconBlock(message: forked.altairBlock,
                                            root: blockRoot,
                                            signature: signature))
  of BeaconBlockFork.Merge:
    T(kind: BeaconBlockFork.Merge,
      mergeBlock: merge.SignedBeaconBlock(message: forked.mergeBlock,
                                          root: blockRoot,
                                          signature: signature))

template init*(T: type ForkedTrustedSignedBeaconBlock, blck: phase0.TrustedSignedBeaconBlock): T =
  T(kind: BeaconBlockFork.Phase0, phase0Block: blck)
template init*(T: type ForkedTrustedSignedBeaconBlock, blck: altair.TrustedSignedBeaconBlock): T =
  T(kind: BeaconBlockFork.Altair, altairBlock: blck)
template init*(T: type ForkedTrustedSignedBeaconBlock, blck: merge.TrustedSignedBeaconBlock): T =
  T(kind: BeaconBlockFork.Merge,  mergeBlock: blck)

# State-related functionality based on ForkedHashedBeaconState instead of HashedBeaconState

template withState*(x: ForkedHashedBeaconState, body: untyped): untyped =
  case x.beaconStateFork
  of forkMerge:
    const stateFork {.inject.} = forkMerge
    template state: untyped {.inject.} = x.hbsMerge
    body
  of forkAltair:
    const stateFork {.inject.} = forkAltair
    template state: untyped {.inject.} = x.hbsAltair
    body
  of forkPhase0:
    const stateFork {.inject.} = forkPhase0
    template state: untyped {.inject.} = x.hbsPhase0
    body

# Dispatch functions
func assign*(tgt: var ForkedHashedBeaconState, src: ForkedHashedBeaconState) =
  if tgt.beaconStateFork == src.beaconStateFork:
    case tgt.beaconStateFork
    of forkMerge:
      assign(tgt.hbsMerge,  src.hbsMerge):
    of forkAltair:
      assign(tgt.hbsAltair, src.hbsAltair):
    of forkPhase0:
      assign(tgt.hbsPhase0, src.hbsPhase0):
  else:
    # Ensure case object and discriminator get updated simultaneously, even
    # with nimOldCaseObjects. This is infrequent.
    tgt = src

template getStateField*(x: ForkedHashedBeaconState, y: untyped): untyped =
  # The use of `unsafeAddr` avoids excessive copying in certain situations, e.g.,
  # ```
  #   for index, validator in getStateField(stateData.data, validators).pairs():
  # ```
  # Without `unsafeAddr`, the `validators` list would be copied to a temporary variable.
  (case x.beaconStateFork
  of forkMerge: unsafeAddr x.hbsMerge.data.y
  of forkAltair: unsafeAddr x.hbsAltair.data.y
  of forkPhase0: unsafeAddr x.hbsPhase0.data.y)[]

func getStateRoot*(x: ForkedHashedBeaconState): Eth2Digest =
  withState(x): state.root

func setStateRoot*(x: var ForkedHashedBeaconState, root: Eth2Digest) =
  withState(x): state.root = root

func hash_tree_root*(x: ForkedHashedBeaconState): Eth2Digest =
  # This is a bit of a hack because we drill into data here, unlike other places
  withState(x): hash_tree_root(state.data)

func get_active_validator_indices_len*(
    state: ForkedHashedBeaconState; epoch: Epoch): uint64 =
  withState(state):
    get_active_validator_indices_len(state.data, epoch)

func get_beacon_committee*(
    state: ForkedHashedBeaconState, slot: Slot, index: CommitteeIndex,
    cache: var StateCache): seq[ValidatorIndex] =
  # This one is used by tests/, ncli/, and a couple of places in RPC
  # TODO use the iterator version alone, to remove the risk of using
  # diverging get_beacon_committee() in tests and beacon_chain/ by a
  # wrapper approach (e.g., toSeq). This is a perf tradeoff for test
  # correctness/consistency.
  withState(state):
    get_beacon_committee(state.data, slot, index, cache)

func get_beacon_committee_len*(
    state: ForkedHashedBeaconState, slot: Slot, index: CommitteeIndex,
    cache: var StateCache): uint64 =
  # This one is used by tests
  withState(state):
    get_beacon_committee_len(state.data, slot, index, cache)

func get_committee_count_per_slot*(state: ForkedHashedBeaconState,
                                   epoch: Epoch,
                                   cache: var StateCache): uint64 =
  ## Return the number of committees at ``epoch``.
  withState(state):
    get_committee_count_per_slot(state.data, epoch, cache)

func get_beacon_proposer_index*(state: ForkedHashedBeaconState,
                                cache: var StateCache, slot: Slot):
                                Option[ValidatorIndex] =
  withState(state):
    get_beacon_proposer_index(state.data, cache, slot)

func get_shuffled_active_validator_indices*(
    cache: var StateCache, state: ForkedHashedBeaconState, epoch: Epoch):
    seq[ValidatorIndex] =
  withState(state):
    cache.get_shuffled_active_validator_indices(state.data, epoch)

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#get_block_root_at_slot
func get_block_root_at_slot*(state: ForkedHashedBeaconState,
                             slot: Slot): Eth2Digest =
  ## Return the block root at a recent ``slot``.
  withState(state):
    get_block_root_at_slot(state.data, slot)

proc get_attesting_indices*(state: ForkedHashedBeaconState;
                            data: AttestationData;
                            bits: CommitteeValidatorsBits;
                            cache: var StateCache): seq[ValidatorIndex] =
  # TODO when https://github.com/nim-lang/Nim/issues/18188 fixed, use an
  # iterator

  var idxBuf: seq[ValidatorIndex]
  withState(state):
    for vidx in state.data.get_attesting_indices(data, bits, cache):
      idxBuf.add vidx
  idxBuf

proc check_attester_slashing*(
    state: var ForkedHashedBeaconState; attester_slashing: SomeAttesterSlashing;
    flags: UpdateFlags): Result[seq[ValidatorIndex], cstring] =
  withState(state):
    check_attester_slashing(state.data, attester_slashing, flags)

proc check_proposer_slashing*(
    state: var ForkedHashedBeaconState; proposer_slashing: SomeProposerSlashing;
    flags: UpdateFlags): Result[void, cstring] =
  withState(state):
    check_proposer_slashing(state.data, proposer_slashing, flags)

proc check_voluntary_exit*(
    cfg: RuntimeConfig, state: ForkedHashedBeaconState;
    signed_voluntary_exit: SomeSignedVoluntaryExit;
    flags: UpdateFlags): Result[void, cstring] =
  withState(state):
    check_voluntary_exit(cfg, state.data, signed_voluntary_exit, flags)

# Derived utilities

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#get_current_epoch
func get_current_epoch*(x: ForkedHashedBeaconState): Epoch =
  ## Return the current epoch.
  withState(x): state.data.slot.epoch

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#get_previous_epoch
func get_previous_epoch*(stateData: ForkedHashedBeaconState): Epoch =
  ## Return the previous epoch (unless the current epoch is ``GENESIS_EPOCH``).
  let current_epoch = get_current_epoch(stateData)
  if current_epoch == GENESIS_EPOCH:
    GENESIS_EPOCH
  else:
    current_epoch - 1

func init*(T: type ForkDigests,
           cfg: RuntimeConfig,
           genesisValidatorsRoot: Eth2Digest): T =
  let altairForkDigest = compute_fork_digest(
    cfg.ALTAIR_FORK_VERSION,
    genesisValidatorsRoot)

  T(phase0: compute_fork_digest(
      cfg.GENESIS_FORK_VERSION,
      genesisValidatorsRoot),
    altair: altairForkDigest,
    altairTopicPrefix: $altairForkDigest)

template asSigned*(x: phase0.TrustedSignedBeaconBlock or phase0.SigVerifiedBeaconBlock):
    phase0.SignedBeaconBlock =
  isomorphicCast[phase0.SignedBeaconBlock](x)

template asSigned*(x: altair.TrustedSignedBeaconBlock or altair.SigVerifiedBeaconBlock):
    altair.SignedBeaconBlock =
  isomorphicCast[altair.SignedBeaconBlock](x)

template asSigned*(x: ForkedTrustedSignedBeaconBlock): ForkedSignedBeaconBlock =
  isomorphicCast[ForkedSignedBeaconBlock](x)

template asTrusted*(x: phase0.SignedBeaconBlock or phase0.SigVerifiedBeaconBlock):
    phase0.TrustedSignedBeaconBlock =
  isomorphicCast[phase0.TrustedSignedBeaconBlock](x)

template asTrusted*(x: altair.SignedBeaconBlock or altair.SigVerifiedBeaconBlock):
    altair.TrustedSignedBeaconBlock =
  isomorphicCast[altair.TrustedSignedBeaconBlock](x)

template asTrusted*(x: merge.SignedBeaconBlock or merge.SigVerifiedBeaconBlock):
    merge.TrustedSignedBeaconBlock =
  isomorphicCast[merge.TrustedSignedBeaconBlock](x)

template asTrusted*(x: ForkedSignedBeaconBlock): ForkedTrustedSignedBeaconBlock =
  isomorphicCast[ForkedTrustedSignedBeaconBlock](x)

template withBlck*(
    x: ForkedBeaconBlock | ForkedSignedBeaconBlock |
       ForkedTrustedSignedBeaconBlock,
    body: untyped): untyped =
  case x.kind
  of BeaconBlockFork.Phase0:
    const stateFork {.inject.} = forkPhase0
    template blck: untyped {.inject.} = x.phase0Block
    body
  of BeaconBlockFork.Altair:
    const stateFork {.inject.} = forkAltair
    template blck: untyped {.inject.} = x.altairBlock
    body
  of BeaconBlockFork.Merge:
    const stateFork {.inject.} = forkMerge
    template blck: untyped {.inject.} = x.mergeBlock
    body

func proposer_index*(x: ForkedBeaconBlock): uint64 =
  withBlck(x): blck.proposer_index

func hash_tree_root*(x: ForkedBeaconBlock): Eth2Digest =
  withBlck(x): hash_tree_root(blck)

template getForkedBlockField*(x: ForkedSignedBeaconBlock | ForkedTrustedSignedBeaconBlock, y: untyped): untyped =
  # unsafeAddr avoids a copy of the field in some cases
  (case x.kind
  of BeaconBlockFork.Phase0: unsafeAddr x.phase0Block.message.y
  of BeaconBlockFork.Altair: unsafeAddr x.altairBlock.message.y
  of BeaconBlockFork.Merge: unsafeAddr x.mergeBlock.message.y)[]

template signature*(x: ForkedSignedBeaconBlock): ValidatorSig =
  withBlck(x): blck.signature

template signature*(x: ForkedTrustedSignedBeaconBlock): TrustedSig =
  withBlck(x): blck.signature

template root*(x: ForkedSignedBeaconBlock | ForkedTrustedSignedBeaconBlock): Eth2Digest =
  withBlck(x): blck.root

template slot*(x: ForkedSignedBeaconBlock | ForkedTrustedSignedBeaconBlock): Slot =
  withBlck(x): blck.message.slot

template shortLog*(x: ForkedBeaconBlock): auto =
  withBlck(x): shortLog(blck)

template shortLog*(x: ForkedSignedBeaconBlock | ForkedTrustedSignedBeaconBlock): auto =
  withBlck(x): shortLog(blck)

chronicles.formatIt ForkedBeaconBlock: it.shortLog
chronicles.formatIt ForkedSignedBeaconBlock: it.shortLog
chronicles.formatIt ForkedTrustedSignedBeaconBlock: it.shortLog

template withStateAndBlck*(
    s: ForkedHashedBeaconState,
    b: ForkedBeaconBlock | ForkedSignedBeaconBlock |
       ForkedTrustedSignedBeaconBlock,
    body: untyped): untyped =
  case s.beaconStateFork
  of forkMerge:
    const stateFork {.inject.} = forkMerge
    template state: untyped {.inject.} = s.hbsMerge
    template blck: untyped {.inject.} = b.mergeBlock
    body
  of forkAltair:
    const stateFork {.inject.} = forkAltair
    template state: untyped {.inject.} = s.hbsAltair
    template blck: untyped {.inject.} = b.altairBlock
    body
  of forkPhase0:
    const stateFork {.inject.} = forkPhase0
    template state: untyped {.inject.} = s.hbsPhase0
    template blck: untyped {.inject.} = b.phase0Block
    body

proc forkAtEpoch*(cfg: RuntimeConfig, epoch: Epoch): Fork =
  doAssert cfg.ALTAIR_FORK_EPOCH <= cfg.MERGE_FORK_EPOCH
  if epoch < cfg.ALTAIR_FORK_EPOCH:
    genesisFork(cfg)
  elif epoch < cfg.MERGE_FORK_EPOCH:
    altairFork(cfg)
  else:
    mergeFork(cfg)

proc forkVersionAtEpoch*(cfg: RuntimeConfig, epoch: Epoch): Version =
  doAssert cfg.ALTAIR_FORK_EPOCH <= cfg.MERGE_FORK_EPOCH
  if epoch < cfg.ALTAIR_FORK_EPOCH:
    cfg.GENESIS_FORK_VERSION
  elif epoch < cfg.MERGE_FORK_EPOCH:
    cfg.ALTAIR_FORK_VERSION
  else:
    cfg.MERGE_FORK_VERSION

proc nextForkEpochAtEpoch*(cfg: RuntimeConfig, epoch: Epoch): Epoch =
  doAssert cfg.ALTAIR_FORK_EPOCH <= cfg.MERGE_FORK_EPOCH
  if epoch < cfg.ALTAIR_FORK_EPOCH:
    cfg.ALTAIR_FORK_EPOCH
  elif epoch < cfg.MERGE_FORK_EPOCH:
    cfg.MERGE_FORK_EPOCH
  else:
    FAR_FUTURE_EPOCH

func getForkSchedule*(cfg: RuntimeConfig): array[2, Fork] =
  ## This procedure returns list of known and/or scheduled forks.
  ##
  ## This procedure is used by HTTP REST framework and validator client.
  ##
  ## NOTE: Update this procedure when new fork will be scheduled.
  [cfg.genesisFork(), cfg.altairFork()]
