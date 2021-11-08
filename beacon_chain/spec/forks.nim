# beacon_chain
# Copyright (c) 2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  stew/[assign2],
  chronicles,
  ../extras,
  "."/[eth2_merkleization, eth2_ssz_serialization, presets],
  ./datatypes/[phase0, altair, merge]

export
  extras, phase0, altair, merge, eth2_merkleization, eth2_ssz_serialization,
  presets

# This file contains helpers for dealing with forks - we have two ways we can
# deal with forks:
# * generics - this means using the static typing and differentiating forks
#   at compile time - this is preferred in fork-specific code where the fork
#   is known up-front, for example spec functions.
# * variants - this means using a variant object and determining the fork at
#   runtime - this carries the obvious risk and complexity of dealing with
#   runtime checking, but is of course needed for external data that may be
#   of any fork kind.
#
# For generics, we define `Forky*` type classes that cover "similar" objects
# across forks - for variants, they're called `Forked*` instead.
# See withXxx and `init` for convenient ways of moving between these two worlds.
# A clever programmer would use templates, macros and dark magic to create all
# these types and converters :)

type
  BeaconStateFork* {.pure.} = enum
    Phase0,
    Altair,
    Merge

  ForkyBeaconState* =
    phase0.BeaconState |
    altair.BeaconState |
    merge.BeaconState

  ForkyHashedBeaconState* =
    phase0.HashedBeaconState |
    altair.HashedBeaconState |
    merge.HashedBeaconState

  ForkedHashedBeaconState* = object
    case kind*: BeaconStateFork
    of BeaconStateFork.Phase0: phase0Data*: phase0.HashedBeaconState
    of BeaconStateFork.Altair: altairData*: altair.HashedBeaconState
    of BeaconStateFork.Merge:  mergeData*:  merge.HashedBeaconState

  BeaconBlockFork* {.pure.} = enum
    Phase0
    Altair
    Merge

  ForkyBeaconBlock* =
    phase0.BeaconBlock |
    altair.BeaconBlock |
    merge.BeaconBlock

  ForkyTrustedBeaconBlock* =
    phase0.TrustedBeaconBlock |
    altair.TrustedBeaconBlock |
    merge.TrustedBeaconBlock

  ForkedBeaconBlock* = object
    case kind*: BeaconBlockFork
    of BeaconBlockFork.Phase0: phase0Data*: phase0.BeaconBlock
    of BeaconBlockFork.Altair: altairData*: altair.BeaconBlock
    of BeaconBlockFork.Merge:  mergeData*:  merge.BeaconBlock

  ForkedTrustedBeaconBlock* = object
    case kind*: BeaconBlockFork
    of BeaconBlockFork.Phase0: phase0Data*: phase0.TrustedBeaconBlock
    of BeaconBlockFork.Altair: altairData*: altair.TrustedBeaconBlock
    of BeaconBlockFork.Merge:  mergeData*:  merge.TrustedBeaconBlock

  ForkySignedBeaconBlock* =
    phase0.SignedBeaconBlock |
    altair.SignedBeaconBlock |
    merge.SignedBeaconBlock

  ForkedSignedBeaconBlock* = object
    case kind*: BeaconBlockFork
    of BeaconBlockFork.Phase0: phase0Data*: phase0.SignedBeaconBlock
    of BeaconBlockFork.Altair: altairData*: altair.SignedBeaconBlock
    of BeaconBlockFork.Merge:  mergeData*:  merge.SignedBeaconBlock

  ForkyTrustedSignedBeaconBlock* =
    phase0.TrustedSignedBeaconBlock |
    altair.TrustedSignedBeaconBlock |
    merge.TrustedSignedBeaconBlock

  ForkedTrustedSignedBeaconBlock* = object
    case kind*: BeaconBlockFork
    of BeaconBlockFork.Phase0: phase0Data*: phase0.TrustedSignedBeaconBlock
    of BeaconBlockFork.Altair: altairData*: altair.TrustedSignedBeaconBlock
    of BeaconBlockFork.Merge:  mergeData*:  merge.TrustedSignedBeaconBlock

  EpochInfoFork* {.pure.} = enum
    Phase0
    Altair

  ForkedEpochInfo* = object
    case kind*: EpochInfoFork
    of EpochInfoFork.Phase0: phase0Data*: phase0.EpochInfo
    of EpochInfoFork.Altair: altairData*: altair.EpochInfo

  ForkyEpochInfo* = phase0.EpochInfo | altair.EpochInfo

  ForkDigests* = object
    phase0*: ForkDigest
    altair*: ForkDigest
    merge*:  ForkDigest

template toFork*[T: phase0.BeaconState | phase0.HashedBeaconState](
    t: type T): BeaconStateFork =
  BeaconStateFork.Phase0
template toFork*[T: altair.BeaconState | altair.HashedBeaconState](
    t: type T): BeaconStateFork =
  BeaconStateFork.Altair
template toFork*[T: merge.BeaconState | merge.HashedBeaconState](
    t: type T): BeaconStateFork =
  BeaconStateFork.Merge

template init*(T: type ForkedHashedBeaconState, data: phase0.HashedBeaconState): T =
  T(kind: BeaconStateFork.Phase0, phase0Data: data)
template init*(T: type ForkedHashedBeaconState, data: altair.HashedBeaconState): T =
  T(kind: BeaconStateFork.Altair, altairData: data)
template init*(T: type ForkedHashedBeaconState, data: merge.HashedBeaconState): T =
  T(kind: BeaconStateFork.Merge, mergeData: data)

template init*(T: type ForkedBeaconBlock, blck: phase0.BeaconBlock): T =
  T(kind: BeaconBlockFork.Phase0, phase0Data: blck)
template init*(T: type ForkedBeaconBlock, blck: altair.BeaconBlock): T =
  T(kind: BeaconBlockFork.Altair, altairData: blck)
template init*(T: type ForkedBeaconBlock, blck: merge.BeaconBlock): T =
  T(kind: BeaconBlockFork.Merge, mergeData: blck)

template init*(T: type ForkedTrustedBeaconBlock, blck: phase0.TrustedBeaconBlock): T =
  T(kind: BeaconBlockFork.Phase0, phase0Data: blck)
template init*(T: type ForkedTrustedBeaconBlock, blck: altair.TrustedBeaconBlock): T =
  T(kind: BeaconBlockFork.Altair, altairData: blck)
template init*(T: type ForkedTrustedBeaconBlock, blck: merge.TrustedBeaconBlock): T =
  T(kind: BeaconBlockFork.Merge, mergeData: blck)

template init*(T: type ForkedSignedBeaconBlock, blck: phase0.SignedBeaconBlock): T =
  T(kind: BeaconBlockFork.Phase0, phase0Data: blck)
template init*(T: type ForkedSignedBeaconBlock, blck: altair.SignedBeaconBlock): T =
  T(kind: BeaconBlockFork.Altair, altairData: blck)
template init*(T: type ForkedSignedBeaconBlock, blck: merge.SignedBeaconBlock): T =
  T(kind: BeaconBlockFork.Merge, mergeData: blck)

template init*(T: type ForkedSignedBeaconBlock, forked: ForkedBeaconBlock,
               blockRoot: Eth2Digest, signature: ValidatorSig): T =
  case forked.kind
  of BeaconBlockFork.Phase0:
    T(kind: BeaconBlockFork.Phase0,
      phase0Data: phase0.SignedBeaconBlock(message: forked.phase0Data,
                                           root: blockRoot,
                                           signature: signature))
  of BeaconBlockFork.Altair:
    T(kind: BeaconBlockFork.Altair,
      altairData: altair.SignedBeaconBlock(message: forked.altairData,
                                           root: blockRoot,
                                           signature: signature))
  of BeaconBlockFork.Merge:
    T(kind: BeaconBlockFork.Merge,
      mergeData: merge.SignedBeaconBlock(message: forked.mergeData,
                                          root: blockRoot,
                                          signature: signature))

template init*(T: type ForkedTrustedSignedBeaconBlock, blck: phase0.TrustedSignedBeaconBlock): T =
  T(kind: BeaconBlockFork.Phase0, phase0Data: blck)
template init*(T: type ForkedTrustedSignedBeaconBlock, blck: altair.TrustedSignedBeaconBlock): T =
  T(kind: BeaconBlockFork.Altair, altairData: blck)
template init*(T: type ForkedTrustedSignedBeaconBlock, blck: merge.TrustedSignedBeaconBlock): T =
  T(kind: BeaconBlockFork.Merge,  mergeData: blck)

template toFork*[T: phase0.TrustedSignedBeaconBlock](
    t: type T): BeaconBlockFork =
  BeaconBlockFork.Phase0
template toFork*[T: altair.TrustedSignedBeaconBlock](
    t: type T): BeaconBlockFork =
  BeaconBlockFork.Altair
template toFork*[T: merge.TrustedSignedBeaconBlock](
    t: type T): BeaconBlockFork =
  BeaconBlockFork.Merge

template init*(T: type ForkedEpochInfo, info: phase0.EpochInfo): T =
  T(kind: EpochInfoFork.Phase0, phase0Data: info)
template init*(T: type ForkedEpochInfo, info: altair.EpochInfo): T =
  T(kind: EpochInfoFork.Altair, altairData: info)

template withState*(x: ForkedHashedBeaconState, body: untyped): untyped =
  case x.kind
  of BeaconStateFork.Merge:
    const stateFork {.inject.} = BeaconStateFork.Merge
    template state: untyped {.inject.} = x.mergeData
    body
  of BeaconStateFork.Altair:
    const stateFork {.inject.} = BeaconStateFork.Altair
    template state: untyped {.inject.} = x.altairData
    body
  of BeaconStateFork.Phase0:
    const stateFork {.inject.} = BeaconStateFork.Phase0
    template state: untyped {.inject.} = x.phase0Data
    body

template withEpochInfo*(x: ForkedEpochInfo, body: untyped): untyped =
  case x.kind
  of EpochInfoFork.Phase0:
    template info: untyped {.inject.} = x.phase0Data
    body
  of EpochInfoFork.Altair:
    template info: untyped {.inject.} = x.altairData
    body

template withEpochInfo*(
    state: phase0.BeaconState, x: var ForkedEpochInfo, body: untyped): untyped =
  x.kind = EpochInfoFork.Phase0
  template info: untyped {.inject.} = x.phase0Data
  body

template withEpochInfo*(
    state: altair.BeaconState | merge.BeaconState, x: var ForkedEpochInfo,
    body: untyped): untyped =
  x.kind = EpochInfoFork.Altair
  template info: untyped {.inject.} = x.altairData
  body

func assign*(tgt: var ForkedHashedBeaconState, src: ForkedHashedBeaconState) =
  if tgt.kind == src.kind:
    case tgt.kind
    of BeaconStateFork.Merge:
      assign(tgt.mergeData,  src.mergeData):
    of BeaconStateFork.Altair:
      assign(tgt.altairData, src.altairData):
    of BeaconStateFork.Phase0:
      assign(tgt.phase0Data, src.phase0Data):
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
  (case x.kind
  of BeaconStateFork.Merge: unsafeAddr x.mergeData.data.y
  of BeaconStateFork.Altair: unsafeAddr x.altairData.data.y
  of BeaconStateFork.Phase0: unsafeAddr x.phase0Data.data.y)[]

func getStateRoot*(x: ForkedHashedBeaconState): Eth2Digest =
  withState(x): state.root

func setStateRoot*(x: var ForkedHashedBeaconState, root: Eth2Digest) =
  withState(x): state.root = root

func stateForkAtEpoch*(cfg: RuntimeConfig, epoch: Epoch): BeaconStateFork =
  ## Return the current fork for the given epoch.
  static:
    doAssert BeaconStateFork.Merge  > BeaconStateFork.Altair
    doAssert BeaconStateFork.Altair > BeaconStateFork.Phase0
    doAssert GENESIS_EPOCH == 0

  if   epoch >= cfg.MERGE_FORK_EPOCH:  BeaconStateFork.Merge
  elif epoch >= cfg.ALTAIR_FORK_EPOCH: BeaconStateFork.Altair
  else:                                BeaconStateFork.Phase0

func blockForkAtEpoch*(cfg: RuntimeConfig, epoch: Epoch): BeaconBlockFork =
  ## Return the current fork for the given epoch.
  if   epoch >= cfg.MERGE_FORK_EPOCH:  BeaconBlockFork.Merge
  elif epoch >= cfg.ALTAIR_FORK_EPOCH: BeaconBlockFork.Altair
  else:                                BeaconBlockFork.Phase0

template asSigned*(x: ForkedTrustedSignedBeaconBlock): ForkedSignedBeaconBlock =
  isomorphicCast[ForkedSignedBeaconBlock](x)

template asTrusted*(x: ForkedSignedBeaconBlock): ForkedTrustedSignedBeaconBlock =
  isomorphicCast[ForkedTrustedSignedBeaconBlock](x)

template withBlck*(
    x: ForkedBeaconBlock | ForkedSignedBeaconBlock |
       ForkedTrustedSignedBeaconBlock,
    body: untyped): untyped =
  case x.kind
  of BeaconBlockFork.Phase0:
    const stateFork {.inject.} = BeaconStateFork.Phase0
    template blck: untyped {.inject.} = x.phase0Data
    body
  of BeaconBlockFork.Altair:
    const stateFork {.inject.} = BeaconStateFork.Altair
    template blck: untyped {.inject.} = x.altairData
    body
  of BeaconBlockFork.Merge:
    const stateFork {.inject.} = BeaconStateFork.Merge
    template blck: untyped {.inject.} = x.mergeData
    body

func proposer_index*(x: ForkedBeaconBlock): uint64 =
  withBlck(x): blck.proposer_index

func hash_tree_root*(x: ForkedBeaconBlock): Eth2Digest =
  withBlck(x): hash_tree_root(blck)

template getForkedBlockField*(x: ForkedSignedBeaconBlock | ForkedTrustedSignedBeaconBlock, y: untyped): untyped =
  # unsafeAddr avoids a copy of the field in some cases
  (case x.kind
  of BeaconBlockFork.Phase0: unsafeAddr x.phase0Data.message.y
  of BeaconBlockFork.Altair: unsafeAddr x.altairData.message.y
  of BeaconBlockFork.Merge: unsafeAddr x.mergeData.message.y)[]

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
  case s.kind
  of BeaconStateFork.Merge:
    const stateFork {.inject.} = BeaconStateFork.Merge
    template state: untyped {.inject.} = s.mergeData
    template blck: untyped {.inject.} = b.mergeData
    body
  of BeaconStateFork.Altair:
    const stateFork {.inject.} = BeaconStateFork.Altair
    template state: untyped {.inject.} = s.altairData
    template blck: untyped {.inject.} = b.altairData
    body
  of BeaconStateFork.Phase0:
    const stateFork {.inject.} = BeaconStateFork.Phase0
    template state: untyped {.inject.} = s.phase0Data
    template blck: untyped {.inject.} = b.phase0Data
    body

func genesisFork*(cfg: RuntimeConfig): Fork =
  Fork(
    previous_version: cfg.GENESIS_FORK_VERSION,
    current_version: cfg.GENESIS_FORK_VERSION,
    epoch: GENESIS_EPOCH)

func altairFork*(cfg: RuntimeConfig): Fork =
  Fork(
    previous_version: cfg.GENESIS_FORK_VERSION,
    current_version: cfg.ALTAIR_FORK_VERSION,
    epoch: cfg.ALTAIR_FORK_EPOCH)

func mergeFork*(cfg: RuntimeConfig): Fork =
  # TODO in theory, the altair + merge forks could be in same epoch, so the
  # previous fork version would be the GENESIS_FORK_VERSION
  Fork(
    previous_version: cfg.ALTAIR_FORK_VERSION,
    current_version: cfg.MERGE_FORK_VERSION,
    epoch: cfg.MERGE_FORK_EPOCH)

proc forkAtEpoch*(cfg: RuntimeConfig, epoch: Epoch): Fork =
  case cfg.stateForkAtEpoch(epoch)
  of BeaconStateFork.Merge:  cfg.mergeFork
  of BeaconStateFork.Altair: cfg.altairFork
  of BeaconStateFork.Phase0: cfg.genesisFork

proc forkVersionAtEpoch*(cfg: RuntimeConfig, epoch: Epoch): Version =
  case cfg.stateForkAtEpoch(epoch)
  of BeaconStateFork.Merge:  cfg.MERGE_FORK_VERSION
  of BeaconStateFork.Altair: cfg.ALTAIR_FORK_VERSION
  of BeaconStateFork.Phase0: cfg.GENESIS_FORK_VERSION

proc nextForkEpochAtEpoch*(cfg: RuntimeConfig, epoch: Epoch): Epoch =
  case cfg.stateForkAtEpoch(epoch)
  of BeaconStateFork.Merge:  FAR_FUTURE_EPOCH
  of BeaconStateFork.Altair: cfg.MERGE_FORK_EPOCH
  of BeaconStateFork.Phase0: cfg.ALTAIR_FORK_EPOCH

func getForkSchedule*(cfg: RuntimeConfig): array[2, Fork] =
  ## This procedure returns list of known and/or scheduled forks.
  ##
  ## This procedure is used by HTTP REST framework and validator client.
  ##
  ## NOTE: Update this procedure when new fork will be scheduled.
  [cfg.genesisFork(), cfg.altairFork()]

func readSszForkedHashedBeaconState*(
    data: openArray[byte], likelyFork: BeaconStateFork):
    ForkedHashedBeaconState {.raises: [Defect, SszError].} =
  ## Helper to read a state from bytes when it's not certain what kind of state
  ## it is - this happens for example when loading an SSZ state from command
  ## line - we'll use wall time to "guess" which state to start with
  # careful - `result` is used, RVO didn't seem to work without
  result = ForkedHashedBeaconState(kind: likelyFork)
  var tried: set[BeaconStateFork]

  template readFork() =
    withState(result):
      try:
        readSszBytes(data, state.data)
        state.root = hash_tree_root(state.data)
        return result
      except SszError as exc:
        tried.incl result.kind

  readFork()

  for fork in BeaconStateFork:
    if fork in tried: continue
    result = ForkedHashedBeaconState(kind: fork)
    readFork()

  raise (ref SszError)(msg: "Unable to match data to any known fork")

func readSszForkedTrustedSignedBeaconBlock*(
    data: openArray[byte], likelyFork: BeaconBlockFork):
    ForkedTrustedSignedBeaconBlock {.raises: [Defect, SszError].} =
  ## Helper to read a state from bytes when it's not certain what kind of state
  ## it is - this happens for example when loading an SSZ state from command
  ## line - we'll use wall time to "guess" which state to start with

  var
    res = ForkedTrustedSignedBeaconBlock(kind: likelyFork)
    tried: set[BeaconBlockFork]

  template readFork() =
    withBlck(res):
      try:
        readSszBytes(data, blck)
        return res
      except SszError as exc:
        tried.incl res.kind

  readFork()

  for fork in BeaconBlockFork:
    if fork in tried: continue
    res = ForkedTrustedSignedBeaconBlock(kind: fork)
    readFork()
  raise (ref SszError)(msg: "Unable to match data to any known fork")

func toBeaconBlockFork*(fork: BeaconStateFork): BeaconBlockFork =
  case fork
  of BeaconStateFork.Phase0: BeaconBlockFork.Phase0
  of BeaconStateFork.Altair: BeaconBlockFork.Altair
  of BeaconStateFork.Merge: BeaconBlockFork.Merge

# https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#compute_fork_data_root
func compute_fork_data_root*(current_version: Version,
    genesis_validators_root: Eth2Digest): Eth2Digest =
  ## Return the 32-byte fork data root for the ``current_version`` and
  ## ``genesis_validators_root``.
  ## This is used primarily in signature domains to avoid collisions across
  ## forks/chains.
  hash_tree_root(ForkData(
    current_version: current_version,
    genesis_validators_root: genesis_validators_root
  ))

# https://github.com/ethereum/consensus-specs/blob/v1.1.4/specs/phase0/beacon-chain.md#compute_fork_digest
func compute_fork_digest*(current_version: Version,
                          genesis_validators_root: Eth2Digest): ForkDigest =
  ## Return the 4-byte fork digest for the ``current_version`` and
  ## ``genesis_validators_root``.
  ## This is a digest primarily used for domain separation on the p2p layer.
  ## 4-bytes suffices for practical separation of forks/chains.
  array[4, byte](result)[0..3] =
    compute_fork_data_root(
      current_version, genesis_validators_root).data.toOpenArray(0, 3)

func init*(T: type ForkDigests,
           cfg: RuntimeConfig,
           genesisValidatorsRoot: Eth2Digest): T =
  T(
    phase0:
      compute_fork_digest(cfg.GENESIS_FORK_VERSION, genesisValidatorsRoot),
    altair:
      compute_fork_digest(cfg.ALTAIR_FORK_VERSION, genesisValidatorsRoot),
    merge:
      compute_fork_digest(cfg.MERGE_FORK_VERSION, genesisValidatorsRoot),
  )
