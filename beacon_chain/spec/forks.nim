# beacon_chain
# Copyright (c) 2021-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import
  stew/assign2,
  chronicles,
  ../extras,
  "."/[block_id, eth2_merkleization, eth2_ssz_serialization, presets],
  ./datatypes/[phase0, altair, bellatrix, capella],
  ./mev/bellatrix_mev

# TODO re-export capella, but for now it could cause knock-on effects, so stage
# it sequentially
export
  extras, block_id, phase0, altair, bellatrix, eth2_merkleization,
  eth2_ssz_serialization, presets, bellatrix_mev

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
    Bellatrix,
    Capella

  ForkyBeaconState* =
    phase0.BeaconState |
    altair.BeaconState |
    bellatrix.BeaconState |
    capella.BeaconState

  ForkyHashedBeaconState* =
    phase0.HashedBeaconState |
    altair.HashedBeaconState |
    bellatrix.HashedBeaconState |
    capella.HashedBeaconState

  ForkedHashedBeaconState* = object
    case kind*: BeaconStateFork
    of BeaconStateFork.Phase0:    phase0Data*:    phase0.HashedBeaconState
    of BeaconStateFork.Altair:    altairData*:    altair.HashedBeaconState
    of BeaconStateFork.Bellatrix: bellatrixData*: bellatrix.HashedBeaconState
    of BeaconStateFork.Capella:   capellaData*:   capella.HashedBeaconState

  BeaconBlockFork* {.pure.} = enum
    Phase0
    Altair
    Bellatrix,
    Capella

  ForkyBeaconBlockBody* =
    phase0.BeaconBlockBody |
    altair.BeaconBlockBody |
    bellatrix.BeaconBlockBody |
    capella.BeaconBlockBody

  ForkySigVerifiedBeaconBlockBody* =
    phase0.SigVerifiedBeaconBlockBody |
    altair.SigVerifiedBeaconBlockBody |
    bellatrix.SigVerifiedBeaconBlockBody |
    capella.SigVerifiedBeaconBlockBody

  ForkyTrustedBeaconBlockBody* =
    phase0.TrustedBeaconBlockBody |
    altair.TrustedBeaconBlockBody |
    bellatrix.TrustedBeaconBlockBody |
    capella.TrustedBeaconBlockBody

  SomeForkyBeaconBlockBody* =
    ForkyBeaconBlockBody |
    ForkySigVerifiedBeaconBlockBody |
    ForkyTrustedBeaconBlockBody

  ForkyBeaconBlock* =
    phase0.BeaconBlock |
    altair.BeaconBlock |
    bellatrix.BeaconBlock |
    capella.BeaconBlock

  ForkySigVerifiedBeaconBlock* =
    phase0.SigVerifiedBeaconBlock |
    altair.SigVerifiedBeaconBlock |
    bellatrix.SigVerifiedBeaconBlock |
    capella.SigVerifiedBeaconBlock

  ForkyTrustedBeaconBlock* =
    phase0.TrustedBeaconBlock |
    altair.TrustedBeaconBlock |
    bellatrix.TrustedBeaconBlock |
    capella.TrustedBeaconBlock

  SomeForkyBeaconBlock* =
    ForkyBeaconBlock |
    ForkySigVerifiedBeaconBlock |
    ForkyTrustedBeaconBlock

  ForkedBeaconBlock* = object
    case kind*: BeaconBlockFork
    of BeaconBlockFork.Phase0:    phase0Data*:    phase0.BeaconBlock
    of BeaconBlockFork.Altair:    altairData*:    altair.BeaconBlock
    of BeaconBlockFork.Bellatrix: bellatrixData*: bellatrix.BeaconBlock
    of BeaconBlockFork.Capella:   capellaData*:   capella.BeaconBlock

  Web3SignerForkedBeaconBlock* = object
    case kind*: BeaconBlockFork
    of BeaconBlockFork.Phase0:    phase0Data*:    phase0.BeaconBlock
    of BeaconBlockFork.Altair:    altairData*:    altair.BeaconBlock
    of BeaconBlockFork.Bellatrix: bellatrixData*: BeaconBlockHeader
    of BeaconBlockFork.Capella:   capellaData*:   BeaconBlockHeader

  ForkedBlindedBeaconBlock* = object
    case kind*: BeaconBlockFork
    of BeaconBlockFork.Phase0:    phase0Data*:    phase0.BeaconBlock
    of BeaconBlockFork.Altair:    altairData*:    altair.BeaconBlock
    of BeaconBlockFork.Bellatrix: bellatrixData*: BlindedBeaconBlock
    of BeaconBlockFork.Capella:   capellaData*:   BlindedBeaconBlock

  ForkedTrustedBeaconBlock* = object
    case kind*: BeaconBlockFork
    of BeaconBlockFork.Phase0:    phase0Data*:     phase0.TrustedBeaconBlock
    of BeaconBlockFork.Altair:    altairData*:     altair.TrustedBeaconBlock
    of BeaconBlockFork.Bellatrix: bellatrixData*:  bellatrix.TrustedBeaconBlock
    of BeaconBlockFork.Capella:   capellaData*:    capella.TrustedBeaconBlock

  ForkySignedBeaconBlock* =
    phase0.SignedBeaconBlock |
    altair.SignedBeaconBlock |
    bellatrix.SignedBeaconBlock |
    capella.SignedBeaconBlock

  ForkedSignedBeaconBlock* = object
    case kind*: BeaconBlockFork
    of BeaconBlockFork.Phase0:    phase0Data*:    phase0.SignedBeaconBlock
    of BeaconBlockFork.Altair:    altairData*:    altair.SignedBeaconBlock
    of BeaconBlockFork.Bellatrix: bellatrixData*: bellatrix.SignedBeaconBlock
    of BeaconBlockFork.Capella:   capellaData*:   capella.SignedBeaconBlock

  ForkySignedBlindedBeaconBlock* =
    phase0.SignedBeaconBlock |
    altair.SignedBeaconBlock |
    SignedBlindedBeaconBlock

  ForkedSignedBlindedBeaconBlock* = object
    case kind*: BeaconBlockFork
    of BeaconBlockFork.Phase0:    phase0Data*:    phase0.SignedBeaconBlock
    of BeaconBlockFork.Altair:    altairData*:    altair.SignedBeaconBlock
    of BeaconBlockFork.Bellatrix: bellatrixData*: SignedBlindedBeaconBlock
    of BeaconBlockFork.Capella:   capellaData*:   SignedBlindedBeaconBlock

  ForkySigVerifiedSignedBeaconBlock* =
    phase0.SigVerifiedSignedBeaconBlock |
    altair.SigVerifiedSignedBeaconBlock |
    bellatrix.SigVerifiedSignedBeaconBlock |
    capella.SigVerifiedSignedBeaconBlock

  ForkyMsgTrustedSignedBeaconBlock* =
    phase0.MsgTrustedSignedBeaconBlock |
    altair.MsgTrustedSignedBeaconBlock |
    bellatrix.MsgTrustedSignedBeaconBlock |
    capella.MsgTrustedSignedBeaconBlock

  ForkyTrustedSignedBeaconBlock* =
    phase0.TrustedSignedBeaconBlock |
    altair.TrustedSignedBeaconBlock |
    bellatrix.TrustedSignedBeaconBlock |
    capella.TrustedSignedBeaconBlock

  ForkedMsgTrustedSignedBeaconBlock* = object
    case kind*: BeaconBlockFork
    of BeaconBlockFork.Phase0:    phase0Data*:    phase0.MsgTrustedSignedBeaconBlock
    of BeaconBlockFork.Altair:    altairData*:    altair.MsgTrustedSignedBeaconBlock
    of BeaconBlockFork.Bellatrix: bellatrixData*: bellatrix.MsgTrustedSignedBeaconBlock
    of BeaconBlockFork.Capella:   capellaData*:   capella.MsgTrustedSignedBeaconBlock

  ForkedTrustedSignedBeaconBlock* = object
    case kind*: BeaconBlockFork
    of BeaconBlockFork.Phase0:    phase0Data*:    phase0.TrustedSignedBeaconBlock
    of BeaconBlockFork.Altair:    altairData*:    altair.TrustedSignedBeaconBlock
    of BeaconBlockFork.Bellatrix: bellatrixData*: bellatrix.TrustedSignedBeaconBlock
    of BeaconBlockFork.Capella:   capellaData*:   capella.TrustedSignedBeaconBlock

  SomeForkySignedBeaconBlock* =
    ForkySignedBeaconBlock |
    ForkySigVerifiedSignedBeaconBlock |
    ForkyMsgTrustedSignedBeaconBlock |
    ForkyTrustedSignedBeaconBlock

  EpochInfoFork* {.pure.} = enum
    Phase0
    Altair

  ForkedEpochInfo* = object
    case kind*: EpochInfoFork
    of EpochInfoFork.Phase0: phase0Data*: phase0.EpochInfo
    of EpochInfoFork.Altair: altairData*: altair.EpochInfo

  ForkyEpochInfo* = phase0.EpochInfo | altair.EpochInfo

  ForkDigests* = object
    phase0*:    ForkDigest
    altair*:    ForkDigest
    bellatrix*: ForkDigest
    capella*:   ForkDigest
    sharding*:  ForkDigest

template toFork*[T: phase0.BeaconState | phase0.HashedBeaconState](
    t: type T): BeaconStateFork =
  BeaconStateFork.Phase0
template toFork*[T: altair.BeaconState | altair.HashedBeaconState](
    t: type T): BeaconStateFork =
  BeaconStateFork.Altair
template toFork*[T: bellatrix.BeaconState | bellatrix.HashedBeaconState](
    t: type T): BeaconStateFork =
  BeaconStateFork.Bellatrix
template toFork*[T: capella.BeaconState | capella.HashedBeaconState](
    t: type T): BeaconStateFork =
  BeaconStateFork.Capella

# TODO these cause stack overflows due to large temporaries getting allocated
# template init*(T: type ForkedHashedBeaconState, data: phase0.HashedBeaconState): T =
#   T(kind: BeaconStateFork.Phase0, phase0Data: data)
# template init*(T: type ForkedHashedBeaconState, data: altair.HashedBeaconState): T =
#   T(kind: BeaconStateFork.Altair, altairData: data)
# template init*(T: type ForkedHashedBeaconState, data: bellatrix.HashedBeaconState): T =
#   T(kind: BeaconStateFork.Bellatrix, bellatrixData: data)

template init*(T: type ForkedBeaconBlock, blck: phase0.BeaconBlock): T =
  T(kind: BeaconBlockFork.Phase0, phase0Data: blck)
template init*(T: type ForkedBeaconBlock, blck: altair.BeaconBlock): T =
  T(kind: BeaconBlockFork.Altair, altairData: blck)
template init*(T: type ForkedBeaconBlock, blck: bellatrix.BeaconBlock): T =
  T(kind: BeaconBlockFork.Bellatrix, bellatrixData: blck)

template init*(T: type ForkedTrustedBeaconBlock, blck: phase0.TrustedBeaconBlock): T =
  T(kind: BeaconBlockFork.Phase0, phase0Data: blck)
template init*(T: type ForkedTrustedBeaconBlock, blck: altair.TrustedBeaconBlock): T =
  T(kind: BeaconBlockFork.Altair, altairData: blck)
template init*(T: type ForkedTrustedBeaconBlock, blck: bellatrix.TrustedBeaconBlock): T =
  T(kind: BeaconBlockFork.Bellatrix, bellatrixData: blck)

template init*(T: type ForkedSignedBeaconBlock, blck: phase0.SignedBeaconBlock): T =
  T(kind: BeaconBlockFork.Phase0, phase0Data: blck)
template init*(T: type ForkedSignedBeaconBlock, blck: altair.SignedBeaconBlock): T =
  T(kind: BeaconBlockFork.Altair, altairData: blck)
template init*(T: type ForkedSignedBeaconBlock, blck: bellatrix.SignedBeaconBlock): T =
  T(kind: BeaconBlockFork.Bellatrix, bellatrixData: blck)
template init*(T: type ForkedSignedBeaconBlock, blck: capella.SignedBeaconBlock): T =
  T(kind: BeaconBlockFork.Capella, capellaData: blck)

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
  of BeaconBlockFork.Bellatrix:
    T(kind: BeaconBlockFork.Bellatrix,
      bellatrixData: bellatrix.SignedBeaconBlock(message: forked.bellatrixData,
                                                 root: blockRoot,
                                                 signature: signature))
  of BeaconBlockFork.Capella:
    T(kind: BeaconBlockFork.Capella,
      capellaData: capella.SignedBeaconBlock(message: forked.capellaData,
                                             root: blockRoot,
                                             signature: signature))

template init*(T: type ForkedSignedBlindedBeaconBlock,
               forked: ForkedBlindedBeaconBlock, blockRoot: Eth2Digest,
               signature: ValidatorSig): T =
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
  of BeaconBlockFork.Bellatrix:
    T(kind: BeaconBlockFork.Bellatrix,
      bellatrixData: SignedBlindedBeaconBlock(message: forked.bellatrixData,
                                              signature: signature))
  of BeaconBlockFork.Capella:
    T(kind: BeaconBlockFork.Capella,
      capellaData: SignedBlindedBeaconBlock(message: forked.capellaData,
                                            signature: signature))

template init*(T: type ForkedMsgTrustedSignedBeaconBlock, blck: phase0.MsgTrustedSignedBeaconBlock): T =
  T(kind: BeaconBlockFork.Phase0,    phase0Data: blck)
template init*(T: type ForkedMsgTrustedSignedBeaconBlock, blck: altair.MsgTrustedSignedBeaconBlock): T =
  T(kind: BeaconBlockFork.Altair,    altairData: blck)
template init*(T: type ForkedMsgTrustedSignedBeaconBlock, blck: bellatrix.MsgTrustedSignedBeaconBlock): T =
  T(kind: BeaconBlockFork.Bellatrix, bellatrixData: blck)
template init*(T: type ForkedMsgTrustedSignedBeaconBlock, blck: capella.MsgTrustedSignedBeaconBlock): T =
  T(kind: BeaconBlockFork.Capella,   capellaData: blck)

template init*(T: type ForkedTrustedSignedBeaconBlock, blck: phase0.TrustedSignedBeaconBlock): T =
  T(kind: BeaconBlockFork.Phase0, phase0Data: blck)
template init*(T: type ForkedTrustedSignedBeaconBlock, blck: altair.TrustedSignedBeaconBlock): T =
  T(kind: BeaconBlockFork.Altair, altairData: blck)
template init*(T: type ForkedTrustedSignedBeaconBlock, blck: bellatrix.TrustedSignedBeaconBlock): T =
  T(kind: BeaconBlockFork.Bellatrix, bellatrixData: blck)
template init*(T: type ForkedTrustedSignedBeaconBlock, blck: capella.TrustedSignedBeaconBlock): T =
  T(kind: BeaconBlockFork.Capella, capellaData: blck)

template toString*(kind: BeaconBlockFork): string =
  case kind
  of BeaconBlockFork.Phase0:
    "phase0"
  of BeaconBlockFork.Altair:
    "altair"
  of BeaconBlockFork.Bellatrix:
    "bellatrix"
  of BeaconBlockFork.Capella:
    "capella"

template toString*(kind: BeaconStateFork): string =
  case kind
  of BeaconStateFork.Phase0:
    "phase0"
  of BeaconStateFork.Altair:
    "altair"
  of BeaconStateFork.Bellatrix:
    "bellatrix"
  of BeaconStateFork.Capella:
    "capella"

template toFork*[T:
    phase0.BeaconBlock |
    phase0.SignedBeaconBlock |
    phase0.TrustedBeaconBlock |
    phase0.SigVerifiedSignedBeaconBlock |
    phase0.MsgTrustedSignedBeaconBlock |
    phase0.TrustedSignedBeaconBlock](
    t: type T): BeaconBlockFork =
  BeaconBlockFork.Phase0
template toFork*[T:
    altair.BeaconBlock |
    altair.SignedBeaconBlock |
    altair.TrustedBeaconBlock |
    altair.SigVerifiedSignedBeaconBlock |
    altair.MsgTrustedSignedBeaconBlock |
    altair.TrustedSignedBeaconBlock](
    t: type T): BeaconBlockFork =
  BeaconBlockFork.Altair
template toFork*[T:
    bellatrix.BeaconBlock |
    bellatrix.SignedBeaconBlock |
    bellatrix.TrustedBeaconBlock |
    bellatrix.SigVerifiedSignedBeaconBlock |
    bellatrix.MsgTrustedSignedBeaconBlock |
    bellatrix.TrustedSignedBeaconBlock](
    t: type T): BeaconBlockFork =
  BeaconBlockFork.Bellatrix
template toFork*[T:
    capella.BeaconBlock |
    capella.SignedBeaconBlock |
    capella.TrustedBeaconBlock |
    capella.SigVerifiedSignedBeaconBlock |
    capella.MsgTrustedSignedBeaconBlock |
    capella.TrustedSignedBeaconBlock](
    t: type T): BeaconBlockFork =
  BeaconBlockFork.Capella

template init*(T: type ForkedEpochInfo, info: phase0.EpochInfo): T =
  T(kind: EpochInfoFork.Phase0, phase0Data: info)
template init*(T: type ForkedEpochInfo, info: altair.EpochInfo): T =
  T(kind: EpochInfoFork.Altair, altairData: info)

template withState*(x: ForkedHashedBeaconState, body: untyped): untyped =
  case x.kind
  of BeaconStateFork.Capella:
    const stateFork {.inject, used.} = BeaconStateFork.Capella
    template forkyState: untyped {.inject, used.} = x.capellaData
    body
  of BeaconStateFork.Bellatrix:
    const stateFork {.inject, used.} = BeaconStateFork.Bellatrix
    template forkyState: untyped {.inject, used.} = x.bellatrixData
    body
  of BeaconStateFork.Altair:
    const stateFork {.inject, used.} = BeaconStateFork.Altair
    template forkyState: untyped {.inject, used.} = x.altairData
    body
  of BeaconStateFork.Phase0:
    const stateFork {.inject, used.} = BeaconStateFork.Phase0
    template forkyState: untyped {.inject, used.} = x.phase0Data
    body

template withEpochInfo*(x: ForkedEpochInfo, body: untyped): untyped =
  case x.kind
  of EpochInfoFork.Phase0:
    const infoFork {.inject.} = EpochInfoFork.Phase0
    template info: untyped {.inject.} = x.phase0Data
    body
  of EpochInfoFork.Altair:
    const infoFork {.inject.} = EpochInfoFork.Altair
    template info: untyped {.inject.} = x.altairData
    body

template withEpochInfo*(
    state: phase0.BeaconState, x: var ForkedEpochInfo, body: untyped): untyped =
  x.kind = EpochInfoFork.Phase0
  template info: untyped {.inject.} = x.phase0Data
  body

template withEpochInfo*(
    state: altair.BeaconState | bellatrix.BeaconState | capella.BeaconState,
    x: var ForkedEpochInfo, body: untyped): untyped =
  x.kind = EpochInfoFork.Altair
  template info: untyped {.inject.} = x.altairData
  body

func assign*(tgt: var ForkedHashedBeaconState, src: ForkedHashedBeaconState) =
  if tgt.kind == src.kind:
    case tgt.kind
    of BeaconStateFork.Capella:
      assign(tgt.capellaData, src.capellaData):
    of BeaconStateFork.Bellatrix:
      assign(tgt.bellatrixData, src.bellatrixData):
    of BeaconStateFork.Altair:
      assign(tgt.altairData,    src.altairData):
    of BeaconStateFork.Phase0:
      assign(tgt.phase0Data,    src.phase0Data):
  else:
    # Ensure case object and discriminator get updated simultaneously, even
    # with nimOldCaseObjects. This is infrequent.
    tgt = src

template getStateField*(x: ForkedHashedBeaconState, y: untyped): untyped =
  # The use of `unsafeAddr` avoids excessive copying in certain situations, e.g.,
  # ```
  #   for index, validator in getStateField(stateData.data, validators):
  # ```
  # Without `unsafeAddr`, the `validators` list would be copied to a temporary variable.
  (case x.kind
  of BeaconStateFork.Capella:   unsafeAddr x.capellaData.data.y
  of BeaconStateFork.Bellatrix: unsafeAddr x.bellatrixData.data.y
  of BeaconStateFork.Altair:    unsafeAddr x.altairData.data.y
  of BeaconStateFork.Phase0:    unsafeAddr x.phase0Data.data.y)[]

func getStateRoot*(x: ForkedHashedBeaconState): Eth2Digest =
  withState(x): forkyState.root

func setStateRoot*(x: var ForkedHashedBeaconState, root: Eth2Digest) =
  withState(x): forkyState.root = root

func stateForkAtEpoch*(cfg: RuntimeConfig, epoch: Epoch): BeaconStateFork =
  ## Return the current fork for the given epoch.
  static:
    doAssert BeaconStateFork.Capella   > BeaconStateFork.Bellatrix
    doAssert BeaconStateFork.Bellatrix > BeaconStateFork.Altair
    doAssert BeaconStateFork.Altair    > BeaconStateFork.Phase0
    doAssert GENESIS_EPOCH == 0

  if   epoch >= cfg.CAPELLA_FORK_EPOCH:   BeaconStateFork.Capella
  elif epoch >= cfg.BELLATRIX_FORK_EPOCH: BeaconStateFork.Bellatrix
  elif epoch >= cfg.ALTAIR_FORK_EPOCH:    BeaconStateFork.Altair
  else:                                   BeaconStateFork.Phase0

func blockForkAtEpoch*(cfg: RuntimeConfig, epoch: Epoch): BeaconBlockFork =
  ## Return the current fork for the given epoch.
  if   epoch >= cfg.CAPELLA_FORK_EPOCH:   BeaconBlockFork.Capella
  elif epoch >= cfg.BELLATRIX_FORK_EPOCH: BeaconBlockFork.Bellatrix
  elif epoch >= cfg.ALTAIR_FORK_EPOCH:    BeaconBlockFork.Altair
  else:                                   BeaconBlockFork.Phase0

func stateForkForDigest*(
    forkDigests: ForkDigests, forkDigest: ForkDigest): Opt[BeaconStateFork] =
  if   forkDigest == forkDigests.capella:
    ok BeaconStateFork.Capella
  elif forkDigest == forkDigests.bellatrix:
    ok BeaconStateFork.Bellatrix
  elif forkDigest == forkDigests.altair:
    ok BeaconStateFork.Altair
  elif forkDigest == forkDigests.phase0:
    ok BeaconStateFork.Phase0
  else:
    err()

func atStateFork*(
    forkDigests: ForkDigests, stateFork: BeaconStateFork): ForkDigest =
  case stateFork
  of BeaconStateFork.Capella:
    forkDigests.capella
  of BeaconStateFork.Bellatrix:
    forkDigests.bellatrix
  of BeaconStateFork.Altair:
    forkDigests.altair
  of BeaconStateFork.Phase0:
    forkDigests.phase0

template atEpoch*(
    forkDigests: ForkDigests, epoch: Epoch, cfg: RuntimeConfig): ForkDigest =
  forkDigests.atStateFork(cfg.stateForkAtEpoch(epoch))

template asSigned*(
    x: ForkedMsgTrustedSignedBeaconBlock |
       ForkedTrustedSignedBeaconBlock
): ForkedSignedBeaconBlock =
  isomorphicCast[ForkedSignedBeaconBlock](x)

template asSigned*(
    x: ref ForkedMsgTrustedSignedBeaconBlock |
       ref ForkedTrustedSignedBeaconBlock
): ref ForkedSignedBeaconBlock =
  isomorphicCast[ref ForkedSignedBeaconBlock](x)

template asMsgTrusted*(
    x: ForkedSignedBeaconBlock |
       ForkedTrustedSignedBeaconBlock
): ForkedMsgTrustedSignedBeaconBlock =
  isomorphicCast[ForkedMsgTrustedSignedBeaconBlock](x)

template asMsgTrusted*(
    x: ref ForkedSignedBeaconBlock |
       ref ForkedTrustedSignedBeaconBlock
): ref ForkedMsgTrustedSignedBeaconBlock =
  isomorphicCast[ref ForkedMsgTrustedSignedBeaconBlock](x)

template asTrusted*(
    x: ForkedSignedBeaconBlock |
       ForkedMsgTrustedSignedBeaconBlock
): ForkedTrustedSignedBeaconBlock =
  isomorphicCast[ForkedTrustedSignedBeaconBlock](x)

template asTrusted*(
    x: ref ForkedSignedBeaconBlock |
       ref ForkedMsgTrustedSignedBeaconBlock
): ref ForkedTrustedSignedBeaconBlock =
  isomorphicCast[ref ForkedTrustedSignedBeaconBlock](x)

template withBlck*(
    x: ForkedBeaconBlock | Web3SignerForkedBeaconBlock |
       ForkedSignedBeaconBlock | ForkedMsgTrustedSignedBeaconBlock |
       ForkedTrustedSignedBeaconBlock | ForkedBlindedBeaconBlock |
       ForkedSignedBlindedBeaconBlock,
    body: untyped): untyped =
  case x.kind
  of BeaconBlockFork.Phase0:
    const stateFork {.inject, used.} = BeaconStateFork.Phase0
    template blck: untyped {.inject.} = x.phase0Data
    body
  of BeaconBlockFork.Altair:
    const stateFork {.inject, used.} = BeaconStateFork.Altair
    template blck: untyped {.inject.} = x.altairData
    body
  of BeaconBlockFork.Bellatrix:
    const stateFork {.inject, used.} = BeaconStateFork.Bellatrix
    template blck: untyped {.inject.} = x.bellatrixData
    body
  of BeaconBlockFork.Capella:
    const stateFork {.inject, used.} = BeaconStateFork.Capella
    template blck: untyped {.inject.} = x.capellaData
    body

func proposer_index*(x: ForkedBeaconBlock): uint64 =
  withBlck(x): blck.proposer_index

func hash_tree_root*(x: ForkedBeaconBlock | Web3SignerForkedBeaconBlock):
    Eth2Digest =
  withBlck(x): hash_tree_root(blck)

template getForkedBlockField*(
    x: ForkedSignedBeaconBlock |
       ForkedMsgTrustedSignedBeaconBlock |
       ForkedTrustedSignedBeaconBlock,
    y: untyped): untyped =
  # unsafeAddr avoids a copy of the field in some cases
  (case x.kind
  of BeaconBlockFork.Phase0:    unsafeAddr x.phase0Data.message.y
  of BeaconBlockFork.Altair:    unsafeAddr x.altairData.message.y
  of BeaconBlockFork.Bellatrix: unsafeAddr x.bellatrixData.message.y
  of BeaconBlockFork.Capella:   unsafeAddr x.capellaData.message.y)[]

template signature*(x: ForkedSignedBeaconBlock |
                       ForkedMsgTrustedSignedBeaconBlock |
                       ForkedSignedBlindedBeaconBlock): ValidatorSig =
  withBlck(x): blck.signature

template signature*(x: ForkedTrustedSignedBeaconBlock): TrustedSig =
  withBlck(x): blck.signature

template root*(x: ForkedSignedBeaconBlock |
                  ForkedMsgTrustedSignedBeaconBlock |
                  ForkedTrustedSignedBeaconBlock): Eth2Digest =
  withBlck(x): blck.root

template slot*(x: ForkedSignedBeaconBlock |
                  ForkedMsgTrustedSignedBeaconBlock |
                  ForkedTrustedSignedBeaconBlock): Slot =
  withBlck(x): blck.message.slot

template shortLog*(x: ForkedBeaconBlock | ForkedBlindedBeaconBlock): auto =
  withBlck(x): shortLog(blck)

template shortLog*(x: ForkedSignedBeaconBlock |
                      ForkedMsgTrustedSignedBeaconBlock |
                      ForkedTrustedSignedBeaconBlock |
                      ForkedSignedBlindedBeaconBlock): auto =
  withBlck(x): shortLog(blck)

chronicles.formatIt ForkedBeaconBlock: it.shortLog
chronicles.formatIt ForkedSignedBeaconBlock: it.shortLog
chronicles.formatIt ForkedMsgTrustedSignedBeaconBlock: it.shortLog
chronicles.formatIt ForkedTrustedSignedBeaconBlock: it.shortLog

template withStateAndBlck*(
    s: ForkedHashedBeaconState,
    b: ForkedBeaconBlock | ForkedSignedBeaconBlock |
       ForkedMsgTrustedSignedBeaconBlock |
       ForkedTrustedSignedBeaconBlock,
    body: untyped): untyped =
  case s.kind
  of BeaconStateFork.Capella:
    const stateFork {.inject.} = BeaconStateFork.Capella
    template forkyState: untyped {.inject.} = s.capellaData
    template blck: untyped {.inject.} = b.capellaData
    body
  of BeaconStateFork.Bellatrix:
    const stateFork {.inject.} = BeaconStateFork.Bellatrix
    template forkyState: untyped {.inject.} = s.bellatrixData
    template blck: untyped {.inject.} = b.bellatrixData
    body
  of BeaconStateFork.Altair:
    const stateFork {.inject.} = BeaconStateFork.Altair
    template forkyState: untyped {.inject.} = s.altairData
    template blck: untyped {.inject.} = b.altairData
    body
  of BeaconStateFork.Phase0:
    const stateFork {.inject.} = BeaconStateFork.Phase0
    template forkyState: untyped {.inject.} = s.phase0Data
    template blck: untyped {.inject.} = b.phase0Data
    body

func toBeaconBlockHeader*(
    blck: SomeForkyBeaconBlock | BlindedBeaconBlock): BeaconBlockHeader =
  ## Reduce a given `BeaconBlock` to its `BeaconBlockHeader`.
  BeaconBlockHeader(
    slot: blck.slot,
    proposer_index: blck.proposer_index,
    parent_root: blck.parent_root,
    state_root: blck.state_root,
    body_root: blck.body.hash_tree_root())

template toBeaconBlockHeader*(
    blck: SomeForkySignedBeaconBlock): BeaconBlockHeader =
  ## Reduce a given `SignedBeaconBlock` to its `BeaconBlockHeader`.
  blck.message.toBeaconBlockHeader

template toBeaconBlockHeader*(
    blckParam: ForkedMsgTrustedSignedBeaconBlock |
               ForkedTrustedSignedBeaconBlock): BeaconBlockHeader =
  ## Reduce a given signed beacon block to its `BeaconBlockHeader`.
  withBlck(blckParam): blck.toBeaconBlockHeader()

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

func bellatrixFork*(cfg: RuntimeConfig): Fork =
  Fork(
    previous_version: cfg.ALTAIR_FORK_VERSION,
    current_version: cfg.BELLATRIX_FORK_VERSION,
    epoch: cfg.BELLATRIX_FORK_EPOCH)

func capellaFork*(cfg: RuntimeConfig): Fork =
  Fork(
    previous_version: cfg.BELLATRIX_FORK_VERSION,
    current_version: cfg.CAPELLA_FORK_VERSION,
    epoch: cfg.CAPELLA_FORK_EPOCH)

func forkAtEpoch*(cfg: RuntimeConfig, epoch: Epoch): Fork =
  case cfg.stateForkAtEpoch(epoch)
  of BeaconStateFork.Capella:   cfg.capellaFork
  of BeaconStateFork.Bellatrix: cfg.bellatrixFork
  of BeaconStateFork.Altair:    cfg.altairFork
  of BeaconStateFork.Phase0:    cfg.genesisFork

func forkVersionAtEpoch*(cfg: RuntimeConfig, epoch: Epoch): Version =
  case cfg.stateForkAtEpoch(epoch)
  of BeaconStateFork.Capella:   cfg.CAPELLA_FORK_VERSION
  of BeaconStateFork.Bellatrix: cfg.BELLATRIX_FORK_VERSION
  of BeaconStateFork.Altair:    cfg.ALTAIR_FORK_VERSION
  of BeaconStateFork.Phase0:    cfg.GENESIS_FORK_VERSION

func nextForkEpochAtEpoch*(cfg: RuntimeConfig, epoch: Epoch): Epoch =
  case cfg.stateForkAtEpoch(epoch)
  of BeaconStateFork.Capella:   FAR_FUTURE_EPOCH
  of BeaconStateFork.Bellatrix: cfg.CAPELLA_FORK_EPOCH
  of BeaconStateFork.Altair:    cfg.BELLATRIX_FORK_EPOCH
  of BeaconStateFork.Phase0:    cfg.ALTAIR_FORK_EPOCH

func getForkSchedule*(cfg: RuntimeConfig): array[3, Fork] =
  ## This procedure returns list of known and/or scheduled forks.
  ##
  ## This procedure is used by HTTP REST framework and validator client.
  ##
  ## NOTE: Update this procedure when new fork will be scheduled.
  [cfg.genesisFork(), cfg.altairFork(), cfg.bellatrixFork()]

type
  # The first few fields of a state, shared across all forks
  BeaconStateHeader = object
    genesis_time: uint64
    genesis_validators_root: Eth2Digest
    slot: Slot

func readSszForkedHashedBeaconState*(cfg: RuntimeConfig, data: openArray[byte]):
    ForkedHashedBeaconState {.raises: [Defect, SszError].} =
  ## Helper to read a header from bytes when it's not certain what kind of state
  ## it is - this happens for example when loading an SSZ state from command
  ## line
  if data.len() < sizeof(BeaconStateHeader):
    raise (ref MalformedSszError)(msg: "Not enough data for BeaconState header")
  let header = SSZ.decode(
    data.toOpenArray(0, sizeof(BeaconStateHeader) - 1),
    BeaconStateHeader)

  # TODO https://github.com/nim-lang/Nim/issues/19357
  result = ForkedHashedBeaconState(
    kind: cfg.stateForkAtEpoch(header.slot.epoch()))

  withState(result):
    readSszBytes(data, forkyState.data)
    forkyState.root = hash_tree_root(forkyState.data)

type
  ForkedBeaconBlockHeader = object
    message*: uint32 # message offset
    signature*: ValidatorSig
    slot: Slot # start of BeaconBlock

func readSszForkedSignedBeaconBlock*(
    cfg: RuntimeConfig, data: openArray[byte]):
    ForkedSignedBeaconBlock {.raises: [Defect, SszError].} =
  ## Helper to read a header from bytes when it's not certain what kind of block
  ## it is
  if data.len() < sizeof(ForkedBeaconBlockHeader):
    raise (ref MalformedSszError)(msg: "Not enough data for SignedBeaconBlock header")
  let header = SSZ.decode(
    data.toOpenArray(0, sizeof(ForkedBeaconBlockHeader) - 1),
    ForkedBeaconBlockHeader)

  # TODO https://github.com/nim-lang/Nim/issues/19357
  result = ForkedSignedBeaconBlock(
    kind: cfg.blockForkAtEpoch(header.slot.epoch()))

  withBlck(result):
    readSszBytes(data, blck)

func toBeaconBlockFork*(fork: BeaconStateFork): BeaconBlockFork =
  case fork
  of BeaconStateFork.Phase0:    BeaconBlockFork.Phase0
  of BeaconStateFork.Altair:    BeaconBlockFork.Altair
  of BeaconStateFork.Bellatrix: BeaconBlockFork.Bellatrix
  of BeaconStateFork.Capella:   BeaconBlockFork.Capella

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-alpha.0/specs/phase0/beacon-chain.md#compute_fork_data_root
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

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-alpha.0/specs/phase0/beacon-chain.md#compute_fork_digest
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
           genesis_validators_root: Eth2Digest): T =
  T(
    phase0:
      compute_fork_digest(cfg.GENESIS_FORK_VERSION, genesis_validators_root),
    altair:
      compute_fork_digest(cfg.ALTAIR_FORK_VERSION, genesis_validators_root),
    bellatrix:
      compute_fork_digest(cfg.BELLATRIX_FORK_VERSION, genesis_validators_root),
    capella:
      compute_fork_digest(cfg.CAPELLA_FORK_VERSION, genesis_validators_root),
    sharding:
      compute_fork_digest(cfg.SHARDING_FORK_VERSION, genesis_validators_root),
  )

func toBlockId*(header: BeaconBlockHeader): BlockId =
  BlockId(root: header.hash_tree_root(), slot: header.slot)

func toBlockId*(blck: SomeForkySignedBeaconBlock): BlockId =
  BlockId(root: blck.root, slot: blck.message.slot)

func toBlockId*(blck: ForkedSignedBeaconBlock |
                      ForkedMsgTrustedSignedBeaconBlock |
                      ForkedTrustedSignedBeaconBlock): BlockId =
  withBlck(blck): BlockId(root: blck.root, slot: blck.message.slot)
