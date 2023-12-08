# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/macros,
  stew/assign2,
  stew/results,
  chronicles,
  ../extras,
  "."/[
    block_id, eth2_merkleization, eth2_ssz_serialization,
    forks_light_client, presets],
  ./datatypes/[phase0, altair, bellatrix, capella, deneb],
  ./mev/bellatrix_mev, ./mev/capella_mev, ./mev/deneb_mev

export
  extras, block_id, phase0, altair, bellatrix, capella, deneb,
  eth2_merkleization, eth2_ssz_serialization, forks_light_client,
  presets, capella_mev, deneb_mev

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
  ConsensusFork* {.pure.} = enum
    Phase0,
    Altair,
    Bellatrix,
    Capella,
    Deneb

  ForkyBeaconState* =
    phase0.BeaconState |
    altair.BeaconState |
    bellatrix.BeaconState |
    capella.BeaconState |
    deneb.BeaconState

  ForkyHashedBeaconState* =
    phase0.HashedBeaconState |
    altair.HashedBeaconState |
    bellatrix.HashedBeaconState |
    capella.HashedBeaconState |
    deneb.HashedBeaconState

  ForkedHashedBeaconState* = object
    case kind*: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data*:    phase0.HashedBeaconState
    of ConsensusFork.Altair:    altairData*:    altair.HashedBeaconState
    of ConsensusFork.Bellatrix: bellatrixData*: bellatrix.HashedBeaconState
    of ConsensusFork.Capella:   capellaData*:   capella.HashedBeaconState
    of ConsensusFork.Deneb:     denebData*:     deneb.HashedBeaconState

  ForkyExecutionPayload* =
    bellatrix.ExecutionPayload |
    capella.ExecutionPayload |
    deneb.ExecutionPayload

  ForkyExecutionPayloadHeader* =
    bellatrix.ExecutionPayloadHeader |
    capella.ExecutionPayloadHeader |
    deneb.ExecutionPayloadHeader

  ForkyBeaconBlockBody* =
    phase0.BeaconBlockBody |
    altair.BeaconBlockBody |
    bellatrix.BeaconBlockBody |
    capella.BeaconBlockBody |
    deneb.BeaconBlockBody

  ForkySigVerifiedBeaconBlockBody* =
    phase0.SigVerifiedBeaconBlockBody |
    altair.SigVerifiedBeaconBlockBody |
    bellatrix.SigVerifiedBeaconBlockBody |
    capella.SigVerifiedBeaconBlockBody |
    deneb.SigVerifiedBeaconBlockBody

  ForkyTrustedBeaconBlockBody* =
    phase0.TrustedBeaconBlockBody |
    altair.TrustedBeaconBlockBody |
    bellatrix.TrustedBeaconBlockBody |
    capella.TrustedBeaconBlockBody |
    deneb.TrustedBeaconBlockBody

  SomeForkyBeaconBlockBody* =
    ForkyBeaconBlockBody |
    ForkySigVerifiedBeaconBlockBody |
    ForkyTrustedBeaconBlockBody

  ForkyBeaconBlock* =
    phase0.BeaconBlock |
    altair.BeaconBlock |
    bellatrix.BeaconBlock |
    capella.BeaconBlock |
    deneb.BeaconBlock

  ForkySigVerifiedBeaconBlock* =
    phase0.SigVerifiedBeaconBlock |
    altair.SigVerifiedBeaconBlock |
    bellatrix.SigVerifiedBeaconBlock |
    capella.SigVerifiedBeaconBlock |
    deneb.SigVerifiedBeaconBlock

  ForkyTrustedBeaconBlock* =
    phase0.TrustedBeaconBlock |
    altair.TrustedBeaconBlock |
    bellatrix.TrustedBeaconBlock |
    capella.TrustedBeaconBlock |
    deneb.TrustedBeaconBlock

  SomeForkyBeaconBlock* =
    ForkyBeaconBlock |
    ForkySigVerifiedBeaconBlock |
    ForkyTrustedBeaconBlock

  ForkyExecutionPayloadForSigning* =
    bellatrix.ExecutionPayloadForSigning |
    capella.ExecutionPayloadForSigning |
    deneb.ExecutionPayloadForSigning

  ForkyBlindedBeaconBlock* =
    capella_mev.BlindedBeaconBlock |
    deneb_mev.BlindedBeaconBlock

  ForkedBeaconBlock* = object
    case kind*: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data*:    phase0.BeaconBlock
    of ConsensusFork.Altair:    altairData*:    altair.BeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData*: bellatrix.BeaconBlock
    of ConsensusFork.Capella:   capellaData*:   capella.BeaconBlock
    of ConsensusFork.Deneb:     denebData*:     deneb.BeaconBlock

  ForkedMaybeBlindedBeaconBlock* = object
    case kind*: ConsensusFork
    of ConsensusFork.Phase0:
      phase0Data*: phase0.BeaconBlock
    of ConsensusFork.Altair:
      altairData*: altair.BeaconBlock
    of ConsensusFork.Bellatrix:
      bellatrixData*: bellatrix.BeaconBlock
    of ConsensusFork.Capella:
      capellaData*: capella_mev.MaybeBlindedBeaconBlock
    of ConsensusFork.Deneb:
      denebData*: deneb_mev.MaybeBlindedBeaconBlock
    consensusValue*: Opt[UInt256]
    executionValue*: Opt[UInt256]

  Web3SignerForkedBeaconBlock* = object
    kind*: ConsensusFork
    data*: BeaconBlockHeader

  ForkedBlindedBeaconBlock* = object
    case kind*: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data*:    phase0.BeaconBlock
    of ConsensusFork.Altair:    altairData*:    altair.BeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData*: bellatrix_mev.BlindedBeaconBlock
    of ConsensusFork.Capella:   capellaData*:   capella_mev.BlindedBeaconBlock
    of ConsensusFork.Deneb:     denebData*:     deneb_mev.BlindedBeaconBlock

  ForkedTrustedBeaconBlock* = object
    case kind*: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data*:     phase0.TrustedBeaconBlock
    of ConsensusFork.Altair:    altairData*:     altair.TrustedBeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData*:  bellatrix.TrustedBeaconBlock
    of ConsensusFork.Capella:   capellaData*:    capella.TrustedBeaconBlock
    of ConsensusFork.Deneb:     denebData*:      deneb.TrustedBeaconBlock

  ForkySignedBeaconBlock* =
    phase0.SignedBeaconBlock |
    altair.SignedBeaconBlock |
    bellatrix.SignedBeaconBlock |
    capella.SignedBeaconBlock |
    deneb.SignedBeaconBlock

  ForkedSignedBeaconBlock* = object
    case kind*: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data*:    phase0.SignedBeaconBlock
    of ConsensusFork.Altair:    altairData*:    altair.SignedBeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData*: bellatrix.SignedBeaconBlock
    of ConsensusFork.Capella:   capellaData*:   capella.SignedBeaconBlock
    of ConsensusFork.Deneb:     denebData*:     deneb.SignedBeaconBlock

  ForkySignedBlindedBeaconBlock* =
    phase0.SignedBeaconBlock |
    altair.SignedBeaconBlock |
    capella_mev.SignedBlindedBeaconBlock

  ForkedSignedBlindedBeaconBlock* = object
    case kind*: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data*:    phase0.SignedBeaconBlock
    of ConsensusFork.Altair:    altairData*:    altair.SignedBeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData*: bellatrix_mev.SignedBlindedBeaconBlock
    of ConsensusFork.Capella:   capellaData*:   capella_mev.SignedBlindedBeaconBlock
    of ConsensusFork.Deneb:     denebData*:     deneb_mev.SignedBlindedBeaconBlock

  ForkySigVerifiedSignedBeaconBlock* =
    phase0.SigVerifiedSignedBeaconBlock |
    altair.SigVerifiedSignedBeaconBlock |
    bellatrix.SigVerifiedSignedBeaconBlock |
    capella.SigVerifiedSignedBeaconBlock |
    deneb.SigVerifiedSignedBeaconBlock

  ForkyMsgTrustedSignedBeaconBlock* =
    phase0.MsgTrustedSignedBeaconBlock |
    altair.MsgTrustedSignedBeaconBlock |
    bellatrix.MsgTrustedSignedBeaconBlock |
    capella.MsgTrustedSignedBeaconBlock |
    deneb.MsgTrustedSignedBeaconBlock

  ForkyTrustedSignedBeaconBlock* =
    phase0.TrustedSignedBeaconBlock |
    altair.TrustedSignedBeaconBlock |
    bellatrix.TrustedSignedBeaconBlock |
    capella.TrustedSignedBeaconBlock |
    deneb.TrustedSignedBeaconBlock

  ForkedMsgTrustedSignedBeaconBlock* = object
    case kind*: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data*:    phase0.MsgTrustedSignedBeaconBlock
    of ConsensusFork.Altair:    altairData*:    altair.MsgTrustedSignedBeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData*: bellatrix.MsgTrustedSignedBeaconBlock
    of ConsensusFork.Capella:   capellaData*:   capella.MsgTrustedSignedBeaconBlock
    of ConsensusFork.Deneb:     denebData*:     deneb.MsgTrustedSignedBeaconBlock

  ForkedTrustedSignedBeaconBlock* = object
    case kind*: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data*:    phase0.TrustedSignedBeaconBlock
    of ConsensusFork.Altair:    altairData*:    altair.TrustedSignedBeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData*: bellatrix.TrustedSignedBeaconBlock
    of ConsensusFork.Capella:   capellaData*:   capella.TrustedSignedBeaconBlock
    of ConsensusFork.Deneb:     denebData*:     deneb.TrustedSignedBeaconBlock

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
    deneb*:     ForkDigest

template kind*(
    x: typedesc[
      phase0.BeaconState |
      phase0.HashedBeaconState |
      phase0.BeaconBlock |
      phase0.SignedBeaconBlock |
      phase0.TrustedBeaconBlock |
      phase0.BeaconBlockBody |
      phase0.SigVerifiedBeaconBlockBody |
      phase0.TrustedBeaconBlockBody |
      phase0.SigVerifiedSignedBeaconBlock |
      phase0.MsgTrustedSignedBeaconBlock |
      phase0.TrustedSignedBeaconBlock]): ConsensusFork =
  ConsensusFork.Phase0

template kind*(
    x: typedesc[
      altair.BeaconState |
      altair.HashedBeaconState |
      altair.BeaconBlock |
      altair.SignedBeaconBlock |
      altair.TrustedBeaconBlock |
      altair.BeaconBlockBody |
      altair.SigVerifiedBeaconBlockBody |
      altair.TrustedBeaconBlockBody |
      altair.SigVerifiedSignedBeaconBlock |
      altair.MsgTrustedSignedBeaconBlock |
      altair.TrustedSignedBeaconBlock]): ConsensusFork =
  ConsensusFork.Altair

template kind*(
    x: typedesc[
      bellatrix.BeaconState |
      bellatrix.HashedBeaconState |
      bellatrix.ExecutionPayload |
      bellatrix.ExecutionPayloadForSigning |
      bellatrix.ExecutionPayloadHeader |
      bellatrix.BeaconBlock |
      bellatrix.SignedBeaconBlock |
      bellatrix.TrustedBeaconBlock |
      bellatrix.BeaconBlockBody |
      bellatrix.SigVerifiedBeaconBlockBody |
      bellatrix.TrustedBeaconBlockBody |
      bellatrix.SigVerifiedSignedBeaconBlock |
      bellatrix.MsgTrustedSignedBeaconBlock |
      bellatrix.TrustedSignedBeaconBlock]): ConsensusFork =
  ConsensusFork.Bellatrix

template kind*(
    x: typedesc[
      capella.BeaconState |
      capella.HashedBeaconState |
      capella.ExecutionPayload |
      capella.ExecutionPayloadForSigning |
      capella.ExecutionPayloadHeader |
      capella.BeaconBlock |
      capella.SignedBeaconBlock |
      capella.TrustedBeaconBlock |
      capella.BeaconBlockBody |
      capella.SigVerifiedBeaconBlockBody |
      capella.TrustedBeaconBlockBody |
      capella.SigVerifiedSignedBeaconBlock |
      capella.MsgTrustedSignedBeaconBlock |
      capella.TrustedSignedBeaconBlock |
      capella_mev.SignedBlindedBeaconBlock]): ConsensusFork =
  ConsensusFork.Capella

template kind*(
    x: typedesc[
      deneb.BeaconState |
      deneb.HashedBeaconState |
      deneb.ExecutionPayload |
      deneb.ExecutionPayloadForSigning |
      deneb.ExecutionPayloadHeader |
      deneb.BeaconBlock |
      deneb.SignedBeaconBlock |
      deneb.TrustedBeaconBlock |
      deneb.BeaconBlockBody |
      deneb.SigVerifiedBeaconBlockBody |
      deneb.TrustedBeaconBlockBody |
      deneb.SigVerifiedSignedBeaconBlock |
      deneb.MsgTrustedSignedBeaconBlock |
      deneb.TrustedSignedBeaconBlock |
      deneb_mev.SignedBlindedBeaconBlock]): ConsensusFork =
  ConsensusFork.Deneb

template BeaconState*(kind: static ConsensusFork): auto =
  when kind == ConsensusFork.Deneb:
    typedesc[deneb.BeaconState]
  elif kind == ConsensusFork.Capella:
    typedesc[capella.BeaconState]
  elif kind == ConsensusFork.Bellatrix:
    typedesc[bellatrix.BeaconState]
  elif kind == ConsensusFork.Altair:
    typedesc[altair.BeaconState]
  elif kind == ConsensusFork.Phase0:
    typedesc[phase0.BeaconState]
  else:
    static: raiseAssert "Unreachable"

template BeaconBlock*(kind: static ConsensusFork): auto =
  when kind == ConsensusFork.Deneb:
    typedesc[deneb.BeaconBlock]
  elif kind == ConsensusFork.Capella:
    typedesc[capella.BeaconBlock]
  elif kind == ConsensusFork.Bellatrix:
    typedesc[bellatrix.BeaconBlock]
  elif kind == ConsensusFork.Altair:
    typedesc[altair.BeaconBlock]
  elif kind == ConsensusFork.Phase0:
    typedesc[phase0.BeaconBlock]
  else:
    static: raiseAssert "Unreachable"

template BeaconBlockBody*(kind: static ConsensusFork): auto =
  when kind == ConsensusFork.Deneb:
    typedesc[deneb.BeaconBlockBody]
  elif kind == ConsensusFork.Capella:
    typedesc[capella.BeaconBlockBody]
  elif kind == ConsensusFork.Bellatrix:
    typedesc[bellatrix.BeaconBlockBody]
  elif kind == ConsensusFork.Altair:
    typedesc[altair.BeaconBlockBody]
  elif kind == ConsensusFork.Phase0:
    typedesc[phase0.BeaconBlockBody]
  else:
    static: raiseAssert "Unreachable"

template SignedBeaconBlock*(kind: static ConsensusFork): auto =
  when kind == ConsensusFork.Deneb:
    typedesc[deneb.SignedBeaconBlock]
  elif kind == ConsensusFork.Capella:
    typedesc[capella.SignedBeaconBlock]
  elif kind == ConsensusFork.Bellatrix:
    typedesc[bellatrix.SignedBeaconBlock]
  elif kind == ConsensusFork.Altair:
    typedesc[altair.SignedBeaconBlock]
  elif kind == ConsensusFork.Phase0:
    typedesc[phase0.SignedBeaconBlock]
  else:
    static: raiseAssert "Unreachable"

template TrustedSignedBeaconBlock*(kind: static ConsensusFork): auto =
  when kind == ConsensusFork.Deneb:
    typedesc[deneb.TrustedSignedBeaconBlock]
  elif kind == ConsensusFork.Capella:
    typedesc[capella.TrustedSignedBeaconBlock]
  elif kind == ConsensusFork.Bellatrix:
    typedesc[bellatrix.TrustedSignedBeaconBlock]
  elif kind == ConsensusFork.Altair:
    typedesc[altair.TrustedSignedBeaconBlock]
  elif kind == ConsensusFork.Phase0:
    typedesc[phase0.TrustedSignedBeaconBlock]
  else:
    static: raiseAssert "Unreachable"

template ExecutionPayloadForSigning*(kind: static ConsensusFork): auto =
  when kind == ConsensusFork.Deneb:
    typedesc[deneb.ExecutionPayloadForSigning]
  elif kind == ConsensusFork.Capella:
    typedesc[capella.ExecutionPayloadForSigning]
  elif kind == ConsensusFork.Bellatrix:
    typedesc[bellatrix.ExecutionPayloadForSigning]
  else:
    static: raiseAssert "Unreachable"

template BlindedBeaconBlock*(kind: static ConsensusFork): auto =
  when kind == ConsensusFork.Deneb:
    typedesc[deneb_mev.BlindedBeaconBlock]
  elif kind == ConsensusFork.Capella:
    typedesc[capella_mev.BlindedBeaconBlock]
  elif kind == ConsensusFork.Bellatrix:
    static: raiseAssert "Unsupported"
  else:
    static: raiseAssert "Unreachable"

template MaybeBlindedBeaconBlock*(kind: static ConsensusFork): auto =
  when kind == ConsensusFork.Deneb:
    typedesc[deneb_mev.MaybeBlindedBeaconBlock]
  elif kind == ConsensusFork.Capella:
    typedesc[capella_mev.MaybeBlindedBeaconBlock]
  elif kind == ConsensusFork.Bellatrix:
    static: raiseAssert "Unsupported"
  else:
    static: raiseAssert "Unreachable"

template SignedBlindedBeaconBlock*(kind: static ConsensusFork): auto =
  when kind == ConsensusFork.Deneb:
    typedesc[deneb_mev.SignedBlindedBeaconBlock]
  elif kind == ConsensusFork.Capella:
    typedesc[capella_mev.SignedBlindedBeaconBlock]
  elif kind == ConsensusFork.Bellatrix:
    static: raiseAssert "Unsupported"
  else:
    static: raiseAssert "Unreachable"

template withAll*(
    x: typedesc[ConsensusFork], body: untyped): untyped =
  static: doAssert ConsensusFork.high == ConsensusFork.Deneb
  block:
    const consensusFork {.inject, used.} = ConsensusFork.Deneb
    body
  block:
    const consensusFork {.inject, used.} = ConsensusFork.Capella
    body
  block:
    const consensusFork {.inject, used.} = ConsensusFork.Bellatrix
    body
  block:
    const consensusFork {.inject, used.} = ConsensusFork.Altair
    body
  block:
    const consensusFork {.inject, used.} = ConsensusFork.Phase0
    body

template withConsensusFork*(
    x: ConsensusFork, body: untyped): untyped =
  case x
  of ConsensusFork.Deneb:
    const consensusFork {.inject, used.} = ConsensusFork.Deneb
    body
  of ConsensusFork.Capella:
    const consensusFork {.inject, used.} = ConsensusFork.Capella
    body
  of ConsensusFork.Bellatrix:
    const consensusFork {.inject, used.} = ConsensusFork.Bellatrix
    body
  of ConsensusFork.Altair:
    const consensusFork {.inject, used.} = ConsensusFork.Altair
    body
  of ConsensusFork.Phase0:
    const consensusFork {.inject, used.} = ConsensusFork.Phase0
    body

template BlockContents*(
    kind: static ConsensusFork): auto =
  when kind == ConsensusFork.Deneb:
    typedesc[deneb.BlockContents]
  elif kind == ConsensusFork.Capella:
    typedesc[capella.BeaconBlock]
  elif kind == ConsensusFork.Bellatrix:
    typedesc[bellatrix.BeaconBlock]
  elif kind == ConsensusFork.Altair:
    typedesc[altair.BeaconBlock]
  elif kind == ConsensusFork.Phase0:
    typedesc[phase0.BeaconBlock]
  else:
    {.error: "BlockContents does not support " & $kind.}

template BlindedBlockContents*(
    kind: static ConsensusFork): auto =
  when kind == ConsensusFork.Deneb:
    typedesc[deneb_mev.BlindedBeaconBlock]
  elif kind == ConsensusFork.Capella:
    typedesc[capella_mev.BlindedBeaconBlock]
  else:
    {.error: "BlindedBlockContents does not support " & $kind.}

template PayloadAttributes*(
    kind: static ConsensusFork): auto =
  # This also determines what `engine_forkchoiceUpdated` version will be used.
  when kind >= ConsensusFork.Deneb:
    typedesc[PayloadAttributesV3]
  elif kind >= ConsensusFork.Capella:
    # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.3/src/engine/shanghai.md#specification-1
    # Consensus layer client MUST call this method instead of
    # `engine_forkchoiceUpdatedV1` under any of the following conditions:
    # `headBlockHash` references a block which `timestamp` is greater or
    # equal to the Shanghai timestamp
    typedesc[PayloadAttributesV2]
  elif kind >= ConsensusFork.Bellatrix:
    typedesc[PayloadAttributesV1]
  else:
    {.error: "PayloadAttributes does not support " & $kind.}

# TODO when https://github.com/nim-lang/Nim/issues/21086 fixed, use return type
# `ref T`
func new*(T: type ForkedHashedBeaconState, data: phase0.BeaconState):
    ref ForkedHashedBeaconState =
  (ref T)(kind: ConsensusFork.Phase0, phase0Data: phase0.HashedBeaconState(
    data: data, root: hash_tree_root(data)))
func new*(T: type ForkedHashedBeaconState, data: altair.BeaconState):
    ref ForkedHashedBeaconState =
  (ref T)(kind: ConsensusFork.Altair, altairData: altair.HashedBeaconState(
    data: data, root: hash_tree_root(data)))
func new*(T: type ForkedHashedBeaconState, data: bellatrix.BeaconState):
    ref ForkedHashedBeaconState =
  (ref T)(kind: ConsensusFork.Bellatrix, bellatrixData: bellatrix.HashedBeaconState(
    data: data, root: hash_tree_root(data)))
func new*(T: type ForkedHashedBeaconState, data: capella.BeaconState):
    ref ForkedHashedBeaconState =
  (ref T)(kind: ConsensusFork.Capella, capellaData: capella.HashedBeaconState(
    data: data, root: hash_tree_root(data)))
func new*(T: type ForkedHashedBeaconState, data: deneb.BeaconState):
    ref ForkedHashedBeaconState =
  (ref T)(kind: ConsensusFork.Deneb, denebData: deneb.HashedBeaconState(
    data: data, root: hash_tree_root(data)))

template init*(T: type ForkedBeaconBlock, blck: phase0.BeaconBlock): T =
  T(kind: ConsensusFork.Phase0, phase0Data: blck)
template init*(T: type ForkedBeaconBlock, blck: altair.BeaconBlock): T =
  T(kind: ConsensusFork.Altair, altairData: blck)
template init*(T: type ForkedBeaconBlock, blck: bellatrix.BeaconBlock): T =
  T(kind: ConsensusFork.Bellatrix, bellatrixData: blck)
template init*(T: type ForkedBeaconBlock, blck: capella.BeaconBlock): T =
  T(kind: ConsensusFork.Capella, capellaData: blck)
template init*(T: type ForkedBeaconBlock, blck: deneb.BeaconBlock): T =
  T(kind: ConsensusFork.Deneb, denebData: blck)

template init*(T: type ForkedTrustedBeaconBlock, blck: phase0.TrustedBeaconBlock): T =
  T(kind: ConsensusFork.Phase0, phase0Data: blck)
template init*(T: type ForkedTrustedBeaconBlock, blck: altair.TrustedBeaconBlock): T =
  T(kind: ConsensusFork.Altair, altairData: blck)
template init*(T: type ForkedTrustedBeaconBlock, blck: bellatrix.TrustedBeaconBlock): T =
  T(kind: ConsensusFork.Bellatrix, bellatrixData: blck)
template init*(T: type ForkedTrustedBeaconBlock, blck: capella.TrustedBeaconBlock): T =
  T(kind: ConsensusFork.Capella, capellaData: blck)

template init*(T: type ForkedSignedBeaconBlock, blck: phase0.SignedBeaconBlock): T =
  T(kind: ConsensusFork.Phase0, phase0Data: blck)
template init*(T: type ForkedSignedBeaconBlock, blck: altair.SignedBeaconBlock): T =
  T(kind: ConsensusFork.Altair, altairData: blck)
template init*(T: type ForkedSignedBeaconBlock, blck: bellatrix.SignedBeaconBlock): T =
  T(kind: ConsensusFork.Bellatrix, bellatrixData: blck)
template init*(T: type ForkedSignedBeaconBlock, blck: capella.SignedBeaconBlock): T =
  T(kind: ConsensusFork.Capella, capellaData: blck)
template init*(T: type ForkedSignedBeaconBlock, blck: deneb.SignedBeaconBlock): T =
  T(kind: ConsensusFork.Deneb, denebData: blck)

func init*(T: type ForkedSignedBeaconBlock, forked: ForkedBeaconBlock,
           blockRoot: Eth2Digest, signature: ValidatorSig): T =
  case forked.kind
  of ConsensusFork.Phase0:
    T(kind: ConsensusFork.Phase0,
      phase0Data: phase0.SignedBeaconBlock(message: forked.phase0Data,
                                           root: blockRoot,
                                           signature: signature))
  of ConsensusFork.Altair:
    T(kind: ConsensusFork.Altair,
      altairData: altair.SignedBeaconBlock(message: forked.altairData,
                                           root: blockRoot,
                                           signature: signature))
  of ConsensusFork.Bellatrix:
    T(kind: ConsensusFork.Bellatrix,
      bellatrixData: bellatrix.SignedBeaconBlock(message: forked.bellatrixData,
                                                 root: blockRoot,
                                                 signature: signature))
  of ConsensusFork.Capella:
    T(kind: ConsensusFork.Capella,
      capellaData: capella.SignedBeaconBlock(message: forked.capellaData,
                                             root: blockRoot,
                                             signature: signature))
  of ConsensusFork.Deneb:
    T(kind: ConsensusFork.Deneb,
      denebData: deneb.SignedBeaconBlock(message: forked.denebData,
                                         root: blockRoot,
                                         signature: signature))

func init*(T: type ForkedSignedBlindedBeaconBlock,
           forked: ForkedBlindedBeaconBlock, blockRoot: Eth2Digest,
           signature: ValidatorSig): T =
  case forked.kind
  of ConsensusFork.Phase0:
    T(kind: ConsensusFork.Phase0,
      phase0Data: phase0.SignedBeaconBlock(message: forked.phase0Data,
                                           root: blockRoot,
                                           signature: signature))
  of ConsensusFork.Altair:
    T(kind: ConsensusFork.Altair,
      altairData: altair.SignedBeaconBlock(message: forked.altairData,
                                           root: blockRoot,
                                           signature: signature))
  of ConsensusFork.Bellatrix:
    T(kind: ConsensusFork.Bellatrix,
      bellatrixData: default(bellatrix_mev.SignedBlindedBeaconBlock))
  of ConsensusFork.Capella:
    T(kind: ConsensusFork.Capella,
      capellaData: capella_mev.SignedBlindedBeaconBlock(message: forked.capellaData,
                                                        signature: signature))
  of ConsensusFork.Deneb:
    T(kind: ConsensusFork.Deneb,
      denebData: deneb_mev.SignedBlindedBeaconBlock(message: forked.denebData,
                                                    signature: signature))

template init*(T: type ForkedMsgTrustedSignedBeaconBlock, blck: phase0.MsgTrustedSignedBeaconBlock): T =
  T(kind: ConsensusFork.Phase0,    phase0Data: blck)
template init*(T: type ForkedMsgTrustedSignedBeaconBlock, blck: altair.MsgTrustedSignedBeaconBlock): T =
  T(kind: ConsensusFork.Altair,    altairData: blck)
template init*(T: type ForkedMsgTrustedSignedBeaconBlock, blck: bellatrix.MsgTrustedSignedBeaconBlock): T =
  T(kind: ConsensusFork.Bellatrix, bellatrixData: blck)
template init*(T: type ForkedMsgTrustedSignedBeaconBlock, blck: capella.MsgTrustedSignedBeaconBlock): T =
  T(kind: ConsensusFork.Capella,   capellaData: blck)
template init*(T: type ForkedMsgTrustedSignedBeaconBlock, blck: deneb.MsgTrustedSignedBeaconBlock): T =
  T(kind: ConsensusFork.Deneb,     denebData: blck)

template init*(T: type ForkedTrustedSignedBeaconBlock, blck: phase0.TrustedSignedBeaconBlock): T =
  T(kind: ConsensusFork.Phase0, phase0Data: blck)
template init*(T: type ForkedTrustedSignedBeaconBlock, blck: altair.TrustedSignedBeaconBlock): T =
  T(kind: ConsensusFork.Altair, altairData: blck)
template init*(T: type ForkedTrustedSignedBeaconBlock, blck: bellatrix.TrustedSignedBeaconBlock): T =
  T(kind: ConsensusFork.Bellatrix, bellatrixData: blck)
template init*(T: type ForkedTrustedSignedBeaconBlock, blck: capella.TrustedSignedBeaconBlock): T =
  T(kind: ConsensusFork.Capella, capellaData: blck)
template init*(T: type ForkedTrustedSignedBeaconBlock, blck: deneb.TrustedSignedBeaconBlock): T =
  T(kind: ConsensusFork.Deneb,   denebData: blck)

template toString*(kind: ConsensusFork): string =
  case kind
  of ConsensusFork.Phase0:
    "phase0"
  of ConsensusFork.Altair:
    "altair"
  of ConsensusFork.Bellatrix:
    "bellatrix"
  of ConsensusFork.Capella:
    "capella"
  of ConsensusFork.Deneb:
    "deneb"

template init*(T: typedesc[ConsensusFork], value: string): Opt[ConsensusFork] =
  case value
  of "deneb":
    Opt.some ConsensusFork.Deneb
  of "capella":
    Opt.some ConsensusFork.Capella
  of "bellatrix":
    Opt.some ConsensusFork.Bellatrix
  of "altair":
    Opt.some ConsensusFork.Altair
  of "phase0":
    Opt.some ConsensusFork.Phase0
  else:
    Opt.none(ConsensusFork)

static:
  for fork in ConsensusFork:
    doAssert ConsensusFork.init(fork.toString()).expect("init defined") == fork

template init*(T: type ForkedEpochInfo, info: phase0.EpochInfo): T =
  T(kind: EpochInfoFork.Phase0, phase0Data: info)
template init*(T: type ForkedEpochInfo, info: altair.EpochInfo): T =
  T(kind: EpochInfoFork.Altair, altairData: info)

template withState*(x: ForkedHashedBeaconState, body: untyped): untyped =
  case x.kind
  of ConsensusFork.Deneb:
    const consensusFork {.inject, used.} = ConsensusFork.Deneb
    template forkyState: untyped {.inject, used.} = x.denebData
    body
  of ConsensusFork.Capella:
    const consensusFork {.inject, used.} = ConsensusFork.Capella
    template forkyState: untyped {.inject, used.} = x.capellaData
    body
  of ConsensusFork.Bellatrix:
    const consensusFork {.inject, used.} = ConsensusFork.Bellatrix
    template forkyState: untyped {.inject, used.} = x.bellatrixData
    body
  of ConsensusFork.Altair:
    const consensusFork {.inject, used.} = ConsensusFork.Altair
    template forkyState: untyped {.inject, used.} = x.altairData
    body
  of ConsensusFork.Phase0:
    const consensusFork {.inject, used.} = ConsensusFork.Phase0
    template forkyState: untyped {.inject, used.} = x.phase0Data
    body

template forky*(
    x:
      ForkedBeaconBlock |
      ForkedHashedBeaconState,
    kind: static ConsensusFork): untyped =
  when kind == ConsensusFork.Deneb:
    x.denebData
  elif kind == ConsensusFork.Capella:
    x.capellaData
  elif kind == ConsensusFork.Bellatrix:
    x.bellatrixData
  elif kind == ConsensusFork.Altair:
    x.altairData
  elif kind == ConsensusFork.Phase0:
    x.phase0Data
  else:
    static: raiseAssert "Unreachable"

template withEpochInfo*(x: ForkedEpochInfo, body: untyped): untyped =
  case x.kind
  of EpochInfoFork.Phase0:
    const infoFork {.inject, used.} = EpochInfoFork.Phase0
    template info: untyped {.inject.} = x.phase0Data
    body
  of EpochInfoFork.Altair:
    const infoFork {.inject, used.} = EpochInfoFork.Altair
    template info: untyped {.inject.} = x.altairData
    body

template withEpochInfo*(
    state: phase0.BeaconState, x: var ForkedEpochInfo, body: untyped): untyped =
  if x.kind != EpochInfoFork.Phase0:
    # Rare, should never happen even, so efficiency a non-issue
    x = ForkedEpochInfo(kind: EpochInfoFork.Phase0)
  template info: untyped {.inject.} = x.phase0Data
  body

template withEpochInfo*(
    state: altair.BeaconState | bellatrix.BeaconState | capella.BeaconState |
           deneb.BeaconState,
    x: var ForkedEpochInfo, body: untyped): untyped =
  if x.kind != EpochInfoFork.Altair:
    # Rare, so efficiency not critical
    x = ForkedEpochInfo(kind: EpochInfoFork.Altair)
  template info: untyped {.inject.} = x.altairData
  body

{.push warning[ProveField]:off.}
func assign*(tgt: var ForkedHashedBeaconState, src: ForkedHashedBeaconState) =
  if tgt.kind == src.kind:
    withState(tgt):
      template forkyTgt: untyped = forkyState
      template forkySrc: untyped = src.forky(consensusFork)
      assign(forkyTgt, forkySrc)
  else:
    # Ensure case object and discriminator get updated simultaneously, even
    # with nimOldCaseObjects. This is infrequent.
    tgt = src
{.pop.}

template getStateField*(x: ForkedHashedBeaconState, y: untyped): untyped =
  # The use of `unsafeAddr` avoids excessive copying in certain situations, e.g.,
  # ```
  #   for index, validator in getStateField(stateData.data, validators):
  # ```
  # Without `unsafeAddr`, the `validators` list would be copied to a temporary variable.
  (block:
    withState(x): unsafeAddr forkyState.data.y)[]

func getStateRoot*(x: ForkedHashedBeaconState): Eth2Digest =
  withState(x): forkyState.root

{.push warning[ProveField]:off.}  # https://github.com/nim-lang/Nim/issues/22060
func setStateRoot*(x: var ForkedHashedBeaconState, root: Eth2Digest) =
  withState(x): forkyState.root = root
{.pop.}

func consensusForkAtEpoch*(cfg: RuntimeConfig, epoch: Epoch): ConsensusFork =
  ## Return the current fork for the given epoch.
  static:
    doAssert high(ConsensusFork) == ConsensusFork.Deneb
    doAssert ConsensusFork.Deneb     > ConsensusFork.Capella
    doAssert ConsensusFork.Capella   > ConsensusFork.Bellatrix
    doAssert ConsensusFork.Bellatrix > ConsensusFork.Altair
    doAssert ConsensusFork.Altair    > ConsensusFork.Phase0
    doAssert GENESIS_EPOCH == 0

  if   epoch >= cfg.DENEB_FORK_EPOCH:     ConsensusFork.Deneb
  elif epoch >= cfg.CAPELLA_FORK_EPOCH:   ConsensusFork.Capella
  elif epoch >= cfg.BELLATRIX_FORK_EPOCH: ConsensusFork.Bellatrix
  elif epoch >= cfg.ALTAIR_FORK_EPOCH:    ConsensusFork.Altair
  else:                                   ConsensusFork.Phase0

func consensusForkForDigest*(
    forkDigests: ForkDigests, forkDigest: ForkDigest): Opt[ConsensusFork] =
  static: doAssert high(ConsensusFork) == ConsensusFork.Deneb
  if   forkDigest == forkDigests.deneb:
    ok ConsensusFork.Deneb
  elif forkDigest == forkDigests.capella:
    ok ConsensusFork.Capella
  elif forkDigest == forkDigests.bellatrix:
    ok ConsensusFork.Bellatrix
  elif forkDigest == forkDigests.altair:
    ok ConsensusFork.Altair
  elif forkDigest == forkDigests.phase0:
    ok ConsensusFork.Phase0
  else:
    err()

func atConsensusFork*(
    forkDigests: ForkDigests, consensusFork: ConsensusFork): ForkDigest =
  case consensusFork
  of ConsensusFork.Deneb:
    forkDigests.deneb
  of ConsensusFork.Capella:
    forkDigests.capella
  of ConsensusFork.Bellatrix:
    forkDigests.bellatrix
  of ConsensusFork.Altair:
    forkDigests.altair
  of ConsensusFork.Phase0:
    forkDigests.phase0

template atEpoch*(
    forkDigests: ForkDigests, epoch: Epoch, cfg: RuntimeConfig): ForkDigest =
  forkDigests.atConsensusFork(cfg.consensusForkAtEpoch(epoch))

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
    x: ForkedBeaconBlock |
       ForkedSignedBeaconBlock | ForkedMsgTrustedSignedBeaconBlock |
       ForkedTrustedSignedBeaconBlock | ForkedBlindedBeaconBlock |
       ForkedSignedBlindedBeaconBlock,
    body: untyped): untyped =
  case x.kind
  of ConsensusFork.Phase0:
    const consensusFork {.inject, used.} = ConsensusFork.Phase0
    template forkyBlck: untyped {.inject, used.} = x.phase0Data
    body
  of ConsensusFork.Altair:
    const consensusFork {.inject, used.} = ConsensusFork.Altair
    template forkyBlck: untyped {.inject, used.} = x.altairData
    body
  of ConsensusFork.Bellatrix:
    const consensusFork {.inject, used.} = ConsensusFork.Bellatrix
    template forkyBlck: untyped {.inject, used.} = x.bellatrixData
    body
  of ConsensusFork.Capella:
    const consensusFork {.inject, used.} = ConsensusFork.Capella
    template forkyBlck: untyped {.inject, used.} = x.capellaData
    body
  of ConsensusFork.Deneb:
    const consensusFork {.inject, used.} = ConsensusFork.Deneb
    template forkyBlck: untyped {.inject, used.} = x.denebData
    body

func proposer_index*(x: ForkedBeaconBlock): uint64 =
  withBlck(x): forkyBlck.proposer_index

func hash_tree_root*(x: ForkedBeaconBlock): Eth2Digest =
  withBlck(x): hash_tree_root(forkyBlck)

func hash_tree_root*(x: Web3SignerForkedBeaconBlock): Eth2Digest =
  hash_tree_root(x.data)

func hash_tree_root*(_: Opt[auto]) {.error.}

template getForkedBlockField*(
    x: ForkedSignedBeaconBlock |
       ForkedMsgTrustedSignedBeaconBlock |
       ForkedTrustedSignedBeaconBlock,
    y: untyped): untyped =
  # unsafeAddr avoids a copy of the field in some cases
  (case x.kind
  of ConsensusFork.Phase0:    unsafeAddr x.phase0Data.message.y
  of ConsensusFork.Altair:    unsafeAddr x.altairData.message.y
  of ConsensusFork.Bellatrix: unsafeAddr x.bellatrixData.message.y
  of ConsensusFork.Capella:   unsafeAddr x.capellaData.message.y
  of ConsensusFork.Deneb:     unsafeAddr x.denebData.message.y)[]

template signature*(x: ForkedSignedBeaconBlock |
                       ForkedMsgTrustedSignedBeaconBlock |
                       ForkedSignedBlindedBeaconBlock): ValidatorSig =
  withBlck(x): forkyBlck.signature

template signature*(x: ForkedTrustedSignedBeaconBlock): TrustedSig =
  withBlck(x): forkyBlck.signature

template root*(x: ForkedSignedBeaconBlock |
                  ForkedMsgTrustedSignedBeaconBlock |
                  ForkedTrustedSignedBeaconBlock): Eth2Digest =
  withBlck(x): forkyBlck.root

template slot*(x: ForkedSignedBeaconBlock |
                  ForkedMsgTrustedSignedBeaconBlock |
                  ForkedTrustedSignedBeaconBlock): Slot =
  withBlck(x): forkyBlck.message.slot

template shortLog*(x: ForkedBeaconBlock | ForkedBlindedBeaconBlock): auto =
  withBlck(x): shortLog(forkyBlck)

template shortLog*(x: ForkedSignedBeaconBlock |
                      ForkedMsgTrustedSignedBeaconBlock |
                      ForkedTrustedSignedBeaconBlock |
                      ForkedSignedBlindedBeaconBlock): auto =
  withBlck(x): shortLog(forkyBlck)

chronicles.formatIt ForkedBeaconBlock: it.shortLog
chronicles.formatIt ForkedSignedBeaconBlock: it.shortLog
chronicles.formatIt ForkedMsgTrustedSignedBeaconBlock: it.shortLog
chronicles.formatIt ForkedTrustedSignedBeaconBlock: it.shortLog

template withForkyMaybeBlindedBlck*(
    b: ForkedMaybeBlindedBeaconBlock,
    body: untyped): untyped =
  case b.kind
  of ConsensusFork.Deneb:
    const consensusFork {.inject, used.} = ConsensusFork.Deneb
    template d: untyped = b.denebData
    case d.isBlinded:
    of true:
      const isBlinded {.inject, used.} = true
      template forkyMaybeBlindedBlck: untyped {.inject, used.} = d.blindedData
      body
    of false:
      const isBlinded {.inject, used.} = false
      template forkyMaybeBlindedBlck: untyped {.inject, used.} = d.data
      body
  of ConsensusFork.Capella:
    const consensusFork {.inject, used.} = ConsensusFork.Capella
    template d: untyped = b.capellaData
    case d.isBlinded:
    of true:
      const isBlinded {.inject, used.} = true
      template forkyMaybeBlindedBlck: untyped {.inject, used.} = d.blindedData
      body
    of false:
      const isBlinded {.inject, used.} = false
      template forkyMaybeBlindedBlck: untyped {.inject, used.} = d.data
      body
  of ConsensusFork.Bellatrix:
    const
      consensusFork {.inject, used.} = ConsensusFork.Bellatrix
      isBlinded {.inject, used.} = false
    template forkyMaybeBlindedBlck: untyped {.inject, used.} = b.bellatrixData
    body
  of ConsensusFork.Altair:
    const
      consensusFork {.inject, used.} = ConsensusFork.Altair
      isBlinded {.inject, used.} = false
    template forkyMaybeBlindedBlck: untyped {.inject, used.} = b.altairData
    body
  of ConsensusFork.Phase0:
    const
      consensusFork {.inject, used.} = ConsensusFork.Phase0
      isBlinded {.inject, used.} = false
    template forkyMaybeBlindedBlck: untyped {.inject, used.} = b.phase0Data
    body

template withStateAndBlck*(
    s: ForkedHashedBeaconState,
    b: ForkedBeaconBlock | ForkedSignedBeaconBlock |
       ForkedMsgTrustedSignedBeaconBlock |
       ForkedTrustedSignedBeaconBlock,
    body: untyped): untyped =
  case s.kind
  of ConsensusFork.Deneb:
    const consensusFork {.inject, used.} = ConsensusFork.Deneb
    template forkyState: untyped {.inject.} = s.denebData
    template forkyBlck: untyped {.inject.} = b.denebData
    body
  of ConsensusFork.Capella:
    const consensusFork {.inject, used.} = ConsensusFork.Capella
    template forkyState: untyped {.inject.} = s.capellaData
    template forkyBlck: untyped {.inject.} = b.capellaData
    body
  of ConsensusFork.Bellatrix:
    const consensusFork {.inject, used.} = ConsensusFork.Bellatrix
    template forkyState: untyped {.inject.} = s.bellatrixData
    template forkyBlck: untyped {.inject.} = b.bellatrixData
    body
  of ConsensusFork.Altair:
    const consensusFork {.inject, used.} = ConsensusFork.Altair
    template forkyState: untyped {.inject.} = s.altairData
    template forkyBlck: untyped {.inject.} = b.altairData
    body
  of ConsensusFork.Phase0:
    const consensusFork {.inject, used.} = ConsensusFork.Phase0
    template forkyState: untyped {.inject, used.} = s.phase0Data
    template forkyBlck: untyped {.inject, used.} = b.phase0Data
    body

func toBeaconBlockHeader*(
    blck: SomeForkyBeaconBlock |
          capella_mev.BlindedBeaconBlock |
          deneb_mev.BlindedBeaconBlock
): BeaconBlockHeader =
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
  blck.message.toBeaconBlockHeader()

template toBeaconBlockHeader*(
    blckParam: ForkedMsgTrustedSignedBeaconBlock |
               ForkedTrustedSignedBeaconBlock): BeaconBlockHeader =
  ## Reduce a given signed beacon block to its `BeaconBlockHeader`.
  withBlck(blckParam): forkyBlck.toBeaconBlockHeader()

func toSignedBeaconBlockHeader*(
    signedBlock: SomeForkySignedBeaconBlock |
                 capella_mev.SignedBlindedBeaconBlock |
                 deneb_mev.SignedBlindedBeaconBlock
): SignedBeaconBlockHeader =
  ## Reduce a given `SignedBeaconBlock` to its `SignedBeaconBlockHeader`.
  SignedBeaconBlockHeader(
    message: signedBlock.message.toBeaconBlockHeader(),
    signature: signedBlock.signature)

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

func denebFork*(cfg: RuntimeConfig): Fork =
  Fork(
    previous_version: cfg.CAPELLA_FORK_VERSION,
    current_version: cfg.DENEB_FORK_VERSION,
    epoch: cfg.DENEB_FORK_EPOCH)

func forkAtEpoch*(cfg: RuntimeConfig, epoch: Epoch): Fork =
  case cfg.consensusForkAtEpoch(epoch)
  of ConsensusFork.Deneb:     cfg.denebFork
  of ConsensusFork.Capella:   cfg.capellaFork
  of ConsensusFork.Bellatrix: cfg.bellatrixFork
  of ConsensusFork.Altair:    cfg.altairFork
  of ConsensusFork.Phase0:    cfg.genesisFork

func forkVersionAtEpoch*(cfg: RuntimeConfig, epoch: Epoch): Version =
  case cfg.consensusForkAtEpoch(epoch)
  of ConsensusFork.Deneb:     cfg.DENEB_FORK_VERSION
  of ConsensusFork.Capella:   cfg.CAPELLA_FORK_VERSION
  of ConsensusFork.Bellatrix: cfg.BELLATRIX_FORK_VERSION
  of ConsensusFork.Altair:    cfg.ALTAIR_FORK_VERSION
  of ConsensusFork.Phase0:    cfg.GENESIS_FORK_VERSION

func nextForkEpochAtEpoch*(cfg: RuntimeConfig, epoch: Epoch): Epoch =
  static: doAssert high(ConsensusFork) == ConsensusFork.Deneb
  case cfg.consensusForkAtEpoch(epoch)
  of ConsensusFork.Deneb:     FAR_FUTURE_EPOCH
  of ConsensusFork.Capella:   cfg.DENEB_FORK_EPOCH
  of ConsensusFork.Bellatrix: cfg.CAPELLA_FORK_EPOCH
  of ConsensusFork.Altair:    cfg.BELLATRIX_FORK_EPOCH
  of ConsensusFork.Phase0:    cfg.ALTAIR_FORK_EPOCH

func forkVersion*(cfg: RuntimeConfig, consensusFork: ConsensusFork): Version =
  case consensusFork
  of ConsensusFork.Phase0:      cfg.GENESIS_FORK_VERSION
  of ConsensusFork.Altair:      cfg.ALTAIR_FORK_VERSION
  of ConsensusFork.Bellatrix:   cfg.BELLATRIX_FORK_VERSION
  of ConsensusFork.Capella:     cfg.CAPELLA_FORK_VERSION
  of ConsensusFork.Deneb:       cfg.DENEB_FORK_VERSION

func lcDataForkAtConsensusFork*(
    consensusFork: ConsensusFork): LightClientDataFork =
  static: doAssert LightClientDataFork.high == LightClientDataFork.Deneb
  if consensusFork >= ConsensusFork.Deneb:
    LightClientDataFork.Deneb
  elif consensusFork >= ConsensusFork.Capella:
    LightClientDataFork.Capella
  elif consensusFork >= ConsensusFork.Altair:
    LightClientDataFork.Altair
  else:
    LightClientDataFork.None

func getForkSchedule*(cfg: RuntimeConfig): array[5, Fork] =
  ## This procedure returns list of known and/or scheduled forks.
  ##
  ## This procedure is used by HTTP REST framework and validator client.
  ##
  ## NOTE: Update this procedure when new fork will be scheduled.
  [cfg.genesisFork(), cfg.altairFork(), cfg.bellatrixFork(), cfg.capellaFork(),
   cfg.denebFork()]

type
  # The first few fields of a state, shared across all forks
  BeaconStateHeader* = object
    genesis_time*: uint64
    genesis_validators_root*: Eth2Digest
    slot*: Slot

func readSszForkedHashedBeaconState*(
    consensusFork: ConsensusFork, data: openArray[byte]):
    ForkedHashedBeaconState {.raises: [SszError].} =
  # TODO https://github.com/nim-lang/Nim/issues/19357
  result = ForkedHashedBeaconState(kind: consensusFork)

  withState(result):
    readSszBytes(data, forkyState.data)
    forkyState.root = hash_tree_root(forkyState.data)

template readSszForkedHashedBeaconState*(
    cfg: RuntimeConfig, slot: Slot, data: openArray[byte]):
    ForkedHashedBeaconState =
  cfg.consensusForkAtEpoch(slot.epoch()).readSszForkedHashedBeaconState(data)

func readSszForkedHashedBeaconState*(cfg: RuntimeConfig, data: openArray[byte]):
    ForkedHashedBeaconState {.raises: [SerializationError].} =
  ## Read a state picking the right fork by first reading the slot from the byte
  ## source
  if data.len() < sizeof(BeaconStateHeader):
    raise (ref MalformedSszError)(msg: "Not enough data for BeaconState header")
  let header = SSZ.decode(
    data.toOpenArray(0, sizeof(BeaconStateHeader) - 1),
    BeaconStateHeader)

  # TODO https://github.com/nim-lang/Nim/issues/19357
  result = readSszForkedHashedBeaconState(cfg, header.slot, data)

type
  ForkedBeaconBlockHeader = object
    message*: uint32 # message offset
    signature*: ValidatorSig
    slot: Slot # start of BeaconBlock

func readSszForkedSignedBeaconBlock*(
    cfg: RuntimeConfig, data: openArray[byte]):
    ForkedSignedBeaconBlock {.raises: [SerializationError].} =
  ## Helper to read a header from bytes when it's not certain what kind of block
  ## it is
  if data.len() < sizeof(ForkedBeaconBlockHeader):
    raise (ref MalformedSszError)(msg: "Not enough data for SignedBeaconBlock header")
  let header = SSZ.decode(
    data.toOpenArray(0, sizeof(ForkedBeaconBlockHeader) - 1),
    ForkedBeaconBlockHeader)

  # TODO https://github.com/nim-lang/Nim/issues/19357
  result = ForkedSignedBeaconBlock(
    kind: cfg.consensusForkAtEpoch(header.slot.epoch()))

  withBlck(result):
    readSszBytes(data, forkyBlck)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#compute_fork_data_root
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#compute_fork_digest
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
  static: doAssert high(ConsensusFork) == ConsensusFork.Deneb
  T(
    phase0:
      compute_fork_digest(cfg.GENESIS_FORK_VERSION, genesis_validators_root),
    altair:
      compute_fork_digest(cfg.ALTAIR_FORK_VERSION, genesis_validators_root),
    bellatrix:
      compute_fork_digest(cfg.BELLATRIX_FORK_VERSION, genesis_validators_root),
    capella:
      compute_fork_digest(cfg.CAPELLA_FORK_VERSION, genesis_validators_root),
    deneb:
      compute_fork_digest(cfg.DENEB_FORK_VERSION, genesis_validators_root)
  )

func toBlockId*(header: BeaconBlockHeader): BlockId =
  BlockId(root: header.hash_tree_root(), slot: header.slot)

func toBlockId*(blck: SomeForkySignedBeaconBlock): BlockId =
  BlockId(root: blck.root, slot: blck.message.slot)

func toBlockId*(blck: ForkedSignedBeaconBlock |
                      ForkedMsgTrustedSignedBeaconBlock |
                      ForkedTrustedSignedBeaconBlock): BlockId =
  withBlck(blck): BlockId(root: forkyBlck.root, slot: forkyBlck.message.slot)

func historical_summaries*(state: ForkedHashedBeaconState):
    HashList[HistoricalSummary, Limit HISTORICAL_ROOTS_LIMIT] =
  withState(state):
    when consensusFork >= ConsensusFork.Capella:
      forkyState.data.historical_summaries
    else:
      HashList[HistoricalSummary, Limit HISTORICAL_ROOTS_LIMIT]()

template init*(T: type ForkedMaybeBlindedBeaconBlock,
               blck: phase0.BeaconBlock): T =
  ForkedMaybeBlindedBeaconBlock(
    kind: ConsensusFork.Phase0,
    phase0Data: blck)

template init*(T: type ForkedMaybeBlindedBeaconBlock,
               blck: altair.BeaconBlock): T =
  ForkedMaybeBlindedBeaconBlock(
    kind: ConsensusFork.Altair,
    altairData: blck)

template init*(T: type ForkedMaybeBlindedBeaconBlock,
               blck: bellatrix.BeaconBlock,
               evalue: Opt[UInt256], cvalue: Opt[UInt256]): T =
  ForkedMaybeBlindedBeaconBlock(
    kind: ConsensusFork.Bellatrix,
    bellatrixData: blck,
    consensusValue: cvalue,
    executionValue: evalue)

template init*(T: type ForkedMaybeBlindedBeaconBlock,
               blck: capella.BeaconBlock,
               evalue: Opt[UInt256], cvalue: Opt[UInt256]): T =
  ForkedMaybeBlindedBeaconBlock(
    kind: ConsensusFork.Capella,
    capellaData: capella_mev.MaybeBlindedBeaconBlock(
      isBlinded: false,
      data: blck),
    consensusValue: cvalue,
    executionValue: evalue)

template init*(T: type ForkedMaybeBlindedBeaconBlock,
               blck: capella_mev.BlindedBeaconBlock,
               evalue: Opt[UInt256], cvalue: Opt[UInt256]): T =
  ForkedMaybeBlindedBeaconBlock(
    kind: ConsensusFork.Capella,
    capellaData: capella_mev.MaybeBlindedBeaconBlock(
      isBlinded: true,
      blindedData: blck),
    consensusValue: cvalue,
    executionValue: evalue)

template init*(T: type ForkedMaybeBlindedBeaconBlock,
               blck: deneb.BlockContents,
               evalue: Opt[UInt256], cvalue: Opt[UInt256]): T =
  ForkedMaybeBlindedBeaconBlock(
    kind: ConsensusFork.Deneb,
    denebData: deneb_mev.MaybeBlindedBeaconBlock(
      isBlinded: false,
      data: blck),
    consensusValue: cvalue,
    executionValue: evalue)

template init*(T: type ForkedMaybeBlindedBeaconBlock,
               blck: deneb_mev.BlindedBeaconBlock,
               evalue: Opt[UInt256], cvalue: Opt[UInt256]): T =
  ForkedMaybeBlindedBeaconBlock(
    kind: ConsensusFork.Deneb,
    denebData: deneb_mev.MaybeBlindedBeaconBlock(
      isBlinded: true,
      blindedData: blck),
    consensusValue: cvalue,
    executionValue: evalue)
