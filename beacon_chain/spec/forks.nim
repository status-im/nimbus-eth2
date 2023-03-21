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
  ./mev/bellatrix_mev, ./mev/capella_mev

export
  extras, block_id, phase0, altair, bellatrix, capella, deneb,
  eth2_merkleization, eth2_ssz_serialization, forks_light_client,
  presets, bellatrix_mev, capella_mev

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

  ForkedBeaconBlock* = object
    case kind*: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data*:    phase0.BeaconBlock
    of ConsensusFork.Altair:    altairData*:    altair.BeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData*: bellatrix.BeaconBlock
    of ConsensusFork.Capella:   capellaData*:   capella.BeaconBlock
    of ConsensusFork.Deneb:     denebData*:     deneb.BeaconBlock

  Web3SignerForkedBeaconBlock* = object
    case kind*: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data*:    phase0.BeaconBlock
    of ConsensusFork.Altair:    altairData*:    altair.BeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData*: BeaconBlockHeader
    of ConsensusFork.Capella:   capellaData*:   BeaconBlockHeader
    of ConsensusFork.Deneb:     denebData*:     BeaconBlockHeader

  ForkedBlindedBeaconBlock* = object
    case kind*: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data*:    phase0.BeaconBlock
    of ConsensusFork.Altair:    altairData*:    altair.BeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData*: bellatrix_mev.BlindedBeaconBlock
    of ConsensusFork.Capella:   capellaData*:   capella_mev.BlindedBeaconBlock
    of ConsensusFork.Deneb:     denebData*:     capella_mev.BlindedBeaconBlock

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
    bellatrix_mev.SignedBlindedBeaconBlock |
    capella_mev.SignedBlindedBeaconBlock

  ForkedSignedBlindedBeaconBlock* = object
    case kind*: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data*:    phase0.SignedBeaconBlock
    of ConsensusFork.Altair:    altairData*:    altair.SignedBeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData*: bellatrix_mev.SignedBlindedBeaconBlock
    of ConsensusFork.Capella:   capellaData*:   capella_mev.SignedBlindedBeaconBlock
    of ConsensusFork.Deneb:     denebData*:     capella_mev.SignedBlindedBeaconBlock

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

macro getSymbolFromForkModule(fork: static ConsensusFork,
                              symbolName: static string): untyped =
  let moduleName = case fork
    of ConsensusFork.Phase0: "phase0"
    of ConsensusFork.Altair: "altair"
    of ConsensusFork.Bellatrix: "bellatrix"
    of ConsensusFork.Capella: "capella"
    of ConsensusFork.Deneb:   "deneb"
  newDotExpr(ident moduleName, ident symbolName)

template BeaconStateType*(fork: static ConsensusFork): auto =
  getSymbolFromForkModule(fork, "BeaconState")

template BeaconBlockType*(fork: static ConsensusFork): auto =
  getSymbolFromForkModule(fork, "BeaconBlock")

template BeaconBlockBodyType*(fork: static ConsensusFork): auto =
  getSymbolFromForkModule(fork, "BeaconBlockBody")

template ExecutionPayloadForSigning*(kind: static ConsensusFork): auto =
  when kind == ConsensusFork.Deneb:
    typedesc[deneb.ExecutionPayloadForSigning]
  elif kind == ConsensusFork.Capella:
    typedesc[capella.ExecutionPayloadForSigning]
  elif kind == ConsensusFork.Bellatrix:
    typedesc[bellatrix.ExecutionPayloadForSigning]
  else:
    static: raiseAssert "Unreachable"

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
      bellatrixData: bellatrix_mev.SignedBlindedBeaconBlock(message: forked.bellatrixData,
                                                            signature: signature))
  of ConsensusFork.Capella:
    T(kind: ConsensusFork.Capella,
      capellaData: capella_mev.SignedBlindedBeaconBlock(message: forked.capellaData,
                                                        signature: signature))
  of ConsensusFork.Deneb:
    discard $denebImplementationMissing & "forks.nim:init(T: type ForkedSignedBlindedBeaconBlock)"
    T(kind: ConsensusFork.Deneb,
      denebData: capella_mev.SignedBlindedBeaconBlock(message: forked.denebData,
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

template toFork*[T:
    phase0.BeaconState |
    phase0.HashedBeaconState |
    phase0.BeaconBlock |
    phase0.SignedBeaconBlock |
    phase0.TrustedBeaconBlock |
    phase0.SigVerifiedSignedBeaconBlock |
    phase0.MsgTrustedSignedBeaconBlock |
    phase0.TrustedSignedBeaconBlock](
    t: type T): ConsensusFork =
  ConsensusFork.Phase0

template toFork*[T:
    altair.BeaconState |
    altair.HashedBeaconState |
    altair.BeaconBlock |
    altair.SignedBeaconBlock |
    altair.TrustedBeaconBlock |
    altair.SigVerifiedSignedBeaconBlock |
    altair.MsgTrustedSignedBeaconBlock |
    altair.TrustedSignedBeaconBlock](
    t: type T): ConsensusFork =
  ConsensusFork.Altair

template toFork*[T:
    bellatrix.BeaconState |
    bellatrix.HashedBeaconState |
    bellatrix.ExecutionPayload |
    bellatrix.ExecutionPayloadForSigning |
    bellatrix.ExecutionPayloadHeader |
    bellatrix.BeaconBlock |
    bellatrix.SignedBeaconBlock |
    bellatrix.TrustedBeaconBlock |
    bellatrix.SigVerifiedSignedBeaconBlock |
    bellatrix.MsgTrustedSignedBeaconBlock |
    bellatrix.TrustedSignedBeaconBlock](
    t: type T): ConsensusFork =
  ConsensusFork.Bellatrix

template toFork*[T:
    capella.BeaconState |
    capella.HashedBeaconState |
    capella.ExecutionPayload |
    capella.ExecutionPayloadForSigning |
    capella.ExecutionPayloadHeader |
    capella.BeaconBlock |
    capella.SignedBeaconBlock |
    capella.TrustedBeaconBlock |
    capella.SigVerifiedSignedBeaconBlock |
    capella.MsgTrustedSignedBeaconBlock |
    capella.TrustedSignedBeaconBlock](
    t: type T): ConsensusFork =
  ConsensusFork.Capella

template toFork*[T:
    deneb.BeaconState |
    deneb.HashedBeaconState |
    deneb.ExecutionPayload |
    deneb.ExecutionPayloadForSigning |
    deneb.ExecutionPayloadHeader |
    deneb.BeaconBlock |
    deneb.SignedBeaconBlock |
    deneb.TrustedBeaconBlock |
    deneb.SigVerifiedSignedBeaconBlock |
    deneb.MsgTrustedSignedBeaconBlock |
    deneb.TrustedSignedBeaconBlock](
    t: type T): ConsensusFork =
  ConsensusFork.Deneb

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

func assign*(tgt: var ForkedHashedBeaconState, src: ForkedHashedBeaconState) =
  if tgt.kind == src.kind:
    case tgt.kind
    of ConsensusFork.Deneb:
      assign(tgt.denebData,     src.denebData):
    of ConsensusFork.Capella:
      assign(tgt.capellaData,   src.capellaData):
    of ConsensusFork.Bellatrix:
      assign(tgt.bellatrixData, src.bellatrixData):
    of ConsensusFork.Altair:
      assign(tgt.altairData,    src.altairData):
    of ConsensusFork.Phase0:
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
  of ConsensusFork.Deneb:     unsafeAddr x.denebData.data.y
  of ConsensusFork.Capella:   unsafeAddr x.capellaData.data.y
  of ConsensusFork.Bellatrix: unsafeAddr x.bellatrixData.data.y
  of ConsensusFork.Altair:    unsafeAddr x.altairData.data.y
  of ConsensusFork.Phase0:    unsafeAddr x.phase0Data.data.y)[]

func getStateRoot*(x: ForkedHashedBeaconState): Eth2Digest =
  withState(x): forkyState.root

func setStateRoot*(x: var ForkedHashedBeaconState, root: Eth2Digest) =
  withState(x): forkyState.root = root

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
    x: ForkedBeaconBlock | Web3SignerForkedBeaconBlock |
       ForkedSignedBeaconBlock | ForkedMsgTrustedSignedBeaconBlock |
       ForkedTrustedSignedBeaconBlock | ForkedBlindedBeaconBlock |
       ForkedSignedBlindedBeaconBlock,
    body: untyped): untyped =
  case x.kind
  of ConsensusFork.Phase0:
    const consensusFork {.inject, used.} = ConsensusFork.Phase0
    template blck: untyped {.inject.} = x.phase0Data
    body
  of ConsensusFork.Altair:
    const consensusFork {.inject, used.} = ConsensusFork.Altair
    template blck: untyped {.inject.} = x.altairData
    body
  of ConsensusFork.Bellatrix:
    const consensusFork {.inject, used.} = ConsensusFork.Bellatrix
    template blck: untyped {.inject.} = x.bellatrixData
    body
  of ConsensusFork.Capella:
    const consensusFork {.inject, used.} = ConsensusFork.Capella
    template blck: untyped {.inject.} = x.capellaData
    body
  of ConsensusFork.Deneb:
    const consensusFork {.inject, used.} = ConsensusFork.Deneb
    template blck: untyped {.inject.} = x.denebData
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
  of ConsensusFork.Phase0:    unsafeAddr x.phase0Data.message.y
  of ConsensusFork.Altair:    unsafeAddr x.altairData.message.y
  of ConsensusFork.Bellatrix: unsafeAddr x.bellatrixData.message.y
  of ConsensusFork.Capella:   unsafeAddr x.capellaData.message.y
  of ConsensusFork.Deneb:     unsafeAddr x.denebData.message.y)[]

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
  of ConsensusFork.Deneb:
    const consensusFork {.inject.} = ConsensusFork.Deneb
    template forkyState: untyped {.inject.} = s.denebData
    template blck: untyped {.inject.} = b.denebData
    body
  of ConsensusFork.Capella:
    const consensusFork {.inject.} = ConsensusFork.Capella
    template forkyState: untyped {.inject.} = s.capellaData
    template blck: untyped {.inject.} = b.capellaData
    body
  of ConsensusFork.Bellatrix:
    const consensusFork {.inject.} = ConsensusFork.Bellatrix
    template forkyState: untyped {.inject.} = s.bellatrixData
    template blck: untyped {.inject.} = b.bellatrixData
    body
  of ConsensusFork.Altair:
    const consensusFork {.inject.} = ConsensusFork.Altair
    template forkyState: untyped {.inject.} = s.altairData
    template blck: untyped {.inject.} = b.altairData
    body
  of ConsensusFork.Phase0:
    const consensusFork {.inject.} = ConsensusFork.Phase0
    template forkyState: untyped {.inject.} = s.phase0Data
    template blck: untyped {.inject.} = b.phase0Data
    body

func toBeaconBlockHeader*(
    blck: SomeForkyBeaconBlock | bellatrix_mev.BlindedBeaconBlock |
          capella_mev.BlindedBeaconBlock): BeaconBlockHeader =
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
  BeaconStateHeader = object
    genesis_time: uint64
    genesis_validators_root: Eth2Digest
    slot: Slot

func readSszForkedHashedBeaconState*(
    cfg: RuntimeConfig, slot: Slot, data: openArray[byte]):
    ForkedHashedBeaconState {.raises: [Defect, SszError].} =
  # TODO https://github.com/nim-lang/Nim/issues/19357
  result = ForkedHashedBeaconState(
    kind: cfg.consensusForkAtEpoch(slot.epoch()))

  withState(result):
    readSszBytes(data, forkyState.data)
    forkyState.root = hash_tree_root(forkyState.data)

func readSszForkedHashedBeaconState*(cfg: RuntimeConfig, data: openArray[byte]):
    ForkedHashedBeaconState {.raises: [Defect, SszError].} =
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
    kind: cfg.consensusForkAtEpoch(header.slot.epoch()))

  withBlck(result):
    readSszBytes(data, blck)

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.3/specs/phase0/beacon-chain.md#compute_fork_data_root
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

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.5/specs/phase0/beacon-chain.md#compute_fork_digest
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
  withBlck(blck): BlockId(root: blck.root, slot: blck.message.slot)
