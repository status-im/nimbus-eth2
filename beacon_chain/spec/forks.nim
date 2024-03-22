import
  results,
  "."/[
    block_id,
    presets],
  ./datatypes/[phase0, altair, bellatrix, capella],
  ./mev/bellatrix_mev

type
  ConsensusFork* {.pure.} = enum
    Phase0,
    Altair,
    Bellatrix,
    Capella,
    Deneb,
    Electra

  ForkedHashedBeaconState* = object
    case kind*: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data:    phase0.HashedBeaconState
    of ConsensusFork.Altair:    altairData:    altair.HashedBeaconState
    of ConsensusFork.Bellatrix: bellatrixData: bellatrix.HashedBeaconState
    of ConsensusFork.Capella:   capellaData:   capella.HashedBeaconState
    of ConsensusFork.Deneb:     denebData:     phase0.HashedBeaconState
    of ConsensusFork.Electra:   electraData:   phase0.HashedBeaconState

  ForkyExecutionPayloadForSigning* =
    bellatrix.ExecutionPayloadForSigning |
    capella.ExecutionPayloadForSigning

  ForkedBeaconBlock* = object
    case kind: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data:    phase0.BeaconBlock
    of ConsensusFork.Altair:    altairData:    altair.BeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData: bellatrix.BeaconBlock
    of ConsensusFork.Capella:   capellaData:   capella.BeaconBlock
    of ConsensusFork.Deneb:     denebData:     phase0.BeaconBlock
    of ConsensusFork.Electra:   electraData:   phase0.BeaconBlock

  ForkedBlindedBeaconBlock = object
    case kind: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data:    phase0.BeaconBlock
    of ConsensusFork.Altair:    altairData:    altair.BeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData: bellatrix_mev.BlindedBeaconBlock
    of ConsensusFork.Capella:   capellaData:   phase0.BeaconBlock
    of ConsensusFork.Deneb:     denebData:     phase0.BeaconBlock
    of ConsensusFork.Electra:   electraData:   phase0.BeaconBlock

  ForkySignedBeaconBlock* =
    phase0.SignedBeaconBlock |
    altair.SignedBeaconBlock |
    bellatrix.SignedBeaconBlock |
    capella.SignedBeaconBlock

  ForkedSignedBeaconBlock* = object
    case kind: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data:    phase0.SignedBeaconBlock
    of ConsensusFork.Altair:    altairData:    altair.SignedBeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData: bellatrix.SignedBeaconBlock
    of ConsensusFork.Capella:   capellaData:   capella.SignedBeaconBlock
    of ConsensusFork.Deneb:     denebData:     phase0.SignedBeaconBlock
    of ConsensusFork.Electra:   electraData:   phase0.SignedBeaconBlock

  ForkedSignedBlindedBeaconBlock = object
    case kind: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data:    phase0.SignedBeaconBlock
    of ConsensusFork.Altair:    altairData:    altair.SignedBeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData: bellatrix_mev.SignedBlindedBeaconBlock
    of ConsensusFork.Capella:   capellaData:   phase0.SignedBeaconBlock
    of ConsensusFork.Deneb:     denebData:     phase0.SignedBeaconBlock
    of ConsensusFork.Electra:   electraData:   phase0.SignedBeaconBlock

template kind*(
    x: typedesc[
      phase0.BeaconState |
      phase0.HashedBeaconState |
      phase0.BeaconBlock |
      phase0.SignedBeaconBlock |
      phase0.BeaconBlockBody]): ConsensusFork =
  ConsensusFork.Phase0

template kind*(
    x: typedesc[
      altair.BeaconState |
      altair.HashedBeaconState |
      altair.BeaconBlock |
      altair.SignedBeaconBlock |
      altair.BeaconBlockBody]): ConsensusFork =
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
      bellatrix.BeaconBlockBody |
      bellatrix_mev.SignedBlindedBeaconBlock]): ConsensusFork =
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
      capella.BeaconBlockBody]): ConsensusFork =
  ConsensusFork.Capella

template SignedBeaconBlock*(kind: static ConsensusFork): auto =
  when kind == ConsensusFork.Electra:
    typedesc[phase0.SignedBeaconBlock]
  elif kind == ConsensusFork.Deneb:
    typedesc[phase0.SignedBeaconBlock]
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

template withConsensusFork*(
    x: ConsensusFork, body: untyped): untyped =
  case x
  of ConsensusFork.Electra:
    const consensusFork {.inject, used.} = ConsensusFork.Electra
    body
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

template init*(T: type ForkedSignedBeaconBlock, blck: phase0.SignedBeaconBlock): T =
  T(kind: ConsensusFork.Phase0, phase0Data: blck)
template init*(T: type ForkedSignedBeaconBlock, blck: altair.SignedBeaconBlock): T =
  T(kind: ConsensusFork.Altair, altairData: blck)
template init*(T: type ForkedSignedBeaconBlock, blck: bellatrix.SignedBeaconBlock): T =
  T(kind: ConsensusFork.Bellatrix, bellatrixData: blck)
template init*(T: type ForkedSignedBeaconBlock, blck: capella.SignedBeaconBlock): T =
  T(kind: ConsensusFork.Capella, capellaData: blck)

template withBlck*(
    x: ForkedBeaconBlock |
       ForkedSignedBeaconBlock |
       ForkedBlindedBeaconBlock |
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
  of ConsensusFork.Electra:
    const consensusFork {.inject, used.} = ConsensusFork.Electra
    template forkyBlck: untyped {.inject, used.} = x.electraData
    body

type
  BeaconStateHeader* = object
    genesis_time*: uint64
    genesis_validators_root*: Eth2Digest
    slot*: Slot
