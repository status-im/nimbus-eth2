import
  results,
  "."/block_id,
  ./datatypes/phase0

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
    of ConsensusFork.Altair:    altairData:    phase0.HashedBeaconState
    of ConsensusFork.Bellatrix: bellatrixData: phase0.HashedBeaconState
    of ConsensusFork.Capella:   capellaData:   phase0.HashedBeaconState
    of ConsensusFork.Deneb:     denebData:     phase0.HashedBeaconState
    of ConsensusFork.Electra:   electraData:   phase0.HashedBeaconState

  ForkyExecutionPayloadForSigning* = int

  ForkedBeaconBlock* = object
    case kind: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data:    phase0.BeaconBlock
    of ConsensusFork.Altair:    altairData:    phase0.BeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData: phase0.BeaconBlock
    of ConsensusFork.Capella:   capellaData:   phase0.BeaconBlock
    of ConsensusFork.Deneb:     denebData:     phase0.BeaconBlock
    of ConsensusFork.Electra:   electraData:   phase0.BeaconBlock

  ForkedBlindedBeaconBlock = object
    case kind: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data:    phase0.BeaconBlock
    of ConsensusFork.Altair:    altairData:    phase0.BeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData: phase0.BeaconBlock
    of ConsensusFork.Capella:   capellaData:   phase0.BeaconBlock
    of ConsensusFork.Deneb:     denebData:     phase0.BeaconBlock
    of ConsensusFork.Electra:   electraData:   phase0.BeaconBlock

  ForkySignedBeaconBlock* = phase0.SignedBeaconBlock

  ForkedSignedBeaconBlock* = object
    case kind: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data:    phase0.SignedBeaconBlock
    of ConsensusFork.Altair:    altairData:    phase0.SignedBeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData: phase0.SignedBeaconBlock
    of ConsensusFork.Capella:   capellaData:   phase0.SignedBeaconBlock
    of ConsensusFork.Deneb:     denebData:     phase0.SignedBeaconBlock
    of ConsensusFork.Electra:   electraData:   phase0.SignedBeaconBlock

  ForkedSignedBlindedBeaconBlock = object
    case kind: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data:    phase0.SignedBeaconBlock
    of ConsensusFork.Altair:    altairData:    phase0.SignedBeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData: phase0.SignedBeaconBlock
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

template SignedBeaconBlock*(kind: static ConsensusFork): auto =
  when kind == ConsensusFork.Electra:
    typedesc[phase0.SignedBeaconBlock]
  elif kind == ConsensusFork.Deneb:
    typedesc[phase0.SignedBeaconBlock]
  elif kind == ConsensusFork.Capella:
    typedesc[phase0.SignedBeaconBlock]
  elif kind == ConsensusFork.Bellatrix:
    typedesc[phase0.SignedBeaconBlock]
  elif kind == ConsensusFork.Altair:
    typedesc[phase0.SignedBeaconBlock]
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
