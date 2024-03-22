import
  results,
  "."/block_id

type
  ConsensusFork* {.pure.} = enum
    Phase0,
    Altair,
    Bellatrix,
    Capella,
    Deneb,
    Electra

  Mock* = object

  ForkedHashedBeaconState* = object
    case kind*: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data:    Mock
    of ConsensusFork.Altair:    altairData:    Mock
    of ConsensusFork.Bellatrix: bellatrixData: Mock
    of ConsensusFork.Capella:   capellaData:   Mock
    of ConsensusFork.Deneb:     denebData:     Mock
    of ConsensusFork.Electra:   electraData:   Mock

  ForkyExecutionPayloadForSigning* = int

  ForkedBeaconBlock* = object
    case kind: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data:    Mock
    of ConsensusFork.Altair:    altairData:    Mock
    of ConsensusFork.Bellatrix: bellatrixData: Mock
    of ConsensusFork.Capella:   capellaData:   Mock
    of ConsensusFork.Deneb:     denebData:     Mock
    of ConsensusFork.Electra:   electraData:   Mock

  ForkedBlindedBeaconBlock = object
    case kind: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data:    Mock
    of ConsensusFork.Altair:    altairData:    Mock
    of ConsensusFork.Bellatrix: bellatrixData: Mock
    of ConsensusFork.Capella:   capellaData:   Mock
    of ConsensusFork.Deneb:     denebData:     Mock
    of ConsensusFork.Electra:   electraData:   Mock

  ForkySignedBeaconBlock* = Mock

  ForkedSignedBeaconBlock* = object
    case kind: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data:    Mock
    of ConsensusFork.Altair:    altairData:    Mock
    of ConsensusFork.Bellatrix: bellatrixData: Mock
    of ConsensusFork.Capella:   capellaData:   Mock
    of ConsensusFork.Deneb:     denebData:     Mock
    of ConsensusFork.Electra:   electraData:   Mock

  ForkedSignedBlindedBeaconBlock = object
    case kind: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data:    Mock
    of ConsensusFork.Altair:    altairData:    Mock
    of ConsensusFork.Bellatrix: bellatrixData: Mock
    of ConsensusFork.Capella:   capellaData:   Mock
    of ConsensusFork.Deneb:     denebData:     Mock
    of ConsensusFork.Electra:   electraData:   Mock

template kind*(
    x: typedesc[Mock]): ConsensusFork =
  ConsensusFork.Phase0

template SignedBeaconBlock*(kind: static ConsensusFork): auto =
  when kind == ConsensusFork.Electra:
    typedesc[Mock]
  elif kind == ConsensusFork.Deneb:
    typedesc[Mock]
  elif kind == ConsensusFork.Capella:
    typedesc[Mock]
  elif kind == ConsensusFork.Bellatrix:
    typedesc[Mock]
  elif kind == ConsensusFork.Altair:
    typedesc[Mock]
  elif kind == ConsensusFork.Phase0:
    typedesc[Mock]
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

template init*(T: type ForkedSignedBeaconBlock, blck: Mock): T =
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
    slot*: uint64
