import
  results,
  "."/[
    block_id, eth2_merkleization, eth2_ssz_serialization,
    presets],
  ./datatypes/[phase0, altair, bellatrix, capella, deneb, electra],
  ./mev/bellatrix_mev, ./mev/capella_mev, ./mev/deneb_mev

export
  eth2_merkleization, eth2_ssz_serialization

type
  ConsensusFork* {.pure.} = enum
    Phase0,
    Altair,
    Bellatrix,
    Capella,
    Deneb,
    Electra

  ForkedHashedBeaconState* = object
    case kind: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data:    phase0.HashedBeaconState
    of ConsensusFork.Altair:    altairData:    altair.HashedBeaconState
    of ConsensusFork.Bellatrix: bellatrixData: bellatrix.HashedBeaconState
    of ConsensusFork.Capella:   capellaData:   capella.HashedBeaconState
    of ConsensusFork.Deneb:     denebData:     deneb.HashedBeaconState
    of ConsensusFork.Electra:   electraData:   electra.HashedBeaconState

  ForkyBeaconBlock =
    phase0.BeaconBlock |
    altair.BeaconBlock |
    bellatrix.BeaconBlock |
    capella.BeaconBlock |
    deneb.BeaconBlock |
    electra.BeaconBlock

  SomeForkyBeaconBlock* =
    ForkyBeaconBlock

  ForkyExecutionPayloadForSigning* =
    bellatrix.ExecutionPayloadForSigning |
    capella.ExecutionPayloadForSigning |
    deneb.ExecutionPayloadForSigning |
    electra.ExecutionPayloadForSigning

  ForkedBeaconBlock* = object
    case kind: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data:    phase0.BeaconBlock
    of ConsensusFork.Altair:    altairData:    altair.BeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData: bellatrix.BeaconBlock
    of ConsensusFork.Capella:   capellaData:   capella.BeaconBlock
    of ConsensusFork.Deneb:     denebData:     deneb.BeaconBlock
    of ConsensusFork.Electra:   electraData:   electra.BeaconBlock

  ForkedBlindedBeaconBlock = object
    case kind: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data:    phase0.BeaconBlock
    of ConsensusFork.Altair:    altairData:    altair.BeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData: bellatrix_mev.BlindedBeaconBlock
    of ConsensusFork.Capella:   capellaData:   capella_mev.BlindedBeaconBlock
    of ConsensusFork.Deneb:     denebData:     deneb_mev.BlindedBeaconBlock
    of ConsensusFork.Electra:   electraData:   electra.BeaconBlock

  ForkySignedBeaconBlock* =
    phase0.SignedBeaconBlock |
    altair.SignedBeaconBlock |
    bellatrix.SignedBeaconBlock |
    capella.SignedBeaconBlock |
    deneb.SignedBeaconBlock |
    electra.SignedBeaconBlock

  ForkedSignedBeaconBlock* = object
    case kind: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data:    phase0.SignedBeaconBlock
    of ConsensusFork.Altair:    altairData:    altair.SignedBeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData: bellatrix.SignedBeaconBlock
    of ConsensusFork.Capella:   capellaData:   capella.SignedBeaconBlock
    of ConsensusFork.Deneb:     denebData:     deneb.SignedBeaconBlock
    of ConsensusFork.Electra:   electraData:   electra.SignedBeaconBlock

  ForkySignedBlindedBeaconBlock* =
    phase0.SignedBeaconBlock |
    altair.SignedBeaconBlock |
    bellatrix_mev.SignedBlindedBeaconBlock |
    capella_mev.SignedBlindedBeaconBlock |
    deneb_mev.SignedBlindedBeaconBlock

  ForkedSignedBlindedBeaconBlock = object
    case kind: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data:    phase0.SignedBeaconBlock
    of ConsensusFork.Altair:    altairData:    altair.SignedBeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData: bellatrix_mev.SignedBlindedBeaconBlock
    of ConsensusFork.Capella:   capellaData:   capella_mev.SignedBlindedBeaconBlock
    of ConsensusFork.Deneb:     denebData:     deneb_mev.SignedBlindedBeaconBlock
    of ConsensusFork.Electra:   electraData:   electra.SignedBeaconBlock

  SomeForkySignedBeaconBlock =
    ForkySignedBeaconBlock

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
      capella.BeaconBlockBody |
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
      deneb.BeaconBlockBody |
      deneb_mev.SignedBlindedBeaconBlock]): ConsensusFork =
  ConsensusFork.Deneb

template kind*(
    x: typedesc[
      electra.BeaconState |
      electra.HashedBeaconState |
      electra.ExecutionPayload |
      electra.ExecutionPayloadForSigning |
      electra.ExecutionPayloadHeader |
      electra.BeaconBlock |
      electra.SignedBeaconBlock |
      electra.BeaconBlockBody]): ConsensusFork =
  ConsensusFork.Electra

template SignedBeaconBlock*(kind: static ConsensusFork): auto =
  when kind == ConsensusFork.Electra:
    typedesc[electra.SignedBeaconBlock]
  elif kind == ConsensusFork.Deneb:
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

template ExecutionPayloadForSigning*(kind: static ConsensusFork): auto =
  when kind == ConsensusFork.Electra:
    typedesc[electra.ExecutionPayloadForSigning]
  elif kind == ConsensusFork.Deneb:
    typedesc[deneb.ExecutionPayloadForSigning]
  elif kind == ConsensusFork.Capella:
    typedesc[capella.ExecutionPayloadForSigning]
  elif kind == ConsensusFork.Bellatrix:
    typedesc[bellatrix.ExecutionPayloadForSigning]
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
template init*(T: type ForkedSignedBeaconBlock, blck: deneb.SignedBeaconBlock): T =
  T(kind: ConsensusFork.Deneb, denebData: blck)
template init*(T: type ForkedSignedBeaconBlock, blck: electra.SignedBeaconBlock): T =
  T(kind: ConsensusFork.Electra, electraData: blck)

template withState*(x: ForkedHashedBeaconState, body: untyped): untyped =
  case x.kind
  of ConsensusFork.Electra:
    const consensusFork {.inject, used.} = ConsensusFork.Electra
    template forkyState: untyped {.inject, used.} = x.electraData
    body
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

template getStateField*(x: ForkedHashedBeaconState, y: untyped): untyped =
  (block:
    withState(x): unsafeAddr forkyState.data.y)[]

func consensusForkAtEpoch*(cfg: RuntimeConfig, epoch: Epoch): ConsensusFork =
  if   epoch >= cfg.ELECTRA_FORK_EPOCH:   ConsensusFork.Electra
  elif epoch >= cfg.DENEB_FORK_EPOCH:     ConsensusFork.Deneb
  elif epoch >= cfg.CAPELLA_FORK_EPOCH:   ConsensusFork.Capella
  elif epoch >= cfg.BELLATRIX_FORK_EPOCH: ConsensusFork.Bellatrix
  elif epoch >= cfg.ALTAIR_FORK_EPOCH:    ConsensusFork.Altair
  else:                                   ConsensusFork.Phase0

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

func proposer_index(x: ForkedBeaconBlock): uint64 =
  withBlck(x): forkyBlck.proposer_index

func hash_tree_root(x: ForkedBeaconBlock): Eth2Digest =
  withBlck(x): hash_tree_root(forkyBlck)

func hash_tree_root(_: Opt[auto]) {.error.}

template signature(x: ForkedSignedBeaconBlock |
                       ForkedSignedBlindedBeaconBlock): ValidatorSig =
  withBlck(x): forkyBlck.signature

template slot(x: ForkedSignedBeaconBlock): Slot =
  withBlck(x): forkyBlck.message.slot

func toBeaconBlockHeader(
    blck: SomeForkyBeaconBlock |
          capella_mev.BlindedBeaconBlock |
          deneb_mev.BlindedBeaconBlock
): BeaconBlockHeader =
  BeaconBlockHeader(
    slot: blck.slot,
    proposer_index: blck.proposer_index,
    parent_root: blck.parent_root,
    state_root: blck.state_root,
    body_root: blck.body.hash_tree_root())

template toBeaconBlockHeader(
    blck: SomeForkySignedBeaconBlock): BeaconBlockHeader =
  blck.message.toBeaconBlockHeader()

func toSignedBeaconBlockHeader*(
    signedBlock: SomeForkySignedBeaconBlock |
                 capella_mev.SignedBlindedBeaconBlock |
                 deneb_mev.SignedBlindedBeaconBlock
): SignedBeaconBlockHeader =
  SignedBeaconBlockHeader(
    message: signedBlock.message.toBeaconBlockHeader(),
    signature: signedBlock.signature)

func genesisFork(cfg: RuntimeConfig): Fork =
  Fork(
    previous_version: cfg.GENESIS_FORK_VERSION,
    current_version: cfg.GENESIS_FORK_VERSION,
    epoch: GENESIS_EPOCH)

func altairFork(cfg: RuntimeConfig): Fork =
  Fork(
    previous_version: cfg.GENESIS_FORK_VERSION,
    current_version: cfg.ALTAIR_FORK_VERSION,
    epoch: cfg.ALTAIR_FORK_EPOCH)

func bellatrixFork(cfg: RuntimeConfig): Fork =
  Fork(
    previous_version: cfg.ALTAIR_FORK_VERSION,
    current_version: cfg.BELLATRIX_FORK_VERSION,
    epoch: cfg.BELLATRIX_FORK_EPOCH)

func capellaFork(cfg: RuntimeConfig): Fork =
  Fork(
    previous_version: cfg.BELLATRIX_FORK_VERSION,
    current_version: cfg.CAPELLA_FORK_VERSION,
    epoch: cfg.CAPELLA_FORK_EPOCH)

func denebFork(cfg: RuntimeConfig): Fork =
  Fork(
    previous_version: cfg.CAPELLA_FORK_VERSION,
    current_version: cfg.DENEB_FORK_VERSION,
    epoch: cfg.DENEB_FORK_EPOCH)

func electraFork(cfg: RuntimeConfig): Fork =
  Fork(
    previous_version: cfg.DENEB_FORK_VERSION,
    current_version: cfg.ELECTRA_FORK_VERSION,
    epoch: cfg.ELECTRA_FORK_EPOCH)

func forkAtEpoch*(cfg: RuntimeConfig, epoch: Epoch): Fork =
  case cfg.consensusForkAtEpoch(epoch)
  of ConsensusFork.Electra:   cfg.electraFork
  of ConsensusFork.Deneb:     cfg.denebFork
  of ConsensusFork.Capella:   cfg.capellaFork
  of ConsensusFork.Bellatrix: cfg.bellatrixFork
  of ConsensusFork.Altair:    cfg.altairFork
  of ConsensusFork.Phase0:    cfg.genesisFork

type
  BeaconStateHeader* = object
    genesis_time: uint64
    genesis_validators_root*: Eth2Digest
    slot: Slot

func readSszForkedHashedBeaconState*(
    consensusFork: ConsensusFork, data: openArray[byte]):
    ForkedHashedBeaconState {.raises: [SszError].} =
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
  if data.len() < sizeof(BeaconStateHeader):
    raise (ref MalformedSszError)(msg: "Not enough data for BeaconState header")
  let header = SSZ.decode(
    data.toOpenArray(0, sizeof(BeaconStateHeader) - 1),
    BeaconStateHeader)

  result = readSszForkedHashedBeaconState(cfg, header.slot, data)
