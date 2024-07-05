import
  std/[sequtils, times],
  NimQml,
  ../beacon_chain/spec/eth2_apis/rest_beacon_client,
  "."/[
    attestationlist, depositlist, attesterslashinglist, proposerslashinglist,
    voluntaryexitlist, utils]

QtObject:
  type
    BlockModel* = ref object of QObject
      blck: ForkedSignedBeaconBlock
      attestationsx: AttestationList
      depositsx: DepositList
      attester_slashingsx: AttesterSlashingList
      proposer_slashingsx: ProposerSlashingList
      voluntary_exitsx: VoluntaryExitList
      genesis_time*: uint64

  proc delete*(self: BlockModel) =
    self.QObject.delete

  proc setup*(self: BlockModel) =
    self.QObject.setup

  proc newBlockModel*(forked: ForkedSignedBeaconBlock, genesis_time: uint64): BlockModel =
    let res =  withBlck(forked): BlockModel(
      blck: forked,
      attestationsx: newAttestationList(forkyBlck.message.body.attestations.asSeq()),
      depositsx: newDepositList(forkyBlck.message.body.deposits.mapIt(it.toDepositInfo())),
      attester_slashingsx: newAttesterSlashingList(forkyBlck.message.body.attester_slashings.asSeq()),
      proposer_slashingsx: newProposerSlashingList(forkyBlck.message.body.proposer_slashings.asSeq()),
      voluntary_exitsx: newVoluntaryExitList(forkyBlck.message.body.voluntary_exits.asSeq()),
      genesis_time: genesis_time,
    )
    res.setup()
    res

  proc `blck=`*(self: BlockModel, forked: ForkedSignedBeaconBlock) =
    self.blck = forked
    withBlck(forked):
      self.attestationsx.setNewData(forkyBlck.message.body.attestations.asSeq())
      self.depositsx.setNewData(forkyBlck.message.body.deposits.mapIt(it.toDepositInfo()))
      self.attester_slashingsx.setNewData(forkyBlck.message.body.attester_slashings.asSeq())
      self.proposer_slashingsx.setNewData(forkyBlck.message.body.proposer_slashings.asSeq())
      self.voluntary_exitsx.setNewData(forkyBlck.message.body.voluntary_exits.asSeq())

  proc slot*(self: BlockModel): int {.slot.} = getForkedBlockField(self.blck, slot).int
  QtProperty[int] slot: read = slot

  proc time*(self: BlockModel): string {.slot.} =
    let t = self.genesis_time + getForkedBlockField(self.blck, slot) * SECONDS_PER_SLOT
    $fromUnix(t.int64).utc
  QtProperty[string] time: read = time

  proc root*(self: BlockModel): string {.slot.} = toDisplayHex(self.blck.root.data)
  QtProperty[string] root: read = root

  proc proposer_index*(self: BlockModel): int {.slot.} = getForkedBlockField(self.blck, proposer_index).int
  QtProperty[int] proposer_index: read = proposer_index

  proc parent_root*(self: BlockModel): string {.slot.} = toBlockLink(getForkedBlockField(self.blck, parent_root))
  QtProperty[string] parent_root: read = parent_root

  proc state_root*(self: BlockModel): string {.slot.} = toDisplayHex(getForkedBlockField(self.blck, state_root).data)
  QtProperty[string] state_root: read = state_root

  proc randao_reveal*(self: BlockModel): string {.slot.} = toDisplayHex(getForkedBodyField(self.blck, randao_reveal))
  QtProperty[string] randao_reveal: read = randao_reveal

  proc eth1_data*(self: BlockModel): string {.slot.} = RestJson.encode(getForkedBodyField(self.blck, eth1_data), pretty=true)
  QtProperty[string] eth1_data: read = eth1_data

  proc graffiti*(self: BlockModel): string {.slot.} = $getForkedBodyField(self.blck, graffiti)
  QtProperty[string] graffiti: read = graffiti

  proc proposer_slashings*(self: BlockModel): QVariant {.slot.} = newQVariant(self.proposer_slashingsx)
  QtProperty[QVariant] proposer_slashings: read = proposer_slashings

  proc attester_slashings*(self: BlockModel): QVariant {.slot.} = newQVariant(self.attester_slashingsx)
  QtProperty[QVariant] attester_slashings: read = attester_slashings

  proc attestations*(self: BlockModel): QVariant {.slot.} = newQVariant(self.attestationsx)
  QtProperty[QVariant] attestations: read = attestations

  proc deposits*(self: BlockModel): QVariant {.slot.} = newQVariant(self.depositsx)
  QtProperty[QVariant] deposits: read = deposits

  proc voluntary_exits*(self: BlockModel): QVariant {.slot.} = newQVariant(self.voluntary_exitsx)
  QtProperty[QVariant] voluntary_exits: read = voluntary_exits

  proc signature*(self: BlockModel): string {.slot.} = toDisplayHex(self.blck.signature)
  QtProperty[string] signature: read = signature
