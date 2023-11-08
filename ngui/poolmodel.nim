import NimQml

import
  std/[sequtils, times],
  ../beacon_chain/spec/eth2_apis/rest_beacon_client,
  ./attestationlist, ./attesterslashinglist, proposerslashinglist, voluntaryexitlist, ./utils

template xxx(body): untyped =
  try:
    body.data.data
  except CatchableError as exc:
    debugEcho exc.msg
    @[]

QtObject:
  type
    PoolModel* = ref object of QObject
      client: RestClientRef
      attestationsx: AttestationList
      attesterSlashingsx: AttesterSlashingList
      proposerSlashingsx: ProposerSlashingList
      voluntaryExitsx: VoluntaryExitList

  proc delete*(self: PoolModel) =
    self.QObject.delete

  proc setup*(self: PoolModel) =
    self.QObject.setup

  proc newPoolModel*(client: RestClientRef): PoolModel =
    let res = PoolModel(
      client: client,
      attestationsx: newAttestationList(@[]),
      attesterSlashingsx: newAttesterSlashingList(@[]),
      proposerSlashingsx: newProposerSlashingList(@[]),
      voluntaryExitsx: newVoluntaryExitList(@[]),
    )
    res.setup()
    res

  proc attestations*(self: PoolModel): QVariant {.slot.} = newQVariant(self.attestationsx)
  QtProperty[QVariant] attestations: read = attestations

  proc attesterSlashings*(self: PoolModel): QVariant {.slot.} = newQVariant(self.attesterSlashingsx)
  QtProperty[QVariant] attesterSlashings: read = attesterSlashings

  proc proposerSlashings*(self: PoolModel): QVariant {.slot.} = newQVariant(self.proposerSlashingsx)
  QtProperty[QVariant] proposerSlashings: read = proposerSlashings

  proc voluntaryExits*(self: PoolModel): QVariant {.slot.} = newQVariant(self.voluntaryExitsx)
  QtProperty[QVariant] voluntaryExits: read = voluntaryExits

  proc updateAttestations*(self: PoolModel) {.slot.} =
    self.attestationsx.setNewData(xxx(waitFor self.client.getPoolAttestations(none(Slot), none(CommitteeIndex))))

  proc updateAttesterSlashings*(self: PoolModel) {.slot.} =
    self.attesterSlashingsx.setNewData(xxx(waitFor self.client.getPoolAttesterSlashings()))

  proc updateProposerSlashings*(self: PoolModel) {.slot.} =
    self.proposerSlashingsx.setNewData(xxx(waitFor self.client.getPoolProposerSlashings()))

  proc updateVoluntaryExits*(self: PoolModel) {.slot.} =
    self.voluntaryExitsx.setNewData(xxx(waitFor self.client.getPoolVoluntaryExits()))

  proc update*(self: PoolModel) {.slot.} =
    self.updateAttestations()
    self.updateAttesterSlashings()
    self.updateProposerSlashings()
    self.updateVoluntaryExits()
