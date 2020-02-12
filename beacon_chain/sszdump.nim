import
  os,
  ssz,
  serialization,
  beacon_node_types,
  ./spec/[crypto, datatypes, digest]

proc dump*(dir: string, v: AttestationData, validator: ValidatorPubKey) =
  SSZ.saveFile(
    dir / "att-" & $v.slot & "-" &
    $v.index & "-" & validator.shortLog &
    ".ssz", v)

proc dump*(dir: string, v: SignedBeaconBlock, blck: BlockRef) =
  SSZ.saveFile(
    dir / "block-" & $v.message.slot & "-" &
    shortLog(blck.root) & ".ssz", v)

proc dump*(dir: string, v: HashedBeaconState, blck: BlockRef) =
  SSZ.saveFile(
    dir / "state-" & $v.data.slot & "-" &
    shortLog(blck.root) & "-"  & shortLog(v.root) & ".ssz",
    v.data)

