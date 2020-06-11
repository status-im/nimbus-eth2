import
  os, strformat,
  ssz/ssz_serialization,
  beacon_node_types,
  ./spec/[crypto, datatypes, digest]

proc dump*(dir: string, v: AttestationData, validator: ValidatorPubKey) =
  SSZ.saveFile(dir / &"att-{v.slot}-{v.index}-{shortLog(validator)}.ssz", v)

proc dump*(dir: string, v: SignedBeaconBlock, root: Eth2Digest) =
  SSZ.saveFile(dir / &"block-{v.message.slot}-{shortLog(root)}.ssz", v)

proc dump*(dir: string, v: SignedBeaconBlock, blck: BlockRef) =
  dump(dir, v, blck.root)

proc dump*(dir: string, v: HashedBeaconState, blck: BlockRef) =
  SSZ.saveFile(
    dir / &"state-{v.data.slot}-{shortLog(blck.root)}-{shortLog(v.root)}.ssz",
    v.data)

proc dump*(dir: string, v: HashedBeaconState) =
  SSZ.saveFile(
    dir / &"state-{v.data.slot}-{shortLog(v.root)}.ssz",
    v.data)
