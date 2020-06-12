{.push raises: [Defect].}

import
  os, strformat, chronicles,
  ssz/ssz_serialization,
  beacon_node_types,
  ./spec/[crypto, datatypes, digest]

# Dump errors are generally not fatal where used currently - the code calling
# these functions, like most code, is not exception safe
template logErrors(body: untyped) =
  try:
    body
  except CatchableError as err:
    notice "Failed to write SSZ", dir, msg = err.msg

proc dump*(dir: string, v: AttestationData, validator: ValidatorPubKey) =
  logErrors:
    SSZ.saveFile(dir / &"att-{v.slot}-{v.index}-{shortLog(validator)}.ssz", v)

proc dump*(dir: string, v: SignedBeaconBlock, root: Eth2Digest) =
  logErrors:
    SSZ.saveFile(dir / &"block-{v.message.slot}-{shortLog(root)}.ssz", v)

proc dump*(dir: string, v: SignedBeaconBlock, blck: BlockRef) =
  dump(dir, v, blck.root)

proc dump*(dir: string, v: HashedBeaconState, blck: BlockRef) =
  logErrors:
    SSZ.saveFile(
      dir / &"state-{v.data.slot}-{shortLog(blck.root)}-{shortLog(v.root)}.ssz",
      v.data)

proc dump*(dir: string, v: HashedBeaconState) =
  logErrors:
    SSZ.saveFile(
      dir / &"state-{v.data.slot}-{shortLog(v.root)}.ssz",
      v.data)
