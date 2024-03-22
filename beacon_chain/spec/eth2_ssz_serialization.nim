import
  ssz_serialization,
  ./ssz_codec,
  ./eth2_merkleization

export ssz_codec, ssz_serialization, eth2_merkleization

proc readAndUpdateRoot(
    data: openArray[byte], val: var auto, updateRoot = true
) {.raises: [SszError].} =
  readSszValue(data, val)
  if updateRoot:
    val.root = hash_tree_root(val.message)

template readSszBytes*(
    data: openArray[byte], val: var auto, updateRoot: bool) =
  readSszValue(data, val)

func readSszBytes(
    T: type, data: openArray[byte], updateRoot = true
): T {.raises: [SszError].} =
  var res: T
  readSszBytes(data, res, updateRoot)
  res

proc fromSszBytes*(
    T: type HashedValidatorPubKey, bytes: openArray[byte]
): T {.raises: [SszError].} =
  let
    key = ValidatorPubKey.fromSszBytes(bytes)

  HashedValidatorPubKey.init(key)
