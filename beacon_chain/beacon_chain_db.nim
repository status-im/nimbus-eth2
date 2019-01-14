import
  os, json, tables, options,
  chronicles, json_serialization, eth_common/eth_types_json_serialization,
  spec/[datatypes, digest, crypto],
  eth_trie/db, ssz

type
  BeaconChainDB* = ref object
    backend: TrieDatabaseRef

  BeaconStateRef* = ref BeaconState

  DbKey = object
    data: array[33, byte]
    dataEndPos: uint8

  DbKeyKind = enum
    kLastFinalizedState
    kHashToBlock


template toOpenArray*(k: DbKey): openarray[byte] =
  k.data.toOpenArray(0, int(k.dataEndPos))

proc lastFinalizedStateKey(): DbKey =
  result.data[0] = byte ord(kLastFinalizedState)
  result.dataEndPos = 0

proc hashToBlockKey(h: Eth2Digest): DbKey =
  result.data[0] = byte ord(kHashToBlock)
  result.data[1 .. ^1] = h.data
  result.dataEndPos = 32

proc init*(T: type BeaconChainDB, backend: TrieDatabaseRef): BeaconChainDB =
  new result
  result.backend = backend

proc lastFinalizedState*(db: BeaconChainDB): BeaconStateRef =
  try:
    let res = db.backend.get(lastFinalizedStateKey().toOpenArray)
    if res.len != 0:
      result.new
      result[] = ssz.deserialize(res, BeaconState).get
  except:
    error "Failed to load the latest finalized state",
          err = getCurrentExceptionMsg()
    return nil

proc persistBlock*(db: BeaconChainDB, s: BeaconState, b: BeaconBlock) =
  db.backend.put(lastFinalizedStateKey().toOpenArray, ssz.serialize(s))

proc getBlock*(db: BeaconChainDB, hash: Eth2Digest, output: var BeaconBlock): bool =
  let res = db.backend.get(hashToBlockKey(hash).toOpenArray)
  if res.len != 0:
    output = ssz.deserialize(res, BeaconBlock).get
    true
  else:
    false

proc getBlock*(db: BeaconChainDB, hash: Eth2Digest): BeaconBlock =
  if not db.getBlock(hash, result):
    raise newException(Exception, "Block not found")

