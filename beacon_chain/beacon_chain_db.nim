import
  os, json, tables, options,
  chronicles, json_serialization, eth_common/eth_types_json_serialization,
  spec/[datatypes, digest, crypto],
  eth_trie/db, ssz

const STATE_STORAGE_PERIOD = 1000 # Save states once per this number of slots. TODO: Find a good number.

type
  BeaconChainDB* = ref object
    backend: TrieDatabaseRef

  DbKey = object
    data: array[33, byte]
    dataEndPos: uint8

  DbKeyKind = enum
    kLastFinalizedState
    kHashToBlock
    kSlotToBlockHash
    kSlotToState
    kHashToValidatorRegistryChangeLog


template toOpenArray*(k: DbKey): openarray[byte] =
  k.data.toOpenArray(0, int(k.dataEndPos))

proc lastFinalizedStateKey(): DbKey =
  result.data[0] = byte ord(kLastFinalizedState)
  result.dataEndPos = 0

proc hashToBlockKey(h: Eth2Digest): DbKey =
  result.data[0] = byte ord(kHashToBlock)
  result.data[1 .. ^1] = h.data
  result.dataEndPos = 32

proc slotToBlockHashKey(s: uint64): DbKey =
  result.data[0] = byte ord(kSlotToBlockHash)
  copyMem(addr result.data[1], unsafeAddr(s), sizeof(s))
  result.dataEndPos = uint8 sizeof(s)

proc slotToStateKey(s: uint64): DbKey =
  result.data[0] = byte ord(kSlotToState)
  copyMem(addr result.data[1], unsafeAddr(s), sizeof(s))
  result.dataEndPos = uint8 sizeof(s)

proc hashToValidatorRegistryChangeLogKey(deltaChainTip: Eth2Digest): DbKey =
  result.data[0] = byte ord(kHashToValidatorRegistryChangeLog)
  result.data[1 .. ^1] = deltaChainTip.data
  result.dataEndPos = 32

proc init*(T: type BeaconChainDB, backend: TrieDatabaseRef): BeaconChainDB =
  new result
  result.backend = backend

proc lastFinalizedState*(db: BeaconChainDB): BeaconState =
  let res = db.backend.get(lastFinalizedStateKey().toOpenArray)
  if res.len == 0:
    raise newException(Exception, "Internal error: Database has no finalized state")
  ssz.deserialize(res, BeaconState).get

proc isInitialized*(db: BeaconChainDB): bool =
  db.backend.get(lastFinalizedStateKey().toOpenArray).len != 0

proc persistState*(db: BeaconChainDB, s: BeaconState) =
  if s.slot != GENESIS_SLOT:
    # TODO: Verify incoming state slot is higher than lastFinalizedState one
    discard
  else:
    # Make sure we have no states
    assert(not db.isInitialized)

  var prevState: BeaconState
  if s.slot != GENESIS_SLOT:
    prevState = db.lastFinalizedState()
    if prevState.validator_registry_delta_chain_tip != s.validator_registry_delta_chain_tip:
      # Validator registry has changed in the incoming state.
      # TODO: Save the changelog.
      discard

  let serializedState = ssz.serialize(s)
  db.backend.put(lastFinalizedStateKey().toOpenArray, serializedState)

  if s.slot mod STATE_STORAGE_PERIOD == 0:
    # Save slot to state mapping
    db.backend.put(slotToStateKey(s.slot).toOpenArray, serializedState)

proc persistBlock*(db: BeaconChainDB, s: BeaconState, b: BeaconBlock) =
  var prevState = db.lastFinalizedState()

  db.persistState(s)

  let blockHash = b.hash_tree_root_final
  db.backend.put(hashToBlockKey(blockHash).toOpenArray, ssz.serialize(b))
  db.backend.put(slotToBlockHashKey(b.slot).toOpenArray, blockHash.data)

# proc getValidatorChangeLog*(deltaChainTip: Eth2Digest)

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

