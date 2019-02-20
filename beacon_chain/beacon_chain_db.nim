import
  os, json, tables, options,
  chronicles, json_serialization, eth/common/eth_types_json_serialization,
  spec/[datatypes, digest, crypto],
  eth/trie/db, ssz


type
  BeaconChainDB* = ref object
    backend: TrieDatabaseRef

  DbKeyKind = enum
    kLastFinalizedState
    kHashToBlock
    kSlotToBlockHash
    kSlotToState
    kHashToValidatorRegistryChangeLog

proc lastFinalizedStateKey(): array[1, byte] =
  result[0] = byte ord(kLastFinalizedState)

proc hashToBlockKey(h: Eth2Digest): array[32 + 1, byte] =
  result[0] = byte ord(kHashToBlock)
  result[1 .. ^1] = h.data

proc slotToBlockHashKey(s: Slot): array[sizeof(Slot) + 1, byte] =
  result[0] = byte ord(kSlotToBlockHash)
  copyMem(addr result[1], unsafeAddr(s), sizeof(s))

proc slotToStateKey(s: Slot): array[sizeof(Slot) + 1, byte] =
  result[0] = byte ord(kSlotToState)
  copyMem(addr result[1], unsafeAddr(s), sizeof(s))

proc hashToValidatorRegistryChangeLogKey(deltaChainTip: Eth2Digest): array[32 + 1, byte] =
  result[0] = byte ord(kHashToValidatorRegistryChangeLog)
  result[1 .. ^1] = deltaChainTip.data

proc init*(T: type BeaconChainDB, backend: TrieDatabaseRef): BeaconChainDB =
  new result
  result.backend = backend

proc lastFinalizedState*(db: BeaconChainDB): BeaconState =
  let res = db.backend.get(lastFinalizedStateKey())
  if res.len == 0:
    raise newException(Exception, "Internal error: Database has no finalized state")
  ssz.deserialize(res, BeaconState).get

proc isInitialized*(db: BeaconChainDB): bool =
  db.backend.get(lastFinalizedStateKey()).len != 0

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
  # TODO: Consider mapping slots and last pointer to state hashes to avoid
  # duplicating in the db
  db.backend.put(lastFinalizedStateKey(), serializedState)
  db.backend.put(slotToStateKey(s.slot), serializedState)

proc persistBlock*(db: BeaconChainDB, b: BeaconBlock) =
  let blockHash = b.hash_tree_root_final
  db.backend.put(hashToBlockKey(blockHash), ssz.serialize(b))
  db.backend.put(slotToBlockHashKey(b.slot), blockHash.data)

# proc getValidatorChangeLog*(deltaChainTip: Eth2Digest)

proc getBlock*(db: BeaconChainDB, hash: Eth2Digest, output: var BeaconBlock): bool =
  let res = db.backend.get(hashToBlockKey(hash))
  if res.len != 0:
    output = ssz.deserialize(res, BeaconBlock).get
    true
  else:
    false

proc getBlock*(db: BeaconChainDB, hash: Eth2Digest): BeaconBlock =
  if not db.getBlock(hash, result):
    raise newException(Exception, "Block not found")

