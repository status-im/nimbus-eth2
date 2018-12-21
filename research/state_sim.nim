import
  cligen,
  json, strformat,
  options, sequtils,
  ../tests/[testutil],
  ../beacon_chain/spec/[beaconstate, crypto, datatypes, digest, helpers],
  ../beacon_chain/[extras, ssz, state_transition]

proc `%`(v: uint64): JsonNode = newJInt(v.BiggestInt)
proc `%`(v: Eth2Digest): JsonNode = newJString($v)

proc writeJson*(prefix, slot, v: auto) =
  var f: File
  defer: close(f)
  discard open(f, fmt"{prefix:04}-{slot:08}.json", fmWrite)
  write(f, pretty(%*(v)))

proc transition(
    slots = 1945,
    validators = EPOCH_LENGTH, # One per shard is minimum
    json_interval = EPOCH_LENGTH,
    prefix = 0) =
  let
    genesisState = get_initial_beacon_state(
      makeInitialDeposits(validators), 0, Eth2Digest())
    genesisBlock = makeGenesisBlock(genesisState)

  var
    state = genesisState
    latest_block_root = hash_tree_root_final(genesisBlock)

  for i in 0..<slots:
    if state.slot mod json_interval.uint64 == 0:
      writeJson(prefix, state.slot, state)
      write(stdout, ":")
    else:
      write(stdout, ".")

    latest_block_root = hash_tree_root_final(
      addBlock(state, latest_block_root, BeaconBlockBody()))

    flushFile(stdout)

  echo "done!"

dispatch(transition)
