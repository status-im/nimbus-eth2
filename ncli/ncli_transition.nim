import
  confutils, chronicles,
  ../beacon_chain/spec/[crypto, datatypes, state_transition],
  ../beacon_chain/extras,
  ../beacon_chain/ssz/[merkleization, ssz_serialization]

cli do(pre: string, blck: string, post: string, verifyStateRoot = true):
  let
    stateY = (ref HashedBeaconState)(
      data: SSZ.loadFile(pre, BeaconState),
    )
    blckX = SSZ.loadFile(blck, SignedBeaconBlock)
    flags = if not verifyStateRoot: {skipStateRootValidation} else: {}

  stateY.root = hash_tree_root(stateY.data)

  if not state_transition(stateY[], blckX, flags, noRollback):
    error "State transition failed"
    quit 1
  else:
    SSZ.saveFile(post, stateY.data)
