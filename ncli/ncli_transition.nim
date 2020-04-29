import
  confutils, chronicles,
  ../beacon_chain/spec/[crypto, datatypes],
  ../beacon_chain/[extras, state_transition, ssz]

cli do(pre: string, blck: string, post: string, verifyStateRoot = false):
  let
    stateY = (ref HashedBeaconState)(
      data: SSZ.loadFile(pre, BeaconState),
    )
    blckX = SSZ.loadFile(blck, SignedBeaconBlock)
    flags = if verifyStateRoot: {skipStateRootValidation} else: {}

  stateY.root = hash_tree_root(stateY.data)

  if not state_transition(stateY[], blckX, flags, noRollback):
    error "State transition failed"
  else:
    SSZ.saveFile(post, stateY.data)
