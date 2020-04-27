import
  confutils, chronicles,
  ../beacon_chain/spec/[crypto, datatypes],
  ../beacon_chain/[extras, state_transition, ssz]

cli do(pre: string, blck: string, post: string, verifyStateRoot = false):

  let
    stateY = (ref HashedBeaconState)()
    blckX = SSZ.loadFile(blck, SignedBeaconBlock)
    flags = if verifyStateRoot: {skipStateRootValidation} else: {}

  stateY.data = SSZ.loadFile(pre, BeaconState)
  stateY.root = hash_tree_root(stateY.data)

  if not state_transition(stateY[], blckX, flags, noRollback):
    error "State transition failed"
  else:
    SSZ.saveFile(post, stateY.data)
