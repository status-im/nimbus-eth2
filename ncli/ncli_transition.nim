import
  confutils, chronicles,
  ../beacon_chain/spec/[crypto, datatypes],
  ../beacon_chain/[extras, state_transition, ssz]

cli do(pre: string, blck: string, post: string, verifyStateRoot = false):
  let
    stateX = SSZ.loadFile(pre, BeaconStateRef)
    blckX = SSZ.loadFile(blck, SignedBeaconBlock)
    flags = if verifyStateRoot: {skipStateRootValidation} else: {}

  var stateY = HashedBeaconState(data: stateX, root: hash_tree_root(stateX))
  if not state_transition(stateY, blckX, flags):
    error "State transition failed"

  SSZ.saveFile(post, stateY.data)
