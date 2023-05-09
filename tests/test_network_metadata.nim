import
  unittest2,
  ../beacon_chain/networking/network_metadata,
  ../beacon_chain/spec/forks

{.used.}

template checkRoot(name, root) =
  let
    metadata = getMetadataForNetwork(name)
    cfg = metadata.cfg
    state = newClone(readSszForkedHashedBeaconState(
      metadata.cfg, metadata.genesisData))

  check:
    $getStateRoot(state[]) == root

suite "Network metadata":
  test "Mainnet":
    checkRoot(
      "mainnet",
      "7e76880eb67bbdc86250aa578958e9d0675e64e714337855204fb5abaaf82c2b")

  test "goerli":
    checkRoot(
      "goerli",
      "895390e92edc03df7096e9f51e51896e8dbe6e7e838180dadbfd869fdd77a659")

  test "sepolia":
    checkRoot(
      "sepolia",
      "fb9afe32150fa39f4b346be2519a67e2a4f5efcd50a1dc192c3f6b3d013d2798")
