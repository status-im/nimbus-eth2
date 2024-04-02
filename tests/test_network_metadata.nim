# beacon_chain
# Copyright (c) 2023-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

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
      metadata.cfg, metadata.genesis.bakedBytes))

  check:
    $getStateRoot(state[]) == root

suite "Network metadata":
  test "mainnet":
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
