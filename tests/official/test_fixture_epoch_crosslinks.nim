# beacon_chain
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  os, unittest, strutils,
  # Beacon chain internals
  ../../beacon_chain/spec/[datatypes, validator, state_transition_epoch],
  # Test utilities
  ../testutil,
  ./fixtures_utils

const CrosslinksDir = SszTestsDir/const_preset/"phase0"/"epoch_processing"/"crosslinks"/"pyspec_tests"

# TODO: parsing SSZ
#       can overwrite the calling function stack
#       https://github.com/status-im/nim-beacon-chain/issues/369
#
# We store the state on the heap to avoid that

proc crosslinkTest(testDir: string) =
  let name = testDir.rsplit(DirSep, 1)[1]
  test "Crosslinks - " & name & preset():
    var stateRef, postRef: ref BeaconState
    new stateRef
    new postRef
    stateRef[] = parseTest(testDir/"pre.ssz", SSZ, BeaconState)
    postRef[] = parseTest(testDir/"post.ssz", SSZ, BeaconState)

    var cache = get_empty_per_epoch_cache()
    process_crosslinks(stateRef[], cache)

    check: stateRef.hash_tree_root() == postRef.hash_tree_root()

suite "Official - Epoch Processing - Crosslinks [Preset: " & preset():
  for dir in walkDirRec(CrosslinksDir, yieldFilter = {pcDir}):
    crosslinkTest(dir)
