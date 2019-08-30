# beacon_chain
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  os, unittest,
  # Beacon chain internals
  ../../beacon_chain/spec/[datatypes, validator, state_transition_epoch],
  # Test utilities
  ../testutil,
  ./fixtures_utils

const CrosslinksDir = SszTestsDir/const_preset/"phase0"/"epoch_processing"/"crosslinks"/"pyspec_tests"

# TODO: parsing pre and post
#       in the same scope crashes Nim with preset: mainnet
#       https://github.com/status-im/nim-beacon-chain/issues/369
proc parsePre(): BeaconState =
  parseTest(CrosslinksDir/"no_attestations"/"pre.ssz", SSZ, BeaconState)

proc parsePost(): BeaconState =
  parseTest(CrosslinksDir/"no_attestations"/"post.ssz", SSZ, BeaconState)

suite "Official - Epoch Processing - Crosslinks [Preset: " & preset():
  test "Crosslinks - no attestation" & preset():
    var state = parsePre()
    let post = parsePost()

    var cache = get_empty_per_epoch_cache()
    process_crosslinks(state, cache)

    check: state.hash_tree_root() == post.hash_tree_root()
