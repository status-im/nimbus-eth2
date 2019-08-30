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
  ../../beacon_chain/spec/[beaconstate, datatypes, validator, helpers, state_transition_epoch],
  # Test utilities
  ../testutil,
  ./fixtures_utils

const CrosslinksDir = SszTestsDir/const_preset/"phase0"/"epoch_processing"/"crosslinks"/"pyspec_tests"

suite "Official - Epoch Processing - Crosslinks [Preset: " & preset():
  test "Crosslinks - no attestation" & preset():
    let
      preState = parseTest(CrosslinksDir/"no_attestations"/"pre.ssz", SSZ, BeaconState)
      postState = parseTest(CrosslinksDir/"no_attestations"/"post.ssz", SSZ, BeaconState)
