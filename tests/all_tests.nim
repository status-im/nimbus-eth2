# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import ./testutil

import # Official constants
  ./official/test_fixture_const_sanity_check

import # Unit test
  ./test_attestation_pool,
  ./test_beacon_chain_db,
  ./test_beacon_node,
  ./test_beaconstate,
  ./test_bitseqs,
  ./test_block_pool,
  ./test_helpers,
  ./test_keystore,
  ./test_mocking,
  ./test_mainchain_monitor,
  ./test_ssz,
  ./test_state_transition,
  ./test_sync_protocol,
  ./test_zero_signature,
  ./test_peer_pool,
  ./test_sync_manager,
  ./test_honest_validator,
  ./test_interop,
  ./fork_choice/tests_fork_choice

import # Refactor state transition unit tests
  # In mainnet these take 2 minutes and are empty TODOs
  ./spec_block_processing/test_process_deposits,
  ./spec_block_processing/test_process_attestation,
  ./spec_epoch_processing/test_process_justification_and_finalization

# TODO: json tests were removed

# import # Official fixtures that don't require SSZ parsing of invalid BLS signatures
#        # https://github.com/status-im/nim-beacon-chain/issues/374
#   ./official/test_fixture_shuffling,
#   ./official/test_fixture_bls

summarizeLongTests("AllTests")
