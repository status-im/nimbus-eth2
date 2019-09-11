# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import # Unit test
  ./test_attestation_pool,
  ./test_beacon_chain_db,
  ./test_beacon_node,
  ./test_block_pool,
  ./test_helpers,
  ./test_interop,
  ./test_ssz,
  ./test_sync_protocol,
  # ./test_validator # Empty!
  ./test_zero_signature

  # Outdated (?) - crashes https://github.com/status-im/nim-beacon-chain/pull/406
  # ./test_beaconstate,
  # Outdated (?) - crashes
  #   - https://github.com/status-im/nim-beacon-chain/pull/406
  #   - https://github.com/status-im/nim-beacon-chain/pull/403
  #     - PR 403, 399, 395
  # ./test_state_transition,


import # Refactor state transition unit tests
  ./spec_block_processing/test_genesis,
  ./spec_block_processing/test_process_deposits,
  ./spec_block_processing/test_process_attestation,
  ./spec_epoch_processing/test_process_crosslinks

import # Official fixtures that don't require SSZ parsing of invalid BLS signatures
       # https://github.com/status-im/nim-beacon-chain/issues/374
  ./official/test_fixture_shuffling,
  ./official/test_fixture_bls,
  ./official/test_fixture_ssz_uint
