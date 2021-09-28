# beacon_chain
# Copyright (c) 2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# All non-pure SSZ tests that require the -d:ssz_testing
# to ignore invalid BLS signature in EF test vectors
# https://github.com/status-im/nimbus-eth2/issues/374

{.used.}

import
  ./test_fixture_operations_attestations,
  ./test_fixture_operations_attester_slashings,
  ./test_fixture_operations_block_header,
  ./test_fixture_operations_deposits,
  ./test_fixture_operations_execution_payload,
  ./test_fixture_operations_proposer_slashings,
  ./test_fixture_operations_voluntary_exit,
  ./test_fixture_sanity_blocks,
  ./test_fixture_sanity_slots,
  ./test_fixture_ssz_consensus_objects,
  ./test_fixture_state_transition_epoch
