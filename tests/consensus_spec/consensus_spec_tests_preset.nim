# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import ../testutil

# Tests that depend on `mainnet` vs `minimal` compile-time configuration

import
  ./phase0/all_phase0_fixtures,
  ./altair/all_altair_fixtures,
  ./bellatrix/all_bellatrix_fixtures,
  ./capella/all_capella_fixtures,
  ./deneb/all_deneb_fixtures,
  ./test_fixture_fork,
  ./test_fixture_fork_choice,
  ./test_fixture_light_client_single_merkle_proof,
  ./test_fixture_light_client_sync,
  ./test_fixture_light_client_update_ranking,
  ./test_fixture_merkle_proof,
  ./test_fixture_sanity_blocks,
  ./test_fixture_sanity_slots,
  ./test_fixture_transition

summarizeLongTests("ConsensusSpecPreset")
