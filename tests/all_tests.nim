# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# All tests except scenarios, which as compiled separately for mainnet and minimal

import
  ./testutil

import # Unit test
  ./test_action_tracker,
  ./test_attestation_pool,
  ./test_beacon_chain_db,
  ./test_beacon_time,
  ./test_block_dag,
  ./test_block_processor,
  ./test_block_quarantine,
  ./test_conf,
  ./test_datatypes,
  ./test_deposit_snapshots,
  ./test_discovery,
  ./test_engine_authentication,
  ./test_el_manager,
  ./test_el_conf,
  ./test_eth2_ssz_serialization,
  ./test_exit_pool,
  ./test_forks,
  ./test_gossip_transition,
  ./test_gossip_validation,
  ./test_helpers,
  ./test_honest_validator,
  ./test_key_splitting,
  ./test_light_client_processor,
  ./test_light_client,
  ./test_message_signatures,
  ./test_network_metadata,
  ./test_peer_pool,
  ./test_remote_keystore,
  ./test_rest_json_serialization,
  ./test_serialization,
  ./test_spec,
  ./test_statediff,
  ./test_sync_committee_pool,
  ./test_sync_manager,
  ./test_validator_pool,
  ./test_zero_signature,
  ./test_signing_node,
  ./consensus_spec/all_tests as consensus_all_tests,
  ./slashing_protection/test_fixtures,
  ./slashing_protection/test_slashing_protection_db,
  ./test_validator_client

when not defined(i386):
  # Avoids "Out of memory" CI failures
  import
    ./test_blockchain_dag,
    ./test_keystore,
    ./test_keystore_management

  when not defined(windows):
    import ./test_keymanager_api

summarizeLongTests("AllTests")
