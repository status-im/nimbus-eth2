# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# All tests except scenarios, which as compiled separately for mainnet and minimal

import
  ./testutil

import # Unit test
  ./test_action_tracker,
  ./test_attestation_pool,
  ./test_beacon_chain_db,
  ./test_beacon_time,
  ./test_blockchain_dag,
  ./test_block_dag,
  ./test_block_processor,
  ./test_block_quarantine,
  ./test_conf,
  ./test_datatypes,
  ./test_discovery,
  ./test_engine_api_conversions,
  ./test_engine_authentication,
  ./test_envelope_quarantine,
  ./test_el_manager,
  ./test_el_conf,
  ./test_eth2_rest_serialization,
  ./test_eth2_ssz_serialization,
  ./test_execution_payload_pool,
  ./test_forks,
  ./test_gossip_transition,
  ./test_gossip_validation,
  ./test_helpers,
  ./test_honest_validator,
  ./test_keystore,
  ./test_keystore_management,
  ./test_key_splitting,
  ./test_light_client_processor,
  ./test_light_client,
  ./test_network_metadata,
  ./test_partial_column_quarantine,
  ./test_payload_attestation_pool,
  ./test_peer_pool,
  ./test_peerdas_helpers,
  ./test_remote_keystore,
  ./test_spec,
  ./test_spec_signatures,
  ./test_statediff,
  ./test_sync_committee_pool,
  ./test_sync_manager,
  ./test_toblindedblock,
  ./test_validator_bucket_sort,
  ./test_validator_change_pool,
  ./test_validator_pool,
  ./test_zero_signature,
  ./test_signing_node,
  ./consensus_spec/all_tests as consensus_all_tests,
  ./slashing_protection/test_fixtures,
  ./slashing_protection/test_slashing_protection_db,
  ./test_validator_client,
  ./test_block_payloads,
  ./test_beacon_chain_file,
  ./test_mev_calls,
  ./test_column_map,
  ./test_quarantine,
  ./test_keymanager_api   # currently has to run after test_remote_keystore

summarizeLongTests("AllTests")
