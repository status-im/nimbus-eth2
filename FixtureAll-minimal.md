FixtureAll-minimal
===
## 
```diff
+ Rewards - all_balances_too_low_for_reward [Preset: minimal]                                OK
+ Rewards - duplicate_attestations_at_later_slots [Preset: minimal]                          OK
+ Rewards - empty [Preset: minimal]                                                          OK
+ Rewards - empty_leak [Preset: minimal]                                                     OK
+ Rewards - full_all_correct [Preset: minimal]                                               OK
+ Rewards - full_but_partial_participation [Preset: minimal]                                 OK
+ Rewards - full_but_partial_participation_leak [Preset: minimal]                            OK
+ Rewards - full_correct_target_incorrect_head [Preset: minimal]                             OK
+ Rewards - full_correct_target_incorrect_head_leak [Preset: minimal]                        OK
+ Rewards - full_delay_max_slots [Preset: minimal]                                           OK
+ Rewards - full_delay_one_slot [Preset: minimal]                                            OK
+ Rewards - full_half_correct_target_incorrect_head [Preset: minimal]                        OK
+ Rewards - full_half_correct_target_incorrect_head_leak [Preset: minimal]                   OK
+ Rewards - full_half_incorrect_target_correct_head [Preset: minimal]                        OK
+ Rewards - full_half_incorrect_target_correct_head_leak [Preset: minimal]                   OK
+ Rewards - full_half_incorrect_target_incorrect_head [Preset: minimal]                      OK
+ Rewards - full_half_incorrect_target_incorrect_head_leak [Preset: minimal]                 OK
+ Rewards - full_leak [Preset: minimal]                                                      OK
+ Rewards - full_mixed_delay [Preset: minimal]                                               OK
+ Rewards - full_random_0 [Preset: minimal]                                                  OK
+ Rewards - full_random_1 [Preset: minimal]                                                  OK
+ Rewards - full_random_2 [Preset: minimal]                                                  OK
+ Rewards - full_random_3 [Preset: minimal]                                                  OK
+ Rewards - full_random_4 [Preset: minimal]                                                  OK
+ Rewards - full_random_leak [Preset: minimal]                                               OK
+ Rewards - full_random_low_balances_0 [Preset: minimal]                                     OK
+ Rewards - full_random_low_balances_1 [Preset: minimal]                                     OK
+ Rewards - full_random_misc_balances [Preset: minimal]                                      OK
+ Rewards - full_random_seven_epoch_leak [Preset: minimal]                                   OK
+ Rewards - full_random_ten_epoch_leak [Preset: minimal]                                     OK
+ Rewards - full_random_without_leak_0 [Preset: minimal]                                     OK
+ Rewards - full_random_without_leak_and_current_exit_0 [Preset: minimal]                    OK
+ Rewards - half_full [Preset: minimal]                                                      OK
+ Rewards - half_full_leak [Preset: minimal]                                                 OK
+ Rewards - one_attestation_one_correct [Preset: minimal]                                    OK
+ Rewards - one_attestation_one_correct_leak [Preset: minimal]                               OK
+ Rewards - proposer_not_in_attestations [Preset: minimal]                                   OK
+ Rewards - quarter_full [Preset: minimal]                                                   OK
+ Rewards - quarter_full_leak [Preset: minimal]                                              OK
+ Rewards - some_very_low_effective_balances_that_attested [Preset: minimal]                 OK
+ Rewards - some_very_low_effective_balances_that_attested_leak [Preset: minimal]            OK
+ Rewards - some_very_low_effective_balances_that_did_not_attest [Preset: minimal]           OK
+ Rewards - some_very_low_effective_balances_that_did_not_attest_leak [Preset: minimal]      OK
+ Rewards - with_exited_validators [Preset: minimal]                                         OK
+ Rewards - with_exited_validators_leak [Preset: minimal]                                    OK
+ Rewards - with_not_yet_activated_validators [Preset: minimal]                              OK
+ Rewards - with_not_yet_activated_validators_leak [Preset: minimal]                         OK
+ Rewards - with_slashed_validators [Preset: minimal]                                        OK
+ Rewards - with_slashed_validators_leak [Preset: minimal]                                   OK
+ Slots - double_empty_epoch                                                                 OK
+ Slots - empty_epoch                                                                        OK
+ Slots - over_epoch_boundary                                                                OK
+ Slots - slots_1                                                                            OK
+ Slots - slots_2                                                                            OK
+ [Invalid]  bad_merkle_proof                                                                OK
+ [Invalid]  wrong_deposit_for_deposit_count                                                 OK
+ [Invalid] Ethereum Foundation - Altair - Sanity - Blocks - double_same_proposer_slashings_ OK
+ [Invalid] Ethereum Foundation - Altair - Sanity - Blocks - double_similar_proposer_slashin OK
+ [Invalid] Ethereum Foundation - Altair - Sanity - Blocks - double_validator_exit_same_bloc OK
+ [Invalid] Ethereum Foundation - Altair - Sanity - Blocks - duplicate_attester_slashing [Pr OK
+ [Invalid] Ethereum Foundation - Altair - Sanity - Blocks - expected_deposit_in_block [Pres OK
+ [Invalid] Ethereum Foundation - Altair - Sanity - Blocks - invalid_block_sig [Preset: mini OK
+ [Invalid] Ethereum Foundation - Altair - Sanity - Blocks - invalid_proposer_index_sig_from OK
+ [Invalid] Ethereum Foundation - Altair - Sanity - Blocks - invalid_proposer_index_sig_from OK
+ [Invalid] Ethereum Foundation - Altair - Sanity - Blocks - invalid_state_root [Preset: min OK
+ [Invalid] Ethereum Foundation - Altair - Sanity - Blocks - parent_from_same_slot [Preset:  OK
+ [Invalid] Ethereum Foundation - Altair - Sanity - Blocks - prev_slot_block_transition [Pre OK
+ [Invalid] Ethereum Foundation - Altair - Sanity - Blocks - same_slot_block_transition [Pre OK
+ [Invalid] Ethereum Foundation - Altair - Sanity - Blocks - slash_and_exit_same_index [Pres OK
+ [Invalid] Ethereum Foundation - Altair - Sanity - Blocks - zero_block_sig [Preset: minimal OK
+ [Invalid] Ethereum Foundation - Phase 0 - Sanity - Blocks - double_same_proposer_slashings OK
+ [Invalid] Ethereum Foundation - Phase 0 - Sanity - Blocks - double_similar_proposer_slashi OK
+ [Invalid] Ethereum Foundation - Phase 0 - Sanity - Blocks - double_validator_exit_same_blo OK
+ [Invalid] Ethereum Foundation - Phase 0 - Sanity - Blocks - duplicate_attester_slashing [P OK
+ [Invalid] Ethereum Foundation - Phase 0 - Sanity - Blocks - expected_deposit_in_block [Pre OK
+ [Invalid] Ethereum Foundation - Phase 0 - Sanity - Blocks - invalid_block_sig [Preset: min OK
+ [Invalid] Ethereum Foundation - Phase 0 - Sanity - Blocks - invalid_proposer_index_sig_fro OK
+ [Invalid] Ethereum Foundation - Phase 0 - Sanity - Blocks - invalid_proposer_index_sig_fro OK
+ [Invalid] Ethereum Foundation - Phase 0 - Sanity - Blocks - invalid_state_root [Preset: mi OK
+ [Invalid] Ethereum Foundation - Phase 0 - Sanity - Blocks - parent_from_same_slot [Preset: OK
+ [Invalid] Ethereum Foundation - Phase 0 - Sanity - Blocks - prev_slot_block_transition [Pr OK
+ [Invalid] Ethereum Foundation - Phase 0 - Sanity - Blocks - proposal_for_genesis_slot [Pre OK
+ [Invalid] Ethereum Foundation - Phase 0 - Sanity - Blocks - same_slot_block_transition [Pr OK
+ [Invalid] Ethereum Foundation - Phase 0 - Sanity - Blocks - slash_and_exit_same_index [Pre OK
+ [Invalid] Ethereum Foundation - Phase 0 - Sanity - Blocks - zero_block_sig [Preset: minima OK
+ [Invalid] after_epoch_slots                                                                OK
+ [Invalid] all_empty_indices                                                                OK
+ [Invalid] att1_bad_extra_index                                                             OK
+ [Invalid] att1_bad_replaced_index                                                          OK
+ [Invalid] att1_duplicate_index_double_signed                                               OK
+ [Invalid] att1_duplicate_index_normal_signed                                               OK
+ [Invalid] att1_empty_indices                                                               OK
+ [Invalid] att1_high_index                                                                  OK
+ [Invalid] att2_bad_extra_index                                                             OK
+ [Invalid] att2_bad_replaced_index                                                          OK
+ [Invalid] att2_duplicate_index_double_signed                                               OK
+ [Invalid] att2_duplicate_index_normal_signed                                               OK
+ [Invalid] att2_empty_indices                                                               OK
+ [Invalid] att2_high_index                                                                  OK
+ [Invalid] bad_source_root                                                                  OK
+ [Invalid] before_inclusion_delay                                                           OK
+ [Invalid] correct_after_epoch_delay                                                        OK
+ [Invalid] empty_participants_seemingly_valid_sig                                           OK
+ [Invalid] empty_participants_zeroes_sig                                                    OK
+ [Invalid] epochs_are_different                                                             OK
+ [Invalid] future_target_epoch                                                              OK
+ [Invalid] headers_are_same_sigs_are_different                                              OK
+ [Invalid] headers_are_same_sigs_are_same                                                   OK
+ [Invalid] incorrect_head_after_epoch_delay                                                 OK
+ [Invalid] incorrect_head_and_target_after_epoch_delay                                      OK
+ [Invalid] incorrect_target_after_epoch_delay                                               OK
+ [Invalid] invalid_attestation_signature                                                    OK
+ [Invalid] invalid_current_source_root                                                      OK
+ [Invalid] invalid_different_proposer_indices                                               OK
+ [Invalid] invalid_index                                                                    OK
+ [Invalid] invalid_multiple_blocks_single_slot                                              OK
+ [Invalid] invalid_parent_root                                                              OK
+ [Invalid] invalid_proposer_index                                                           OK
+ [Invalid] invalid_sig_1                                                                    OK
+ [Invalid] invalid_sig_1_and_2                                                              OK
+ [Invalid] invalid_sig_1_and_2_swap                                                         OK
+ [Invalid] invalid_sig_2                                                                    OK
+ [Invalid] invalid_signature                                                                OK
+ [Invalid] invalid_signature_bad_domain                                                     OK
+ [Invalid] invalid_signature_extra_participant                                              OK
+ [Invalid] invalid_signature_infinite_signature_with_all_participants                       OK
+ [Invalid] invalid_signature_infinite_signature_with_single_participant                     OK
+ [Invalid] invalid_signature_missing_participant                                            OK
+ [Invalid] invalid_signature_no_participants                                                OK
+ [Invalid] invalid_signature_past_block                                                     OK
+ [Invalid] invalid_signature_previous_committee                                             OK
+ [Invalid] invalid_slot_block_header                                                        OK
+ [Invalid] mismatched_target_and_slot                                                       OK
+ [Invalid] new_source_epoch                                                                 OK
+ [Invalid] no_double_or_surround                                                            OK
+ [Invalid] old_source_epoch                                                                 OK
+ [Invalid] old_target_epoch                                                                 OK
+ [Invalid] participants_already_slashed                                                     OK
+ [Invalid] proposer_is_not_activated                                                        OK
+ [Invalid] proposer_is_slashed                                                              OK
+ [Invalid] proposer_is_withdrawn                                                            OK
+ [Invalid] proposer_slashed                                                                 OK
+ [Invalid] same_data                                                                        OK
+ [Invalid] source_root_is_target_root                                                       OK
+ [Invalid] too_few_aggregation_bits                                                         OK
+ [Invalid] too_many_aggregation_bits                                                        OK
+ [Invalid] unsorted_att_1                                                                   OK
+ [Invalid] unsorted_att_2                                                                   OK
+ [Invalid] validator_already_exited                                                         OK
+ [Invalid] validator_exit_in_future                                                         OK
+ [Invalid] validator_invalid_validator_index                                                OK
+ [Invalid] validator_not_active                                                             OK
+ [Invalid] validator_not_active_long_enough                                                 OK
+ [Invalid] wrong_index_for_committee_signature                                              OK
+ [Invalid] wrong_index_for_slot_0                                                           OK
+ [Invalid] wrong_index_for_slot_1                                                           OK
+ [Valid]    invalid_sig_new_deposit                                                         OK
+ [Valid]    invalid_sig_other_version                                                       OK
+ [Valid]    invalid_sig_top_up                                                              OK
+ [Valid]    invalid_withdrawal_credentials_top_up                                           OK
+ [Valid]    new_deposit_eth1_withdrawal_credentials                                         OK
+ [Valid]    new_deposit_max                                                                 OK
+ [Valid]    new_deposit_non_versioned_withdrawal_credentials                                OK
+ [Valid]    new_deposit_over_max                                                            OK
+ [Valid]    new_deposit_under_max                                                           OK
+ [Valid]    success_top_up                                                                  OK
+ [Valid]    valid_sig_but_forked_state                                                      OK
+ [Valid]   Ethereum Foundation - Altair - Finality - finality_no_updates_at_genesis [Preset OK
+ [Valid]   Ethereum Foundation - Altair - Finality - finality_rule_1 [Preset: minimal]      OK
+ [Valid]   Ethereum Foundation - Altair - Finality - finality_rule_2 [Preset: minimal]      OK
+ [Valid]   Ethereum Foundation - Altair - Finality - finality_rule_3 [Preset: minimal]      OK
+ [Valid]   Ethereum Foundation - Altair - Finality - finality_rule_4 [Preset: minimal]      OK
+ [Valid]   Ethereum Foundation - Altair - Random - randomized_0 [Preset: minimal]           OK
+ [Valid]   Ethereum Foundation - Altair - Random - randomized_1 [Preset: minimal]           OK
+ [Valid]   Ethereum Foundation - Altair - Random - randomized_10 [Preset: minimal]          OK
+ [Valid]   Ethereum Foundation - Altair - Random - randomized_11 [Preset: minimal]          OK
+ [Valid]   Ethereum Foundation - Altair - Random - randomized_12 [Preset: minimal]          OK
+ [Valid]   Ethereum Foundation - Altair - Random - randomized_13 [Preset: minimal]          OK
+ [Valid]   Ethereum Foundation - Altair - Random - randomized_14 [Preset: minimal]          OK
+ [Valid]   Ethereum Foundation - Altair - Random - randomized_15 [Preset: minimal]          OK
+ [Valid]   Ethereum Foundation - Altair - Random - randomized_2 [Preset: minimal]           OK
+ [Valid]   Ethereum Foundation - Altair - Random - randomized_3 [Preset: minimal]           OK
+ [Valid]   Ethereum Foundation - Altair - Random - randomized_4 [Preset: minimal]           OK
+ [Valid]   Ethereum Foundation - Altair - Random - randomized_5 [Preset: minimal]           OK
+ [Valid]   Ethereum Foundation - Altair - Random - randomized_6 [Preset: minimal]           OK
+ [Valid]   Ethereum Foundation - Altair - Random - randomized_7 [Preset: minimal]           OK
+ [Valid]   Ethereum Foundation - Altair - Random - randomized_8 [Preset: minimal]           OK
+ [Valid]   Ethereum Foundation - Altair - Random - randomized_9 [Preset: minimal]           OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - attestation [Preset: minimal]   OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - attester_slashing [Preset: mini OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - balance_driven_status_transitio OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - deposit_in_block [Preset: minim OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - deposit_top_up [Preset: minimal OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - empty_block_transition [Preset: OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - empty_block_transition_large_va OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - empty_epoch_transition [Preset: OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - empty_epoch_transition_large_va OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - empty_epoch_transition_not_fina OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - eth1_data_votes_consensus [Pres OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - eth1_data_votes_no_consensus [P OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - full_random_operations_0 [Prese OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - full_random_operations_1 [Prese OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - full_random_operations_2 [Prese OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - full_random_operations_3 [Prese OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - high_proposer_index [Preset: mi OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - historical_batch [Preset: minim OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - multiple_attester_slashings_no_ OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - multiple_attester_slashings_par OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - multiple_different_proposer_sla OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - multiple_different_validator_ex OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - proposer_after_inactive_index [ OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - proposer_self_slashing [Preset: OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - proposer_slashing [Preset: mini OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - skipped_slots [Preset: minimal] OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - slash_and_exit_diff_index [Pres OK
+ [Valid]   Ethereum Foundation - Altair - Sanity - Blocks - voluntary_exit [Preset: minimal OK
+ [Valid]   Ethereum Foundation - Phase 0 - Finality - finality_no_updates_at_genesis [Prese OK
+ [Valid]   Ethereum Foundation - Phase 0 - Finality - finality_rule_1 [Preset: minimal]     OK
+ [Valid]   Ethereum Foundation - Phase 0 - Finality - finality_rule_2 [Preset: minimal]     OK
+ [Valid]   Ethereum Foundation - Phase 0 - Finality - finality_rule_3 [Preset: minimal]     OK
+ [Valid]   Ethereum Foundation - Phase 0 - Finality - finality_rule_4 [Preset: minimal]     OK
+ [Valid]   Ethereum Foundation - Phase 0 - Random - randomized_0 [Preset: minimal]          OK
+ [Valid]   Ethereum Foundation - Phase 0 - Random - randomized_1 [Preset: minimal]          OK
+ [Valid]   Ethereum Foundation - Phase 0 - Random - randomized_10 [Preset: minimal]         OK
+ [Valid]   Ethereum Foundation - Phase 0 - Random - randomized_11 [Preset: minimal]         OK
+ [Valid]   Ethereum Foundation - Phase 0 - Random - randomized_12 [Preset: minimal]         OK
+ [Valid]   Ethereum Foundation - Phase 0 - Random - randomized_13 [Preset: minimal]         OK
+ [Valid]   Ethereum Foundation - Phase 0 - Random - randomized_14 [Preset: minimal]         OK
+ [Valid]   Ethereum Foundation - Phase 0 - Random - randomized_15 [Preset: minimal]         OK
+ [Valid]   Ethereum Foundation - Phase 0 - Random - randomized_2 [Preset: minimal]          OK
+ [Valid]   Ethereum Foundation - Phase 0 - Random - randomized_3 [Preset: minimal]          OK
+ [Valid]   Ethereum Foundation - Phase 0 - Random - randomized_4 [Preset: minimal]          OK
+ [Valid]   Ethereum Foundation - Phase 0 - Random - randomized_5 [Preset: minimal]          OK
+ [Valid]   Ethereum Foundation - Phase 0 - Random - randomized_6 [Preset: minimal]          OK
+ [Valid]   Ethereum Foundation - Phase 0 - Random - randomized_7 [Preset: minimal]          OK
+ [Valid]   Ethereum Foundation - Phase 0 - Random - randomized_8 [Preset: minimal]          OK
+ [Valid]   Ethereum Foundation - Phase 0 - Random - randomized_9 [Preset: minimal]          OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - attestation [Preset: minimal]  OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - attester_slashing [Preset: min OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - balance_driven_status_transiti OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - deposit_in_block [Preset: mini OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - deposit_top_up [Preset: minima OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - empty_block_transition [Preset OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - empty_block_transition_large_v OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - empty_epoch_transition [Preset OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - empty_epoch_transition_large_v OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - empty_epoch_transition_not_fin OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - eth1_data_votes_consensus [Pre OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - eth1_data_votes_no_consensus [ OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - full_random_operations_0 [Pres OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - full_random_operations_1 [Pres OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - full_random_operations_2 [Pres OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - full_random_operations_3 [Pres OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - high_proposer_index [Preset: m OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - historical_batch [Preset: mini OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - multiple_attester_slashings_no OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - multiple_attester_slashings_pa OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - multiple_different_proposer_sl OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - multiple_different_validator_e OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - proposer_after_inactive_index  OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - proposer_self_slashing [Preset OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - proposer_slashing [Preset: min OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - skipped_slots [Preset: minimal OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - slash_and_exit_diff_index [Pre OK
+ [Valid]   Ethereum Foundation - Phase 0 - Sanity - Blocks - voluntary_exit [Preset: minima OK
+ [Valid]   correct_epoch_delay                                                              OK
+ [Valid]   correct_min_inclusion_delay                                                      OK
+ [Valid]   correct_sqrt_epoch_delay                                                         OK
+ [Valid]   default_exit_epoch_subsequent_exit                                               OK
+ [Valid]   incorrect_head_and_target_epoch_delay                                            OK
+ [Valid]   incorrect_head_and_target_min_inclusion_delay                                    OK
+ [Valid]   incorrect_head_and_target_sqrt_epoch_delay                                       OK
+ [Valid]   incorrect_head_epoch_delay                                                       OK
+ [Valid]   incorrect_head_min_inclusion_delay                                               OK
+ [Valid]   incorrect_head_sqrt_epoch_delay                                                  OK
+ [Valid]   incorrect_target_epoch_delay                                                     OK
+ [Valid]   incorrect_target_min_inclusion_delay                                             OK
+ [Valid]   incorrect_target_sqrt_epoch_delay                                                OK
+ [Valid]   proposer_in_committee_with_participation                                         OK
+ [Valid]   proposer_in_committee_without_participation                                      OK
+ [Valid]   random_all_but_one_participating_without_duplicates                              OK
+ [Valid]   random_high_participation_without_duplicates                                     OK
+ [Valid]   random_low_participation_without_duplicates                                      OK
+ [Valid]   random_misc_balances_and_half_participation_without_duplicates                   OK
+ [Valid]   random_only_one_participant_without_duplicates                                   OK
+ [Valid]   random_with_exits_without_duplicates                                             OK
+ [Valid]   success                                                                          OK
+ [Valid]   success_already_exited_long_ago                                                  OK
+ [Valid]   success_already_exited_recent                                                    OK
+ [Valid]   success_attestation_from_future                                                  OK
+ [Valid]   success_block_header                                                             OK
+ [Valid]   success_block_header_from_future                                                 OK
+ [Valid]   success_double                                                                   OK
+ [Valid]   success_exit_queue__min_churn                                                    OK
+ [Valid]   success_exit_queue__scaled_churn                                                 OK
+ [Valid]   success_low_balances                                                             OK
+ [Valid]   success_misc_balances                                                            OK
+ [Valid]   success_multi_proposer_index_iterations                                          OK
+ [Valid]   success_previous_epoch                                                           OK
+ [Valid]   success_proposer_index_slashed                                                   OK
+ [Valid]   success_slashed_and_proposer_index_the_same                                      OK
+ [Valid]   success_surround                                                                 OK
+ [Valid]   success_with_effective_balance_disparity                                         OK
+ [Valid]   sync_committee_rewards_empty_participants                                        OK
+ [Valid]   sync_committee_rewards_nonduplicate_committee                                    OK
+ [Valid]   sync_committee_rewards_not_full_participants                                     OK
+ [Valid]   sync_committee_with_nonparticipating_exited_member                               OK
+ [Valid]   sync_committee_with_nonparticipating_withdrawable_member                         OK
+ [Valid]   sync_committee_with_participating_exited_member                                  OK
+ [Valid]   sync_committee_with_participating_withdrawable_member                            OK
+ [Valid]   valid_signature_future_committee                                                 OK
```
OK: 311/311 Fail: 0/311 Skip: 0/311
## Ethereum Foundation - Altair - Epoch Processing - Effective balance updates [Preset: minimal]
```diff
+ Effective balance updates - effective_balance_hysteresis [Preset: minimal]                 OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Ethereum Foundation - Altair - Epoch Processing - Eth1 data reset [Preset: minimal]
```diff
+ Eth1 data reset - eth1_vote_no_reset [Preset: minimal]                                     OK
+ Eth1 data reset - eth1_vote_reset [Preset: minimal]                                        OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## Ethereum Foundation - Altair - Epoch Processing - Historical roots update [Preset: minimal]
```diff
+ Historical roots update - historical_root_accumulator [Preset: minimal]                    OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Ethereum Foundation - Altair - Epoch Processing - Inactivity [Preset: minimal]
```diff
+ Inactivity - all_zero_inactivity_scores_empty_participation [Preset: minimal]              OK
+ Inactivity - all_zero_inactivity_scores_empty_participation_leaking [Preset: minimal]      OK
+ Inactivity - all_zero_inactivity_scores_full_participation [Preset: minimal]               OK
+ Inactivity - all_zero_inactivity_scores_full_participation_leaking [Preset: minimal]       OK
+ Inactivity - all_zero_inactivity_scores_random_participation [Preset: minimal]             OK
+ Inactivity - all_zero_inactivity_scores_random_participation_leaking [Preset: minimal]     OK
+ Inactivity - genesis [Preset: minimal]                                                     OK
+ Inactivity - genesis_random_scores [Preset: minimal]                                       OK
+ Inactivity - random_inactivity_scores_empty_participation [Preset: minimal]                OK
+ Inactivity - random_inactivity_scores_empty_participation_leaking [Preset: minimal]        OK
+ Inactivity - random_inactivity_scores_full_participation [Preset: minimal]                 OK
+ Inactivity - random_inactivity_scores_full_participation_leaking [Preset: minimal]         OK
+ Inactivity - random_inactivity_scores_random_participation [Preset: minimal]               OK
+ Inactivity - random_inactivity_scores_random_participation_leaking [Preset: minimal]       OK
+ Inactivity - some_exited_full_random_leaking [Preset: minimal]                             OK
+ Inactivity - some_slashed_full_random [Preset: minimal]                                    OK
+ Inactivity - some_slashed_full_random_leaking [Preset: minimal]                            OK
+ Inactivity - some_slashed_zero_scores_full_participation [Preset: minimal]                 OK
+ Inactivity - some_slashed_zero_scores_full_participation_leaking [Preset: minimal]         OK
```
OK: 19/19 Fail: 0/19 Skip: 0/19
## Ethereum Foundation - Altair - Epoch Processing - Justification & Finalization [Preset: minimal]
```diff
+ Justification & Finalization - 123_ok_support [Preset: minimal]                            OK
+ Justification & Finalization - 123_poor_support [Preset: minimal]                          OK
+ Justification & Finalization - 12_ok_support [Preset: minimal]                             OK
+ Justification & Finalization - 12_ok_support_messed_target [Preset: minimal]               OK
+ Justification & Finalization - 12_poor_support [Preset: minimal]                           OK
+ Justification & Finalization - 234_ok_support [Preset: minimal]                            OK
+ Justification & Finalization - 234_poor_support [Preset: minimal]                          OK
+ Justification & Finalization - 23_ok_support [Preset: minimal]                             OK
+ Justification & Finalization - 23_poor_support [Preset: minimal]                           OK
+ Justification & Finalization - balance_threshold_with_exited_validators [Preset: minimal]  OK
```
OK: 10/10 Fail: 0/10 Skip: 0/10
## Ethereum Foundation - Altair - Epoch Processing - Participation flag updates [Preset: minimal]
```diff
+ Participation flag updates - all_zeroed [Preset: minimal]                                  OK
+ Participation flag updates - current_epoch_zeroed [Preset: minimal]                        OK
+ Participation flag updates - current_filled [Preset: minimal]                              OK
+ Participation flag updates - filled [Preset: minimal]                                      OK
+ Participation flag updates - large_random [Preset: minimal]                                OK
+ Participation flag updates - previous_epoch_zeroed [Preset: minimal]                       OK
+ Participation flag updates - previous_filled [Preset: minimal]                             OK
+ Participation flag updates - random_0 [Preset: minimal]                                    OK
+ Participation flag updates - random_1 [Preset: minimal]                                    OK
+ Participation flag updates - random_2 [Preset: minimal]                                    OK
+ Participation flag updates - random_genesis [Preset: minimal]                              OK
+ Participation flag updates - slightly_larger_random [Preset: minimal]                      OK
```
OK: 12/12 Fail: 0/12 Skip: 0/12
## Ethereum Foundation - Altair - Epoch Processing - RANDAO mixes reset [Preset: minimal]
```diff
+ RANDAO mixes reset - updated_randao_mixes [Preset: minimal]                                OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Ethereum Foundation - Altair - Epoch Processing - Registry updates [Preset: minimal]
```diff
+ Registry updates - activation_queue_activation_and_ejection__1 [Preset: minimal]           OK
+ Registry updates - activation_queue_activation_and_ejection__churn_limit [Preset: minimal] OK
+ Registry updates - activation_queue_activation_and_ejection__exceed_churn_limit [Preset: m OK
+ Registry updates - activation_queue_activation_and_ejection__exceed_scaled_churn_limit [Pr OK
+ Registry updates - activation_queue_activation_and_ejection__scaled_churn_limit [Preset: m OK
+ Registry updates - activation_queue_efficiency_min [Preset: minimal]                       OK
+ Registry updates - activation_queue_efficiency_scaled [Preset: minimal]                    OK
+ Registry updates - activation_queue_no_activation_no_finality [Preset: minimal]            OK
+ Registry updates - activation_queue_sorting [Preset: minimal]                              OK
+ Registry updates - activation_queue_to_activated_if_finalized [Preset: minimal]            OK
+ Registry updates - add_to_activation_queue [Preset: minimal]                               OK
+ Registry updates - ejection [Preset: minimal]                                              OK
+ Registry updates - ejection_past_churn_limit_min [Preset: minimal]                         OK
+ Registry updates - ejection_past_churn_limit_scaled [Preset: minimal]                      OK
```
OK: 14/14 Fail: 0/14 Skip: 0/14
## Ethereum Foundation - Altair - Epoch Processing - Slashings [Preset: minimal]
```diff
+ Slashings - low_penalty [Preset: minimal]                                                  OK
+ Slashings - max_penalties [Preset: minimal]                                                OK
+ Slashings - minimal_penalty [Preset: minimal]                                              OK
+ Slashings - scaled_penalties [Preset: minimal]                                             OK
+ Slashings - slashings_with_random_state [Preset: minimal]                                  OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## Ethereum Foundation - Altair - Epoch Processing - Slashings reset [Preset: minimal]
```diff
+ Slashings reset - flush_slashings [Preset: minimal]                                        OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Ethereum Foundation - Altair - Epoch Processing - Sync committee updates [Preset: minimal]
```diff
+ Sync committee updates - sync_committees_no_progress_not_boundary [Preset: minimal]        OK
+ Sync committee updates - sync_committees_progress_genesis [Preset: minimal]                OK
+ Sync committee updates - sync_committees_progress_misc_balances_genesis [Preset: minimal]  OK
+ Sync committee updates - sync_committees_progress_misc_balances_not_genesis [Preset: minim OK
+ Sync committee updates - sync_committees_progress_not_genesis [Preset: minimal]            OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## Ethereum Foundation - Altair - SSZ consensus objects  [Preset: minimal]
```diff
+   Testing    AggregateAndProof                                                             OK
+   Testing    Attestation                                                                   OK
+   Testing    AttestationData                                                               OK
+   Testing    AttesterSlashing                                                              OK
+   Testing    BeaconBlock                                                                   OK
+   Testing    BeaconBlockBody                                                               OK
+   Testing    BeaconBlockHeader                                                             OK
+   Testing    BeaconState                                                                   OK
+   Testing    Checkpoint                                                                    OK
+   Testing    ContributionAndProof                                                          OK
+   Testing    Deposit                                                                       OK
+   Testing    DepositData                                                                   OK
+   Testing    DepositMessage                                                                OK
+   Testing    Eth1Block                                                                     OK
+   Testing    Eth1Data                                                                      OK
+   Testing    Fork                                                                          OK
+   Testing    ForkData                                                                      OK
+   Testing    HistoricalBatch                                                               OK
+   Testing    IndexedAttestation                                                            OK
+   Testing    LightClientSnapshot                                                           OK
+   Testing    LightClientUpdate                                                             OK
+   Testing    PendingAttestation                                                            OK
+   Testing    ProposerSlashing                                                              OK
+   Testing    SignedAggregateAndProof                                                       OK
+   Testing    SignedBeaconBlock                                                             OK
+   Testing    SignedBeaconBlockHeader                                                       OK
+   Testing    SignedContributionAndProof                                                    OK
+   Testing    SignedVoluntaryExit                                                           OK
+   Testing    SigningData                                                                   OK
+   Testing    SyncAggregate                                                                 OK
+   Testing    SyncAggregatorSelectionData                                                   OK
+   Testing    SyncCommittee                                                                 OK
+   Testing    SyncCommitteeContribution                                                     OK
+   Testing    SyncCommitteeMessage                                                          OK
+   Testing    Validator                                                                     OK
+   Testing    VoluntaryExit                                                                 OK
```
OK: 36/36 Fail: 0/36 Skip: 0/36
## Ethereum Foundation - Phase 0 - Epoch Processing - Effective balance updates [Preset: minimal]
```diff
+ Effective balance updates - effective_balance_hysteresis [Preset: minimal]                 OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Ethereum Foundation - Phase 0 - Epoch Processing - Eth1 data reset [Preset: minimal]
```diff
+ Eth1 data reset - eth1_vote_no_reset [Preset: minimal]                                     OK
+ Eth1 data reset - eth1_vote_reset [Preset: minimal]                                        OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## Ethereum Foundation - Phase 0 - Epoch Processing - Historical roots update [Preset: minimal]
```diff
+ Historical roots update - historical_root_accumulator [Preset: minimal]                    OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Ethereum Foundation - Phase 0 - Epoch Processing - Justification & Finalization [Preset: minimal]
```diff
+ Justification & Finalization - 123_ok_support [Preset: minimal]                            OK
+ Justification & Finalization - 123_poor_support [Preset: minimal]                          OK
+ Justification & Finalization - 12_ok_support [Preset: minimal]                             OK
+ Justification & Finalization - 12_ok_support_messed_target [Preset: minimal]               OK
+ Justification & Finalization - 12_poor_support [Preset: minimal]                           OK
+ Justification & Finalization - 234_ok_support [Preset: minimal]                            OK
+ Justification & Finalization - 234_poor_support [Preset: minimal]                          OK
+ Justification & Finalization - 23_ok_support [Preset: minimal]                             OK
+ Justification & Finalization - 23_poor_support [Preset: minimal]                           OK
+ Justification & Finalization - balance_threshold_with_exited_validators [Preset: minimal]  OK
```
OK: 10/10 Fail: 0/10 Skip: 0/10
## Ethereum Foundation - Phase 0 - Epoch Processing - Participation record updates [Preset: minimal]
```diff
+ Participation record updates - updated_participation_record [Preset: minimal]              OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Ethereum Foundation - Phase 0 - Epoch Processing - RANDAO mixes reset [Preset: minimal]
```diff
+ RANDAO mixes reset - updated_randao_mixes [Preset: minimal]                                OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Ethereum Foundation - Phase 0 - Epoch Processing - Registry updates [Preset: minimal]
```diff
+ Registry updates - activation_queue_activation_and_ejection__1 [Preset: minimal]           OK
+ Registry updates - activation_queue_activation_and_ejection__churn_limit [Preset: minimal] OK
+ Registry updates - activation_queue_activation_and_ejection__exceed_churn_limit [Preset: m OK
+ Registry updates - activation_queue_activation_and_ejection__exceed_scaled_churn_limit [Pr OK
+ Registry updates - activation_queue_activation_and_ejection__scaled_churn_limit [Preset: m OK
+ Registry updates - activation_queue_efficiency_min [Preset: minimal]                       OK
+ Registry updates - activation_queue_efficiency_scaled [Preset: minimal]                    OK
+ Registry updates - activation_queue_no_activation_no_finality [Preset: minimal]            OK
+ Registry updates - activation_queue_sorting [Preset: minimal]                              OK
+ Registry updates - activation_queue_to_activated_if_finalized [Preset: minimal]            OK
+ Registry updates - add_to_activation_queue [Preset: minimal]                               OK
+ Registry updates - ejection [Preset: minimal]                                              OK
+ Registry updates - ejection_past_churn_limit_min [Preset: minimal]                         OK
+ Registry updates - ejection_past_churn_limit_scaled [Preset: minimal]                      OK
```
OK: 14/14 Fail: 0/14 Skip: 0/14
## Ethereum Foundation - Phase 0 - Epoch Processing - Slashings [Preset: minimal]
```diff
+ Slashings - low_penalty [Preset: minimal]                                                  OK
+ Slashings - max_penalties [Preset: minimal]                                                OK
+ Slashings - minimal_penalty [Preset: minimal]                                              OK
+ Slashings - scaled_penalties [Preset: minimal]                                             OK
+ Slashings - slashings_with_random_state [Preset: minimal]                                  OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## Ethereum Foundation - Phase 0 - Epoch Processing - Slashings reset [Preset: minimal]
```diff
+ Slashings reset - flush_slashings [Preset: minimal]                                        OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## Ethereum Foundation - Phase 0 - SSZ consensus objects  [Preset: minimal]
```diff
+   Testing    AggregateAndProof                                                             OK
+   Testing    Attestation                                                                   OK
+   Testing    AttestationData                                                               OK
+   Testing    AttesterSlashing                                                              OK
+   Testing    BeaconBlock                                                                   OK
+   Testing    BeaconBlockBody                                                               OK
+   Testing    BeaconBlockHeader                                                             OK
+   Testing    BeaconState                                                                   OK
+   Testing    Checkpoint                                                                    OK
+   Testing    Deposit                                                                       OK
+   Testing    DepositData                                                                   OK
+   Testing    DepositMessage                                                                OK
+   Testing    Eth1Block                                                                     OK
+   Testing    Eth1Data                                                                      OK
+   Testing    Fork                                                                          OK
+   Testing    ForkData                                                                      OK
+   Testing    HistoricalBatch                                                               OK
+   Testing    IndexedAttestation                                                            OK
+   Testing    PendingAttestation                                                            OK
+   Testing    ProposerSlashing                                                              OK
+   Testing    SignedAggregateAndProof                                                       OK
+   Testing    SignedBeaconBlock                                                             OK
+   Testing    SignedBeaconBlockHeader                                                       OK
+   Testing    SignedVoluntaryExit                                                           OK
+   Testing    SigningData                                                                   OK
+   Testing    Validator                                                                     OK
+   Testing    VoluntaryExit                                                                 OK
```
OK: 27/27 Fail: 0/27 Skip: 0/27

---TOTAL---
OK: 481/481 Fail: 0/481 Skip: 0/481
