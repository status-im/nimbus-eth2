ConsensusSpecPreset-minimal
===
## EF - Altair - Epoch Processing - Effective balance updates [Preset: minimal]
```diff
+ Effective balance updates - effective_balance_hysteresis [Preset: minimal]                 OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## EF - Altair - Epoch Processing - Eth1 data reset [Preset: minimal]
```diff
+ Eth1 data reset - eth1_vote_no_reset [Preset: minimal]                                     OK
+ Eth1 data reset - eth1_vote_reset [Preset: minimal]                                        OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## EF - Altair - Epoch Processing - Historical roots update [Preset: minimal]
```diff
+ Historical roots update - historical_root_accumulator [Preset: minimal]                    OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## EF - Altair - Epoch Processing - Inactivity [Preset: minimal]
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
+ Inactivity - randomized_state [Preset: minimal]                                            OK
+ Inactivity - randomized_state_leaking [Preset: minimal]                                    OK
+ Inactivity - some_exited_full_random_leaking [Preset: minimal]                             OK
+ Inactivity - some_slashed_full_random [Preset: minimal]                                    OK
+ Inactivity - some_slashed_full_random_leaking [Preset: minimal]                            OK
+ Inactivity - some_slashed_zero_scores_full_participation [Preset: minimal]                 OK
+ Inactivity - some_slashed_zero_scores_full_participation_leaking [Preset: minimal]         OK
```
OK: 21/21 Fail: 0/21 Skip: 0/21
## EF - Altair - Epoch Processing - Justification & Finalization [Preset: minimal]
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
## EF - Altair - Epoch Processing - Participation flag updates [Preset: minimal]
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
## EF - Altair - Epoch Processing - RANDAO mixes reset [Preset: minimal]
```diff
+ RANDAO mixes reset - updated_randao_mixes [Preset: minimal]                                OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## EF - Altair - Epoch Processing - Registry updates [Preset: minimal]
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
+ Registry updates - invalid_large_withdrawable_epoch [Preset: minimal]                      OK
```
OK: 15/15 Fail: 0/15 Skip: 0/15
## EF - Altair - Epoch Processing - Rewards and penalties [Preset: minimal]
```diff
+ Rewards and penalties - almost_empty_attestations [Preset: minimal]                        OK
+ Rewards and penalties - almost_empty_attestations_with_leak [Preset: minimal]              OK
+ Rewards and penalties - almost_full_attestations [Preset: minimal]                         OK
+ Rewards and penalties - almost_full_attestations_with_leak [Preset: minimal]               OK
+ Rewards and penalties - attestations_some_slashed [Preset: minimal]                        OK
+ Rewards and penalties - duplicate_attestation [Preset: minimal]                            OK
+ Rewards and penalties - full_attestation_participation [Preset: minimal]                   OK
+ Rewards and penalties - full_attestation_participation_with_leak [Preset: minimal]         OK
+ Rewards and penalties - full_attestations_misc_balances [Preset: minimal]                  OK
+ Rewards and penalties - full_attestations_one_validaor_one_gwei [Preset: minimal]          OK
+ Rewards and penalties - genesis_epoch_full_attestations_no_rewards [Preset: minimal]       OK
+ Rewards and penalties - genesis_epoch_no_attestations_no_penalties [Preset: minimal]       OK
+ Rewards and penalties - no_attestations_all_penalties [Preset: minimal]                    OK
+ Rewards and penalties - random_fill_attestations [Preset: minimal]                         OK
+ Rewards and penalties - random_fill_attestations_with_leak [Preset: minimal]               OK
```
OK: 15/15 Fail: 0/15 Skip: 0/15
## EF - Altair - Epoch Processing - Slashings [Preset: minimal]
```diff
+ Slashings - low_penalty [Preset: minimal]                                                  OK
+ Slashings - max_penalties [Preset: minimal]                                                OK
+ Slashings - minimal_penalty [Preset: minimal]                                              OK
+ Slashings - scaled_penalties [Preset: minimal]                                             OK
+ Slashings - slashings_with_random_state [Preset: minimal]                                  OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## EF - Altair - Epoch Processing - Slashings reset [Preset: minimal]
```diff
+ Slashings reset - flush_slashings [Preset: minimal]                                        OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## EF - Altair - Epoch Processing - Sync committee updates [Preset: minimal]
```diff
+ Sync committee updates - sync_committees_no_progress_not_at_period_boundary [Preset: minim OK
+ Sync committee updates - sync_committees_progress_genesis [Preset: minimal]                OK
+ Sync committee updates - sync_committees_progress_misc_balances_genesis [Preset: minimal]  OK
+ Sync committee updates - sync_committees_progress_misc_balances_not_genesis [Preset: minim OK
+ Sync committee updates - sync_committees_progress_not_genesis [Preset: minimal]            OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## EF - Altair - Finality  [Preset: minimal]
```diff
+ [Valid]   EF - Altair - Finality - finality_no_updates_at_genesis [Preset: minimal]        OK
+ [Valid]   EF - Altair - Finality - finality_rule_1 [Preset: minimal]                       OK
+ [Valid]   EF - Altair - Finality - finality_rule_2 [Preset: minimal]                       OK
+ [Valid]   EF - Altair - Finality - finality_rule_3 [Preset: minimal]                       OK
+ [Valid]   EF - Altair - Finality - finality_rule_4 [Preset: minimal]                       OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## EF - Altair - Fork  [Preset: minimal]
```diff
+ EF - Altair - Fork - altair_fork_random_0 [Preset: minimal]                                OK
+ EF - Altair - Fork - altair_fork_random_1 [Preset: minimal]                                OK
+ EF - Altair - Fork - altair_fork_random_2 [Preset: minimal]                                OK
+ EF - Altair - Fork - altair_fork_random_3 [Preset: minimal]                                OK
+ EF - Altair - Fork - altair_fork_random_duplicate_attestations [Preset: minimal]           OK
+ EF - Altair - Fork - altair_fork_random_large_validator_set [Preset: minimal]              OK
+ EF - Altair - Fork - altair_fork_random_low_balances [Preset: minimal]                     OK
+ EF - Altair - Fork - altair_fork_random_misc_balances [Preset: minimal]                    OK
+ EF - Altair - Fork - altair_fork_random_mismatched_attestations [Preset: minimal]          OK
+ EF - Altair - Fork - fork_base_state [Preset: minimal]                                     OK
+ EF - Altair - Fork - fork_many_next_epoch [Preset: minimal]                                OK
+ EF - Altair - Fork - fork_next_epoch [Preset: minimal]                                     OK
+ EF - Altair - Fork - fork_next_epoch_with_block [Preset: minimal]                          OK
+ EF - Altair - Fork - fork_random_large_validator_set [Preset: minimal]                     OK
+ EF - Altair - Fork - fork_random_low_balances [Preset: minimal]                            OK
+ EF - Altair - Fork - fork_random_misc_balances [Preset: minimal]                           OK
```
OK: 16/16 Fail: 0/16 Skip: 0/16
## EF - Altair - Operations - Attestation  [Preset: minimal]
```diff
+ [Invalid] EF - Altair - Operations - Attestation - invalid_after_max_inclusion_slot        OK
+ [Invalid] EF - Altair - Operations - Attestation - invalid_attestation_signature           OK
+ [Invalid] EF - Altair - Operations - Attestation - invalid_bad_source_root                 OK
+ [Invalid] EF - Altair - Operations - Attestation - invalid_before_inclusion_delay          OK
+ [Invalid] EF - Altair - Operations - Attestation - invalid_correct_attestation_included_af OK
+ [Invalid] EF - Altair - Operations - Attestation - invalid_current_source_root             OK
+ [Invalid] EF - Altair - Operations - Attestation - invalid_empty_participants_seemingly_va OK
+ [Invalid] EF - Altair - Operations - Attestation - invalid_empty_participants_zeroes_sig   OK
+ [Invalid] EF - Altair - Operations - Attestation - invalid_future_target_epoch             OK
+ [Invalid] EF - Altair - Operations - Attestation - invalid_incorrect_head_and_target_inclu OK
+ [Invalid] EF - Altair - Operations - Attestation - invalid_incorrect_head_included_after_m OK
+ [Invalid] EF - Altair - Operations - Attestation - invalid_incorrect_target_included_after OK
+ [Invalid] EF - Altair - Operations - Attestation - invalid_index                           OK
+ [Invalid] EF - Altair - Operations - Attestation - invalid_mismatched_target_and_slot      OK
+ [Invalid] EF - Altair - Operations - Attestation - invalid_new_source_epoch                OK
+ [Invalid] EF - Altair - Operations - Attestation - invalid_old_source_epoch                OK
+ [Invalid] EF - Altair - Operations - Attestation - invalid_old_target_epoch                OK
+ [Invalid] EF - Altair - Operations - Attestation - invalid_previous_source_root            OK
+ [Invalid] EF - Altair - Operations - Attestation - invalid_source_root_is_target_root      OK
+ [Invalid] EF - Altair - Operations - Attestation - invalid_too_few_aggregation_bits        OK
+ [Invalid] EF - Altair - Operations - Attestation - invalid_too_many_aggregation_bits       OK
+ [Invalid] EF - Altair - Operations - Attestation - invalid_wrong_index_for_committee_signa OK
+ [Invalid] EF - Altair - Operations - Attestation - invalid_wrong_index_for_slot_0          OK
+ [Invalid] EF - Altair - Operations - Attestation - invalid_wrong_index_for_slot_1          OK
+ [Valid]   EF - Altair - Operations - Attestation - at_max_inclusion_slot                   OK
+ [Valid]   EF - Altair - Operations - Attestation - correct_attestation_included_at_max_inc OK
+ [Valid]   EF - Altair - Operations - Attestation - correct_attestation_included_at_min_inc OK
+ [Valid]   EF - Altair - Operations - Attestation - correct_attestation_included_at_one_epo OK
+ [Valid]   EF - Altair - Operations - Attestation - correct_attestation_included_at_sqrt_ep OK
+ [Valid]   EF - Altair - Operations - Attestation - incorrect_head_and_target_included_at_e OK
+ [Valid]   EF - Altair - Operations - Attestation - incorrect_head_and_target_included_at_s OK
+ [Valid]   EF - Altair - Operations - Attestation - incorrect_head_and_target_min_inclusion OK
+ [Valid]   EF - Altair - Operations - Attestation - incorrect_head_included_at_max_inclusio OK
+ [Valid]   EF - Altair - Operations - Attestation - incorrect_head_included_at_min_inclusio OK
+ [Valid]   EF - Altair - Operations - Attestation - incorrect_head_included_at_sqrt_epoch_d OK
+ [Valid]   EF - Altair - Operations - Attestation - incorrect_target_included_at_epoch_dela OK
+ [Valid]   EF - Altair - Operations - Attestation - incorrect_target_included_at_min_inclus OK
+ [Valid]   EF - Altair - Operations - Attestation - incorrect_target_included_at_sqrt_epoch OK
+ [Valid]   EF - Altair - Operations - Attestation - multi_proposer_index_iterations         OK
+ [Valid]   EF - Altair - Operations - Attestation - one_basic_attestation                   OK
+ [Valid]   EF - Altair - Operations - Attestation - previous_epoch                          OK
```
OK: 41/41 Fail: 0/41 Skip: 0/41
## EF - Altair - Operations - Attester Slashing  [Preset: minimal]
```diff
+ [Invalid] EF - Altair - Operations - Attester Slashing - invalid_all_empty_indices         OK
+ [Invalid] EF - Altair - Operations - Attester Slashing - invalid_att1_bad_extra_index      OK
+ [Invalid] EF - Altair - Operations - Attester Slashing - invalid_att1_bad_replaced_index   OK
+ [Invalid] EF - Altair - Operations - Attester Slashing - invalid_att1_duplicate_index_doub OK
+ [Invalid] EF - Altair - Operations - Attester Slashing - invalid_att1_duplicate_index_norm OK
+ [Invalid] EF - Altair - Operations - Attester Slashing - invalid_att1_empty_indices        OK
+ [Invalid] EF - Altair - Operations - Attester Slashing - invalid_att1_high_index           OK
+ [Invalid] EF - Altair - Operations - Attester Slashing - invalid_att2_bad_extra_index      OK
+ [Invalid] EF - Altair - Operations - Attester Slashing - invalid_att2_bad_replaced_index   OK
+ [Invalid] EF - Altair - Operations - Attester Slashing - invalid_att2_duplicate_index_doub OK
+ [Invalid] EF - Altair - Operations - Attester Slashing - invalid_att2_duplicate_index_norm OK
+ [Invalid] EF - Altair - Operations - Attester Slashing - invalid_att2_empty_indices        OK
+ [Invalid] EF - Altair - Operations - Attester Slashing - invalid_att2_high_index           OK
+ [Invalid] EF - Altair - Operations - Attester Slashing - invalid_incorrect_sig_1           OK
+ [Invalid] EF - Altair - Operations - Attester Slashing - invalid_incorrect_sig_1_and_2     OK
+ [Invalid] EF - Altair - Operations - Attester Slashing - invalid_incorrect_sig_2           OK
+ [Invalid] EF - Altair - Operations - Attester Slashing - invalid_no_double_or_surround     OK
+ [Invalid] EF - Altair - Operations - Attester Slashing - invalid_participants_already_slas OK
+ [Invalid] EF - Altair - Operations - Attester Slashing - invalid_same_data                 OK
+ [Invalid] EF - Altair - Operations - Attester Slashing - invalid_unsorted_att_1            OK
+ [Invalid] EF - Altair - Operations - Attester Slashing - invalid_unsorted_att_2            OK
+ [Valid]   EF - Altair - Operations - Attester Slashing - already_exited_long_ago           OK
+ [Valid]   EF - Altair - Operations - Attester Slashing - already_exited_recent             OK
+ [Valid]   EF - Altair - Operations - Attester Slashing - attestation_from_future           OK
+ [Valid]   EF - Altair - Operations - Attester Slashing - basic_double                      OK
+ [Valid]   EF - Altair - Operations - Attester Slashing - basic_surround                    OK
+ [Valid]   EF - Altair - Operations - Attester Slashing - low_balances                      OK
+ [Valid]   EF - Altair - Operations - Attester Slashing - misc_balances                     OK
+ [Valid]   EF - Altair - Operations - Attester Slashing - proposer_index_slashed            OK
+ [Valid]   EF - Altair - Operations - Attester Slashing - with_effective_balance_disparity  OK
```
OK: 30/30 Fail: 0/30 Skip: 0/30
## EF - Altair - Operations - Block Header  [Preset: minimal]
```diff
+ [Invalid] EF - Altair - Operations - Block Header - invalid_multiple_blocks_single_slot    OK
+ [Invalid] EF - Altair - Operations - Block Header - invalid_parent_root                    OK
+ [Invalid] EF - Altair - Operations - Block Header - invalid_proposer_index                 OK
+ [Invalid] EF - Altair - Operations - Block Header - invalid_proposer_slashed               OK
+ [Invalid] EF - Altair - Operations - Block Header - invalid_slot_block_header              OK
+ [Valid]   EF - Altair - Operations - Block Header - basic_block_header                     OK
```
OK: 6/6 Fail: 0/6 Skip: 0/6
## EF - Altair - Operations - Deposit  [Preset: minimal]
```diff
+ [Invalid] EF - Altair - Operations - Deposit - invalid_bad_merkle_proof                    OK
+ [Invalid] EF - Altair - Operations - Deposit - invalid_wrong_deposit_for_deposit_count     OK
+ [Valid]   EF - Altair - Operations - Deposit - correct_sig_but_forked_state                OK
+ [Valid]   EF - Altair - Operations - Deposit - effective_deposit_with_previous_fork_versio OK
+ [Valid]   EF - Altair - Operations - Deposit - incorrect_sig_new_deposit                   OK
+ [Valid]   EF - Altair - Operations - Deposit - incorrect_sig_top_up                        OK
+ [Valid]   EF - Altair - Operations - Deposit - incorrect_withdrawal_credentials_top_up     OK
+ [Valid]   EF - Altair - Operations - Deposit - ineffective_deposit_with_bad_fork_version   OK
+ [Valid]   EF - Altair - Operations - Deposit - ineffective_deposit_with_current_fork_versi OK
+ [Valid]   EF - Altair - Operations - Deposit - key_validate_invalid_decompression          OK
+ [Valid]   EF - Altair - Operations - Deposit - key_validate_invalid_subgroup               OK
+ [Valid]   EF - Altair - Operations - Deposit - new_deposit_eth1_withdrawal_credentials     OK
+ [Valid]   EF - Altair - Operations - Deposit - new_deposit_max                             OK
+ [Valid]   EF - Altair - Operations - Deposit - new_deposit_non_versioned_withdrawal_creden OK
+ [Valid]   EF - Altair - Operations - Deposit - new_deposit_over_max                        OK
+ [Valid]   EF - Altair - Operations - Deposit - new_deposit_under_max                       OK
+ [Valid]   EF - Altair - Operations - Deposit - top_up__less_effective_balance              OK
+ [Valid]   EF - Altair - Operations - Deposit - top_up__max_effective_balance               OK
+ [Valid]   EF - Altair - Operations - Deposit - top_up__zero_balance                        OK
```
OK: 19/19 Fail: 0/19 Skip: 0/19
## EF - Altair - Operations - Proposer Slashing  [Preset: minimal]
```diff
+ [Invalid] EF - Altair - Operations - Proposer Slashing - invalid_different_proposer_indice OK
+ [Invalid] EF - Altair - Operations - Proposer Slashing - invalid_headers_are_same_sigs_are OK
+ [Invalid] EF - Altair - Operations - Proposer Slashing - invalid_headers_are_same_sigs_are OK
+ [Invalid] EF - Altair - Operations - Proposer Slashing - invalid_incorrect_proposer_index  OK
+ [Invalid] EF - Altair - Operations - Proposer Slashing - invalid_incorrect_sig_1           OK
+ [Invalid] EF - Altair - Operations - Proposer Slashing - invalid_incorrect_sig_1_and_2     OK
+ [Invalid] EF - Altair - Operations - Proposer Slashing - invalid_incorrect_sig_1_and_2_swa OK
+ [Invalid] EF - Altair - Operations - Proposer Slashing - invalid_incorrect_sig_2           OK
+ [Invalid] EF - Altair - Operations - Proposer Slashing - invalid_proposer_is_not_activated OK
+ [Invalid] EF - Altair - Operations - Proposer Slashing - invalid_proposer_is_slashed       OK
+ [Invalid] EF - Altair - Operations - Proposer Slashing - invalid_proposer_is_withdrawn     OK
+ [Invalid] EF - Altair - Operations - Proposer Slashing - invalid_slots_of_different_epochs OK
+ [Valid]   EF - Altair - Operations - Proposer Slashing - basic                             OK
+ [Valid]   EF - Altair - Operations - Proposer Slashing - block_header_from_future          OK
+ [Valid]   EF - Altair - Operations - Proposer Slashing - slashed_and_proposer_index_the_sa OK
```
OK: 15/15 Fail: 0/15 Skip: 0/15
## EF - Altair - Operations - Sync Aggregate  [Preset: minimal]
```diff
+ [Invalid] EF - Altair - Operations - Sync Aggregate - invalid_signature_bad_domain         OK
+ [Invalid] EF - Altair - Operations - Sync Aggregate - invalid_signature_extra_participant  OK
+ [Invalid] EF - Altair - Operations - Sync Aggregate - invalid_signature_infinite_signature OK
+ [Invalid] EF - Altair - Operations - Sync Aggregate - invalid_signature_infinite_signature OK
+ [Invalid] EF - Altair - Operations - Sync Aggregate - invalid_signature_missing_participan OK
+ [Invalid] EF - Altair - Operations - Sync Aggregate - invalid_signature_no_participants    OK
+ [Invalid] EF - Altair - Operations - Sync Aggregate - invalid_signature_past_block         OK
+ [Invalid] EF - Altair - Operations - Sync Aggregate - invalid_signature_previous_committee OK
+ [Valid]   EF - Altair - Operations - Sync Aggregate - proposer_in_committee_with_participa OK
+ [Valid]   EF - Altair - Operations - Sync Aggregate - proposer_in_committee_without_partic OK
+ [Valid]   EF - Altair - Operations - Sync Aggregate - random_all_but_one_participating_wit OK
+ [Valid]   EF - Altair - Operations - Sync Aggregate - random_high_participation_without_du OK
+ [Valid]   EF - Altair - Operations - Sync Aggregate - random_low_participation_without_dup OK
+ [Valid]   EF - Altair - Operations - Sync Aggregate - random_misc_balances_and_half_partic OK
+ [Valid]   EF - Altair - Operations - Sync Aggregate - random_only_one_participant_without_ OK
+ [Valid]   EF - Altair - Operations - Sync Aggregate - random_with_exits_without_duplicates OK
+ [Valid]   EF - Altair - Operations - Sync Aggregate - sync_committee_rewards_empty_partici OK
+ [Valid]   EF - Altair - Operations - Sync Aggregate - sync_committee_rewards_nonduplicate_ OK
+ [Valid]   EF - Altair - Operations - Sync Aggregate - sync_committee_rewards_not_full_part OK
+ [Valid]   EF - Altair - Operations - Sync Aggregate - sync_committee_with_nonparticipating OK
+ [Valid]   EF - Altair - Operations - Sync Aggregate - sync_committee_with_nonparticipating OK
+ [Valid]   EF - Altair - Operations - Sync Aggregate - sync_committee_with_participating_ex OK
+ [Valid]   EF - Altair - Operations - Sync Aggregate - sync_committee_with_participating_wi OK
+ [Valid]   EF - Altair - Operations - Sync Aggregate - valid_signature_future_committee     OK
```
OK: 24/24 Fail: 0/24 Skip: 0/24
## EF - Altair - Operations - Voluntary Exit  [Preset: minimal]
```diff
+ [Invalid] EF - Altair - Operations - Voluntary Exit - invalid_incorrect_signature          OK
+ [Invalid] EF - Altair - Operations - Voluntary Exit - invalid_validator_already_exited     OK
+ [Invalid] EF - Altair - Operations - Voluntary Exit - invalid_validator_exit_in_future     OK
+ [Invalid] EF - Altair - Operations - Voluntary Exit - invalid_validator_incorrect_validato OK
+ [Invalid] EF - Altair - Operations - Voluntary Exit - invalid_validator_not_active         OK
+ [Invalid] EF - Altair - Operations - Voluntary Exit - invalid_validator_not_active_long_en OK
+ [Valid]   EF - Altair - Operations - Voluntary Exit - basic                                OK
+ [Valid]   EF - Altair - Operations - Voluntary Exit - default_exit_epoch_subsequent_exit   OK
+ [Valid]   EF - Altair - Operations - Voluntary Exit - success_exit_queue__min_churn        OK
+ [Valid]   EF - Altair - Operations - Voluntary Exit - success_exit_queue__scaled_churn     OK
```
OK: 10/10 Fail: 0/10 Skip: 0/10
## EF - Altair - Random  [Preset: minimal]
```diff
+ [Valid]   EF - Altair - Random - randomized_0 [Preset: minimal]                            OK
+ [Valid]   EF - Altair - Random - randomized_1 [Preset: minimal]                            OK
+ [Valid]   EF - Altair - Random - randomized_10 [Preset: minimal]                           OK
+ [Valid]   EF - Altair - Random - randomized_11 [Preset: minimal]                           OK
+ [Valid]   EF - Altair - Random - randomized_12 [Preset: minimal]                           OK
+ [Valid]   EF - Altair - Random - randomized_13 [Preset: minimal]                           OK
+ [Valid]   EF - Altair - Random - randomized_14 [Preset: minimal]                           OK
+ [Valid]   EF - Altair - Random - randomized_15 [Preset: minimal]                           OK
+ [Valid]   EF - Altair - Random - randomized_2 [Preset: minimal]                            OK
+ [Valid]   EF - Altair - Random - randomized_3 [Preset: minimal]                            OK
+ [Valid]   EF - Altair - Random - randomized_4 [Preset: minimal]                            OK
+ [Valid]   EF - Altair - Random - randomized_5 [Preset: minimal]                            OK
+ [Valid]   EF - Altair - Random - randomized_6 [Preset: minimal]                            OK
+ [Valid]   EF - Altair - Random - randomized_7 [Preset: minimal]                            OK
+ [Valid]   EF - Altair - Random - randomized_8 [Preset: minimal]                            OK
+ [Valid]   EF - Altair - Random - randomized_9 [Preset: minimal]                            OK
```
OK: 16/16 Fail: 0/16 Skip: 0/16
## EF - Altair - Rewards  [Preset: minimal]
```diff
+ EF - Altair - Rewards - all_balances_too_low_for_reward [Preset: minimal]                  OK
+ EF - Altair - Rewards - empty [Preset: minimal]                                            OK
+ EF - Altair - Rewards - empty_leak [Preset: minimal]                                       OK
+ EF - Altair - Rewards - full_all_correct [Preset: minimal]                                 OK
+ EF - Altair - Rewards - full_but_partial_participation [Preset: minimal]                   OK
+ EF - Altair - Rewards - full_but_partial_participation_leak [Preset: minimal]              OK
+ EF - Altair - Rewards - full_leak [Preset: minimal]                                        OK
+ EF - Altair - Rewards - full_random_0 [Preset: minimal]                                    OK
+ EF - Altair - Rewards - full_random_1 [Preset: minimal]                                    OK
+ EF - Altair - Rewards - full_random_2 [Preset: minimal]                                    OK
+ EF - Altair - Rewards - full_random_3 [Preset: minimal]                                    OK
+ EF - Altair - Rewards - full_random_4 [Preset: minimal]                                    OK
+ EF - Altair - Rewards - full_random_leak [Preset: minimal]                                 OK
+ EF - Altair - Rewards - full_random_low_balances_0 [Preset: minimal]                       OK
+ EF - Altair - Rewards - full_random_low_balances_1 [Preset: minimal]                       OK
+ EF - Altair - Rewards - full_random_misc_balances [Preset: minimal]                        OK
+ EF - Altair - Rewards - full_random_seven_epoch_leak [Preset: minimal]                     OK
+ EF - Altair - Rewards - full_random_ten_epoch_leak [Preset: minimal]                       OK
+ EF - Altair - Rewards - full_random_without_leak_0 [Preset: minimal]                       OK
+ EF - Altair - Rewards - full_random_without_leak_and_current_exit_0 [Preset: minimal]      OK
+ EF - Altair - Rewards - half_full [Preset: minimal]                                        OK
+ EF - Altair - Rewards - half_full_leak [Preset: minimal]                                   OK
+ EF - Altair - Rewards - quarter_full [Preset: minimal]                                     OK
+ EF - Altair - Rewards - quarter_full_leak [Preset: minimal]                                OK
+ EF - Altair - Rewards - some_very_low_effective_balances_that_attested [Preset: minimal]   OK
+ EF - Altair - Rewards - some_very_low_effective_balances_that_attested_leak [Preset: minim OK
+ EF - Altair - Rewards - some_very_low_effective_balances_that_did_not_attest [Preset: mini OK
+ EF - Altair - Rewards - some_very_low_effective_balances_that_did_not_attest_leak [Preset: OK
+ EF - Altair - Rewards - with_exited_validators [Preset: minimal]                           OK
+ EF - Altair - Rewards - with_exited_validators_leak [Preset: minimal]                      OK
+ EF - Altair - Rewards - with_not_yet_activated_validators [Preset: minimal]                OK
+ EF - Altair - Rewards - with_not_yet_activated_validators_leak [Preset: minimal]           OK
+ EF - Altair - Rewards - with_slashed_validators [Preset: minimal]                          OK
+ EF - Altair - Rewards - with_slashed_validators_leak [Preset: minimal]                     OK
```
OK: 34/34 Fail: 0/34 Skip: 0/34
## EF - Altair - SSZ consensus objects  [Preset: minimal]
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
+   Testing    LightClientBootstrap                                                          OK
+   Testing    LightClientFinalityUpdate                                                     OK
+   Testing    LightClientHeader                                                             OK
+   Testing    LightClientOptimisticUpdate                                                   OK
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
OK: 39/39 Fail: 0/39 Skip: 0/39
## EF - Altair - Sanity - Blocks  [Preset: minimal]
```diff
+ [Invalid] EF - Altair - Sanity - Blocks - invalid_all_zeroed_sig [Preset: minimal]         OK
+ [Invalid] EF - Altair - Sanity - Blocks - invalid_duplicate_attester_slashing_same_block [ OK
+ [Invalid] EF - Altair - Sanity - Blocks - invalid_duplicate_deposit_same_block [Preset: mi OK
+ [Invalid] EF - Altair - Sanity - Blocks - invalid_duplicate_proposer_slashings_same_block  OK
+ [Invalid] EF - Altair - Sanity - Blocks - invalid_duplicate_validator_exit_same_block [Pre OK
+ [Invalid] EF - Altair - Sanity - Blocks - invalid_incorrect_block_sig [Preset: minimal]    OK
+ [Invalid] EF - Altair - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_expect OK
+ [Invalid] EF - Altair - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_propos OK
+ [Invalid] EF - Altair - Sanity - Blocks - invalid_incorrect_state_root [Preset: minimal]   OK
+ [Invalid] EF - Altair - Sanity - Blocks - invalid_only_increase_deposit_count [Preset: min OK
+ [Invalid] EF - Altair - Sanity - Blocks - invalid_parent_from_same_slot [Preset: minimal]  OK
+ [Invalid] EF - Altair - Sanity - Blocks - invalid_prev_slot_block_transition [Preset: mini OK
+ [Invalid] EF - Altair - Sanity - Blocks - invalid_same_slot_block_transition [Preset: mini OK
+ [Invalid] EF - Altair - Sanity - Blocks - invalid_similar_proposer_slashings_same_block [P OK
+ [Invalid] EF - Altair - Sanity - Blocks - slash_and_exit_same_index [Preset: minimal]      OK
+ [Valid]   EF - Altair - Sanity - Blocks - attestation [Preset: minimal]                    OK
+ [Valid]   EF - Altair - Sanity - Blocks - attester_slashing [Preset: minimal]              OK
+ [Valid]   EF - Altair - Sanity - Blocks - balance_driven_status_transitions [Preset: minim OK
+ [Valid]   EF - Altair - Sanity - Blocks - deposit_in_block [Preset: minimal]               OK
+ [Valid]   EF - Altair - Sanity - Blocks - deposit_top_up [Preset: minimal]                 OK
+ [Valid]   EF - Altair - Sanity - Blocks - duplicate_attestation_same_block [Preset: minima OK
+ [Valid]   EF - Altair - Sanity - Blocks - empty_block_transition [Preset: minimal]         OK
+ [Valid]   EF - Altair - Sanity - Blocks - empty_block_transition_large_validator_set [Pres OK
+ [Valid]   EF - Altair - Sanity - Blocks - empty_epoch_transition [Preset: minimal]         OK
+ [Valid]   EF - Altair - Sanity - Blocks - empty_epoch_transition_large_validator_set [Pres OK
+ [Valid]   EF - Altair - Sanity - Blocks - empty_epoch_transition_not_finalizing [Preset: m OK
+ [Valid]   EF - Altair - Sanity - Blocks - eth1_data_votes_consensus [Preset: minimal]      OK
+ [Valid]   EF - Altair - Sanity - Blocks - eth1_data_votes_no_consensus [Preset: minimal]   OK
+ [Valid]   EF - Altair - Sanity - Blocks - full_random_operations_0 [Preset: minimal]       OK
+ [Valid]   EF - Altair - Sanity - Blocks - full_random_operations_1 [Preset: minimal]       OK
+ [Valid]   EF - Altair - Sanity - Blocks - full_random_operations_2 [Preset: minimal]       OK
+ [Valid]   EF - Altair - Sanity - Blocks - full_random_operations_3 [Preset: minimal]       OK
+ [Valid]   EF - Altair - Sanity - Blocks - high_proposer_index [Preset: minimal]            OK
+ [Valid]   EF - Altair - Sanity - Blocks - historical_batch [Preset: minimal]               OK
+ [Valid]   EF - Altair - Sanity - Blocks - inactivity_scores_full_participation_leaking [Pr OK
+ [Valid]   EF - Altair - Sanity - Blocks - inactivity_scores_leaking [Preset: minimal]      OK
+ [Valid]   EF - Altair - Sanity - Blocks - multiple_attester_slashings_no_overlap [Preset:  OK
+ [Valid]   EF - Altair - Sanity - Blocks - multiple_attester_slashings_partial_overlap [Pre OK
+ [Valid]   EF - Altair - Sanity - Blocks - multiple_different_proposer_slashings_same_block OK
+ [Valid]   EF - Altair - Sanity - Blocks - multiple_different_validator_exits_same_block [P OK
+ [Valid]   EF - Altair - Sanity - Blocks - proposer_after_inactive_index [Preset: minimal]  OK
+ [Valid]   EF - Altair - Sanity - Blocks - proposer_self_slashing [Preset: minimal]         OK
+ [Valid]   EF - Altair - Sanity - Blocks - proposer_slashing [Preset: minimal]              OK
+ [Valid]   EF - Altair - Sanity - Blocks - skipped_slots [Preset: minimal]                  OK
+ [Valid]   EF - Altair - Sanity - Blocks - slash_and_exit_diff_index [Preset: minimal]      OK
+ [Valid]   EF - Altair - Sanity - Blocks - sync_committee_committee__empty [Preset: minimal OK
+ [Valid]   EF - Altair - Sanity - Blocks - sync_committee_committee__full [Preset: minimal] OK
+ [Valid]   EF - Altair - Sanity - Blocks - sync_committee_committee__half [Preset: minimal] OK
+ [Valid]   EF - Altair - Sanity - Blocks - sync_committee_committee_genesis__empty [Preset: OK
+ [Valid]   EF - Altair - Sanity - Blocks - sync_committee_committee_genesis__full [Preset:  OK
+ [Valid]   EF - Altair - Sanity - Blocks - sync_committee_committee_genesis__half [Preset:  OK
+ [Valid]   EF - Altair - Sanity - Blocks - voluntary_exit [Preset: minimal]                 OK
```
OK: 52/52 Fail: 0/52 Skip: 0/52
## EF - Altair - Sanity - Slots  [Preset: minimal]
```diff
+ EF - Altair - Slots - double_empty_epoch [Preset: minimal]                                 OK
+ EF - Altair - Slots - empty_epoch [Preset: minimal]                                        OK
+ EF - Altair - Slots - historical_accumulator [Preset: minimal]                             OK
+ EF - Altair - Slots - over_epoch_boundary [Preset: minimal]                                OK
+ EF - Altair - Slots - slots_1 [Preset: minimal]                                            OK
+ EF - Altair - Slots - slots_2 [Preset: minimal]                                            OK
```
OK: 6/6 Fail: 0/6 Skip: 0/6
## EF - Altair - Transition  [Preset: minimal]
```diff
+ EF - Altair - Transition - normal_transition [Preset: minimal]                             OK
+ EF - Altair - Transition - simple_transition [Preset: minimal]                             OK
+ EF - Altair - Transition - transition_missing_first_post_block [Preset: minimal]           OK
+ EF - Altair - Transition - transition_missing_last_pre_fork_block [Preset: minimal]        OK
+ EF - Altair - Transition - transition_only_blocks_post_fork [Preset: minimal]              OK
+ EF - Altair - Transition - transition_randomized_state [Preset: minimal]                   OK
+ EF - Altair - Transition - transition_with_activation_at_fork_epoch [Preset: minimal]      OK
+ EF - Altair - Transition - transition_with_attester_slashing_right_after_fork [Preset: min OK
+ EF - Altair - Transition - transition_with_attester_slashing_right_before_fork [Preset: mi OK
+ EF - Altair - Transition - transition_with_deposit_right_after_fork [Preset: minimal]      OK
+ EF - Altair - Transition - transition_with_deposit_right_before_fork [Preset: minimal]     OK
+ EF - Altair - Transition - transition_with_finality [Preset: minimal]                      OK
+ EF - Altair - Transition - transition_with_leaking_at_fork [Preset: minimal]               OK
+ EF - Altair - Transition - transition_with_leaking_pre_fork [Preset: minimal]              OK
+ EF - Altair - Transition - transition_with_no_attestations_until_after_fork [Preset: minim OK
+ EF - Altair - Transition - transition_with_non_empty_activation_queue [Preset: minimal]    OK
+ EF - Altair - Transition - transition_with_one_fourth_exiting_validators_exit_at_fork [Pre OK
+ EF - Altair - Transition - transition_with_one_fourth_exiting_validators_exit_post_fork [P OK
+ EF - Altair - Transition - transition_with_one_fourth_slashed_active_validators_pre_fork [ OK
+ EF - Altair - Transition - transition_with_proposer_slashing_right_after_fork [Preset: min OK
+ EF - Altair - Transition - transition_with_proposer_slashing_right_before_fork [Preset: mi OK
+ EF - Altair - Transition - transition_with_random_half_participation [Preset: minimal]     OK
+ EF - Altair - Transition - transition_with_random_three_quarters_participation [Preset: mi OK
+ EF - Altair - Transition - transition_with_voluntary_exit_right_after_fork [Preset: minima OK
+ EF - Altair - Transition - transition_with_voluntary_exit_right_before_fork [Preset: minim OK
```
OK: 25/25 Fail: 0/25 Skip: 0/25
## EF - Altair - Unittests - Light client - Sync protocol [Preset: minimal]
```diff
+ process_light_client_update_finality_updated                                               OK
+ process_light_client_update_timeout                                                        OK
+ test_process_light_client_update_at_period_boundary                                        OK
+ test_process_light_client_update_not_timeout                                               OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
## EF - Bellatrix - Epoch Processing - Effective balance updates [Preset: minimal]
```diff
+ Effective balance updates - effective_balance_hysteresis [Preset: minimal]                 OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## EF - Bellatrix - Epoch Processing - Eth1 data reset [Preset: minimal]
```diff
+ Eth1 data reset - eth1_vote_no_reset [Preset: minimal]                                     OK
+ Eth1 data reset - eth1_vote_reset [Preset: minimal]                                        OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## EF - Bellatrix - Epoch Processing - Historical roots update [Preset: minimal]
```diff
+ Historical roots update - historical_root_accumulator [Preset: minimal]                    OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## EF - Bellatrix - Epoch Processing - Inactivity [Preset: minimal]
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
+ Inactivity - randomized_state [Preset: minimal]                                            OK
+ Inactivity - randomized_state_leaking [Preset: minimal]                                    OK
+ Inactivity - some_exited_full_random_leaking [Preset: minimal]                             OK
+ Inactivity - some_slashed_full_random [Preset: minimal]                                    OK
+ Inactivity - some_slashed_full_random_leaking [Preset: minimal]                            OK
+ Inactivity - some_slashed_zero_scores_full_participation [Preset: minimal]                 OK
+ Inactivity - some_slashed_zero_scores_full_participation_leaking [Preset: minimal]         OK
```
OK: 21/21 Fail: 0/21 Skip: 0/21
## EF - Bellatrix - Epoch Processing - Justification & Finalization [Preset: minimal]
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
## EF - Bellatrix - Epoch Processing - Participation flag updates [Preset: minimal]
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
## EF - Bellatrix - Epoch Processing - RANDAO mixes reset [Preset: minimal]
```diff
+ RANDAO mixes reset - updated_randao_mixes [Preset: minimal]                                OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## EF - Bellatrix - Epoch Processing - Registry updates [Preset: minimal]
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
+ Registry updates - invalid_large_withdrawable_epoch [Preset: minimal]                      OK
```
OK: 15/15 Fail: 0/15 Skip: 0/15
## EF - Bellatrix - Epoch Processing - Rewards and penalties [Preset: minimal]
```diff
+ Rewards and penalties - almost_empty_attestations [Preset: minimal]                        OK
+ Rewards and penalties - almost_empty_attestations_with_leak [Preset: minimal]              OK
+ Rewards and penalties - almost_full_attestations [Preset: minimal]                         OK
+ Rewards and penalties - almost_full_attestations_with_leak [Preset: minimal]               OK
+ Rewards and penalties - attestations_some_slashed [Preset: minimal]                        OK
+ Rewards and penalties - duplicate_attestation [Preset: minimal]                            OK
+ Rewards and penalties - full_attestation_participation [Preset: minimal]                   OK
+ Rewards and penalties - full_attestation_participation_with_leak [Preset: minimal]         OK
+ Rewards and penalties - full_attestations_misc_balances [Preset: minimal]                  OK
+ Rewards and penalties - full_attestations_one_validaor_one_gwei [Preset: minimal]          OK
+ Rewards and penalties - genesis_epoch_full_attestations_no_rewards [Preset: minimal]       OK
+ Rewards and penalties - genesis_epoch_no_attestations_no_penalties [Preset: minimal]       OK
+ Rewards and penalties - no_attestations_all_penalties [Preset: minimal]                    OK
+ Rewards and penalties - random_fill_attestations [Preset: minimal]                         OK
+ Rewards and penalties - random_fill_attestations_with_leak [Preset: minimal]               OK
```
OK: 15/15 Fail: 0/15 Skip: 0/15
## EF - Bellatrix - Epoch Processing - Slashings [Preset: minimal]
```diff
+ Slashings - low_penalty [Preset: minimal]                                                  OK
+ Slashings - max_penalties [Preset: minimal]                                                OK
+ Slashings - minimal_penalty [Preset: minimal]                                              OK
+ Slashings - scaled_penalties [Preset: minimal]                                             OK
+ Slashings - slashings_with_random_state [Preset: minimal]                                  OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## EF - Bellatrix - Epoch Processing - Slashings reset [Preset: minimal]
```diff
+ Slashings reset - flush_slashings [Preset: minimal]                                        OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## EF - Bellatrix - Epoch Processing - Sync committee updates [Preset: minimal]
```diff
+ Sync committee updates - sync_committees_no_progress_not_at_period_boundary [Preset: minim OK
+ Sync committee updates - sync_committees_progress_genesis [Preset: minimal]                OK
+ Sync committee updates - sync_committees_progress_misc_balances_genesis [Preset: minimal]  OK
+ Sync committee updates - sync_committees_progress_misc_balances_not_genesis [Preset: minim OK
+ Sync committee updates - sync_committees_progress_not_genesis [Preset: minimal]            OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## EF - Bellatrix - Finality  [Preset: minimal]
```diff
+ [Valid]   EF - Bellatrix - Finality - finality_no_updates_at_genesis [Preset: minimal]     OK
+ [Valid]   EF - Bellatrix - Finality - finality_rule_1 [Preset: minimal]                    OK
+ [Valid]   EF - Bellatrix - Finality - finality_rule_2 [Preset: minimal]                    OK
+ [Valid]   EF - Bellatrix - Finality - finality_rule_3 [Preset: minimal]                    OK
+ [Valid]   EF - Bellatrix - Finality - finality_rule_4 [Preset: minimal]                    OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## EF - Bellatrix - Fork  [Preset: minimal]
```diff
+ EF - Bellatrix - Fork - bellatrix_fork_random_0 [Preset: minimal]                          OK
+ EF - Bellatrix - Fork - bellatrix_fork_random_1 [Preset: minimal]                          OK
+ EF - Bellatrix - Fork - bellatrix_fork_random_2 [Preset: minimal]                          OK
+ EF - Bellatrix - Fork - bellatrix_fork_random_3 [Preset: minimal]                          OK
+ EF - Bellatrix - Fork - bellatrix_fork_random_large_validator_set [Preset: minimal]        OK
+ EF - Bellatrix - Fork - bellatrix_fork_random_low_balances [Preset: minimal]               OK
+ EF - Bellatrix - Fork - bellatrix_fork_random_misc_balances [Preset: minimal]              OK
+ EF - Bellatrix - Fork - fork_base_state [Preset: minimal]                                  OK
+ EF - Bellatrix - Fork - fork_many_next_epoch [Preset: minimal]                             OK
+ EF - Bellatrix - Fork - fork_next_epoch [Preset: minimal]                                  OK
+ EF - Bellatrix - Fork - fork_next_epoch_with_block [Preset: minimal]                       OK
+ EF - Bellatrix - Fork - fork_random_large_validator_set [Preset: minimal]                  OK
+ EF - Bellatrix - Fork - fork_random_low_balances [Preset: minimal]                         OK
+ EF - Bellatrix - Fork - fork_random_misc_balances [Preset: minimal]                        OK
```
OK: 14/14 Fail: 0/14 Skip: 0/14
## EF - Bellatrix - Operations - Attestation  [Preset: minimal]
```diff
+ [Invalid] EF - Bellatrix - Operations - Attestation - invalid_after_max_inclusion_slot     OK
+ [Invalid] EF - Bellatrix - Operations - Attestation - invalid_attestation_signature        OK
+ [Invalid] EF - Bellatrix - Operations - Attestation - invalid_bad_source_root              OK
+ [Invalid] EF - Bellatrix - Operations - Attestation - invalid_before_inclusion_delay       OK
+ [Invalid] EF - Bellatrix - Operations - Attestation - invalid_correct_attestation_included OK
+ [Invalid] EF - Bellatrix - Operations - Attestation - invalid_current_source_root          OK
+ [Invalid] EF - Bellatrix - Operations - Attestation - invalid_empty_participants_seemingly OK
+ [Invalid] EF - Bellatrix - Operations - Attestation - invalid_empty_participants_zeroes_si OK
+ [Invalid] EF - Bellatrix - Operations - Attestation - invalid_future_target_epoch          OK
+ [Invalid] EF - Bellatrix - Operations - Attestation - invalid_incorrect_head_and_target_in OK
+ [Invalid] EF - Bellatrix - Operations - Attestation - invalid_incorrect_head_included_afte OK
+ [Invalid] EF - Bellatrix - Operations - Attestation - invalid_incorrect_target_included_af OK
+ [Invalid] EF - Bellatrix - Operations - Attestation - invalid_index                        OK
+ [Invalid] EF - Bellatrix - Operations - Attestation - invalid_mismatched_target_and_slot   OK
+ [Invalid] EF - Bellatrix - Operations - Attestation - invalid_new_source_epoch             OK
+ [Invalid] EF - Bellatrix - Operations - Attestation - invalid_old_source_epoch             OK
+ [Invalid] EF - Bellatrix - Operations - Attestation - invalid_old_target_epoch             OK
+ [Invalid] EF - Bellatrix - Operations - Attestation - invalid_previous_source_root         OK
+ [Invalid] EF - Bellatrix - Operations - Attestation - invalid_source_root_is_target_root   OK
+ [Invalid] EF - Bellatrix - Operations - Attestation - invalid_too_few_aggregation_bits     OK
+ [Invalid] EF - Bellatrix - Operations - Attestation - invalid_too_many_aggregation_bits    OK
+ [Invalid] EF - Bellatrix - Operations - Attestation - invalid_wrong_index_for_committee_si OK
+ [Invalid] EF - Bellatrix - Operations - Attestation - invalid_wrong_index_for_slot_0       OK
+ [Invalid] EF - Bellatrix - Operations - Attestation - invalid_wrong_index_for_slot_1       OK
+ [Valid]   EF - Bellatrix - Operations - Attestation - at_max_inclusion_slot                OK
+ [Valid]   EF - Bellatrix - Operations - Attestation - correct_attestation_included_at_max_ OK
+ [Valid]   EF - Bellatrix - Operations - Attestation - correct_attestation_included_at_min_ OK
+ [Valid]   EF - Bellatrix - Operations - Attestation - correct_attestation_included_at_one_ OK
+ [Valid]   EF - Bellatrix - Operations - Attestation - correct_attestation_included_at_sqrt OK
+ [Valid]   EF - Bellatrix - Operations - Attestation - incorrect_head_and_target_included_a OK
+ [Valid]   EF - Bellatrix - Operations - Attestation - incorrect_head_and_target_included_a OK
+ [Valid]   EF - Bellatrix - Operations - Attestation - incorrect_head_and_target_min_inclus OK
+ [Valid]   EF - Bellatrix - Operations - Attestation - incorrect_head_included_at_max_inclu OK
+ [Valid]   EF - Bellatrix - Operations - Attestation - incorrect_head_included_at_min_inclu OK
+ [Valid]   EF - Bellatrix - Operations - Attestation - incorrect_head_included_at_sqrt_epoc OK
+ [Valid]   EF - Bellatrix - Operations - Attestation - incorrect_target_included_at_epoch_d OK
+ [Valid]   EF - Bellatrix - Operations - Attestation - incorrect_target_included_at_min_inc OK
+ [Valid]   EF - Bellatrix - Operations - Attestation - incorrect_target_included_at_sqrt_ep OK
+ [Valid]   EF - Bellatrix - Operations - Attestation - multi_proposer_index_iterations      OK
+ [Valid]   EF - Bellatrix - Operations - Attestation - one_basic_attestation                OK
+ [Valid]   EF - Bellatrix - Operations - Attestation - previous_epoch                       OK
```
OK: 41/41 Fail: 0/41 Skip: 0/41
## EF - Bellatrix - Operations - Attester Slashing  [Preset: minimal]
```diff
+ [Invalid] EF - Bellatrix - Operations - Attester Slashing - invalid_all_empty_indices      OK
+ [Invalid] EF - Bellatrix - Operations - Attester Slashing - invalid_att1_bad_extra_index   OK
+ [Invalid] EF - Bellatrix - Operations - Attester Slashing - invalid_att1_bad_replaced_inde OK
+ [Invalid] EF - Bellatrix - Operations - Attester Slashing - invalid_att1_duplicate_index_d OK
+ [Invalid] EF - Bellatrix - Operations - Attester Slashing - invalid_att1_duplicate_index_n OK
+ [Invalid] EF - Bellatrix - Operations - Attester Slashing - invalid_att1_empty_indices     OK
+ [Invalid] EF - Bellatrix - Operations - Attester Slashing - invalid_att1_high_index        OK
+ [Invalid] EF - Bellatrix - Operations - Attester Slashing - invalid_att2_bad_extra_index   OK
+ [Invalid] EF - Bellatrix - Operations - Attester Slashing - invalid_att2_bad_replaced_inde OK
+ [Invalid] EF - Bellatrix - Operations - Attester Slashing - invalid_att2_duplicate_index_d OK
+ [Invalid] EF - Bellatrix - Operations - Attester Slashing - invalid_att2_duplicate_index_n OK
+ [Invalid] EF - Bellatrix - Operations - Attester Slashing - invalid_att2_empty_indices     OK
+ [Invalid] EF - Bellatrix - Operations - Attester Slashing - invalid_att2_high_index        OK
+ [Invalid] EF - Bellatrix - Operations - Attester Slashing - invalid_incorrect_sig_1        OK
+ [Invalid] EF - Bellatrix - Operations - Attester Slashing - invalid_incorrect_sig_1_and_2  OK
+ [Invalid] EF - Bellatrix - Operations - Attester Slashing - invalid_incorrect_sig_2        OK
+ [Invalid] EF - Bellatrix - Operations - Attester Slashing - invalid_no_double_or_surround  OK
+ [Invalid] EF - Bellatrix - Operations - Attester Slashing - invalid_participants_already_s OK
+ [Invalid] EF - Bellatrix - Operations - Attester Slashing - invalid_same_data              OK
+ [Invalid] EF - Bellatrix - Operations - Attester Slashing - invalid_unsorted_att_1         OK
+ [Invalid] EF - Bellatrix - Operations - Attester Slashing - invalid_unsorted_att_2         OK
+ [Valid]   EF - Bellatrix - Operations - Attester Slashing - already_exited_long_ago        OK
+ [Valid]   EF - Bellatrix - Operations - Attester Slashing - already_exited_recent          OK
+ [Valid]   EF - Bellatrix - Operations - Attester Slashing - attestation_from_future        OK
+ [Valid]   EF - Bellatrix - Operations - Attester Slashing - basic_double                   OK
+ [Valid]   EF - Bellatrix - Operations - Attester Slashing - basic_surround                 OK
+ [Valid]   EF - Bellatrix - Operations - Attester Slashing - low_balances                   OK
+ [Valid]   EF - Bellatrix - Operations - Attester Slashing - misc_balances                  OK
+ [Valid]   EF - Bellatrix - Operations - Attester Slashing - proposer_index_slashed         OK
+ [Valid]   EF - Bellatrix - Operations - Attester Slashing - with_effective_balance_dispari OK
```
OK: 30/30 Fail: 0/30 Skip: 0/30
## EF - Bellatrix - Operations - Block Header  [Preset: minimal]
```diff
+ [Invalid] EF - Bellatrix - Operations - Block Header - invalid_multiple_blocks_single_slot OK
+ [Invalid] EF - Bellatrix - Operations - Block Header - invalid_parent_root                 OK
+ [Invalid] EF - Bellatrix - Operations - Block Header - invalid_proposer_index              OK
+ [Invalid] EF - Bellatrix - Operations - Block Header - invalid_proposer_slashed            OK
+ [Invalid] EF - Bellatrix - Operations - Block Header - invalid_slot_block_header           OK
+ [Valid]   EF - Bellatrix - Operations - Block Header - basic_block_header                  OK
```
OK: 6/6 Fail: 0/6 Skip: 0/6
## EF - Bellatrix - Operations - Deposit  [Preset: minimal]
```diff
+ [Invalid] EF - Bellatrix - Operations - Deposit - invalid_bad_merkle_proof                 OK
+ [Invalid] EF - Bellatrix - Operations - Deposit - invalid_wrong_deposit_for_deposit_count  OK
+ [Valid]   EF - Bellatrix - Operations - Deposit - correct_sig_but_forked_state             OK
+ [Valid]   EF - Bellatrix - Operations - Deposit - effective_deposit_with_genesis_fork_vers OK
+ [Valid]   EF - Bellatrix - Operations - Deposit - incorrect_sig_new_deposit                OK
+ [Valid]   EF - Bellatrix - Operations - Deposit - incorrect_sig_top_up                     OK
+ [Valid]   EF - Bellatrix - Operations - Deposit - incorrect_withdrawal_credentials_top_up  OK
+ [Valid]   EF - Bellatrix - Operations - Deposit - ineffective_deposit_with_bad_fork_versio OK
+ [Valid]   EF - Bellatrix - Operations - Deposit - ineffective_deposit_with_current_fork_ve OK
+ [Valid]   EF - Bellatrix - Operations - Deposit - ineffective_deposit_with_previous_fork_v OK
+ [Valid]   EF - Bellatrix - Operations - Deposit - key_validate_invalid_decompression       OK
+ [Valid]   EF - Bellatrix - Operations - Deposit - key_validate_invalid_subgroup            OK
+ [Valid]   EF - Bellatrix - Operations - Deposit - new_deposit_eth1_withdrawal_credentials  OK
+ [Valid]   EF - Bellatrix - Operations - Deposit - new_deposit_max                          OK
+ [Valid]   EF - Bellatrix - Operations - Deposit - new_deposit_non_versioned_withdrawal_cre OK
+ [Valid]   EF - Bellatrix - Operations - Deposit - new_deposit_over_max                     OK
+ [Valid]   EF - Bellatrix - Operations - Deposit - new_deposit_under_max                    OK
+ [Valid]   EF - Bellatrix - Operations - Deposit - top_up__less_effective_balance           OK
+ [Valid]   EF - Bellatrix - Operations - Deposit - top_up__max_effective_balance            OK
+ [Valid]   EF - Bellatrix - Operations - Deposit - top_up__zero_balance                     OK
```
OK: 20/20 Fail: 0/20 Skip: 0/20
## EF - Bellatrix - Operations - Execution Payload  [Preset: minimal]
```diff
+ [Invalid] EF - Bellatrix - Operations - Execution Payload - invalid_bad_everything_first_p OK
+ [Invalid] EF - Bellatrix - Operations - Execution Payload - invalid_bad_everything_regular OK
+ [Invalid] EF - Bellatrix - Operations - Execution Payload - invalid_bad_execution_first_pa OK
+ [Invalid] EF - Bellatrix - Operations - Execution Payload - invalid_bad_execution_regular_ OK
+ [Invalid] EF - Bellatrix - Operations - Execution Payload - invalid_bad_parent_hash_regula OK
+ [Invalid] EF - Bellatrix - Operations - Execution Payload - invalid_bad_pre_randao_regular OK
+ [Invalid] EF - Bellatrix - Operations - Execution Payload - invalid_bad_prev_randao_first_ OK
+ [Invalid] EF - Bellatrix - Operations - Execution Payload - invalid_future_timestamp_first OK
+ [Invalid] EF - Bellatrix - Operations - Execution Payload - invalid_future_timestamp_regul OK
+ [Invalid] EF - Bellatrix - Operations - Execution Payload - invalid_past_timestamp_first_p OK
+ [Invalid] EF - Bellatrix - Operations - Execution Payload - invalid_past_timestamp_regular OK
+ [Invalid] EF - Bellatrix - Operations - Execution Payload - invalid_randomized_non_validat OK
+ [Invalid] EF - Bellatrix - Operations - Execution Payload - invalid_randomized_non_validat OK
+ [Valid]   EF - Bellatrix - Operations - Execution Payload - bad_parent_hash_first_payload  OK
+ [Valid]   EF - Bellatrix - Operations - Execution Payload - non_empty_extra_data_first_pay OK
+ [Valid]   EF - Bellatrix - Operations - Execution Payload - non_empty_extra_data_regular_p OK
+ [Valid]   EF - Bellatrix - Operations - Execution Payload - non_empty_transactions_first_p OK
+ [Valid]   EF - Bellatrix - Operations - Execution Payload - non_empty_transactions_regular OK
+ [Valid]   EF - Bellatrix - Operations - Execution Payload - randomized_non_validated_execu OK
+ [Valid]   EF - Bellatrix - Operations - Execution Payload - randomized_non_validated_execu OK
+ [Valid]   EF - Bellatrix - Operations - Execution Payload - success_first_payload          OK
+ [Valid]   EF - Bellatrix - Operations - Execution Payload - success_first_payload_with_gap OK
+ [Valid]   EF - Bellatrix - Operations - Execution Payload - success_regular_payload        OK
+ [Valid]   EF - Bellatrix - Operations - Execution Payload - success_regular_payload_with_g OK
+ [Valid]   EF - Bellatrix - Operations - Execution Payload - zero_length_transaction_first_ OK
+ [Valid]   EF - Bellatrix - Operations - Execution Payload - zero_length_transaction_regula OK
```
OK: 26/26 Fail: 0/26 Skip: 0/26
## EF - Bellatrix - Operations - Proposer Slashing  [Preset: minimal]
```diff
+ [Invalid] EF - Bellatrix - Operations - Proposer Slashing - invalid_different_proposer_ind OK
+ [Invalid] EF - Bellatrix - Operations - Proposer Slashing - invalid_headers_are_same_sigs_ OK
+ [Invalid] EF - Bellatrix - Operations - Proposer Slashing - invalid_headers_are_same_sigs_ OK
+ [Invalid] EF - Bellatrix - Operations - Proposer Slashing - invalid_incorrect_proposer_ind OK
+ [Invalid] EF - Bellatrix - Operations - Proposer Slashing - invalid_incorrect_sig_1        OK
+ [Invalid] EF - Bellatrix - Operations - Proposer Slashing - invalid_incorrect_sig_1_and_2  OK
+ [Invalid] EF - Bellatrix - Operations - Proposer Slashing - invalid_incorrect_sig_1_and_2_ OK
+ [Invalid] EF - Bellatrix - Operations - Proposer Slashing - invalid_incorrect_sig_2        OK
+ [Invalid] EF - Bellatrix - Operations - Proposer Slashing - invalid_proposer_is_not_activa OK
+ [Invalid] EF - Bellatrix - Operations - Proposer Slashing - invalid_proposer_is_slashed    OK
+ [Invalid] EF - Bellatrix - Operations - Proposer Slashing - invalid_proposer_is_withdrawn  OK
+ [Invalid] EF - Bellatrix - Operations - Proposer Slashing - invalid_slots_of_different_epo OK
+ [Valid]   EF - Bellatrix - Operations - Proposer Slashing - basic                          OK
+ [Valid]   EF - Bellatrix - Operations - Proposer Slashing - block_header_from_future       OK
+ [Valid]   EF - Bellatrix - Operations - Proposer Slashing - slashed_and_proposer_index_the OK
```
OK: 15/15 Fail: 0/15 Skip: 0/15
## EF - Bellatrix - Operations - Sync Aggregate  [Preset: minimal]
```diff
+ [Invalid] EF - Bellatrix - Operations - Sync Aggregate - invalid_signature_bad_domain      OK
+ [Invalid] EF - Bellatrix - Operations - Sync Aggregate - invalid_signature_extra_participa OK
+ [Invalid] EF - Bellatrix - Operations - Sync Aggregate - invalid_signature_infinite_signat OK
+ [Invalid] EF - Bellatrix - Operations - Sync Aggregate - invalid_signature_infinite_signat OK
+ [Invalid] EF - Bellatrix - Operations - Sync Aggregate - invalid_signature_missing_partici OK
+ [Invalid] EF - Bellatrix - Operations - Sync Aggregate - invalid_signature_no_participants OK
+ [Invalid] EF - Bellatrix - Operations - Sync Aggregate - invalid_signature_past_block      OK
+ [Invalid] EF - Bellatrix - Operations - Sync Aggregate - invalid_signature_previous_commit OK
+ [Valid]   EF - Bellatrix - Operations - Sync Aggregate - proposer_in_committee_with_partic OK
+ [Valid]   EF - Bellatrix - Operations - Sync Aggregate - proposer_in_committee_without_par OK
+ [Valid]   EF - Bellatrix - Operations - Sync Aggregate - random_all_but_one_participating_ OK
+ [Valid]   EF - Bellatrix - Operations - Sync Aggregate - random_high_participation_without OK
+ [Valid]   EF - Bellatrix - Operations - Sync Aggregate - random_low_participation_without_ OK
+ [Valid]   EF - Bellatrix - Operations - Sync Aggregate - random_misc_balances_and_half_par OK
+ [Valid]   EF - Bellatrix - Operations - Sync Aggregate - random_only_one_participant_witho OK
+ [Valid]   EF - Bellatrix - Operations - Sync Aggregate - random_with_exits_without_duplica OK
+ [Valid]   EF - Bellatrix - Operations - Sync Aggregate - sync_committee_rewards_empty_part OK
+ [Valid]   EF - Bellatrix - Operations - Sync Aggregate - sync_committee_rewards_nonduplica OK
+ [Valid]   EF - Bellatrix - Operations - Sync Aggregate - sync_committee_rewards_not_full_p OK
+ [Valid]   EF - Bellatrix - Operations - Sync Aggregate - sync_committee_with_nonparticipat OK
+ [Valid]   EF - Bellatrix - Operations - Sync Aggregate - sync_committee_with_nonparticipat OK
+ [Valid]   EF - Bellatrix - Operations - Sync Aggregate - sync_committee_with_participating OK
+ [Valid]   EF - Bellatrix - Operations - Sync Aggregate - sync_committee_with_participating OK
+ [Valid]   EF - Bellatrix - Operations - Sync Aggregate - valid_signature_future_committee  OK
```
OK: 24/24 Fail: 0/24 Skip: 0/24
## EF - Bellatrix - Operations - Voluntary Exit  [Preset: minimal]
```diff
+ [Invalid] EF - Bellatrix - Operations - Voluntary Exit - invalid_incorrect_signature       OK
+ [Invalid] EF - Bellatrix - Operations - Voluntary Exit - invalid_validator_already_exited  OK
+ [Invalid] EF - Bellatrix - Operations - Voluntary Exit - invalid_validator_exit_in_future  OK
+ [Invalid] EF - Bellatrix - Operations - Voluntary Exit - invalid_validator_incorrect_valid OK
+ [Invalid] EF - Bellatrix - Operations - Voluntary Exit - invalid_validator_not_active      OK
+ [Invalid] EF - Bellatrix - Operations - Voluntary Exit - invalid_validator_not_active_long OK
+ [Invalid] EF - Bellatrix - Operations - Voluntary Exit - invalid_voluntary_exit_with_curre OK
+ [Invalid] EF - Bellatrix - Operations - Voluntary Exit - invalid_voluntary_exit_with_genes OK
+ [Invalid] EF - Bellatrix - Operations - Voluntary Exit - invalid_voluntary_exit_with_genes OK
+ [Invalid] EF - Bellatrix - Operations - Voluntary Exit - invalid_voluntary_exit_with_previ OK
+ [Valid]   EF - Bellatrix - Operations - Voluntary Exit - basic                             OK
+ [Valid]   EF - Bellatrix - Operations - Voluntary Exit - default_exit_epoch_subsequent_exi OK
+ [Valid]   EF - Bellatrix - Operations - Voluntary Exit - success_exit_queue__min_churn     OK
+ [Valid]   EF - Bellatrix - Operations - Voluntary Exit - success_exit_queue__scaled_churn  OK
+ [Valid]   EF - Bellatrix - Operations - Voluntary Exit - voluntary_exit_with_current_fork_ OK
+ [Valid]   EF - Bellatrix - Operations - Voluntary Exit - voluntary_exit_with_previous_fork OK
```
OK: 16/16 Fail: 0/16 Skip: 0/16
## EF - Bellatrix - Random  [Preset: minimal]
```diff
+ [Valid]   EF - Bellatrix - Random - randomized_0 [Preset: minimal]                         OK
+ [Valid]   EF - Bellatrix - Random - randomized_1 [Preset: minimal]                         OK
+ [Valid]   EF - Bellatrix - Random - randomized_10 [Preset: minimal]                        OK
+ [Valid]   EF - Bellatrix - Random - randomized_11 [Preset: minimal]                        OK
+ [Valid]   EF - Bellatrix - Random - randomized_12 [Preset: minimal]                        OK
+ [Valid]   EF - Bellatrix - Random - randomized_13 [Preset: minimal]                        OK
+ [Valid]   EF - Bellatrix - Random - randomized_14 [Preset: minimal]                        OK
+ [Valid]   EF - Bellatrix - Random - randomized_15 [Preset: minimal]                        OK
+ [Valid]   EF - Bellatrix - Random - randomized_2 [Preset: minimal]                         OK
+ [Valid]   EF - Bellatrix - Random - randomized_3 [Preset: minimal]                         OK
+ [Valid]   EF - Bellatrix - Random - randomized_4 [Preset: minimal]                         OK
+ [Valid]   EF - Bellatrix - Random - randomized_5 [Preset: minimal]                         OK
+ [Valid]   EF - Bellatrix - Random - randomized_6 [Preset: minimal]                         OK
+ [Valid]   EF - Bellatrix - Random - randomized_7 [Preset: minimal]                         OK
+ [Valid]   EF - Bellatrix - Random - randomized_8 [Preset: minimal]                         OK
+ [Valid]   EF - Bellatrix - Random - randomized_9 [Preset: minimal]                         OK
```
OK: 16/16 Fail: 0/16 Skip: 0/16
## EF - Bellatrix - Rewards  [Preset: minimal]
```diff
+ EF - Bellatrix - Rewards - all_balances_too_low_for_reward [Preset: minimal]               OK
+ EF - Bellatrix - Rewards - empty [Preset: minimal]                                         OK
+ EF - Bellatrix - Rewards - empty_leak [Preset: minimal]                                    OK
+ EF - Bellatrix - Rewards - full_all_correct [Preset: minimal]                              OK
+ EF - Bellatrix - Rewards - full_but_partial_participation [Preset: minimal]                OK
+ EF - Bellatrix - Rewards - full_but_partial_participation_leak [Preset: minimal]           OK
+ EF - Bellatrix - Rewards - full_leak [Preset: minimal]                                     OK
+ EF - Bellatrix - Rewards - full_random_0 [Preset: minimal]                                 OK
+ EF - Bellatrix - Rewards - full_random_1 [Preset: minimal]                                 OK
+ EF - Bellatrix - Rewards - full_random_2 [Preset: minimal]                                 OK
+ EF - Bellatrix - Rewards - full_random_3 [Preset: minimal]                                 OK
+ EF - Bellatrix - Rewards - full_random_4 [Preset: minimal]                                 OK
+ EF - Bellatrix - Rewards - full_random_leak [Preset: minimal]                              OK
+ EF - Bellatrix - Rewards - full_random_low_balances_0 [Preset: minimal]                    OK
+ EF - Bellatrix - Rewards - full_random_low_balances_1 [Preset: minimal]                    OK
+ EF - Bellatrix - Rewards - full_random_misc_balances [Preset: minimal]                     OK
+ EF - Bellatrix - Rewards - full_random_seven_epoch_leak [Preset: minimal]                  OK
+ EF - Bellatrix - Rewards - full_random_ten_epoch_leak [Preset: minimal]                    OK
+ EF - Bellatrix - Rewards - full_random_without_leak_0 [Preset: minimal]                    OK
+ EF - Bellatrix - Rewards - full_random_without_leak_and_current_exit_0 [Preset: minimal]   OK
+ EF - Bellatrix - Rewards - half_full [Preset: minimal]                                     OK
+ EF - Bellatrix - Rewards - half_full_leak [Preset: minimal]                                OK
+ EF - Bellatrix - Rewards - quarter_full [Preset: minimal]                                  OK
+ EF - Bellatrix - Rewards - quarter_full_leak [Preset: minimal]                             OK
+ EF - Bellatrix - Rewards - some_very_low_effective_balances_that_attested [Preset: minimal OK
+ EF - Bellatrix - Rewards - some_very_low_effective_balances_that_attested_leak [Preset: mi OK
+ EF - Bellatrix - Rewards - some_very_low_effective_balances_that_did_not_attest [Preset: m OK
+ EF - Bellatrix - Rewards - some_very_low_effective_balances_that_did_not_attest_leak [Pres OK
+ EF - Bellatrix - Rewards - with_exited_validators [Preset: minimal]                        OK
+ EF - Bellatrix - Rewards - with_exited_validators_leak [Preset: minimal]                   OK
+ EF - Bellatrix - Rewards - with_not_yet_activated_validators [Preset: minimal]             OK
+ EF - Bellatrix - Rewards - with_not_yet_activated_validators_leak [Preset: minimal]        OK
+ EF - Bellatrix - Rewards - with_slashed_validators [Preset: minimal]                       OK
+ EF - Bellatrix - Rewards - with_slashed_validators_leak [Preset: minimal]                  OK
```
OK: 34/34 Fail: 0/34 Skip: 0/34
## EF - Bellatrix - SSZ consensus objects  [Preset: minimal]
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
+   Testing    ExecutionPayload                                                              OK
+   Testing    ExecutionPayloadHeader                                                        OK
+   Testing    Fork                                                                          OK
+   Testing    ForkData                                                                      OK
+   Testing    HistoricalBatch                                                               OK
+   Testing    IndexedAttestation                                                            OK
+   Testing    LightClientBootstrap                                                          OK
+   Testing    LightClientFinalityUpdate                                                     OK
+   Testing    LightClientHeader                                                             OK
+   Testing    LightClientOptimisticUpdate                                                   OK
+   Testing    LightClientUpdate                                                             OK
+   Testing    PendingAttestation                                                            OK
+   Testing    PowBlock                                                                      OK
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
OK: 42/42 Fail: 0/42 Skip: 0/42
## EF - Bellatrix - Sanity - Blocks  [Preset: minimal]
```diff
+ [Invalid] EF - Bellatrix - Sanity - Blocks - invalid_all_zeroed_sig [Preset: minimal]      OK
+ [Invalid] EF - Bellatrix - Sanity - Blocks - invalid_duplicate_attester_slashing_same_bloc OK
+ [Invalid] EF - Bellatrix - Sanity - Blocks - invalid_duplicate_deposit_same_block [Preset: OK
+ [Invalid] EF - Bellatrix - Sanity - Blocks - invalid_duplicate_proposer_slashings_same_blo OK
+ [Invalid] EF - Bellatrix - Sanity - Blocks - invalid_duplicate_validator_exit_same_block [ OK
+ [Invalid] EF - Bellatrix - Sanity - Blocks - invalid_incorrect_block_sig [Preset: minimal] OK
+ [Invalid] EF - Bellatrix - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_exp OK
+ [Invalid] EF - Bellatrix - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_pro OK
+ [Invalid] EF - Bellatrix - Sanity - Blocks - invalid_incorrect_state_root [Preset: minimal OK
+ [Invalid] EF - Bellatrix - Sanity - Blocks - invalid_only_increase_deposit_count [Preset:  OK
+ [Invalid] EF - Bellatrix - Sanity - Blocks - invalid_parent_from_same_slot [Preset: minima OK
+ [Invalid] EF - Bellatrix - Sanity - Blocks - invalid_prev_slot_block_transition [Preset: m OK
+ [Invalid] EF - Bellatrix - Sanity - Blocks - invalid_same_slot_block_transition [Preset: m OK
+ [Invalid] EF - Bellatrix - Sanity - Blocks - invalid_similar_proposer_slashings_same_block OK
+ [Invalid] EF - Bellatrix - Sanity - Blocks - slash_and_exit_same_index [Preset: minimal]   OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - attestation [Preset: minimal]                 OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - attester_slashing [Preset: minimal]           OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - balance_driven_status_transitions [Preset: mi OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - block_transition_randomized_payload [Preset:  OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - deposit_in_block [Preset: minimal]            OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - deposit_top_up [Preset: minimal]              OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - duplicate_attestation_same_block [Preset: min OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - empty_block_transition [Preset: minimal]      OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - empty_block_transition_large_validator_set [P OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - empty_block_transition_no_tx [Preset: minimal OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - empty_epoch_transition [Preset: minimal]      OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - empty_epoch_transition_large_validator_set [P OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - empty_epoch_transition_not_finalizing [Preset OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - eth1_data_votes_consensus [Preset: minimal]   OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - eth1_data_votes_no_consensus [Preset: minimal OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - full_random_operations_0 [Preset: minimal]    OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - full_random_operations_1 [Preset: minimal]    OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - full_random_operations_2 [Preset: minimal]    OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - full_random_operations_3 [Preset: minimal]    OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - high_proposer_index [Preset: minimal]         OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - historical_batch [Preset: minimal]            OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - inactivity_scores_full_participation_leaking  OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - inactivity_scores_leaking [Preset: minimal]   OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - is_execution_enabled_false [Preset: minimal]  OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - multiple_attester_slashings_no_overlap [Prese OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - multiple_attester_slashings_partial_overlap [ OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - multiple_different_proposer_slashings_same_bl OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - multiple_different_validator_exits_same_block OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - proposer_after_inactive_index [Preset: minima OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - proposer_self_slashing [Preset: minimal]      OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - proposer_slashing [Preset: minimal]           OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - skipped_slots [Preset: minimal]               OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - slash_and_exit_diff_index [Preset: minimal]   OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - sync_committee_committee__empty [Preset: mini OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - sync_committee_committee__full [Preset: minim OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - sync_committee_committee__half [Preset: minim OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - sync_committee_committee_genesis__empty [Pres OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - sync_committee_committee_genesis__full [Prese OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - sync_committee_committee_genesis__half [Prese OK
+ [Valid]   EF - Bellatrix - Sanity - Blocks - voluntary_exit [Preset: minimal]              OK
```
OK: 55/55 Fail: 0/55 Skip: 0/55
## EF - Bellatrix - Sanity - Slots  [Preset: minimal]
```diff
+ EF - Bellatrix - Slots - double_empty_epoch [Preset: minimal]                              OK
+ EF - Bellatrix - Slots - empty_epoch [Preset: minimal]                                     OK
+ EF - Bellatrix - Slots - historical_accumulator [Preset: minimal]                          OK
+ EF - Bellatrix - Slots - over_epoch_boundary [Preset: minimal]                             OK
+ EF - Bellatrix - Slots - slots_1 [Preset: minimal]                                         OK
+ EF - Bellatrix - Slots - slots_2 [Preset: minimal]                                         OK
```
OK: 6/6 Fail: 0/6 Skip: 0/6
## EF - Bellatrix - Transition  [Preset: minimal]
```diff
+ EF - Bellatrix - Transition - normal_transition [Preset: minimal]                          OK
+ EF - Bellatrix - Transition - simple_transition [Preset: minimal]                          OK
+ EF - Bellatrix - Transition - transition_missing_first_post_block [Preset: minimal]        OK
+ EF - Bellatrix - Transition - transition_missing_last_pre_fork_block [Preset: minimal]     OK
+ EF - Bellatrix - Transition - transition_only_blocks_post_fork [Preset: minimal]           OK
+ EF - Bellatrix - Transition - transition_randomized_state [Preset: minimal]                OK
+ EF - Bellatrix - Transition - transition_with_activation_at_fork_epoch [Preset: minimal]   OK
+ EF - Bellatrix - Transition - transition_with_attester_slashing_right_after_fork [Preset:  OK
+ EF - Bellatrix - Transition - transition_with_attester_slashing_right_before_fork [Preset: OK
+ EF - Bellatrix - Transition - transition_with_deposit_right_after_fork [Preset: minimal]   OK
+ EF - Bellatrix - Transition - transition_with_deposit_right_before_fork [Preset: minimal]  OK
+ EF - Bellatrix - Transition - transition_with_finality [Preset: minimal]                   OK
+ EF - Bellatrix - Transition - transition_with_leaking_at_fork [Preset: minimal]            OK
+ EF - Bellatrix - Transition - transition_with_leaking_pre_fork [Preset: minimal]           OK
+ EF - Bellatrix - Transition - transition_with_no_attestations_until_after_fork [Preset: mi OK
+ EF - Bellatrix - Transition - transition_with_non_empty_activation_queue [Preset: minimal] OK
+ EF - Bellatrix - Transition - transition_with_one_fourth_exiting_validators_exit_at_fork [ OK
+ EF - Bellatrix - Transition - transition_with_one_fourth_exiting_validators_exit_post_fork OK
+ EF - Bellatrix - Transition - transition_with_one_fourth_slashed_active_validators_pre_for OK
+ EF - Bellatrix - Transition - transition_with_proposer_slashing_right_after_fork [Preset:  OK
+ EF - Bellatrix - Transition - transition_with_proposer_slashing_right_before_fork [Preset: OK
+ EF - Bellatrix - Transition - transition_with_random_half_participation [Preset: minimal]  OK
+ EF - Bellatrix - Transition - transition_with_random_three_quarters_participation [Preset: OK
+ EF - Bellatrix - Transition - transition_with_voluntary_exit_right_after_fork [Preset: min OK
+ EF - Bellatrix - Transition - transition_with_voluntary_exit_right_before_fork [Preset: mi OK
```
OK: 25/25 Fail: 0/25 Skip: 0/25
## EF - Capella - Epoch Processing - Effective balance updates [Preset: minimal]
```diff
+ Effective balance updates - effective_balance_hysteresis [Preset: minimal]                 OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## EF - Capella - Epoch Processing - Eth1 data reset [Preset: minimal]
```diff
+ Eth1 data reset - eth1_vote_no_reset [Preset: minimal]                                     OK
+ Eth1 data reset - eth1_vote_reset [Preset: minimal]                                        OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## EF - Capella - Epoch Processing - Historical summaries update [Preset: minimal]
```diff
+ Historical summaries update - historical_summaries_accumulator [Preset: minimal]           OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## EF - Capella - Epoch Processing - Inactivity [Preset: minimal]
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
+ Inactivity - randomized_state [Preset: minimal]                                            OK
+ Inactivity - randomized_state_leaking [Preset: minimal]                                    OK
+ Inactivity - some_exited_full_random_leaking [Preset: minimal]                             OK
+ Inactivity - some_slashed_full_random [Preset: minimal]                                    OK
+ Inactivity - some_slashed_full_random_leaking [Preset: minimal]                            OK
+ Inactivity - some_slashed_zero_scores_full_participation [Preset: minimal]                 OK
+ Inactivity - some_slashed_zero_scores_full_participation_leaking [Preset: minimal]         OK
```
OK: 21/21 Fail: 0/21 Skip: 0/21
## EF - Capella - Epoch Processing - Justification & Finalization [Preset: minimal]
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
## EF - Capella - Epoch Processing - Participation flag updates [Preset: minimal]
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
## EF - Capella - Epoch Processing - RANDAO mixes reset [Preset: minimal]
```diff
+ RANDAO mixes reset - updated_randao_mixes [Preset: minimal]                                OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## EF - Capella - Epoch Processing - Registry updates [Preset: minimal]
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
+ Registry updates - invalid_large_withdrawable_epoch [Preset: minimal]                      OK
```
OK: 15/15 Fail: 0/15 Skip: 0/15
## EF - Capella - Epoch Processing - Rewards and penalties [Preset: minimal]
```diff
+ Rewards and penalties - almost_empty_attestations [Preset: minimal]                        OK
+ Rewards and penalties - almost_empty_attestations_with_leak [Preset: minimal]              OK
+ Rewards and penalties - almost_full_attestations [Preset: minimal]                         OK
+ Rewards and penalties - almost_full_attestations_with_leak [Preset: minimal]               OK
+ Rewards and penalties - attestations_some_slashed [Preset: minimal]                        OK
+ Rewards and penalties - duplicate_attestation [Preset: minimal]                            OK
+ Rewards and penalties - full_attestation_participation [Preset: minimal]                   OK
+ Rewards and penalties - full_attestation_participation_with_leak [Preset: minimal]         OK
+ Rewards and penalties - full_attestations_misc_balances [Preset: minimal]                  OK
+ Rewards and penalties - full_attestations_one_validaor_one_gwei [Preset: minimal]          OK
+ Rewards and penalties - genesis_epoch_full_attestations_no_rewards [Preset: minimal]       OK
+ Rewards and penalties - genesis_epoch_no_attestations_no_penalties [Preset: minimal]       OK
+ Rewards and penalties - no_attestations_all_penalties [Preset: minimal]                    OK
+ Rewards and penalties - random_fill_attestations [Preset: minimal]                         OK
+ Rewards and penalties - random_fill_attestations_with_leak [Preset: minimal]               OK
```
OK: 15/15 Fail: 0/15 Skip: 0/15
## EF - Capella - Epoch Processing - Slashings [Preset: minimal]
```diff
+ Slashings - low_penalty [Preset: minimal]                                                  OK
+ Slashings - max_penalties [Preset: minimal]                                                OK
+ Slashings - minimal_penalty [Preset: minimal]                                              OK
+ Slashings - scaled_penalties [Preset: minimal]                                             OK
+ Slashings - slashings_with_random_state [Preset: minimal]                                  OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## EF - Capella - Epoch Processing - Slashings reset [Preset: minimal]
```diff
+ Slashings reset - flush_slashings [Preset: minimal]                                        OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## EF - Capella - Epoch Processing - Sync committee updates [Preset: minimal]
```diff
+ Sync committee updates - sync_committees_no_progress_not_at_period_boundary [Preset: minim OK
+ Sync committee updates - sync_committees_progress_genesis [Preset: minimal]                OK
+ Sync committee updates - sync_committees_progress_misc_balances_genesis [Preset: minimal]  OK
+ Sync committee updates - sync_committees_progress_misc_balances_not_genesis [Preset: minim OK
+ Sync committee updates - sync_committees_progress_not_genesis [Preset: minimal]            OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## EF - Capella - Finality  [Preset: minimal]
```diff
+ [Valid]   EF - Capella - Finality - finality_no_updates_at_genesis [Preset: minimal]       OK
+ [Valid]   EF - Capella - Finality - finality_rule_1 [Preset: minimal]                      OK
+ [Valid]   EF - Capella - Finality - finality_rule_2 [Preset: minimal]                      OK
+ [Valid]   EF - Capella - Finality - finality_rule_3 [Preset: minimal]                      OK
+ [Valid]   EF - Capella - Finality - finality_rule_4 [Preset: minimal]                      OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## EF - Capella - Fork  [Preset: minimal]
```diff
+ EF - Capella - Fork - capella_fork_random_0 [Preset: minimal]                              OK
+ EF - Capella - Fork - capella_fork_random_1 [Preset: minimal]                              OK
+ EF - Capella - Fork - capella_fork_random_2 [Preset: minimal]                              OK
+ EF - Capella - Fork - capella_fork_random_3 [Preset: minimal]                              OK
+ EF - Capella - Fork - capella_fork_random_large_validator_set [Preset: minimal]            OK
+ EF - Capella - Fork - capella_fork_random_low_balances [Preset: minimal]                   OK
+ EF - Capella - Fork - capella_fork_random_misc_balances [Preset: minimal]                  OK
+ EF - Capella - Fork - fork_base_state [Preset: minimal]                                    OK
+ EF - Capella - Fork - fork_many_next_epoch [Preset: minimal]                               OK
+ EF - Capella - Fork - fork_next_epoch [Preset: minimal]                                    OK
+ EF - Capella - Fork - fork_next_epoch_with_block [Preset: minimal]                         OK
+ EF - Capella - Fork - fork_random_large_validator_set [Preset: minimal]                    OK
+ EF - Capella - Fork - fork_random_low_balances [Preset: minimal]                           OK
+ EF - Capella - Fork - fork_random_misc_balances [Preset: minimal]                          OK
```
OK: 14/14 Fail: 0/14 Skip: 0/14
## EF - Capella - Operations - Attestation  [Preset: minimal]
```diff
+ [Invalid] EF - Capella - Operations - Attestation - invalid_after_max_inclusion_slot       OK
+ [Invalid] EF - Capella - Operations - Attestation - invalid_attestation_signature          OK
+ [Invalid] EF - Capella - Operations - Attestation - invalid_bad_source_root                OK
+ [Invalid] EF - Capella - Operations - Attestation - invalid_before_inclusion_delay         OK
+ [Invalid] EF - Capella - Operations - Attestation - invalid_correct_attestation_included_a OK
+ [Invalid] EF - Capella - Operations - Attestation - invalid_current_source_root            OK
+ [Invalid] EF - Capella - Operations - Attestation - invalid_empty_participants_seemingly_v OK
+ [Invalid] EF - Capella - Operations - Attestation - invalid_empty_participants_zeroes_sig  OK
+ [Invalid] EF - Capella - Operations - Attestation - invalid_future_target_epoch            OK
+ [Invalid] EF - Capella - Operations - Attestation - invalid_incorrect_head_and_target_incl OK
+ [Invalid] EF - Capella - Operations - Attestation - invalid_incorrect_head_included_after_ OK
+ [Invalid] EF - Capella - Operations - Attestation - invalid_incorrect_target_included_afte OK
+ [Invalid] EF - Capella - Operations - Attestation - invalid_index                          OK
+ [Invalid] EF - Capella - Operations - Attestation - invalid_mismatched_target_and_slot     OK
+ [Invalid] EF - Capella - Operations - Attestation - invalid_new_source_epoch               OK
+ [Invalid] EF - Capella - Operations - Attestation - invalid_old_source_epoch               OK
+ [Invalid] EF - Capella - Operations - Attestation - invalid_old_target_epoch               OK
+ [Invalid] EF - Capella - Operations - Attestation - invalid_previous_source_root           OK
+ [Invalid] EF - Capella - Operations - Attestation - invalid_source_root_is_target_root     OK
+ [Invalid] EF - Capella - Operations - Attestation - invalid_too_few_aggregation_bits       OK
+ [Invalid] EF - Capella - Operations - Attestation - invalid_too_many_aggregation_bits      OK
+ [Invalid] EF - Capella - Operations - Attestation - invalid_wrong_index_for_committee_sign OK
+ [Invalid] EF - Capella - Operations - Attestation - invalid_wrong_index_for_slot_0         OK
+ [Invalid] EF - Capella - Operations - Attestation - invalid_wrong_index_for_slot_1         OK
+ [Valid]   EF - Capella - Operations - Attestation - at_max_inclusion_slot                  OK
+ [Valid]   EF - Capella - Operations - Attestation - correct_attestation_included_at_max_in OK
+ [Valid]   EF - Capella - Operations - Attestation - correct_attestation_included_at_min_in OK
+ [Valid]   EF - Capella - Operations - Attestation - correct_attestation_included_at_one_ep OK
+ [Valid]   EF - Capella - Operations - Attestation - correct_attestation_included_at_sqrt_e OK
+ [Valid]   EF - Capella - Operations - Attestation - incorrect_head_and_target_included_at_ OK
+ [Valid]   EF - Capella - Operations - Attestation - incorrect_head_and_target_included_at_ OK
+ [Valid]   EF - Capella - Operations - Attestation - incorrect_head_and_target_min_inclusio OK
+ [Valid]   EF - Capella - Operations - Attestation - incorrect_head_included_at_max_inclusi OK
+ [Valid]   EF - Capella - Operations - Attestation - incorrect_head_included_at_min_inclusi OK
+ [Valid]   EF - Capella - Operations - Attestation - incorrect_head_included_at_sqrt_epoch_ OK
+ [Valid]   EF - Capella - Operations - Attestation - incorrect_target_included_at_epoch_del OK
+ [Valid]   EF - Capella - Operations - Attestation - incorrect_target_included_at_min_inclu OK
+ [Valid]   EF - Capella - Operations - Attestation - incorrect_target_included_at_sqrt_epoc OK
+ [Valid]   EF - Capella - Operations - Attestation - multi_proposer_index_iterations        OK
+ [Valid]   EF - Capella - Operations - Attestation - one_basic_attestation                  OK
+ [Valid]   EF - Capella - Operations - Attestation - previous_epoch                         OK
```
OK: 41/41 Fail: 0/41 Skip: 0/41
## EF - Capella - Operations - Attester Slashing  [Preset: minimal]
```diff
+ [Invalid] EF - Capella - Operations - Attester Slashing - invalid_all_empty_indices        OK
+ [Invalid] EF - Capella - Operations - Attester Slashing - invalid_att1_bad_extra_index     OK
+ [Invalid] EF - Capella - Operations - Attester Slashing - invalid_att1_bad_replaced_index  OK
+ [Invalid] EF - Capella - Operations - Attester Slashing - invalid_att1_duplicate_index_dou OK
+ [Invalid] EF - Capella - Operations - Attester Slashing - invalid_att1_duplicate_index_nor OK
+ [Invalid] EF - Capella - Operations - Attester Slashing - invalid_att1_empty_indices       OK
+ [Invalid] EF - Capella - Operations - Attester Slashing - invalid_att1_high_index          OK
+ [Invalid] EF - Capella - Operations - Attester Slashing - invalid_att2_bad_extra_index     OK
+ [Invalid] EF - Capella - Operations - Attester Slashing - invalid_att2_bad_replaced_index  OK
+ [Invalid] EF - Capella - Operations - Attester Slashing - invalid_att2_duplicate_index_dou OK
+ [Invalid] EF - Capella - Operations - Attester Slashing - invalid_att2_duplicate_index_nor OK
+ [Invalid] EF - Capella - Operations - Attester Slashing - invalid_att2_empty_indices       OK
+ [Invalid] EF - Capella - Operations - Attester Slashing - invalid_att2_high_index          OK
+ [Invalid] EF - Capella - Operations - Attester Slashing - invalid_incorrect_sig_1          OK
+ [Invalid] EF - Capella - Operations - Attester Slashing - invalid_incorrect_sig_1_and_2    OK
+ [Invalid] EF - Capella - Operations - Attester Slashing - invalid_incorrect_sig_2          OK
+ [Invalid] EF - Capella - Operations - Attester Slashing - invalid_no_double_or_surround    OK
+ [Invalid] EF - Capella - Operations - Attester Slashing - invalid_participants_already_sla OK
+ [Invalid] EF - Capella - Operations - Attester Slashing - invalid_same_data                OK
+ [Invalid] EF - Capella - Operations - Attester Slashing - invalid_unsorted_att_1           OK
+ [Invalid] EF - Capella - Operations - Attester Slashing - invalid_unsorted_att_2           OK
+ [Valid]   EF - Capella - Operations - Attester Slashing - already_exited_long_ago          OK
+ [Valid]   EF - Capella - Operations - Attester Slashing - already_exited_recent            OK
+ [Valid]   EF - Capella - Operations - Attester Slashing - attestation_from_future          OK
+ [Valid]   EF - Capella - Operations - Attester Slashing - basic_double                     OK
+ [Valid]   EF - Capella - Operations - Attester Slashing - basic_surround                   OK
+ [Valid]   EF - Capella - Operations - Attester Slashing - low_balances                     OK
+ [Valid]   EF - Capella - Operations - Attester Slashing - misc_balances                    OK
+ [Valid]   EF - Capella - Operations - Attester Slashing - proposer_index_slashed           OK
+ [Valid]   EF - Capella - Operations - Attester Slashing - with_effective_balance_disparity OK
```
OK: 30/30 Fail: 0/30 Skip: 0/30
## EF - Capella - Operations - BLS to execution change  [Preset: minimal]
```diff
+ [Invalid] EF - Capella - Operations - BLS to execution change - invalid_already_0x01       OK
+ [Invalid] EF - Capella - Operations - BLS to execution change - invalid_bad_signature      OK
+ [Invalid] EF - Capella - Operations - BLS to execution change - invalid_current_fork_versi OK
+ [Invalid] EF - Capella - Operations - BLS to execution change - invalid_genesis_validators OK
+ [Invalid] EF - Capella - Operations - BLS to execution change - invalid_incorrect_from_bls OK
+ [Invalid] EF - Capella - Operations - BLS to execution change - invalid_previous_fork_vers OK
+ [Invalid] EF - Capella - Operations - BLS to execution change - invalid_val_index_out_of_r OK
+ [Valid]   EF - Capella - Operations - BLS to execution change - genesis_fork_version       OK
+ [Valid]   EF - Capella - Operations - BLS to execution change - success                    OK
+ [Valid]   EF - Capella - Operations - BLS to execution change - success_exited             OK
+ [Valid]   EF - Capella - Operations - BLS to execution change - success_in_activation_queu OK
+ [Valid]   EF - Capella - Operations - BLS to execution change - success_in_exit_queue      OK
+ [Valid]   EF - Capella - Operations - BLS to execution change - success_not_activated      OK
+ [Valid]   EF - Capella - Operations - BLS to execution change - success_withdrawable       OK
```
OK: 14/14 Fail: 0/14 Skip: 0/14
## EF - Capella - Operations - Block Header  [Preset: minimal]
```diff
+ [Invalid] EF - Capella - Operations - Block Header - invalid_multiple_blocks_single_slot   OK
+ [Invalid] EF - Capella - Operations - Block Header - invalid_parent_root                   OK
+ [Invalid] EF - Capella - Operations - Block Header - invalid_proposer_index                OK
+ [Invalid] EF - Capella - Operations - Block Header - invalid_proposer_slashed              OK
+ [Invalid] EF - Capella - Operations - Block Header - invalid_slot_block_header             OK
+ [Valid]   EF - Capella - Operations - Block Header - basic_block_header                    OK
```
OK: 6/6 Fail: 0/6 Skip: 0/6
## EF - Capella - Operations - Deposit  [Preset: minimal]
```diff
+ [Invalid] EF - Capella - Operations - Deposit - invalid_bad_merkle_proof                   OK
+ [Invalid] EF - Capella - Operations - Deposit - invalid_wrong_deposit_for_deposit_count    OK
+ [Valid]   EF - Capella - Operations - Deposit - correct_sig_but_forked_state               OK
+ [Valid]   EF - Capella - Operations - Deposit - effective_deposit_with_genesis_fork_versio OK
+ [Valid]   EF - Capella - Operations - Deposit - incorrect_sig_new_deposit                  OK
+ [Valid]   EF - Capella - Operations - Deposit - incorrect_sig_top_up                       OK
+ [Valid]   EF - Capella - Operations - Deposit - incorrect_withdrawal_credentials_top_up    OK
+ [Valid]   EF - Capella - Operations - Deposit - ineffective_deposit_with_bad_fork_version  OK
+ [Valid]   EF - Capella - Operations - Deposit - ineffective_deposit_with_current_fork_vers OK
+ [Valid]   EF - Capella - Operations - Deposit - ineffective_deposit_with_previous_fork_ver OK
+ [Valid]   EF - Capella - Operations - Deposit - key_validate_invalid_decompression         OK
+ [Valid]   EF - Capella - Operations - Deposit - key_validate_invalid_subgroup              OK
+ [Valid]   EF - Capella - Operations - Deposit - new_deposit_eth1_withdrawal_credentials    OK
+ [Valid]   EF - Capella - Operations - Deposit - new_deposit_max                            OK
+ [Valid]   EF - Capella - Operations - Deposit - new_deposit_non_versioned_withdrawal_crede OK
+ [Valid]   EF - Capella - Operations - Deposit - new_deposit_over_max                       OK
+ [Valid]   EF - Capella - Operations - Deposit - new_deposit_under_max                      OK
+ [Valid]   EF - Capella - Operations - Deposit - success_top_up_to_withdrawn_validator      OK
+ [Valid]   EF - Capella - Operations - Deposit - top_up__less_effective_balance             OK
+ [Valid]   EF - Capella - Operations - Deposit - top_up__max_effective_balance              OK
+ [Valid]   EF - Capella - Operations - Deposit - top_up__zero_balance                       OK
```
OK: 21/21 Fail: 0/21 Skip: 0/21
## EF - Capella - Operations - Execution Payload  [Preset: minimal]
```diff
+ [Invalid] EF - Capella - Operations - Execution Payload - invalid_bad_everything_first_pay OK
+ [Invalid] EF - Capella - Operations - Execution Payload - invalid_bad_everything_regular_p OK
+ [Invalid] EF - Capella - Operations - Execution Payload - invalid_bad_execution_first_payl OK
+ [Invalid] EF - Capella - Operations - Execution Payload - invalid_bad_execution_regular_pa OK
+ [Invalid] EF - Capella - Operations - Execution Payload - invalid_bad_parent_hash_first_pa OK
+ [Invalid] EF - Capella - Operations - Execution Payload - invalid_bad_parent_hash_regular_ OK
+ [Invalid] EF - Capella - Operations - Execution Payload - invalid_bad_pre_randao_regular_p OK
+ [Invalid] EF - Capella - Operations - Execution Payload - invalid_bad_prev_randao_first_pa OK
+ [Invalid] EF - Capella - Operations - Execution Payload - invalid_future_timestamp_first_p OK
+ [Invalid] EF - Capella - Operations - Execution Payload - invalid_future_timestamp_regular OK
+ [Invalid] EF - Capella - Operations - Execution Payload - invalid_past_timestamp_first_pay OK
+ [Invalid] EF - Capella - Operations - Execution Payload - invalid_past_timestamp_regular_p OK
+ [Invalid] EF - Capella - Operations - Execution Payload - invalid_randomized_non_validated OK
+ [Invalid] EF - Capella - Operations - Execution Payload - invalid_randomized_non_validated OK
+ [Valid]   EF - Capella - Operations - Execution Payload - non_empty_extra_data_first_paylo OK
+ [Valid]   EF - Capella - Operations - Execution Payload - non_empty_extra_data_regular_pay OK
+ [Valid]   EF - Capella - Operations - Execution Payload - non_empty_transactions_first_pay OK
+ [Valid]   EF - Capella - Operations - Execution Payload - non_empty_transactions_regular_p OK
+ [Valid]   EF - Capella - Operations - Execution Payload - randomized_non_validated_executi OK
+ [Valid]   EF - Capella - Operations - Execution Payload - randomized_non_validated_executi OK
+ [Valid]   EF - Capella - Operations - Execution Payload - success_first_payload            OK
+ [Valid]   EF - Capella - Operations - Execution Payload - success_first_payload_with_gap_s OK
+ [Valid]   EF - Capella - Operations - Execution Payload - success_regular_payload          OK
+ [Valid]   EF - Capella - Operations - Execution Payload - success_regular_payload_with_gap OK
+ [Valid]   EF - Capella - Operations - Execution Payload - zero_length_transaction_first_pa OK
+ [Valid]   EF - Capella - Operations - Execution Payload - zero_length_transaction_regular_ OK
```
OK: 26/26 Fail: 0/26 Skip: 0/26
## EF - Capella - Operations - Proposer Slashing  [Preset: minimal]
```diff
+ [Invalid] EF - Capella - Operations - Proposer Slashing - invalid_different_proposer_indic OK
+ [Invalid] EF - Capella - Operations - Proposer Slashing - invalid_headers_are_same_sigs_ar OK
+ [Invalid] EF - Capella - Operations - Proposer Slashing - invalid_headers_are_same_sigs_ar OK
+ [Invalid] EF - Capella - Operations - Proposer Slashing - invalid_incorrect_proposer_index OK
+ [Invalid] EF - Capella - Operations - Proposer Slashing - invalid_incorrect_sig_1          OK
+ [Invalid] EF - Capella - Operations - Proposer Slashing - invalid_incorrect_sig_1_and_2    OK
+ [Invalid] EF - Capella - Operations - Proposer Slashing - invalid_incorrect_sig_1_and_2_sw OK
+ [Invalid] EF - Capella - Operations - Proposer Slashing - invalid_incorrect_sig_2          OK
+ [Invalid] EF - Capella - Operations - Proposer Slashing - invalid_proposer_is_not_activate OK
+ [Invalid] EF - Capella - Operations - Proposer Slashing - invalid_proposer_is_slashed      OK
+ [Invalid] EF - Capella - Operations - Proposer Slashing - invalid_proposer_is_withdrawn    OK
+ [Invalid] EF - Capella - Operations - Proposer Slashing - invalid_slots_of_different_epoch OK
+ [Valid]   EF - Capella - Operations - Proposer Slashing - basic                            OK
+ [Valid]   EF - Capella - Operations - Proposer Slashing - block_header_from_future         OK
+ [Valid]   EF - Capella - Operations - Proposer Slashing - slashed_and_proposer_index_the_s OK
```
OK: 15/15 Fail: 0/15 Skip: 0/15
## EF - Capella - Operations - Sync Aggregate  [Preset: minimal]
```diff
+ [Invalid] EF - Capella - Operations - Sync Aggregate - invalid_signature_bad_domain        OK
+ [Invalid] EF - Capella - Operations - Sync Aggregate - invalid_signature_extra_participant OK
+ [Invalid] EF - Capella - Operations - Sync Aggregate - invalid_signature_infinite_signatur OK
+ [Invalid] EF - Capella - Operations - Sync Aggregate - invalid_signature_infinite_signatur OK
+ [Invalid] EF - Capella - Operations - Sync Aggregate - invalid_signature_missing_participa OK
+ [Invalid] EF - Capella - Operations - Sync Aggregate - invalid_signature_no_participants   OK
+ [Invalid] EF - Capella - Operations - Sync Aggregate - invalid_signature_past_block        OK
+ [Invalid] EF - Capella - Operations - Sync Aggregate - invalid_signature_previous_committe OK
+ [Valid]   EF - Capella - Operations - Sync Aggregate - proposer_in_committee_with_particip OK
+ [Valid]   EF - Capella - Operations - Sync Aggregate - proposer_in_committee_without_parti OK
+ [Valid]   EF - Capella - Operations - Sync Aggregate - random_all_but_one_participating_wi OK
+ [Valid]   EF - Capella - Operations - Sync Aggregate - random_high_participation_without_d OK
+ [Valid]   EF - Capella - Operations - Sync Aggregate - random_low_participation_without_du OK
+ [Valid]   EF - Capella - Operations - Sync Aggregate - random_misc_balances_and_half_parti OK
+ [Valid]   EF - Capella - Operations - Sync Aggregate - random_only_one_participant_without OK
+ [Valid]   EF - Capella - Operations - Sync Aggregate - random_with_exits_without_duplicate OK
+ [Valid]   EF - Capella - Operations - Sync Aggregate - sync_committee_rewards_empty_partic OK
+ [Valid]   EF - Capella - Operations - Sync Aggregate - sync_committee_rewards_nonduplicate OK
+ [Valid]   EF - Capella - Operations - Sync Aggregate - sync_committee_rewards_not_full_par OK
+ [Valid]   EF - Capella - Operations - Sync Aggregate - sync_committee_with_nonparticipatin OK
+ [Valid]   EF - Capella - Operations - Sync Aggregate - sync_committee_with_nonparticipatin OK
+ [Valid]   EF - Capella - Operations - Sync Aggregate - sync_committee_with_participating_e OK
+ [Valid]   EF - Capella - Operations - Sync Aggregate - sync_committee_with_participating_w OK
+ [Valid]   EF - Capella - Operations - Sync Aggregate - valid_signature_future_committee    OK
```
OK: 24/24 Fail: 0/24 Skip: 0/24
## EF - Capella - Operations - Voluntary Exit  [Preset: minimal]
```diff
+ [Invalid] EF - Capella - Operations - Voluntary Exit - invalid_incorrect_signature         OK
+ [Invalid] EF - Capella - Operations - Voluntary Exit - invalid_validator_already_exited    OK
+ [Invalid] EF - Capella - Operations - Voluntary Exit - invalid_validator_exit_in_future    OK
+ [Invalid] EF - Capella - Operations - Voluntary Exit - invalid_validator_incorrect_validat OK
+ [Invalid] EF - Capella - Operations - Voluntary Exit - invalid_validator_not_active        OK
+ [Invalid] EF - Capella - Operations - Voluntary Exit - invalid_validator_not_active_long_e OK
+ [Invalid] EF - Capella - Operations - Voluntary Exit - invalid_voluntary_exit_with_current OK
+ [Invalid] EF - Capella - Operations - Voluntary Exit - invalid_voluntary_exit_with_genesis OK
+ [Invalid] EF - Capella - Operations - Voluntary Exit - invalid_voluntary_exit_with_genesis OK
+ [Invalid] EF - Capella - Operations - Voluntary Exit - invalid_voluntary_exit_with_previou OK
+ [Valid]   EF - Capella - Operations - Voluntary Exit - basic                               OK
+ [Valid]   EF - Capella - Operations - Voluntary Exit - default_exit_epoch_subsequent_exit  OK
+ [Valid]   EF - Capella - Operations - Voluntary Exit - success_exit_queue__min_churn       OK
+ [Valid]   EF - Capella - Operations - Voluntary Exit - success_exit_queue__scaled_churn    OK
+ [Valid]   EF - Capella - Operations - Voluntary Exit - voluntary_exit_with_current_fork_ve OK
+ [Valid]   EF - Capella - Operations - Voluntary Exit - voluntary_exit_with_previous_fork_v OK
```
OK: 16/16 Fail: 0/16 Skip: 0/16
## EF - Capella - Operations - Withdrawals  [Preset: minimal]
```diff
+ [Invalid] EF - Capella - Operations - Withdrawals - invalid_a_lot_fully_withdrawable_too_f OK
+ [Invalid] EF - Capella - Operations - Withdrawals - invalid_a_lot_mixed_withdrawable_in_qu OK
+ [Invalid] EF - Capella - Operations - Withdrawals - invalid_a_lot_partially_withdrawable_t OK
+ [Invalid] EF - Capella - Operations - Withdrawals - invalid_incorrect_address_full         OK
+ [Invalid] EF - Capella - Operations - Withdrawals - invalid_incorrect_address_partial      OK
+ [Invalid] EF - Capella - Operations - Withdrawals - invalid_incorrect_amount_full          OK
+ [Invalid] EF - Capella - Operations - Withdrawals - invalid_incorrect_amount_partial       OK
+ [Invalid] EF - Capella - Operations - Withdrawals - invalid_incorrect_withdrawal_index     OK
+ [Invalid] EF - Capella - Operations - Withdrawals - invalid_many_incorrectly_full          OK
+ [Invalid] EF - Capella - Operations - Withdrawals - invalid_many_incorrectly_partial       OK
+ [Invalid] EF - Capella - Operations - Withdrawals - invalid_max_per_slot_full_withdrawals_ OK
+ [Invalid] EF - Capella - Operations - Withdrawals - invalid_max_per_slot_partial_withdrawa OK
+ [Invalid] EF - Capella - Operations - Withdrawals - invalid_non_withdrawable_non_empty_wit OK
+ [Invalid] EF - Capella - Operations - Withdrawals - invalid_one_expected_full_withdrawal_a OK
+ [Invalid] EF - Capella - Operations - Withdrawals - invalid_one_expected_full_withdrawal_a OK
+ [Invalid] EF - Capella - Operations - Withdrawals - invalid_one_expected_partial_withdrawa OK
+ [Invalid] EF - Capella - Operations - Withdrawals - invalid_one_of_many_incorrectly_full   OK
+ [Invalid] EF - Capella - Operations - Withdrawals - invalid_one_of_many_incorrectly_partia OK
+ [Invalid] EF - Capella - Operations - Withdrawals - invalid_two_expected_partial_withdrawa OK
+ [Valid]   EF - Capella - Operations - Withdrawals - all_withdrawal                         OK
+ [Valid]   EF - Capella - Operations - Withdrawals - no_withdrawals_but_some_next_epoch     OK
+ [Valid]   EF - Capella - Operations - Withdrawals - random_0                               OK
+ [Valid]   EF - Capella - Operations - Withdrawals - random_full_withdrawals_0              OK
+ [Valid]   EF - Capella - Operations - Withdrawals - random_full_withdrawals_1              OK
+ [Valid]   EF - Capella - Operations - Withdrawals - random_full_withdrawals_2              OK
+ [Valid]   EF - Capella - Operations - Withdrawals - random_full_withdrawals_3              OK
+ [Valid]   EF - Capella - Operations - Withdrawals - random_partial_withdrawals_1           OK
+ [Valid]   EF - Capella - Operations - Withdrawals - random_partial_withdrawals_2           OK
+ [Valid]   EF - Capella - Operations - Withdrawals - random_partial_withdrawals_3           OK
+ [Valid]   EF - Capella - Operations - Withdrawals - random_partial_withdrawals_4           OK
+ [Valid]   EF - Capella - Operations - Withdrawals - random_partial_withdrawals_5           OK
+ [Valid]   EF - Capella - Operations - Withdrawals - success_all_fully_withdrawable         OK
+ [Valid]   EF - Capella - Operations - Withdrawals - success_all_partially_withdrawable     OK
+ [Valid]   EF - Capella - Operations - Withdrawals - success_excess_balance_but_no_max_effe OK
+ [Valid]   EF - Capella - Operations - Withdrawals - success_max_partial_withdrawable       OK
+ [Valid]   EF - Capella - Operations - Withdrawals - success_max_plus_one_withdrawable      OK
+ [Valid]   EF - Capella - Operations - Withdrawals - success_mixed_fully_and_partial_withdr OK
+ [Valid]   EF - Capella - Operations - Withdrawals - success_no_excess_balance              OK
+ [Valid]   EF - Capella - Operations - Withdrawals - success_no_max_effective_balance       OK
+ [Valid]   EF - Capella - Operations - Withdrawals - success_one_full_withdrawal            OK
+ [Valid]   EF - Capella - Operations - Withdrawals - success_one_partial_withdrawable_activ OK
+ [Valid]   EF - Capella - Operations - Withdrawals - success_one_partial_withdrawable_exite OK
+ [Valid]   EF - Capella - Operations - Withdrawals - success_one_partial_withdrawable_exite OK
+ [Valid]   EF - Capella - Operations - Withdrawals - success_one_partial_withdrawable_in_ex OK
+ [Valid]   EF - Capella - Operations - Withdrawals - success_one_partial_withdrawable_not_y OK
+ [Valid]   EF - Capella - Operations - Withdrawals - success_one_partial_withdrawal         OK
+ [Valid]   EF - Capella - Operations - Withdrawals - success_two_partial_withdrawable       OK
+ [Valid]   EF - Capella - Operations - Withdrawals - success_zero_expected_withdrawals      OK
+ [Valid]   EF - Capella - Operations - Withdrawals - withdrawable_epoch_but_0_balance       OK
+ [Valid]   EF - Capella - Operations - Withdrawals - withdrawable_epoch_but_0_effective_bal OK
+ [Valid]   EF - Capella - Operations - Withdrawals - withdrawable_epoch_but_0_effective_bal OK
```
OK: 51/51 Fail: 0/51 Skip: 0/51
## EF - Capella - Random  [Preset: minimal]
```diff
+ [Valid]   EF - Capella - Random - randomized_0 [Preset: minimal]                           OK
+ [Valid]   EF - Capella - Random - randomized_1 [Preset: minimal]                           OK
+ [Valid]   EF - Capella - Random - randomized_10 [Preset: minimal]                          OK
+ [Valid]   EF - Capella - Random - randomized_11 [Preset: minimal]                          OK
+ [Valid]   EF - Capella - Random - randomized_12 [Preset: minimal]                          OK
+ [Valid]   EF - Capella - Random - randomized_13 [Preset: minimal]                          OK
+ [Valid]   EF - Capella - Random - randomized_14 [Preset: minimal]                          OK
+ [Valid]   EF - Capella - Random - randomized_15 [Preset: minimal]                          OK
+ [Valid]   EF - Capella - Random - randomized_2 [Preset: minimal]                           OK
+ [Valid]   EF - Capella - Random - randomized_3 [Preset: minimal]                           OK
+ [Valid]   EF - Capella - Random - randomized_4 [Preset: minimal]                           OK
+ [Valid]   EF - Capella - Random - randomized_5 [Preset: minimal]                           OK
+ [Valid]   EF - Capella - Random - randomized_6 [Preset: minimal]                           OK
+ [Valid]   EF - Capella - Random - randomized_7 [Preset: minimal]                           OK
+ [Valid]   EF - Capella - Random - randomized_8 [Preset: minimal]                           OK
+ [Valid]   EF - Capella - Random - randomized_9 [Preset: minimal]                           OK
```
OK: 16/16 Fail: 0/16 Skip: 0/16
## EF - Capella - Rewards  [Preset: minimal]
```diff
+ EF - Capella - Rewards - all_balances_too_low_for_reward [Preset: minimal]                 OK
+ EF - Capella - Rewards - empty [Preset: minimal]                                           OK
+ EF - Capella - Rewards - empty_leak [Preset: minimal]                                      OK
+ EF - Capella - Rewards - full_all_correct [Preset: minimal]                                OK
+ EF - Capella - Rewards - full_but_partial_participation [Preset: minimal]                  OK
+ EF - Capella - Rewards - full_but_partial_participation_leak [Preset: minimal]             OK
+ EF - Capella - Rewards - full_leak [Preset: minimal]                                       OK
+ EF - Capella - Rewards - full_random_0 [Preset: minimal]                                   OK
+ EF - Capella - Rewards - full_random_1 [Preset: minimal]                                   OK
+ EF - Capella - Rewards - full_random_2 [Preset: minimal]                                   OK
+ EF - Capella - Rewards - full_random_3 [Preset: minimal]                                   OK
+ EF - Capella - Rewards - full_random_4 [Preset: minimal]                                   OK
+ EF - Capella - Rewards - full_random_leak [Preset: minimal]                                OK
+ EF - Capella - Rewards - full_random_low_balances_0 [Preset: minimal]                      OK
+ EF - Capella - Rewards - full_random_low_balances_1 [Preset: minimal]                      OK
+ EF - Capella - Rewards - full_random_misc_balances [Preset: minimal]                       OK
+ EF - Capella - Rewards - full_random_seven_epoch_leak [Preset: minimal]                    OK
+ EF - Capella - Rewards - full_random_ten_epoch_leak [Preset: minimal]                      OK
+ EF - Capella - Rewards - full_random_without_leak_0 [Preset: minimal]                      OK
+ EF - Capella - Rewards - full_random_without_leak_and_current_exit_0 [Preset: minimal]     OK
+ EF - Capella - Rewards - half_full [Preset: minimal]                                       OK
+ EF - Capella - Rewards - half_full_leak [Preset: minimal]                                  OK
+ EF - Capella - Rewards - quarter_full [Preset: minimal]                                    OK
+ EF - Capella - Rewards - quarter_full_leak [Preset: minimal]                               OK
+ EF - Capella - Rewards - some_very_low_effective_balances_that_attested [Preset: minimal]  OK
+ EF - Capella - Rewards - some_very_low_effective_balances_that_attested_leak [Preset: mini OK
+ EF - Capella - Rewards - some_very_low_effective_balances_that_did_not_attest [Preset: min OK
+ EF - Capella - Rewards - some_very_low_effective_balances_that_did_not_attest_leak [Preset OK
+ EF - Capella - Rewards - with_exited_validators [Preset: minimal]                          OK
+ EF - Capella - Rewards - with_exited_validators_leak [Preset: minimal]                     OK
+ EF - Capella - Rewards - with_not_yet_activated_validators [Preset: minimal]               OK
+ EF - Capella - Rewards - with_not_yet_activated_validators_leak [Preset: minimal]          OK
+ EF - Capella - Rewards - with_slashed_validators [Preset: minimal]                         OK
+ EF - Capella - Rewards - with_slashed_validators_leak [Preset: minimal]                    OK
```
OK: 34/34 Fail: 0/34 Skip: 0/34
## EF - Capella - SSZ consensus objects  [Preset: minimal]
```diff
+   Testing    AggregateAndProof                                                             OK
+   Testing    Attestation                                                                   OK
+   Testing    AttestationData                                                               OK
+   Testing    AttesterSlashing                                                              OK
+   Testing    BLSToExecutionChange                                                          OK
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
+   Testing    ExecutionPayload                                                              OK
+   Testing    ExecutionPayloadHeader                                                        OK
+   Testing    Fork                                                                          OK
+   Testing    ForkData                                                                      OK
+   Testing    HistoricalBatch                                                               OK
+   Testing    HistoricalSummary                                                             OK
+   Testing    IndexedAttestation                                                            OK
+   Testing    LightClientBootstrap                                                          OK
+   Testing    LightClientFinalityUpdate                                                     OK
+   Testing    LightClientHeader                                                             OK
+   Testing    LightClientOptimisticUpdate                                                   OK
+   Testing    LightClientUpdate                                                             OK
+   Testing    PendingAttestation                                                            OK
+   Testing    PowBlock                                                                      OK
+   Testing    ProposerSlashing                                                              OK
+   Testing    SignedAggregateAndProof                                                       OK
+   Testing    SignedBLSToExecutionChange                                                    OK
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
+   Testing    Withdrawal                                                                    OK
```
OK: 46/46 Fail: 0/46 Skip: 0/46
## EF - Capella - Sanity - Blocks  [Preset: minimal]
```diff
+ [Invalid] EF - Capella - Sanity - Blocks - invalid_all_zeroed_sig [Preset: minimal]        OK
+ [Invalid] EF - Capella - Sanity - Blocks - invalid_duplicate_attester_slashing_same_block  OK
+ [Invalid] EF - Capella - Sanity - Blocks - invalid_duplicate_bls_changes_same_block [Prese OK
+ [Invalid] EF - Capella - Sanity - Blocks - invalid_duplicate_deposit_same_block [Preset: m OK
+ [Invalid] EF - Capella - Sanity - Blocks - invalid_duplicate_proposer_slashings_same_block OK
+ [Invalid] EF - Capella - Sanity - Blocks - invalid_duplicate_validator_exit_same_block [Pr OK
+ [Invalid] EF - Capella - Sanity - Blocks - invalid_incorrect_block_sig [Preset: minimal]   OK
+ [Invalid] EF - Capella - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_expec OK
+ [Invalid] EF - Capella - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_propo OK
+ [Invalid] EF - Capella - Sanity - Blocks - invalid_incorrect_state_root [Preset: minimal]  OK
+ [Invalid] EF - Capella - Sanity - Blocks - invalid_is_execution_enabled_false [Preset: min OK
+ [Invalid] EF - Capella - Sanity - Blocks - invalid_only_increase_deposit_count [Preset: mi OK
+ [Invalid] EF - Capella - Sanity - Blocks - invalid_parent_from_same_slot [Preset: minimal] OK
+ [Invalid] EF - Capella - Sanity - Blocks - invalid_prev_slot_block_transition [Preset: min OK
+ [Invalid] EF - Capella - Sanity - Blocks - invalid_same_slot_block_transition [Preset: min OK
+ [Invalid] EF - Capella - Sanity - Blocks - invalid_similar_proposer_slashings_same_block [ OK
+ [Invalid] EF - Capella - Sanity - Blocks - invalid_two_bls_changes_of_different_addresses_ OK
+ [Invalid] EF - Capella - Sanity - Blocks - invalid_withdrawal_fail_second_block_payload_is OK
+ [Invalid] EF - Capella - Sanity - Blocks - slash_and_exit_same_index [Preset: minimal]     OK
+ [Valid]   EF - Capella - Sanity - Blocks - activate_and_partial_withdrawal_max_effective_b OK
+ [Valid]   EF - Capella - Sanity - Blocks - activate_and_partial_withdrawal_overdeposit [Pr OK
+ [Valid]   EF - Capella - Sanity - Blocks - attestation [Preset: minimal]                   OK
+ [Valid]   EF - Capella - Sanity - Blocks - attester_slashing [Preset: minimal]             OK
+ [Valid]   EF - Capella - Sanity - Blocks - balance_driven_status_transitions [Preset: mini OK
+ [Valid]   EF - Capella - Sanity - Blocks - block_transition_randomized_payload [Preset: mi OK
+ [Valid]   EF - Capella - Sanity - Blocks - bls_change [Preset: minimal]                    OK
+ [Valid]   EF - Capella - Sanity - Blocks - deposit_and_bls_change [Preset: minimal]        OK
+ [Valid]   EF - Capella - Sanity - Blocks - deposit_in_block [Preset: minimal]              OK
+ [Valid]   EF - Capella - Sanity - Blocks - deposit_top_up [Preset: minimal]                OK
+ [Valid]   EF - Capella - Sanity - Blocks - duplicate_attestation_same_block [Preset: minim OK
+ [Valid]   EF - Capella - Sanity - Blocks - empty_block_transition [Preset: minimal]        OK
+ [Valid]   EF - Capella - Sanity - Blocks - empty_block_transition_large_validator_set [Pre OK
+ [Valid]   EF - Capella - Sanity - Blocks - empty_block_transition_no_tx [Preset: minimal]  OK
+ [Valid]   EF - Capella - Sanity - Blocks - empty_epoch_transition [Preset: minimal]        OK
+ [Valid]   EF - Capella - Sanity - Blocks - empty_epoch_transition_large_validator_set [Pre OK
+ [Valid]   EF - Capella - Sanity - Blocks - empty_epoch_transition_not_finalizing [Preset:  OK
+ [Valid]   EF - Capella - Sanity - Blocks - eth1_data_votes_consensus [Preset: minimal]     OK
+ [Valid]   EF - Capella - Sanity - Blocks - eth1_data_votes_no_consensus [Preset: minimal]  OK
+ [Valid]   EF - Capella - Sanity - Blocks - exit_and_bls_change [Preset: minimal]           OK
+ [Valid]   EF - Capella - Sanity - Blocks - full_random_operations_0 [Preset: minimal]      OK
+ [Valid]   EF - Capella - Sanity - Blocks - full_random_operations_1 [Preset: minimal]      OK
+ [Valid]   EF - Capella - Sanity - Blocks - full_random_operations_2 [Preset: minimal]      OK
+ [Valid]   EF - Capella - Sanity - Blocks - full_random_operations_3 [Preset: minimal]      OK
+ [Valid]   EF - Capella - Sanity - Blocks - full_withdrawal_in_epoch_transition [Preset: mi OK
+ [Valid]   EF - Capella - Sanity - Blocks - high_proposer_index [Preset: minimal]           OK
+ [Valid]   EF - Capella - Sanity - Blocks - historical_batch [Preset: minimal]              OK
+ [Valid]   EF - Capella - Sanity - Blocks - inactivity_scores_full_participation_leaking [P OK
+ [Valid]   EF - Capella - Sanity - Blocks - inactivity_scores_leaking [Preset: minimal]     OK
+ [Valid]   EF - Capella - Sanity - Blocks - many_partial_withdrawals_in_epoch_transition [P OK
+ [Valid]   EF - Capella - Sanity - Blocks - multiple_attester_slashings_no_overlap [Preset: OK
+ [Valid]   EF - Capella - Sanity - Blocks - multiple_attester_slashings_partial_overlap [Pr OK
+ [Valid]   EF - Capella - Sanity - Blocks - multiple_different_proposer_slashings_same_bloc OK
+ [Valid]   EF - Capella - Sanity - Blocks - multiple_different_validator_exits_same_block [ OK
+ [Valid]   EF - Capella - Sanity - Blocks - partial_withdrawal_in_epoch_transition [Preset: OK
+ [Valid]   EF - Capella - Sanity - Blocks - proposer_after_inactive_index [Preset: minimal] OK
+ [Valid]   EF - Capella - Sanity - Blocks - proposer_self_slashing [Preset: minimal]        OK
+ [Valid]   EF - Capella - Sanity - Blocks - proposer_slashing [Preset: minimal]             OK
+ [Valid]   EF - Capella - Sanity - Blocks - skipped_slots [Preset: minimal]                 OK
+ [Valid]   EF - Capella - Sanity - Blocks - slash_and_exit_diff_index [Preset: minimal]     OK
+ [Valid]   EF - Capella - Sanity - Blocks - sync_committee_committee__empty [Preset: minima OK
+ [Valid]   EF - Capella - Sanity - Blocks - sync_committee_committee__full [Preset: minimal OK
+ [Valid]   EF - Capella - Sanity - Blocks - sync_committee_committee__half [Preset: minimal OK
+ [Valid]   EF - Capella - Sanity - Blocks - sync_committee_committee_genesis__empty [Preset OK
+ [Valid]   EF - Capella - Sanity - Blocks - sync_committee_committee_genesis__full [Preset: OK
+ [Valid]   EF - Capella - Sanity - Blocks - sync_committee_committee_genesis__half [Preset: OK
+ [Valid]   EF - Capella - Sanity - Blocks - top_up_and_partial_withdrawable_validator [Pres OK
+ [Valid]   EF - Capella - Sanity - Blocks - top_up_to_fully_withdrawn_validator [Preset: mi OK
+ [Valid]   EF - Capella - Sanity - Blocks - voluntary_exit [Preset: minimal]                OK
+ [Valid]   EF - Capella - Sanity - Blocks - withdrawal_success_two_blocks [Preset: minimal] OK
```
OK: 69/69 Fail: 0/69 Skip: 0/69
## EF - Capella - Sanity - Slots  [Preset: minimal]
```diff
+ EF - Capella - Slots - double_empty_epoch [Preset: minimal]                                OK
+ EF - Capella - Slots - empty_epoch [Preset: minimal]                                       OK
+ EF - Capella - Slots - historical_accumulator [Preset: minimal]                            OK
+ EF - Capella - Slots - over_epoch_boundary [Preset: minimal]                               OK
+ EF - Capella - Slots - slots_1 [Preset: minimal]                                           OK
+ EF - Capella - Slots - slots_2 [Preset: minimal]                                           OK
```
OK: 6/6 Fail: 0/6 Skip: 0/6
## EF - Capella - Transition  [Preset: minimal]
```diff
+ EF - Capella - Transition - normal_transition [Preset: minimal]                            OK
+ EF - Capella - Transition - simple_transition [Preset: minimal]                            OK
+ EF - Capella - Transition - transition_missing_first_post_block [Preset: minimal]          OK
+ EF - Capella - Transition - transition_missing_last_pre_fork_block [Preset: minimal]       OK
+ EF - Capella - Transition - transition_only_blocks_post_fork [Preset: minimal]             OK
+ EF - Capella - Transition - transition_randomized_state [Preset: minimal]                  OK
+ EF - Capella - Transition - transition_with_activation_at_fork_epoch [Preset: minimal]     OK
+ EF - Capella - Transition - transition_with_attester_slashing_right_after_fork [Preset: mi OK
+ EF - Capella - Transition - transition_with_attester_slashing_right_before_fork [Preset: m OK
+ EF - Capella - Transition - transition_with_deposit_right_after_fork [Preset: minimal]     OK
+ EF - Capella - Transition - transition_with_deposit_right_before_fork [Preset: minimal]    OK
+ EF - Capella - Transition - transition_with_finality [Preset: minimal]                     OK
+ EF - Capella - Transition - transition_with_leaking_at_fork [Preset: minimal]              OK
+ EF - Capella - Transition - transition_with_leaking_pre_fork [Preset: minimal]             OK
+ EF - Capella - Transition - transition_with_no_attestations_until_after_fork [Preset: mini OK
+ EF - Capella - Transition - transition_with_non_empty_activation_queue [Preset: minimal]   OK
+ EF - Capella - Transition - transition_with_one_fourth_exiting_validators_exit_at_fork [Pr OK
+ EF - Capella - Transition - transition_with_one_fourth_exiting_validators_exit_post_fork [ OK
+ EF - Capella - Transition - transition_with_one_fourth_slashed_active_validators_pre_fork  OK
+ EF - Capella - Transition - transition_with_proposer_slashing_right_after_fork [Preset: mi OK
+ EF - Capella - Transition - transition_with_proposer_slashing_right_before_fork [Preset: m OK
+ EF - Capella - Transition - transition_with_random_half_participation [Preset: minimal]    OK
+ EF - Capella - Transition - transition_with_random_three_quarters_participation [Preset: m OK
+ EF - Capella - Transition - transition_with_voluntary_exit_right_after_fork [Preset: minim OK
+ EF - Capella - Transition - transition_with_voluntary_exit_right_before_fork [Preset: mini OK
```
OK: 25/25 Fail: 0/25 Skip: 0/25
## EF - Capella - Unittests - Light client - Sync protocol [Preset: minimal]
```diff
+ process_light_client_update_finality_updated                                               OK
+ process_light_client_update_timeout                                                        OK
+ test_process_light_client_update_at_period_boundary                                        OK
+ test_process_light_client_update_not_timeout                                               OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
## EF - Deneb - Epoch Processing - Effective balance updates [Preset: minimal]
```diff
+ Effective balance updates - effective_balance_hysteresis [Preset: minimal]                 OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## EF - Deneb - Epoch Processing - Eth1 data reset [Preset: minimal]
```diff
+ Eth1 data reset - eth1_vote_no_reset [Preset: minimal]                                     OK
+ Eth1 data reset - eth1_vote_reset [Preset: minimal]                                        OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## EF - Deneb - Epoch Processing - Historical summaries update [Preset: minimal]
```diff
+ Historical summaries update - historical_summaries_accumulator [Preset: minimal]           OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## EF - Deneb - Epoch Processing - Inactivity [Preset: minimal]
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
+ Inactivity - randomized_state [Preset: minimal]                                            OK
+ Inactivity - randomized_state_leaking [Preset: minimal]                                    OK
+ Inactivity - some_exited_full_random_leaking [Preset: minimal]                             OK
+ Inactivity - some_slashed_full_random [Preset: minimal]                                    OK
+ Inactivity - some_slashed_full_random_leaking [Preset: minimal]                            OK
+ Inactivity - some_slashed_zero_scores_full_participation [Preset: minimal]                 OK
+ Inactivity - some_slashed_zero_scores_full_participation_leaking [Preset: minimal]         OK
```
OK: 21/21 Fail: 0/21 Skip: 0/21
## EF - Deneb - Epoch Processing - Justification & Finalization [Preset: minimal]
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
## EF - Deneb - Epoch Processing - Participation flag updates [Preset: minimal]
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
## EF - Deneb - Epoch Processing - RANDAO mixes reset [Preset: minimal]
```diff
+ RANDAO mixes reset - updated_randao_mixes [Preset: minimal]                                OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## EF - Deneb - Epoch Processing - Registry updates [Preset: minimal]
```diff
+ Registry updates - activation_churn_limit__equal_to_activation_limit [Preset: minimal]     OK
+ Registry updates - activation_churn_limit__greater_than_activation_limit [Preset: minimal] OK
+ Registry updates - activation_churn_limit__less_than_activation_limit [Preset: minimal]    OK
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
+ Registry updates - invalid_large_withdrawable_epoch [Preset: minimal]                      OK
```
OK: 18/18 Fail: 0/18 Skip: 0/18
## EF - Deneb - Epoch Processing - Rewards and penalties [Preset: minimal]
```diff
+ Rewards and penalties - almost_empty_attestations [Preset: minimal]                        OK
+ Rewards and penalties - almost_empty_attestations_with_leak [Preset: minimal]              OK
+ Rewards and penalties - almost_full_attestations [Preset: minimal]                         OK
+ Rewards and penalties - almost_full_attestations_with_leak [Preset: minimal]               OK
+ Rewards and penalties - attestations_some_slashed [Preset: minimal]                        OK
+ Rewards and penalties - duplicate_attestation [Preset: minimal]                            OK
+ Rewards and penalties - full_attestation_participation [Preset: minimal]                   OK
+ Rewards and penalties - full_attestation_participation_with_leak [Preset: minimal]         OK
+ Rewards and penalties - full_attestations_misc_balances [Preset: minimal]                  OK
+ Rewards and penalties - full_attestations_one_validaor_one_gwei [Preset: minimal]          OK
+ Rewards and penalties - genesis_epoch_full_attestations_no_rewards [Preset: minimal]       OK
+ Rewards and penalties - genesis_epoch_no_attestations_no_penalties [Preset: minimal]       OK
+ Rewards and penalties - no_attestations_all_penalties [Preset: minimal]                    OK
+ Rewards and penalties - random_fill_attestations [Preset: minimal]                         OK
+ Rewards and penalties - random_fill_attestations_with_leak [Preset: minimal]               OK
```
OK: 15/15 Fail: 0/15 Skip: 0/15
## EF - Deneb - Epoch Processing - Slashings [Preset: minimal]
```diff
+ Slashings - low_penalty [Preset: minimal]                                                  OK
+ Slashings - max_penalties [Preset: minimal]                                                OK
+ Slashings - minimal_penalty [Preset: minimal]                                              OK
+ Slashings - scaled_penalties [Preset: minimal]                                             OK
+ Slashings - slashings_with_random_state [Preset: minimal]                                  OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## EF - Deneb - Epoch Processing - Slashings reset [Preset: minimal]
```diff
+ Slashings reset - flush_slashings [Preset: minimal]                                        OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## EF - Deneb - Epoch Processing - Sync committee updates [Preset: minimal]
```diff
+ Sync committee updates - sync_committees_no_progress_not_at_period_boundary [Preset: minim OK
+ Sync committee updates - sync_committees_progress_genesis [Preset: minimal]                OK
+ Sync committee updates - sync_committees_progress_misc_balances_genesis [Preset: minimal]  OK
+ Sync committee updates - sync_committees_progress_misc_balances_not_genesis [Preset: minim OK
+ Sync committee updates - sync_committees_progress_not_genesis [Preset: minimal]            OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## EF - Deneb - Finality  [Preset: minimal]
```diff
+ [Valid]   EF - Deneb - Finality - finality_no_updates_at_genesis [Preset: minimal]         OK
+ [Valid]   EF - Deneb - Finality - finality_rule_1 [Preset: minimal]                        OK
+ [Valid]   EF - Deneb - Finality - finality_rule_2 [Preset: minimal]                        OK
+ [Valid]   EF - Deneb - Finality - finality_rule_3 [Preset: minimal]                        OK
+ [Valid]   EF - Deneb - Finality - finality_rule_4 [Preset: minimal]                        OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## EF - Deneb - Fork  [Preset: minimal]
```diff
+ EF - Deneb - Fork - deneb_fork_random_0 [Preset: minimal]                                  OK
+ EF - Deneb - Fork - deneb_fork_random_1 [Preset: minimal]                                  OK
+ EF - Deneb - Fork - deneb_fork_random_2 [Preset: minimal]                                  OK
+ EF - Deneb - Fork - deneb_fork_random_3 [Preset: minimal]                                  OK
+ EF - Deneb - Fork - deneb_fork_random_large_validator_set [Preset: minimal]                OK
+ EF - Deneb - Fork - deneb_fork_random_low_balances [Preset: minimal]                       OK
+ EF - Deneb - Fork - deneb_fork_random_misc_balances [Preset: minimal]                      OK
+ EF - Deneb - Fork - fork_base_state [Preset: minimal]                                      OK
+ EF - Deneb - Fork - fork_many_next_epoch [Preset: minimal]                                 OK
+ EF - Deneb - Fork - fork_next_epoch [Preset: minimal]                                      OK
+ EF - Deneb - Fork - fork_next_epoch_with_block [Preset: minimal]                           OK
+ EF - Deneb - Fork - fork_random_large_validator_set [Preset: minimal]                      OK
+ EF - Deneb - Fork - fork_random_low_balances [Preset: minimal]                             OK
+ EF - Deneb - Fork - fork_random_misc_balances [Preset: minimal]                            OK
```
OK: 14/14 Fail: 0/14 Skip: 0/14
## EF - Deneb - Operations - Attestation  [Preset: minimal]
```diff
+ [Invalid] EF - Deneb - Operations - Attestation - invalid_after_max_inclusion_slot         OK
+ [Invalid] EF - Deneb - Operations - Attestation - invalid_attestation_signature            OK
+ [Invalid] EF - Deneb - Operations - Attestation - invalid_bad_source_root                  OK
+ [Invalid] EF - Deneb - Operations - Attestation - invalid_before_inclusion_delay           OK
+ [Invalid] EF - Deneb - Operations - Attestation - invalid_correct_attestation_included_aft OK
+ [Invalid] EF - Deneb - Operations - Attestation - invalid_current_source_root              OK
+ [Invalid] EF - Deneb - Operations - Attestation - invalid_empty_participants_seemingly_val OK
+ [Invalid] EF - Deneb - Operations - Attestation - invalid_empty_participants_zeroes_sig    OK
+ [Invalid] EF - Deneb - Operations - Attestation - invalid_future_target_epoch              OK
+ [Invalid] EF - Deneb - Operations - Attestation - invalid_incorrect_head_and_target_includ OK
+ [Invalid] EF - Deneb - Operations - Attestation - invalid_incorrect_head_included_after_ma OK
+ [Invalid] EF - Deneb - Operations - Attestation - invalid_incorrect_target_included_after_ OK
+ [Invalid] EF - Deneb - Operations - Attestation - invalid_index                            OK
+ [Invalid] EF - Deneb - Operations - Attestation - invalid_mismatched_target_and_slot       OK
+ [Invalid] EF - Deneb - Operations - Attestation - invalid_new_source_epoch                 OK
+ [Invalid] EF - Deneb - Operations - Attestation - invalid_old_source_epoch                 OK
+ [Invalid] EF - Deneb - Operations - Attestation - invalid_old_target_epoch                 OK
+ [Invalid] EF - Deneb - Operations - Attestation - invalid_previous_source_root             OK
+ [Invalid] EF - Deneb - Operations - Attestation - invalid_source_root_is_target_root       OK
+ [Invalid] EF - Deneb - Operations - Attestation - invalid_too_few_aggregation_bits         OK
+ [Invalid] EF - Deneb - Operations - Attestation - invalid_too_many_aggregation_bits        OK
+ [Invalid] EF - Deneb - Operations - Attestation - invalid_wrong_index_for_committee_signat OK
+ [Invalid] EF - Deneb - Operations - Attestation - invalid_wrong_index_for_slot_0           OK
+ [Invalid] EF - Deneb - Operations - Attestation - invalid_wrong_index_for_slot_1           OK
+ [Valid]   EF - Deneb - Operations - Attestation - at_max_inclusion_slot                    OK
+ [Valid]   EF - Deneb - Operations - Attestation - correct_attestation_included_at_max_incl OK
+ [Valid]   EF - Deneb - Operations - Attestation - correct_attestation_included_at_min_incl OK
+ [Valid]   EF - Deneb - Operations - Attestation - correct_attestation_included_at_one_epoc OK
+ [Valid]   EF - Deneb - Operations - Attestation - correct_attestation_included_at_sqrt_epo OK
+ [Valid]   EF - Deneb - Operations - Attestation - incorrect_head_and_target_included_at_ep OK
+ [Valid]   EF - Deneb - Operations - Attestation - incorrect_head_and_target_included_at_sq OK
+ [Valid]   EF - Deneb - Operations - Attestation - incorrect_head_and_target_min_inclusion_ OK
+ [Valid]   EF - Deneb - Operations - Attestation - incorrect_head_included_at_max_inclusion OK
+ [Valid]   EF - Deneb - Operations - Attestation - incorrect_head_included_at_min_inclusion OK
+ [Valid]   EF - Deneb - Operations - Attestation - incorrect_head_included_at_sqrt_epoch_de OK
+ [Valid]   EF - Deneb - Operations - Attestation - incorrect_target_included_at_epoch_delay OK
+ [Valid]   EF - Deneb - Operations - Attestation - incorrect_target_included_at_min_inclusi OK
+ [Valid]   EF - Deneb - Operations - Attestation - incorrect_target_included_at_sqrt_epoch_ OK
+ [Valid]   EF - Deneb - Operations - Attestation - multi_proposer_index_iterations          OK
+ [Valid]   EF - Deneb - Operations - Attestation - one_basic_attestation                    OK
+ [Valid]   EF - Deneb - Operations - Attestation - previous_epoch                           OK
```
OK: 41/41 Fail: 0/41 Skip: 0/41
## EF - Deneb - Operations - Attester Slashing  [Preset: minimal]
```diff
+ [Invalid] EF - Deneb - Operations - Attester Slashing - invalid_all_empty_indices          OK
+ [Invalid] EF - Deneb - Operations - Attester Slashing - invalid_att1_bad_extra_index       OK
+ [Invalid] EF - Deneb - Operations - Attester Slashing - invalid_att1_bad_replaced_index    OK
+ [Invalid] EF - Deneb - Operations - Attester Slashing - invalid_att1_duplicate_index_doubl OK
+ [Invalid] EF - Deneb - Operations - Attester Slashing - invalid_att1_duplicate_index_norma OK
+ [Invalid] EF - Deneb - Operations - Attester Slashing - invalid_att1_empty_indices         OK
+ [Invalid] EF - Deneb - Operations - Attester Slashing - invalid_att1_high_index            OK
+ [Invalid] EF - Deneb - Operations - Attester Slashing - invalid_att2_bad_extra_index       OK
+ [Invalid] EF - Deneb - Operations - Attester Slashing - invalid_att2_bad_replaced_index    OK
+ [Invalid] EF - Deneb - Operations - Attester Slashing - invalid_att2_duplicate_index_doubl OK
+ [Invalid] EF - Deneb - Operations - Attester Slashing - invalid_att2_duplicate_index_norma OK
+ [Invalid] EF - Deneb - Operations - Attester Slashing - invalid_att2_empty_indices         OK
+ [Invalid] EF - Deneb - Operations - Attester Slashing - invalid_att2_high_index            OK
+ [Invalid] EF - Deneb - Operations - Attester Slashing - invalid_incorrect_sig_1            OK
+ [Invalid] EF - Deneb - Operations - Attester Slashing - invalid_incorrect_sig_1_and_2      OK
+ [Invalid] EF - Deneb - Operations - Attester Slashing - invalid_incorrect_sig_2            OK
+ [Invalid] EF - Deneb - Operations - Attester Slashing - invalid_no_double_or_surround      OK
+ [Invalid] EF - Deneb - Operations - Attester Slashing - invalid_participants_already_slash OK
+ [Invalid] EF - Deneb - Operations - Attester Slashing - invalid_same_data                  OK
+ [Invalid] EF - Deneb - Operations - Attester Slashing - invalid_unsorted_att_1             OK
+ [Invalid] EF - Deneb - Operations - Attester Slashing - invalid_unsorted_att_2             OK
+ [Valid]   EF - Deneb - Operations - Attester Slashing - already_exited_long_ago            OK
+ [Valid]   EF - Deneb - Operations - Attester Slashing - already_exited_recent              OK
+ [Valid]   EF - Deneb - Operations - Attester Slashing - attestation_from_future            OK
+ [Valid]   EF - Deneb - Operations - Attester Slashing - basic_double                       OK
+ [Valid]   EF - Deneb - Operations - Attester Slashing - basic_surround                     OK
+ [Valid]   EF - Deneb - Operations - Attester Slashing - low_balances                       OK
+ [Valid]   EF - Deneb - Operations - Attester Slashing - misc_balances                      OK
+ [Valid]   EF - Deneb - Operations - Attester Slashing - proposer_index_slashed             OK
+ [Valid]   EF - Deneb - Operations - Attester Slashing - with_effective_balance_disparity   OK
```
OK: 30/30 Fail: 0/30 Skip: 0/30
## EF - Deneb - Operations - BLS to execution change  [Preset: minimal]
```diff
+ [Invalid] EF - Deneb - Operations - BLS to execution change - invalid_already_0x01         OK
+ [Invalid] EF - Deneb - Operations - BLS to execution change - invalid_bad_signature        OK
+ [Invalid] EF - Deneb - Operations - BLS to execution change - invalid_current_fork_version OK
+ [Invalid] EF - Deneb - Operations - BLS to execution change - invalid_genesis_validators_r OK
+ [Invalid] EF - Deneb - Operations - BLS to execution change - invalid_incorrect_from_bls_p OK
+ [Invalid] EF - Deneb - Operations - BLS to execution change - invalid_previous_fork_versio OK
+ [Invalid] EF - Deneb - Operations - BLS to execution change - invalid_val_index_out_of_ran OK
+ [Valid]   EF - Deneb - Operations - BLS to execution change - genesis_fork_version         OK
+ [Valid]   EF - Deneb - Operations - BLS to execution change - success                      OK
+ [Valid]   EF - Deneb - Operations - BLS to execution change - success_exited               OK
+ [Valid]   EF - Deneb - Operations - BLS to execution change - success_in_activation_queue  OK
+ [Valid]   EF - Deneb - Operations - BLS to execution change - success_in_exit_queue        OK
+ [Valid]   EF - Deneb - Operations - BLS to execution change - success_not_activated        OK
+ [Valid]   EF - Deneb - Operations - BLS to execution change - success_withdrawable         OK
```
OK: 14/14 Fail: 0/14 Skip: 0/14
## EF - Deneb - Operations - Block Header  [Preset: minimal]
```diff
+ [Invalid] EF - Deneb - Operations - Block Header - invalid_multiple_blocks_single_slot     OK
+ [Invalid] EF - Deneb - Operations - Block Header - invalid_parent_root                     OK
+ [Invalid] EF - Deneb - Operations - Block Header - invalid_proposer_index                  OK
+ [Invalid] EF - Deneb - Operations - Block Header - invalid_proposer_slashed                OK
+ [Invalid] EF - Deneb - Operations - Block Header - invalid_slot_block_header               OK
+ [Valid]   EF - Deneb - Operations - Block Header - basic_block_header                      OK
```
OK: 6/6 Fail: 0/6 Skip: 0/6
## EF - Deneb - Operations - Deposit  [Preset: minimal]
```diff
+ [Invalid] EF - Deneb - Operations - Deposit - invalid_bad_merkle_proof                     OK
+ [Invalid] EF - Deneb - Operations - Deposit - invalid_wrong_deposit_for_deposit_count      OK
+ [Valid]   EF - Deneb - Operations - Deposit - correct_sig_but_forked_state                 OK
+ [Valid]   EF - Deneb - Operations - Deposit - effective_deposit_with_genesis_fork_version  OK
+ [Valid]   EF - Deneb - Operations - Deposit - incorrect_sig_new_deposit                    OK
+ [Valid]   EF - Deneb - Operations - Deposit - incorrect_sig_top_up                         OK
+ [Valid]   EF - Deneb - Operations - Deposit - incorrect_withdrawal_credentials_top_up      OK
+ [Valid]   EF - Deneb - Operations - Deposit - ineffective_deposit_with_bad_fork_version    OK
+ [Valid]   EF - Deneb - Operations - Deposit - ineffective_deposit_with_current_fork_versio OK
+ [Valid]   EF - Deneb - Operations - Deposit - ineffective_deposit_with_previous_fork_versi OK
+ [Valid]   EF - Deneb - Operations - Deposit - key_validate_invalid_decompression           OK
+ [Valid]   EF - Deneb - Operations - Deposit - key_validate_invalid_subgroup                OK
+ [Valid]   EF - Deneb - Operations - Deposit - new_deposit_eth1_withdrawal_credentials      OK
+ [Valid]   EF - Deneb - Operations - Deposit - new_deposit_max                              OK
+ [Valid]   EF - Deneb - Operations - Deposit - new_deposit_non_versioned_withdrawal_credent OK
+ [Valid]   EF - Deneb - Operations - Deposit - new_deposit_over_max                         OK
+ [Valid]   EF - Deneb - Operations - Deposit - new_deposit_under_max                        OK
+ [Valid]   EF - Deneb - Operations - Deposit - success_top_up_to_withdrawn_validator        OK
+ [Valid]   EF - Deneb - Operations - Deposit - top_up__less_effective_balance               OK
+ [Valid]   EF - Deneb - Operations - Deposit - top_up__max_effective_balance                OK
+ [Valid]   EF - Deneb - Operations - Deposit - top_up__zero_balance                         OK
```
OK: 21/21 Fail: 0/21 Skip: 0/21
## EF - Deneb - Operations - Execution Payload  [Preset: minimal]
```diff
+ [Invalid] EF - Deneb - Operations - Execution Payload - invalid_bad_everything_first_paylo OK
+ [Invalid] EF - Deneb - Operations - Execution Payload - invalid_bad_everything_regular_pay OK
+ [Invalid] EF - Deneb - Operations - Execution Payload - invalid_bad_execution_first_payloa OK
+ [Invalid] EF - Deneb - Operations - Execution Payload - invalid_bad_execution_regular_payl OK
+ [Invalid] EF - Deneb - Operations - Execution Payload - invalid_bad_parent_hash_first_payl OK
+ [Invalid] EF - Deneb - Operations - Execution Payload - invalid_bad_parent_hash_regular_pa OK
+ [Invalid] EF - Deneb - Operations - Execution Payload - invalid_bad_pre_randao_regular_pay OK
+ [Invalid] EF - Deneb - Operations - Execution Payload - invalid_bad_prev_randao_first_payl OK
+ [Invalid] EF - Deneb - Operations - Execution Payload - invalid_correct_input__execution_i OK
+ [Invalid] EF - Deneb - Operations - Execution Payload - invalid_exceed_max_blobs_per_block OK
+ [Invalid] EF - Deneb - Operations - Execution Payload - invalid_future_timestamp_first_pay OK
+ [Invalid] EF - Deneb - Operations - Execution Payload - invalid_future_timestamp_regular_p OK
+ [Invalid] EF - Deneb - Operations - Execution Payload - invalid_past_timestamp_first_paylo OK
+ [Invalid] EF - Deneb - Operations - Execution Payload - invalid_past_timestamp_regular_pay OK
+ [Invalid] EF - Deneb - Operations - Execution Payload - invalid_randomized_non_validated_e OK
+ [Invalid] EF - Deneb - Operations - Execution Payload - invalid_randomized_non_validated_e OK
+ [Valid]   EF - Deneb - Operations - Execution Payload - incorrect_blob_tx_type             OK
+ [Valid]   EF - Deneb - Operations - Execution Payload - incorrect_block_hash               OK
+ [Valid]   EF - Deneb - Operations - Execution Payload - incorrect_commitment               OK
+ [Valid]   EF - Deneb - Operations - Execution Payload - incorrect_commitments_order        OK
+ [Valid]   EF - Deneb - Operations - Execution Payload - incorrect_transaction_length_1_byt OK
+ [Valid]   EF - Deneb - Operations - Execution Payload - incorrect_transaction_length_1_ext OK
+ [Valid]   EF - Deneb - Operations - Execution Payload - incorrect_transaction_length_32_ex OK
+ [Valid]   EF - Deneb - Operations - Execution Payload - incorrect_transaction_length_empty OK
+ [Valid]   EF - Deneb - Operations - Execution Payload - no_transactions_with_commitments   OK
+ [Valid]   EF - Deneb - Operations - Execution Payload - non_empty_extra_data_first_payload OK
+ [Valid]   EF - Deneb - Operations - Execution Payload - non_empty_extra_data_regular_paylo OK
+ [Valid]   EF - Deneb - Operations - Execution Payload - non_empty_transactions_first_paylo OK
+ [Valid]   EF - Deneb - Operations - Execution Payload - non_empty_transactions_regular_pay OK
+ [Valid]   EF - Deneb - Operations - Execution Payload - randomized_non_validated_execution OK
+ [Valid]   EF - Deneb - Operations - Execution Payload - randomized_non_validated_execution OK
+ [Valid]   EF - Deneb - Operations - Execution Payload - success_first_payload              OK
+ [Valid]   EF - Deneb - Operations - Execution Payload - success_first_payload_with_gap_slo OK
+ [Valid]   EF - Deneb - Operations - Execution Payload - success_regular_payload            OK
+ [Valid]   EF - Deneb - Operations - Execution Payload - success_regular_payload_with_gap_s OK
+ [Valid]   EF - Deneb - Operations - Execution Payload - zero_length_transaction_first_payl OK
+ [Valid]   EF - Deneb - Operations - Execution Payload - zero_length_transaction_regular_pa OK
+ [Valid]   EF - Deneb - Operations - Execution Payload - zeroed_commitment                  OK
```
OK: 38/38 Fail: 0/38 Skip: 0/38
## EF - Deneb - Operations - Proposer Slashing  [Preset: minimal]
```diff
+ [Invalid] EF - Deneb - Operations - Proposer Slashing - invalid_different_proposer_indices OK
+ [Invalid] EF - Deneb - Operations - Proposer Slashing - invalid_headers_are_same_sigs_are_ OK
+ [Invalid] EF - Deneb - Operations - Proposer Slashing - invalid_headers_are_same_sigs_are_ OK
+ [Invalid] EF - Deneb - Operations - Proposer Slashing - invalid_incorrect_proposer_index   OK
+ [Invalid] EF - Deneb - Operations - Proposer Slashing - invalid_incorrect_sig_1            OK
+ [Invalid] EF - Deneb - Operations - Proposer Slashing - invalid_incorrect_sig_1_and_2      OK
+ [Invalid] EF - Deneb - Operations - Proposer Slashing - invalid_incorrect_sig_1_and_2_swap OK
+ [Invalid] EF - Deneb - Operations - Proposer Slashing - invalid_incorrect_sig_2            OK
+ [Invalid] EF - Deneb - Operations - Proposer Slashing - invalid_proposer_is_not_activated  OK
+ [Invalid] EF - Deneb - Operations - Proposer Slashing - invalid_proposer_is_slashed        OK
+ [Invalid] EF - Deneb - Operations - Proposer Slashing - invalid_proposer_is_withdrawn      OK
+ [Invalid] EF - Deneb - Operations - Proposer Slashing - invalid_slots_of_different_epochs  OK
+ [Valid]   EF - Deneb - Operations - Proposer Slashing - basic                              OK
+ [Valid]   EF - Deneb - Operations - Proposer Slashing - block_header_from_future           OK
+ [Valid]   EF - Deneb - Operations - Proposer Slashing - slashed_and_proposer_index_the_sam OK
```
OK: 15/15 Fail: 0/15 Skip: 0/15
## EF - Deneb - Operations - Sync Aggregate  [Preset: minimal]
```diff
+ [Invalid] EF - Deneb - Operations - Sync Aggregate - invalid_signature_bad_domain          OK
+ [Invalid] EF - Deneb - Operations - Sync Aggregate - invalid_signature_extra_participant   OK
+ [Invalid] EF - Deneb - Operations - Sync Aggregate - invalid_signature_infinite_signature_ OK
+ [Invalid] EF - Deneb - Operations - Sync Aggregate - invalid_signature_infinite_signature_ OK
+ [Invalid] EF - Deneb - Operations - Sync Aggregate - invalid_signature_missing_participant OK
+ [Invalid] EF - Deneb - Operations - Sync Aggregate - invalid_signature_no_participants     OK
+ [Invalid] EF - Deneb - Operations - Sync Aggregate - invalid_signature_past_block          OK
+ [Invalid] EF - Deneb - Operations - Sync Aggregate - invalid_signature_previous_committee  OK
+ [Valid]   EF - Deneb - Operations - Sync Aggregate - proposer_in_committee_with_participat OK
+ [Valid]   EF - Deneb - Operations - Sync Aggregate - proposer_in_committee_without_partici OK
+ [Valid]   EF - Deneb - Operations - Sync Aggregate - random_all_but_one_participating_with OK
+ [Valid]   EF - Deneb - Operations - Sync Aggregate - random_high_participation_without_dup OK
+ [Valid]   EF - Deneb - Operations - Sync Aggregate - random_low_participation_without_dupl OK
+ [Valid]   EF - Deneb - Operations - Sync Aggregate - random_misc_balances_and_half_partici OK
+ [Valid]   EF - Deneb - Operations - Sync Aggregate - random_only_one_participant_without_d OK
+ [Valid]   EF - Deneb - Operations - Sync Aggregate - random_with_exits_without_duplicates  OK
+ [Valid]   EF - Deneb - Operations - Sync Aggregate - sync_committee_rewards_empty_particip OK
+ [Valid]   EF - Deneb - Operations - Sync Aggregate - sync_committee_rewards_nonduplicate_c OK
+ [Valid]   EF - Deneb - Operations - Sync Aggregate - sync_committee_rewards_not_full_parti OK
+ [Valid]   EF - Deneb - Operations - Sync Aggregate - sync_committee_with_nonparticipating_ OK
+ [Valid]   EF - Deneb - Operations - Sync Aggregate - sync_committee_with_nonparticipating_ OK
+ [Valid]   EF - Deneb - Operations - Sync Aggregate - sync_committee_with_participating_exi OK
+ [Valid]   EF - Deneb - Operations - Sync Aggregate - sync_committee_with_participating_wit OK
+ [Valid]   EF - Deneb - Operations - Sync Aggregate - valid_signature_future_committee      OK
```
OK: 24/24 Fail: 0/24 Skip: 0/24
## EF - Deneb - Operations - Voluntary Exit  [Preset: minimal]
```diff
+ [Invalid] EF - Deneb - Operations - Voluntary Exit - invalid_incorrect_signature           OK
+ [Invalid] EF - Deneb - Operations - Voluntary Exit - invalid_validator_already_exited      OK
+ [Invalid] EF - Deneb - Operations - Voluntary Exit - invalid_validator_exit_in_future      OK
+ [Invalid] EF - Deneb - Operations - Voluntary Exit - invalid_validator_incorrect_validator OK
+ [Invalid] EF - Deneb - Operations - Voluntary Exit - invalid_validator_not_active          OK
+ [Invalid] EF - Deneb - Operations - Voluntary Exit - invalid_validator_not_active_long_eno OK
+ [Invalid] EF - Deneb - Operations - Voluntary Exit - invalid_voluntary_exit_with_current_f OK
+ [Invalid] EF - Deneb - Operations - Voluntary Exit - invalid_voluntary_exit_with_current_f OK
+ [Invalid] EF - Deneb - Operations - Voluntary Exit - invalid_voluntary_exit_with_genesis_f OK
+ [Invalid] EF - Deneb - Operations - Voluntary Exit - invalid_voluntary_exit_with_genesis_f OK
+ [Valid]   EF - Deneb - Operations - Voluntary Exit - basic                                 OK
+ [Valid]   EF - Deneb - Operations - Voluntary Exit - default_exit_epoch_subsequent_exit    OK
+ [Valid]   EF - Deneb - Operations - Voluntary Exit - success_exit_queue__min_churn         OK
+ [Valid]   EF - Deneb - Operations - Voluntary Exit - success_exit_queue__scaled_churn      OK
+ [Valid]   EF - Deneb - Operations - Voluntary Exit - voluntary_exit_with_previous_fork_ver OK
+ [Valid]   EF - Deneb - Operations - Voluntary Exit - voluntary_exit_with_previous_fork_ver OK
```
OK: 16/16 Fail: 0/16 Skip: 0/16
## EF - Deneb - Operations - Withdrawals  [Preset: minimal]
```diff
+ [Invalid] EF - Deneb - Operations - Withdrawals - invalid_a_lot_fully_withdrawable_too_few OK
+ [Invalid] EF - Deneb - Operations - Withdrawals - invalid_a_lot_mixed_withdrawable_in_queu OK
+ [Invalid] EF - Deneb - Operations - Withdrawals - invalid_a_lot_partially_withdrawable_too OK
+ [Invalid] EF - Deneb - Operations - Withdrawals - invalid_incorrect_address_full           OK
+ [Invalid] EF - Deneb - Operations - Withdrawals - invalid_incorrect_address_partial        OK
+ [Invalid] EF - Deneb - Operations - Withdrawals - invalid_incorrect_amount_full            OK
+ [Invalid] EF - Deneb - Operations - Withdrawals - invalid_incorrect_amount_partial         OK
+ [Invalid] EF - Deneb - Operations - Withdrawals - invalid_incorrect_withdrawal_index       OK
+ [Invalid] EF - Deneb - Operations - Withdrawals - invalid_many_incorrectly_full            OK
+ [Invalid] EF - Deneb - Operations - Withdrawals - invalid_many_incorrectly_partial         OK
+ [Invalid] EF - Deneb - Operations - Withdrawals - invalid_max_per_slot_full_withdrawals_an OK
+ [Invalid] EF - Deneb - Operations - Withdrawals - invalid_max_per_slot_partial_withdrawals OK
+ [Invalid] EF - Deneb - Operations - Withdrawals - invalid_non_withdrawable_non_empty_withd OK
+ [Invalid] EF - Deneb - Operations - Withdrawals - invalid_one_expected_full_withdrawal_and OK
+ [Invalid] EF - Deneb - Operations - Withdrawals - invalid_one_expected_full_withdrawal_and OK
+ [Invalid] EF - Deneb - Operations - Withdrawals - invalid_one_expected_partial_withdrawal_ OK
+ [Invalid] EF - Deneb - Operations - Withdrawals - invalid_one_of_many_incorrectly_full     OK
+ [Invalid] EF - Deneb - Operations - Withdrawals - invalid_one_of_many_incorrectly_partial  OK
+ [Invalid] EF - Deneb - Operations - Withdrawals - invalid_two_expected_partial_withdrawal_ OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - all_withdrawal                           OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - no_withdrawals_but_some_next_epoch       OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - random_0                                 OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - random_full_withdrawals_0                OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - random_full_withdrawals_1                OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - random_full_withdrawals_2                OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - random_full_withdrawals_3                OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - random_partial_withdrawals_1             OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - random_partial_withdrawals_2             OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - random_partial_withdrawals_3             OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - random_partial_withdrawals_4             OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - random_partial_withdrawals_5             OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - success_all_fully_withdrawable           OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - success_all_partially_withdrawable       OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - success_excess_balance_but_no_max_effect OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - success_max_partial_withdrawable         OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - success_max_plus_one_withdrawable        OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - success_mixed_fully_and_partial_withdraw OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - success_no_excess_balance                OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - success_no_max_effective_balance         OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - success_one_full_withdrawal              OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - success_one_partial_withdrawable_active_ OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - success_one_partial_withdrawable_exited  OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - success_one_partial_withdrawable_exited_ OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - success_one_partial_withdrawable_in_exit OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - success_one_partial_withdrawable_not_yet OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - success_one_partial_withdrawal           OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - success_two_partial_withdrawable         OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - success_zero_expected_withdrawals        OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - withdrawable_epoch_but_0_balance         OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - withdrawable_epoch_but_0_effective_balan OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - withdrawable_epoch_but_0_effective_balan OK
```
OK: 51/51 Fail: 0/51 Skip: 0/51
## EF - Deneb - Random  [Preset: minimal]
```diff
+ [Valid]   EF - Deneb - Random - randomized_0 [Preset: minimal]                             OK
+ [Valid]   EF - Deneb - Random - randomized_1 [Preset: minimal]                             OK
+ [Valid]   EF - Deneb - Random - randomized_10 [Preset: minimal]                            OK
+ [Valid]   EF - Deneb - Random - randomized_11 [Preset: minimal]                            OK
+ [Valid]   EF - Deneb - Random - randomized_12 [Preset: minimal]                            OK
+ [Valid]   EF - Deneb - Random - randomized_13 [Preset: minimal]                            OK
+ [Valid]   EF - Deneb - Random - randomized_14 [Preset: minimal]                            OK
+ [Valid]   EF - Deneb - Random - randomized_15 [Preset: minimal]                            OK
+ [Valid]   EF - Deneb - Random - randomized_2 [Preset: minimal]                             OK
+ [Valid]   EF - Deneb - Random - randomized_3 [Preset: minimal]                             OK
+ [Valid]   EF - Deneb - Random - randomized_4 [Preset: minimal]                             OK
+ [Valid]   EF - Deneb - Random - randomized_5 [Preset: minimal]                             OK
+ [Valid]   EF - Deneb - Random - randomized_6 [Preset: minimal]                             OK
+ [Valid]   EF - Deneb - Random - randomized_7 [Preset: minimal]                             OK
+ [Valid]   EF - Deneb - Random - randomized_8 [Preset: minimal]                             OK
+ [Valid]   EF - Deneb - Random - randomized_9 [Preset: minimal]                             OK
```
OK: 16/16 Fail: 0/16 Skip: 0/16
## EF - Deneb - Rewards  [Preset: minimal]
```diff
+ EF - Deneb - Rewards - all_balances_too_low_for_reward [Preset: minimal]                   OK
+ EF - Deneb - Rewards - empty [Preset: minimal]                                             OK
+ EF - Deneb - Rewards - empty_leak [Preset: minimal]                                        OK
+ EF - Deneb - Rewards - full_all_correct [Preset: minimal]                                  OK
+ EF - Deneb - Rewards - full_but_partial_participation [Preset: minimal]                    OK
+ EF - Deneb - Rewards - full_but_partial_participation_leak [Preset: minimal]               OK
+ EF - Deneb - Rewards - full_leak [Preset: minimal]                                         OK
+ EF - Deneb - Rewards - full_random_0 [Preset: minimal]                                     OK
+ EF - Deneb - Rewards - full_random_1 [Preset: minimal]                                     OK
+ EF - Deneb - Rewards - full_random_2 [Preset: minimal]                                     OK
+ EF - Deneb - Rewards - full_random_3 [Preset: minimal]                                     OK
+ EF - Deneb - Rewards - full_random_4 [Preset: minimal]                                     OK
+ EF - Deneb - Rewards - full_random_leak [Preset: minimal]                                  OK
+ EF - Deneb - Rewards - full_random_low_balances_0 [Preset: minimal]                        OK
+ EF - Deneb - Rewards - full_random_low_balances_1 [Preset: minimal]                        OK
+ EF - Deneb - Rewards - full_random_misc_balances [Preset: minimal]                         OK
+ EF - Deneb - Rewards - full_random_seven_epoch_leak [Preset: minimal]                      OK
+ EF - Deneb - Rewards - full_random_ten_epoch_leak [Preset: minimal]                        OK
+ EF - Deneb - Rewards - full_random_without_leak_0 [Preset: minimal]                        OK
+ EF - Deneb - Rewards - full_random_without_leak_and_current_exit_0 [Preset: minimal]       OK
+ EF - Deneb - Rewards - half_full [Preset: minimal]                                         OK
+ EF - Deneb - Rewards - half_full_leak [Preset: minimal]                                    OK
+ EF - Deneb - Rewards - quarter_full [Preset: minimal]                                      OK
+ EF - Deneb - Rewards - quarter_full_leak [Preset: minimal]                                 OK
+ EF - Deneb - Rewards - some_very_low_effective_balances_that_attested [Preset: minimal]    OK
+ EF - Deneb - Rewards - some_very_low_effective_balances_that_attested_leak [Preset: minima OK
+ EF - Deneb - Rewards - some_very_low_effective_balances_that_did_not_attest [Preset: minim OK
+ EF - Deneb - Rewards - some_very_low_effective_balances_that_did_not_attest_leak [Preset:  OK
+ EF - Deneb - Rewards - with_exited_validators [Preset: minimal]                            OK
+ EF - Deneb - Rewards - with_exited_validators_leak [Preset: minimal]                       OK
+ EF - Deneb - Rewards - with_not_yet_activated_validators [Preset: minimal]                 OK
+ EF - Deneb - Rewards - with_not_yet_activated_validators_leak [Preset: minimal]            OK
+ EF - Deneb - Rewards - with_slashed_validators [Preset: minimal]                           OK
+ EF - Deneb - Rewards - with_slashed_validators_leak [Preset: minimal]                      OK
```
OK: 34/34 Fail: 0/34 Skip: 0/34
## EF - Deneb - SSZ consensus objects  [Preset: minimal]
```diff
+   Testing    AggregateAndProof                                                             OK
+   Testing    Attestation                                                                   OK
+   Testing    AttestationData                                                               OK
+   Testing    AttesterSlashing                                                              OK
+   Testing    BLSToExecutionChange                                                          OK
+   Testing    BeaconBlock                                                                   OK
+   Testing    BeaconBlockBody                                                               OK
+   Testing    BeaconBlockHeader                                                             OK
+   Testing    BeaconState                                                                   OK
+   Testing    BlobIdentifier                                                                OK
+   Testing    BlobSidecar                                                                   OK
+   Testing    Checkpoint                                                                    OK
+   Testing    ContributionAndProof                                                          OK
+   Testing    Deposit                                                                       OK
+   Testing    DepositData                                                                   OK
+   Testing    DepositMessage                                                                OK
+   Testing    Eth1Block                                                                     OK
+   Testing    Eth1Data                                                                      OK
+   Testing    ExecutionPayload                                                              OK
+   Testing    ExecutionPayloadHeader                                                        OK
+   Testing    Fork                                                                          OK
+   Testing    ForkData                                                                      OK
+   Testing    HistoricalBatch                                                               OK
+   Testing    HistoricalSummary                                                             OK
+   Testing    IndexedAttestation                                                            OK
+   Testing    LightClientBootstrap                                                          OK
+   Testing    LightClientFinalityUpdate                                                     OK
+   Testing    LightClientHeader                                                             OK
+   Testing    LightClientOptimisticUpdate                                                   OK
+   Testing    LightClientUpdate                                                             OK
+   Testing    PendingAttestation                                                            OK
+   Testing    PowBlock                                                                      OK
+   Testing    ProposerSlashing                                                              OK
+   Testing    SignedAggregateAndProof                                                       OK
+   Testing    SignedBLSToExecutionChange                                                    OK
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
+   Testing    Withdrawal                                                                    OK
```
OK: 48/48 Fail: 0/48 Skip: 0/48
## EF - Deneb - Sanity - Blocks  [Preset: minimal]
```diff
+ [Invalid] EF - Deneb - Sanity - Blocks - invalid_all_zeroed_sig [Preset: minimal]          OK
+ [Invalid] EF - Deneb - Sanity - Blocks - invalid_duplicate_attester_slashing_same_block [P OK
+ [Invalid] EF - Deneb - Sanity - Blocks - invalid_duplicate_bls_changes_same_block [Preset: OK
+ [Invalid] EF - Deneb - Sanity - Blocks - invalid_duplicate_deposit_same_block [Preset: min OK
+ [Invalid] EF - Deneb - Sanity - Blocks - invalid_duplicate_proposer_slashings_same_block [ OK
+ [Invalid] EF - Deneb - Sanity - Blocks - invalid_duplicate_validator_exit_same_block [Pres OK
+ [Invalid] EF - Deneb - Sanity - Blocks - invalid_exceed_max_blobs_per_block [Preset: minim OK
+ [Invalid] EF - Deneb - Sanity - Blocks - invalid_incorrect_block_sig [Preset: minimal]     OK
+ [Invalid] EF - Deneb - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_expecte OK
+ [Invalid] EF - Deneb - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_propose OK
+ [Invalid] EF - Deneb - Sanity - Blocks - invalid_incorrect_state_root [Preset: minimal]    OK
+ [Invalid] EF - Deneb - Sanity - Blocks - invalid_is_execution_enabled_false [Preset: minim OK
+ [Invalid] EF - Deneb - Sanity - Blocks - invalid_max_blobs_per_block_two_txs [Preset: mini OK
+ [Invalid] EF - Deneb - Sanity - Blocks - invalid_one_blob_max_plus_one_txs [Preset: minima OK
+ [Invalid] EF - Deneb - Sanity - Blocks - invalid_only_increase_deposit_count [Preset: mini OK
+ [Invalid] EF - Deneb - Sanity - Blocks - invalid_parent_from_same_slot [Preset: minimal]   OK
+ [Invalid] EF - Deneb - Sanity - Blocks - invalid_prev_slot_block_transition [Preset: minim OK
+ [Invalid] EF - Deneb - Sanity - Blocks - invalid_same_slot_block_transition [Preset: minim OK
+ [Invalid] EF - Deneb - Sanity - Blocks - invalid_similar_proposer_slashings_same_block [Pr OK
+ [Invalid] EF - Deneb - Sanity - Blocks - invalid_two_bls_changes_of_different_addresses_sa OK
+ [Invalid] EF - Deneb - Sanity - Blocks - invalid_withdrawal_fail_second_block_payload_isnt OK
+ [Invalid] EF - Deneb - Sanity - Blocks - slash_and_exit_same_index [Preset: minimal]       OK
+ [Valid]   EF - Deneb - Sanity - Blocks - activate_and_partial_withdrawal_max_effective_bal OK
+ [Valid]   EF - Deneb - Sanity - Blocks - activate_and_partial_withdrawal_overdeposit [Pres OK
+ [Valid]   EF - Deneb - Sanity - Blocks - attestation [Preset: minimal]                     OK
+ [Valid]   EF - Deneb - Sanity - Blocks - attester_slashing [Preset: minimal]               OK
+ [Valid]   EF - Deneb - Sanity - Blocks - balance_driven_status_transitions [Preset: minima OK
+ [Valid]   EF - Deneb - Sanity - Blocks - block_transition_randomized_payload [Preset: mini OK
+ [Valid]   EF - Deneb - Sanity - Blocks - bls_change [Preset: minimal]                      OK
+ [Valid]   EF - Deneb - Sanity - Blocks - deposit_and_bls_change [Preset: minimal]          OK
+ [Valid]   EF - Deneb - Sanity - Blocks - deposit_in_block [Preset: minimal]                OK
+ [Valid]   EF - Deneb - Sanity - Blocks - deposit_top_up [Preset: minimal]                  OK
+ [Valid]   EF - Deneb - Sanity - Blocks - duplicate_attestation_same_block [Preset: minimal OK
+ [Valid]   EF - Deneb - Sanity - Blocks - empty_block_transition [Preset: minimal]          OK
+ [Valid]   EF - Deneb - Sanity - Blocks - empty_block_transition_large_validator_set [Prese OK
+ [Valid]   EF - Deneb - Sanity - Blocks - empty_block_transition_no_tx [Preset: minimal]    OK
+ [Valid]   EF - Deneb - Sanity - Blocks - empty_epoch_transition [Preset: minimal]          OK
+ [Valid]   EF - Deneb - Sanity - Blocks - empty_epoch_transition_large_validator_set [Prese OK
+ [Valid]   EF - Deneb - Sanity - Blocks - empty_epoch_transition_not_finalizing [Preset: mi OK
+ [Valid]   EF - Deneb - Sanity - Blocks - eth1_data_votes_consensus [Preset: minimal]       OK
+ [Valid]   EF - Deneb - Sanity - Blocks - eth1_data_votes_no_consensus [Preset: minimal]    OK
+ [Valid]   EF - Deneb - Sanity - Blocks - exit_and_bls_change [Preset: minimal]             OK
+ [Valid]   EF - Deneb - Sanity - Blocks - full_random_operations_0 [Preset: minimal]        OK
+ [Valid]   EF - Deneb - Sanity - Blocks - full_random_operations_1 [Preset: minimal]        OK
+ [Valid]   EF - Deneb - Sanity - Blocks - full_random_operations_2 [Preset: minimal]        OK
+ [Valid]   EF - Deneb - Sanity - Blocks - full_random_operations_3 [Preset: minimal]        OK
+ [Valid]   EF - Deneb - Sanity - Blocks - full_withdrawal_in_epoch_transition [Preset: mini OK
+ [Valid]   EF - Deneb - Sanity - Blocks - high_proposer_index [Preset: minimal]             OK
+ [Valid]   EF - Deneb - Sanity - Blocks - historical_batch [Preset: minimal]                OK
+ [Valid]   EF - Deneb - Sanity - Blocks - inactivity_scores_full_participation_leaking [Pre OK
+ [Valid]   EF - Deneb - Sanity - Blocks - inactivity_scores_leaking [Preset: minimal]       OK
+ [Valid]   EF - Deneb - Sanity - Blocks - many_partial_withdrawals_in_epoch_transition [Pre OK
+ [Valid]   EF - Deneb - Sanity - Blocks - max_blobs_per_block [Preset: minimal]             OK
+ [Valid]   EF - Deneb - Sanity - Blocks - mix_blob_tx_and_non_blob_tx [Preset: minimal]     OK
+ [Valid]   EF - Deneb - Sanity - Blocks - multiple_attester_slashings_no_overlap [Preset: m OK
+ [Valid]   EF - Deneb - Sanity - Blocks - multiple_attester_slashings_partial_overlap [Pres OK
+ [Valid]   EF - Deneb - Sanity - Blocks - multiple_different_proposer_slashings_same_block  OK
+ [Valid]   EF - Deneb - Sanity - Blocks - multiple_different_validator_exits_same_block [Pr OK
+ [Valid]   EF - Deneb - Sanity - Blocks - one_blob [Preset: minimal]                        OK
+ [Valid]   EF - Deneb - Sanity - Blocks - one_blob_max_txs [Preset: minimal]                OK
+ [Valid]   EF - Deneb - Sanity - Blocks - one_blob_two_txs [Preset: minimal]                OK
+ [Valid]   EF - Deneb - Sanity - Blocks - partial_withdrawal_in_epoch_transition [Preset: m OK
+ [Valid]   EF - Deneb - Sanity - Blocks - proposer_after_inactive_index [Preset: minimal]   OK
+ [Valid]   EF - Deneb - Sanity - Blocks - proposer_self_slashing [Preset: minimal]          OK
+ [Valid]   EF - Deneb - Sanity - Blocks - proposer_slashing [Preset: minimal]               OK
+ [Valid]   EF - Deneb - Sanity - Blocks - skipped_slots [Preset: minimal]                   OK
+ [Valid]   EF - Deneb - Sanity - Blocks - slash_and_exit_diff_index [Preset: minimal]       OK
+ [Valid]   EF - Deneb - Sanity - Blocks - sync_committee_committee__empty [Preset: minimal] OK
+ [Valid]   EF - Deneb - Sanity - Blocks - sync_committee_committee__full [Preset: minimal]  OK
+ [Valid]   EF - Deneb - Sanity - Blocks - sync_committee_committee__half [Preset: minimal]  OK
+ [Valid]   EF - Deneb - Sanity - Blocks - sync_committee_committee_genesis__empty [Preset:  OK
+ [Valid]   EF - Deneb - Sanity - Blocks - sync_committee_committee_genesis__full [Preset: m OK
+ [Valid]   EF - Deneb - Sanity - Blocks - sync_committee_committee_genesis__half [Preset: m OK
+ [Valid]   EF - Deneb - Sanity - Blocks - top_up_and_partial_withdrawable_validator [Preset OK
+ [Valid]   EF - Deneb - Sanity - Blocks - top_up_to_fully_withdrawn_validator [Preset: mini OK
+ [Valid]   EF - Deneb - Sanity - Blocks - voluntary_exit [Preset: minimal]                  OK
+ [Valid]   EF - Deneb - Sanity - Blocks - withdrawal_success_two_blocks [Preset: minimal]   OK
+ [Valid]   EF - Deneb - Sanity - Blocks - zero_blob [Preset: minimal]                       OK
```
OK: 78/78 Fail: 0/78 Skip: 0/78
## EF - Deneb - Sanity - Slots  [Preset: minimal]
```diff
+ EF - Deneb - Slots - double_empty_epoch [Preset: minimal]                                  OK
+ EF - Deneb - Slots - empty_epoch [Preset: minimal]                                         OK
+ EF - Deneb - Slots - historical_accumulator [Preset: minimal]                              OK
+ EF - Deneb - Slots - over_epoch_boundary [Preset: minimal]                                 OK
+ EF - Deneb - Slots - slots_1 [Preset: minimal]                                             OK
+ EF - Deneb - Slots - slots_2 [Preset: minimal]                                             OK
```
OK: 6/6 Fail: 0/6 Skip: 0/6
## EF - Deneb - Transition  [Preset: minimal]
```diff
+ EF - Deneb - Transition - normal_transition [Preset: minimal]                              OK
+ EF - Deneb - Transition - simple_transition [Preset: minimal]                              OK
+ EF - Deneb - Transition - transition_attestation_from_previous_fork_with_new_range [Preset OK
+ EF - Deneb - Transition - transition_missing_first_post_block [Preset: minimal]            OK
+ EF - Deneb - Transition - transition_missing_last_pre_fork_block [Preset: minimal]         OK
+ EF - Deneb - Transition - transition_only_blocks_post_fork [Preset: minimal]               OK
+ EF - Deneb - Transition - transition_randomized_state [Preset: minimal]                    OK
+ EF - Deneb - Transition - transition_with_activation_at_fork_epoch [Preset: minimal]       OK
+ EF - Deneb - Transition - transition_with_attester_slashing_right_after_fork [Preset: mini OK
+ EF - Deneb - Transition - transition_with_attester_slashing_right_before_fork [Preset: min OK
+ EF - Deneb - Transition - transition_with_btec_right_after_fork [Preset: minimal]          OK
+ EF - Deneb - Transition - transition_with_btec_right_before_fork [Preset: minimal]         OK
+ EF - Deneb - Transition - transition_with_deposit_right_after_fork [Preset: minimal]       OK
+ EF - Deneb - Transition - transition_with_deposit_right_before_fork [Preset: minimal]      OK
+ EF - Deneb - Transition - transition_with_finality [Preset: minimal]                       OK
+ EF - Deneb - Transition - transition_with_leaking_at_fork [Preset: minimal]                OK
+ EF - Deneb - Transition - transition_with_leaking_pre_fork [Preset: minimal]               OK
+ EF - Deneb - Transition - transition_with_no_attestations_until_after_fork [Preset: minima OK
+ EF - Deneb - Transition - transition_with_non_empty_activation_queue [Preset: minimal]     OK
+ EF - Deneb - Transition - transition_with_one_fourth_exiting_validators_exit_at_fork [Pres OK
+ EF - Deneb - Transition - transition_with_one_fourth_exiting_validators_exit_post_fork [Pr OK
+ EF - Deneb - Transition - transition_with_one_fourth_slashed_active_validators_pre_fork [P OK
+ EF - Deneb - Transition - transition_with_proposer_slashing_right_after_fork [Preset: mini OK
+ EF - Deneb - Transition - transition_with_proposer_slashing_right_before_fork [Preset: min OK
+ EF - Deneb - Transition - transition_with_random_half_participation [Preset: minimal]      OK
+ EF - Deneb - Transition - transition_with_random_three_quarters_participation [Preset: min OK
+ EF - Deneb - Transition - transition_with_voluntary_exit_right_after_fork [Preset: minimal OK
+ EF - Deneb - Transition - transition_with_voluntary_exit_right_before_fork [Preset: minima OK
```
OK: 28/28 Fail: 0/28 Skip: 0/28
## EF - Deneb - Unittests - Light client - Sync protocol [Preset: minimal]
```diff
+ process_light_client_update_finality_updated                                               OK
+ process_light_client_update_timeout                                                        OK
+ test_process_light_client_update_at_period_boundary                                        OK
+ test_process_light_client_update_not_timeout                                               OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
## EF - Light client - Single merkle proof [Preset: minimal]
```diff
+ Light client - Single merkle proof - minimal/altair/light_client/single_merkle_proof/Beaco OK
+ Light client - Single merkle proof - minimal/altair/light_client/single_merkle_proof/Beaco OK
+ Light client - Single merkle proof - minimal/altair/light_client/single_merkle_proof/Beaco OK
+ Light client - Single merkle proof - minimal/bellatrix/light_client/single_merkle_proof/Be OK
+ Light client - Single merkle proof - minimal/bellatrix/light_client/single_merkle_proof/Be OK
+ Light client - Single merkle proof - minimal/bellatrix/light_client/single_merkle_proof/Be OK
+ Light client - Single merkle proof - minimal/capella/light_client/single_merkle_proof/Beac OK
+ Light client - Single merkle proof - minimal/capella/light_client/single_merkle_proof/Beac OK
+ Light client - Single merkle proof - minimal/capella/light_client/single_merkle_proof/Beac OK
+ Light client - Single merkle proof - minimal/capella/light_client/single_merkle_proof/Beac OK
+ Light client - Single merkle proof - minimal/deneb/light_client/single_merkle_proof/Beacon OK
+ Light client - Single merkle proof - minimal/deneb/light_client/single_merkle_proof/Beacon OK
+ Light client - Single merkle proof - minimal/deneb/light_client/single_merkle_proof/Beacon OK
+ Light client - Single merkle proof - minimal/deneb/light_client/single_merkle_proof/Beacon OK
```
OK: 14/14 Fail: 0/14 Skip: 0/14
## EF - Light client - Sync [Preset: minimal]
```diff
+ Light client - Sync - minimal/altair/light_client/sync/pyspec_tests/advance_finality_witho OK
+ Light client - Sync - minimal/altair/light_client/sync/pyspec_tests/capella_store_with_leg OK
+ Light client - Sync - minimal/altair/light_client/sync/pyspec_tests/deneb_store_with_legac OK
+ Light client - Sync - minimal/altair/light_client/sync/pyspec_tests/light_client_sync      OK
+ Light client - Sync - minimal/altair/light_client/sync/pyspec_tests/supply_sync_committee_ OK
+ Light client - Sync - minimal/bellatrix/light_client/sync/pyspec_tests/advance_finality_wi OK
+ Light client - Sync - minimal/bellatrix/light_client/sync/pyspec_tests/capella_deneb_fork  OK
+ Light client - Sync - minimal/bellatrix/light_client/sync/pyspec_tests/capella_fork        OK
+ Light client - Sync - minimal/bellatrix/light_client/sync/pyspec_tests/capella_store_with_ OK
+ Light client - Sync - minimal/bellatrix/light_client/sync/pyspec_tests/deneb_store_with_le OK
+ Light client - Sync - minimal/bellatrix/light_client/sync/pyspec_tests/light_client_sync   OK
+ Light client - Sync - minimal/bellatrix/light_client/sync/pyspec_tests/supply_sync_committ OK
+ Light client - Sync - minimal/capella/light_client/sync/pyspec_tests/advance_finality_with OK
+ Light client - Sync - minimal/capella/light_client/sync/pyspec_tests/deneb_fork            OK
+ Light client - Sync - minimal/capella/light_client/sync/pyspec_tests/deneb_store_with_lega OK
+ Light client - Sync - minimal/capella/light_client/sync/pyspec_tests/light_client_sync     OK
+ Light client - Sync - minimal/capella/light_client/sync/pyspec_tests/supply_sync_committee OK
+ Light client - Sync - minimal/deneb/light_client/sync/pyspec_tests/advance_finality_withou OK
+ Light client - Sync - minimal/deneb/light_client/sync/pyspec_tests/light_client_sync       OK
+ Light client - Sync - minimal/deneb/light_client/sync/pyspec_tests/supply_sync_committee_f OK
```
OK: 20/20 Fail: 0/20 Skip: 0/20
## EF - Light client - Update ranking [Preset: minimal]
```diff
+ Light client - Update ranking - minimal/altair/light_client/update_ranking/pyspec_tests/up OK
+ Light client - Update ranking - minimal/bellatrix/light_client/update_ranking/pyspec_tests OK
+ Light client - Update ranking - minimal/capella/light_client/update_ranking/pyspec_tests/u OK
+ Light client - Update ranking - minimal/deneb/light_client/update_ranking/pyspec_tests/upd OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
## EF - Merkle proof [Preset: minimal]
```diff
+ Merkle proof - Single merkle proof - minimal/deneb/merkle_proof/single_merkle_proof/Beacon OK
+ Merkle proof - Single merkle proof - minimal/deneb/merkle_proof/single_merkle_proof/Beacon OK
+ Merkle proof - Single merkle proof - minimal/deneb/merkle_proof/single_merkle_proof/Beacon OK
+ Merkle proof - Single merkle proof - minimal/deneb/merkle_proof/single_merkle_proof/Beacon OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
## EF - Phase 0 - Epoch Processing - Effective balance updates [Preset: minimal]
```diff
+ Effective balance updates - effective_balance_hysteresis [Preset: minimal]                 OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## EF - Phase 0 - Epoch Processing - Eth1 data reset [Preset: minimal]
```diff
+ Eth1 data reset - eth1_vote_no_reset [Preset: minimal]                                     OK
+ Eth1 data reset - eth1_vote_reset [Preset: minimal]                                        OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## EF - Phase 0 - Epoch Processing - Historical roots update [Preset: minimal]
```diff
+ Historical roots update - historical_root_accumulator [Preset: minimal]                    OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## EF - Phase 0 - Epoch Processing - Justification & Finalization [Preset: minimal]
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
## EF - Phase 0 - Epoch Processing - Participation record updates [Preset: minimal]
```diff
+ Participation record updates - updated_participation_record [Preset: minimal]              OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## EF - Phase 0 - Epoch Processing - RANDAO mixes reset [Preset: minimal]
```diff
+ RANDAO mixes reset - updated_randao_mixes [Preset: minimal]                                OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## EF - Phase 0 - Epoch Processing - Registry updates [Preset: minimal]
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
+ Registry updates - invalid_large_withdrawable_epoch [Preset: minimal]                      OK
```
OK: 15/15 Fail: 0/15 Skip: 0/15
## EF - Phase 0 - Epoch Processing - Rewards and penalties [Preset: minimal]
```diff
+ Rewards and penalties - almost_empty_attestations [Preset: minimal]                        OK
+ Rewards and penalties - almost_empty_attestations_with_leak [Preset: minimal]              OK
+ Rewards and penalties - almost_full_attestations [Preset: minimal]                         OK
+ Rewards and penalties - almost_full_attestations_with_leak [Preset: minimal]               OK
+ Rewards and penalties - attestations_some_slashed [Preset: minimal]                        OK
+ Rewards and penalties - duplicate_attestation [Preset: minimal]                            OK
+ Rewards and penalties - duplicate_participants_different_attestation_1 [Preset: minimal]   OK
+ Rewards and penalties - duplicate_participants_different_attestation_2 [Preset: minimal]   OK
+ Rewards and penalties - duplicate_participants_different_attestation_3 [Preset: minimal]   OK
+ Rewards and penalties - full_attestation_participation [Preset: minimal]                   OK
+ Rewards and penalties - full_attestation_participation_with_leak [Preset: minimal]         OK
+ Rewards and penalties - full_attestations_misc_balances [Preset: minimal]                  OK
+ Rewards and penalties - full_attestations_one_validaor_one_gwei [Preset: minimal]          OK
+ Rewards and penalties - full_attestations_random_incorrect_fields [Preset: minimal]        OK
+ Rewards and penalties - genesis_epoch_full_attestations_no_rewards [Preset: minimal]       OK
+ Rewards and penalties - genesis_epoch_no_attestations_no_penalties [Preset: minimal]       OK
+ Rewards and penalties - no_attestations_all_penalties [Preset: minimal]                    OK
+ Rewards and penalties - random_fill_attestations [Preset: minimal]                         OK
+ Rewards and penalties - random_fill_attestations_with_leak [Preset: minimal]               OK
```
OK: 19/19 Fail: 0/19 Skip: 0/19
## EF - Phase 0 - Epoch Processing - Slashings [Preset: minimal]
```diff
+ Slashings - low_penalty [Preset: minimal]                                                  OK
+ Slashings - max_penalties [Preset: minimal]                                                OK
+ Slashings - minimal_penalty [Preset: minimal]                                              OK
+ Slashings - scaled_penalties [Preset: minimal]                                             OK
+ Slashings - slashings_with_random_state [Preset: minimal]                                  OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## EF - Phase 0 - Epoch Processing - Slashings reset [Preset: minimal]
```diff
+ Slashings reset - flush_slashings [Preset: minimal]                                        OK
```
OK: 1/1 Fail: 0/1 Skip: 0/1
## EF - Phase 0 - Operations - Attestation  [Preset: minimal]
```diff
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attestation  [Preset: mi OK
```
OK: 41/41 Fail: 0/41 Skip: 0/41
## EF - Phase 0 - Operations - Attester Slashing  [Preset: minimal]
```diff
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Attester Slashing  [Pres OK
```
OK: 30/30 Fail: 0/30 Skip: 0/30
## EF - Phase 0 - Operations - Block Header  [Preset: minimal]
```diff
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Block Header  [Preset: m OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Block Header  [Preset: m OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Block Header  [Preset: m OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Block Header  [Preset: m OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Block Header  [Preset: m OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Block Header  [Preset: m OK
```
OK: 6/6 Fail: 0/6 Skip: 0/6
## EF - Phase 0 - Operations - Deposit  [Preset: minimal]
```diff
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Deposit  [Preset: minima OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Deposit  [Preset: minima OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Deposit  [Preset: minima OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Deposit  [Preset: minima OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Deposit  [Preset: minima OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Deposit  [Preset: minima OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Deposit  [Preset: minima OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Deposit  [Preset: minima OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Deposit  [Preset: minima OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Deposit  [Preset: minima OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Deposit  [Preset: minima OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Deposit  [Preset: minima OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Deposit  [Preset: minima OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Deposit  [Preset: minima OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Deposit  [Preset: minima OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Deposit  [Preset: minima OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Deposit  [Preset: minima OK
```
OK: 17/17 Fail: 0/17 Skip: 0/17
## EF - Phase 0 - Operations - Proposer Slashing  [Preset: minimal]
```diff
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
```
OK: 15/15 Fail: 0/15 Skip: 0/15
## EF - Phase 0 - Operations - Voluntary Exit  [Preset: minimal]
```diff
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Voluntary Exit  [Preset: OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Voluntary Exit  [Preset: OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Voluntary Exit  [Preset: OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Voluntary Exit  [Preset: OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Voluntary Exit  [Preset: OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Voluntary Exit  [Preset: OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Voluntary Exit  [Preset: OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Voluntary Exit  [Preset: OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Voluntary Exit  [Preset: OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Voluntary Exit  [Preset: OK
```
OK: 10/10 Fail: 0/10 Skip: 0/10
## EF - Phase 0 - Rewards  [Preset: minimal]
```diff
+ EF - Phase 0 - Rewards - all_balances_too_low_for_reward [Preset: minimal]                 OK
+ EF - Phase 0 - Rewards - duplicate_attestations_at_later_slots [Preset: minimal]           OK
+ EF - Phase 0 - Rewards - empty [Preset: minimal]                                           OK
+ EF - Phase 0 - Rewards - empty_leak [Preset: minimal]                                      OK
+ EF - Phase 0 - Rewards - full_all_correct [Preset: minimal]                                OK
+ EF - Phase 0 - Rewards - full_but_partial_participation [Preset: minimal]                  OK
+ EF - Phase 0 - Rewards - full_but_partial_participation_leak [Preset: minimal]             OK
+ EF - Phase 0 - Rewards - full_correct_target_incorrect_head [Preset: minimal]              OK
+ EF - Phase 0 - Rewards - full_correct_target_incorrect_head_leak [Preset: minimal]         OK
+ EF - Phase 0 - Rewards - full_delay_max_slots [Preset: minimal]                            OK
+ EF - Phase 0 - Rewards - full_delay_one_slot [Preset: minimal]                             OK
+ EF - Phase 0 - Rewards - full_half_correct_target_incorrect_head [Preset: minimal]         OK
+ EF - Phase 0 - Rewards - full_half_correct_target_incorrect_head_leak [Preset: minimal]    OK
+ EF - Phase 0 - Rewards - full_half_incorrect_target_correct_head [Preset: minimal]         OK
+ EF - Phase 0 - Rewards - full_half_incorrect_target_correct_head_leak [Preset: minimal]    OK
+ EF - Phase 0 - Rewards - full_half_incorrect_target_incorrect_head [Preset: minimal]       OK
+ EF - Phase 0 - Rewards - full_half_incorrect_target_incorrect_head_leak [Preset: minimal]  OK
+ EF - Phase 0 - Rewards - full_leak [Preset: minimal]                                       OK
+ EF - Phase 0 - Rewards - full_mixed_delay [Preset: minimal]                                OK
+ EF - Phase 0 - Rewards - full_random_0 [Preset: minimal]                                   OK
+ EF - Phase 0 - Rewards - full_random_1 [Preset: minimal]                                   OK
+ EF - Phase 0 - Rewards - full_random_2 [Preset: minimal]                                   OK
+ EF - Phase 0 - Rewards - full_random_3 [Preset: minimal]                                   OK
+ EF - Phase 0 - Rewards - full_random_4 [Preset: minimal]                                   OK
+ EF - Phase 0 - Rewards - full_random_leak [Preset: minimal]                                OK
+ EF - Phase 0 - Rewards - full_random_low_balances_0 [Preset: minimal]                      OK
+ EF - Phase 0 - Rewards - full_random_low_balances_1 [Preset: minimal]                      OK
+ EF - Phase 0 - Rewards - full_random_misc_balances [Preset: minimal]                       OK
+ EF - Phase 0 - Rewards - full_random_seven_epoch_leak [Preset: minimal]                    OK
+ EF - Phase 0 - Rewards - full_random_ten_epoch_leak [Preset: minimal]                      OK
+ EF - Phase 0 - Rewards - full_random_without_leak_0 [Preset: minimal]                      OK
+ EF - Phase 0 - Rewards - full_random_without_leak_and_current_exit_0 [Preset: minimal]     OK
+ EF - Phase 0 - Rewards - half_full [Preset: minimal]                                       OK
+ EF - Phase 0 - Rewards - half_full_leak [Preset: minimal]                                  OK
+ EF - Phase 0 - Rewards - one_attestation_one_correct [Preset: minimal]                     OK
+ EF - Phase 0 - Rewards - one_attestation_one_correct_leak [Preset: minimal]                OK
+ EF - Phase 0 - Rewards - proposer_not_in_attestations [Preset: minimal]                    OK
+ EF - Phase 0 - Rewards - quarter_full [Preset: minimal]                                    OK
+ EF - Phase 0 - Rewards - quarter_full_leak [Preset: minimal]                               OK
+ EF - Phase 0 - Rewards - some_very_low_effective_balances_that_attested [Preset: minimal]  OK
+ EF - Phase 0 - Rewards - some_very_low_effective_balances_that_attested_leak [Preset: mini OK
+ EF - Phase 0 - Rewards - some_very_low_effective_balances_that_did_not_attest [Preset: min OK
+ EF - Phase 0 - Rewards - some_very_low_effective_balances_that_did_not_attest_leak [Preset OK
+ EF - Phase 0 - Rewards - with_exited_validators [Preset: minimal]                          OK
+ EF - Phase 0 - Rewards - with_exited_validators_leak [Preset: minimal]                     OK
+ EF - Phase 0 - Rewards - with_not_yet_activated_validators [Preset: minimal]               OK
+ EF - Phase 0 - Rewards - with_not_yet_activated_validators_leak [Preset: minimal]          OK
+ EF - Phase 0 - Rewards - with_slashed_validators [Preset: minimal]                         OK
+ EF - Phase 0 - Rewards - with_slashed_validators_leak [Preset: minimal]                    OK
```
OK: 49/49 Fail: 0/49 Skip: 0/49
## EF - Phase 0 - SSZ consensus objects  [Preset: minimal]
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
## EF - Phase 0 - Sanity - Slots  [Preset: minimal]
```diff
+ EF - Phase 0 - Slots - double_empty_epoch [Preset: minimal]                                OK
+ EF - Phase 0 - Slots - empty_epoch [Preset: minimal]                                       OK
+ EF - Phase 0 - Slots - historical_accumulator [Preset: minimal]                            OK
+ EF - Phase 0 - Slots - over_epoch_boundary [Preset: minimal]                               OK
+ EF - Phase 0 - Slots - slots_1 [Preset: minimal]                                           OK
+ EF - Phase 0 - Slots - slots_2 [Preset: minimal]                                           OK
```
OK: 6/6 Fail: 0/6 Skip: 0/6
## EF - Phase0 - Finality  [Preset: minimal]
```diff
+ [Valid]   EF - Phase0 - Finality - finality_no_updates_at_genesis [Preset: minimal]        OK
+ [Valid]   EF - Phase0 - Finality - finality_rule_1 [Preset: minimal]                       OK
+ [Valid]   EF - Phase0 - Finality - finality_rule_2 [Preset: minimal]                       OK
+ [Valid]   EF - Phase0 - Finality - finality_rule_3 [Preset: minimal]                       OK
+ [Valid]   EF - Phase0 - Finality - finality_rule_4 [Preset: minimal]                       OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## EF - Phase0 - Random  [Preset: minimal]
```diff
+ [Valid]   EF - Phase0 - Random - randomized_0 [Preset: minimal]                            OK
+ [Valid]   EF - Phase0 - Random - randomized_1 [Preset: minimal]                            OK
+ [Valid]   EF - Phase0 - Random - randomized_10 [Preset: minimal]                           OK
+ [Valid]   EF - Phase0 - Random - randomized_11 [Preset: minimal]                           OK
+ [Valid]   EF - Phase0 - Random - randomized_12 [Preset: minimal]                           OK
+ [Valid]   EF - Phase0 - Random - randomized_13 [Preset: minimal]                           OK
+ [Valid]   EF - Phase0 - Random - randomized_14 [Preset: minimal]                           OK
+ [Valid]   EF - Phase0 - Random - randomized_15 [Preset: minimal]                           OK
+ [Valid]   EF - Phase0 - Random - randomized_2 [Preset: minimal]                            OK
+ [Valid]   EF - Phase0 - Random - randomized_3 [Preset: minimal]                            OK
+ [Valid]   EF - Phase0 - Random - randomized_4 [Preset: minimal]                            OK
+ [Valid]   EF - Phase0 - Random - randomized_5 [Preset: minimal]                            OK
+ [Valid]   EF - Phase0 - Random - randomized_6 [Preset: minimal]                            OK
+ [Valid]   EF - Phase0 - Random - randomized_7 [Preset: minimal]                            OK
+ [Valid]   EF - Phase0 - Random - randomized_8 [Preset: minimal]                            OK
+ [Valid]   EF - Phase0 - Random - randomized_9 [Preset: minimal]                            OK
```
OK: 16/16 Fail: 0/16 Skip: 0/16
## EF - Phase0 - Sanity - Blocks  [Preset: minimal]
```diff
+ [Invalid] EF - Phase0 - Sanity - Blocks - invalid_all_zeroed_sig [Preset: minimal]         OK
+ [Invalid] EF - Phase0 - Sanity - Blocks - invalid_duplicate_attester_slashing_same_block [ OK
+ [Invalid] EF - Phase0 - Sanity - Blocks - invalid_duplicate_deposit_same_block [Preset: mi OK
+ [Invalid] EF - Phase0 - Sanity - Blocks - invalid_duplicate_proposer_slashings_same_block  OK
+ [Invalid] EF - Phase0 - Sanity - Blocks - invalid_duplicate_validator_exit_same_block [Pre OK
+ [Invalid] EF - Phase0 - Sanity - Blocks - invalid_incorrect_block_sig [Preset: minimal]    OK
+ [Invalid] EF - Phase0 - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_expect OK
+ [Invalid] EF - Phase0 - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_propos OK
+ [Invalid] EF - Phase0 - Sanity - Blocks - invalid_incorrect_state_root [Preset: minimal]   OK
+ [Invalid] EF - Phase0 - Sanity - Blocks - invalid_only_increase_deposit_count [Preset: min OK
+ [Invalid] EF - Phase0 - Sanity - Blocks - invalid_parent_from_same_slot [Preset: minimal]  OK
+ [Invalid] EF - Phase0 - Sanity - Blocks - invalid_prev_slot_block_transition [Preset: mini OK
+ [Invalid] EF - Phase0 - Sanity - Blocks - invalid_proposal_for_genesis_slot [Preset: minim OK
+ [Invalid] EF - Phase0 - Sanity - Blocks - invalid_same_slot_block_transition [Preset: mini OK
+ [Invalid] EF - Phase0 - Sanity - Blocks - invalid_similar_proposer_slashings_same_block [P OK
+ [Invalid] EF - Phase0 - Sanity - Blocks - slash_and_exit_same_index [Preset: minimal]      OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - attestation [Preset: minimal]                    OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - attester_slashing [Preset: minimal]              OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - balance_driven_status_transitions [Preset: minim OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - deposit_in_block [Preset: minimal]               OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - deposit_top_up [Preset: minimal]                 OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - duplicate_attestation_same_block [Preset: minima OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - empty_block_transition [Preset: minimal]         OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - empty_block_transition_large_validator_set [Pres OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - empty_epoch_transition [Preset: minimal]         OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - empty_epoch_transition_large_validator_set [Pres OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - empty_epoch_transition_not_finalizing [Preset: m OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - eth1_data_votes_consensus [Preset: minimal]      OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - eth1_data_votes_no_consensus [Preset: minimal]   OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - full_random_operations_0 [Preset: minimal]       OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - full_random_operations_1 [Preset: minimal]       OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - full_random_operations_2 [Preset: minimal]       OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - full_random_operations_3 [Preset: minimal]       OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - high_proposer_index [Preset: minimal]            OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - historical_batch [Preset: minimal]               OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - multiple_attester_slashings_no_overlap [Preset:  OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - multiple_attester_slashings_partial_overlap [Pre OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - multiple_different_proposer_slashings_same_block OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - multiple_different_validator_exits_same_block [P OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - proposer_after_inactive_index [Preset: minimal]  OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - proposer_self_slashing [Preset: minimal]         OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - proposer_slashing [Preset: minimal]              OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - skipped_slots [Preset: minimal]                  OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - slash_and_exit_diff_index [Preset: minimal]      OK
+ [Valid]   EF - Phase0 - Sanity - Blocks - voluntary_exit [Preset: minimal]                 OK
```
OK: 45/45 Fail: 0/45 Skip: 0/45
## ForkChoice
```diff
+ ForkChoice - minimal/altair/fork_choice/ex_ante/pyspec_tests/ex_ante_sandwich_with_honest_ OK
+ ForkChoice - minimal/altair/fork_choice/ex_ante/pyspec_tests/ex_ante_sandwich_without_atte OK
+ ForkChoice - minimal/altair/fork_choice/ex_ante/pyspec_tests/ex_ante_vanilla               OK
+ ForkChoice - minimal/altair/fork_choice/get_head/pyspec_tests/chain_no_attestations        OK
+ ForkChoice - minimal/altair/fork_choice/get_head/pyspec_tests/discard_equivocations_on_att OK
+ ForkChoice - minimal/altair/fork_choice/get_head/pyspec_tests/discard_equivocations_slashe OK
+ ForkChoice - minimal/altair/fork_choice/get_head/pyspec_tests/filtered_block_tree          OK
+ ForkChoice - minimal/altair/fork_choice/get_head/pyspec_tests/genesis                      OK
+ ForkChoice - minimal/altair/fork_choice/get_head/pyspec_tests/proposer_boost_correct_head  OK
+ ForkChoice - minimal/altair/fork_choice/get_head/pyspec_tests/shorter_chain_but_heavier_we OK
+ ForkChoice - minimal/altair/fork_choice/get_head/pyspec_tests/split_tie_breaker_no_attesta OK
+ ForkChoice - minimal/altair/fork_choice/get_head/pyspec_tests/voting_source_beyond_two_epo OK
+ ForkChoice - minimal/altair/fork_choice/get_head/pyspec_tests/voting_source_within_two_epo OK
  ForkChoice - minimal/altair/fork_choice/get_proposer_head/pyspec_tests/basic_is_head_root  Skip
  ForkChoice - minimal/altair/fork_choice/get_proposer_head/pyspec_tests/basic_is_parent_roo Skip
+ ForkChoice - minimal/altair/fork_choice/on_block/pyspec_tests/basic                        OK
+ ForkChoice - minimal/altair/fork_choice/on_block/pyspec_tests/incompatible_justification_u OK
+ ForkChoice - minimal/altair/fork_choice/on_block/pyspec_tests/incompatible_justification_u OK
+ ForkChoice - minimal/altair/fork_choice/on_block/pyspec_tests/justification_update_beginni OK
+ ForkChoice - minimal/altair/fork_choice/on_block/pyspec_tests/justification_update_end_of_ OK
+ ForkChoice - minimal/altair/fork_choice/on_block/pyspec_tests/justification_withholding    OK
+ ForkChoice - minimal/altair/fork_choice/on_block/pyspec_tests/justification_withholding_re OK
+ ForkChoice - minimal/altair/fork_choice/on_block/pyspec_tests/justified_update_always_if_b OK
+ ForkChoice - minimal/altair/fork_choice/on_block/pyspec_tests/justified_update_monotonic   OK
+ ForkChoice - minimal/altair/fork_choice/on_block/pyspec_tests/justified_update_not_realize OK
+ ForkChoice - minimal/altair/fork_choice/on_block/pyspec_tests/new_finalized_slot_is_justif OK
+ ForkChoice - minimal/altair/fork_choice/on_block/pyspec_tests/not_pull_up_current_epoch_bl OK
+ ForkChoice - minimal/altair/fork_choice/on_block/pyspec_tests/on_block_bad_parent_root     OK
+ ForkChoice - minimal/altair/fork_choice/on_block/pyspec_tests/on_block_before_finalized    OK
+ ForkChoice - minimal/altair/fork_choice/on_block/pyspec_tests/on_block_checkpoints         OK
+ ForkChoice - minimal/altair/fork_choice/on_block/pyspec_tests/on_block_finalized_skip_slot OK
+ ForkChoice - minimal/altair/fork_choice/on_block/pyspec_tests/on_block_finalized_skip_slot OK
  ForkChoice - minimal/altair/fork_choice/on_block/pyspec_tests/on_block_future_block        Skip
+ ForkChoice - minimal/altair/fork_choice/on_block/pyspec_tests/proposer_boost               OK
+ ForkChoice - minimal/altair/fork_choice/on_block/pyspec_tests/proposer_boost_is_first_bloc OK
+ ForkChoice - minimal/altair/fork_choice/on_block/pyspec_tests/proposer_boost_root_same_slo OK
+ ForkChoice - minimal/altair/fork_choice/on_block/pyspec_tests/pull_up_on_tick              OK
+ ForkChoice - minimal/altair/fork_choice/on_block/pyspec_tests/pull_up_past_epoch_block     OK
+ ForkChoice - minimal/altair/fork_choice/reorg/pyspec_tests/delayed_justification_current_e OK
+ ForkChoice - minimal/altair/fork_choice/reorg/pyspec_tests/delayed_justification_previous_ OK
+ ForkChoice - minimal/altair/fork_choice/reorg/pyspec_tests/include_votes_another_empty_cha OK
+ ForkChoice - minimal/altair/fork_choice/reorg/pyspec_tests/include_votes_another_empty_cha OK
+ ForkChoice - minimal/altair/fork_choice/reorg/pyspec_tests/include_votes_another_empty_cha OK
+ ForkChoice - minimal/altair/fork_choice/reorg/pyspec_tests/simple_attempted_reorg_delayed_ OK
+ ForkChoice - minimal/altair/fork_choice/reorg/pyspec_tests/simple_attempted_reorg_delayed_ OK
+ ForkChoice - minimal/altair/fork_choice/reorg/pyspec_tests/simple_attempted_reorg_without_ OK
+ ForkChoice - minimal/altair/fork_choice/withholding/pyspec_tests/withholding_attack        OK
+ ForkChoice - minimal/altair/fork_choice/withholding/pyspec_tests/withholding_attack_unviab OK
+ ForkChoice - minimal/bellatrix/fork_choice/ex_ante/pyspec_tests/ex_ante_sandwich_with_hone OK
+ ForkChoice - minimal/bellatrix/fork_choice/ex_ante/pyspec_tests/ex_ante_sandwich_without_a OK
+ ForkChoice - minimal/bellatrix/fork_choice/ex_ante/pyspec_tests/ex_ante_vanilla            OK
+ ForkChoice - minimal/bellatrix/fork_choice/get_head/pyspec_tests/chain_no_attestations     OK
+ ForkChoice - minimal/bellatrix/fork_choice/get_head/pyspec_tests/discard_equivocations_on_ OK
+ ForkChoice - minimal/bellatrix/fork_choice/get_head/pyspec_tests/discard_equivocations_sla OK
+ ForkChoice - minimal/bellatrix/fork_choice/get_head/pyspec_tests/filtered_block_tree       OK
+ ForkChoice - minimal/bellatrix/fork_choice/get_head/pyspec_tests/genesis                   OK
+ ForkChoice - minimal/bellatrix/fork_choice/get_head/pyspec_tests/proposer_boost_correct_he OK
+ ForkChoice - minimal/bellatrix/fork_choice/get_head/pyspec_tests/shorter_chain_but_heavier OK
+ ForkChoice - minimal/bellatrix/fork_choice/get_head/pyspec_tests/split_tie_breaker_no_atte OK
+ ForkChoice - minimal/bellatrix/fork_choice/get_head/pyspec_tests/voting_source_beyond_two_ OK
+ ForkChoice - minimal/bellatrix/fork_choice/get_head/pyspec_tests/voting_source_within_two_ OK
  ForkChoice - minimal/bellatrix/fork_choice/get_proposer_head/pyspec_tests/basic_is_head_ro Skip
  ForkChoice - minimal/bellatrix/fork_choice/get_proposer_head/pyspec_tests/basic_is_parent_ Skip
+ ForkChoice - minimal/bellatrix/fork_choice/on_block/pyspec_tests/basic                     OK
+ ForkChoice - minimal/bellatrix/fork_choice/on_block/pyspec_tests/incompatible_justificatio OK
+ ForkChoice - minimal/bellatrix/fork_choice/on_block/pyspec_tests/incompatible_justificatio OK
+ ForkChoice - minimal/bellatrix/fork_choice/on_block/pyspec_tests/justification_update_begi OK
+ ForkChoice - minimal/bellatrix/fork_choice/on_block/pyspec_tests/justification_update_end_ OK
+ ForkChoice - minimal/bellatrix/fork_choice/on_block/pyspec_tests/justification_withholding OK
+ ForkChoice - minimal/bellatrix/fork_choice/on_block/pyspec_tests/justification_withholding OK
+ ForkChoice - minimal/bellatrix/fork_choice/on_block/pyspec_tests/justified_update_always_i OK
+ ForkChoice - minimal/bellatrix/fork_choice/on_block/pyspec_tests/justified_update_monotoni OK
+ ForkChoice - minimal/bellatrix/fork_choice/on_block/pyspec_tests/justified_update_not_real OK
+ ForkChoice - minimal/bellatrix/fork_choice/on_block/pyspec_tests/new_finalized_slot_is_jus OK
+ ForkChoice - minimal/bellatrix/fork_choice/on_block/pyspec_tests/not_pull_up_current_epoch OK
+ ForkChoice - minimal/bellatrix/fork_choice/on_block/pyspec_tests/on_block_bad_parent_root  OK
+ ForkChoice - minimal/bellatrix/fork_choice/on_block/pyspec_tests/on_block_before_finalized OK
+ ForkChoice - minimal/bellatrix/fork_choice/on_block/pyspec_tests/on_block_checkpoints      OK
+ ForkChoice - minimal/bellatrix/fork_choice/on_block/pyspec_tests/on_block_finalized_skip_s OK
+ ForkChoice - minimal/bellatrix/fork_choice/on_block/pyspec_tests/on_block_finalized_skip_s OK
  ForkChoice - minimal/bellatrix/fork_choice/on_block/pyspec_tests/on_block_future_block     Skip
+ ForkChoice - minimal/bellatrix/fork_choice/on_block/pyspec_tests/proposer_boost            OK
+ ForkChoice - minimal/bellatrix/fork_choice/on_block/pyspec_tests/proposer_boost_is_first_b OK
+ ForkChoice - minimal/bellatrix/fork_choice/on_block/pyspec_tests/proposer_boost_root_same_ OK
+ ForkChoice - minimal/bellatrix/fork_choice/on_block/pyspec_tests/pull_up_on_tick           OK
+ ForkChoice - minimal/bellatrix/fork_choice/on_block/pyspec_tests/pull_up_past_epoch_block  OK
  ForkChoice - minimal/bellatrix/fork_choice/on_merge_block/pyspec_tests/all_valid           Skip
  ForkChoice - minimal/bellatrix/fork_choice/on_merge_block/pyspec_tests/block_lookup_failed Skip
  ForkChoice - minimal/bellatrix/fork_choice/on_merge_block/pyspec_tests/too_early_for_merge Skip
  ForkChoice - minimal/bellatrix/fork_choice/on_merge_block/pyspec_tests/too_late_for_merge  Skip
+ ForkChoice - minimal/bellatrix/fork_choice/reorg/pyspec_tests/delayed_justification_curren OK
+ ForkChoice - minimal/bellatrix/fork_choice/reorg/pyspec_tests/delayed_justification_previo OK
+ ForkChoice - minimal/bellatrix/fork_choice/reorg/pyspec_tests/include_votes_another_empty_ OK
+ ForkChoice - minimal/bellatrix/fork_choice/reorg/pyspec_tests/include_votes_another_empty_ OK
+ ForkChoice - minimal/bellatrix/fork_choice/reorg/pyspec_tests/include_votes_another_empty_ OK
+ ForkChoice - minimal/bellatrix/fork_choice/reorg/pyspec_tests/simple_attempted_reorg_delay OK
+ ForkChoice - minimal/bellatrix/fork_choice/reorg/pyspec_tests/simple_attempted_reorg_delay OK
+ ForkChoice - minimal/bellatrix/fork_choice/reorg/pyspec_tests/simple_attempted_reorg_witho OK
  ForkChoice - minimal/bellatrix/fork_choice/should_override_forkchoice_update/pyspec_tests/ Skip
  ForkChoice - minimal/bellatrix/fork_choice/should_override_forkchoice_update/pyspec_tests/ Skip
+ ForkChoice - minimal/bellatrix/fork_choice/withholding/pyspec_tests/withholding_attack     OK
+ ForkChoice - minimal/bellatrix/fork_choice/withholding/pyspec_tests/withholding_attack_unv OK
+ ForkChoice - minimal/capella/fork_choice/ex_ante/pyspec_tests/ex_ante_sandwich_with_honest OK
+ ForkChoice - minimal/capella/fork_choice/ex_ante/pyspec_tests/ex_ante_sandwich_without_att OK
+ ForkChoice - minimal/capella/fork_choice/ex_ante/pyspec_tests/ex_ante_vanilla              OK
+ ForkChoice - minimal/capella/fork_choice/get_head/pyspec_tests/chain_no_attestations       OK
+ ForkChoice - minimal/capella/fork_choice/get_head/pyspec_tests/discard_equivocations_on_at OK
+ ForkChoice - minimal/capella/fork_choice/get_head/pyspec_tests/discard_equivocations_slash OK
+ ForkChoice - minimal/capella/fork_choice/get_head/pyspec_tests/filtered_block_tree         OK
+ ForkChoice - minimal/capella/fork_choice/get_head/pyspec_tests/genesis                     OK
+ ForkChoice - minimal/capella/fork_choice/get_head/pyspec_tests/proposer_boost_correct_head OK
+ ForkChoice - minimal/capella/fork_choice/get_head/pyspec_tests/shorter_chain_but_heavier_w OK
+ ForkChoice - minimal/capella/fork_choice/get_head/pyspec_tests/split_tie_breaker_no_attest OK
+ ForkChoice - minimal/capella/fork_choice/get_head/pyspec_tests/voting_source_beyond_two_ep OK
+ ForkChoice - minimal/capella/fork_choice/get_head/pyspec_tests/voting_source_within_two_ep OK
  ForkChoice - minimal/capella/fork_choice/get_proposer_head/pyspec_tests/basic_is_head_root Skip
  ForkChoice - minimal/capella/fork_choice/get_proposer_head/pyspec_tests/basic_is_parent_ro Skip
+ ForkChoice - minimal/capella/fork_choice/on_block/pyspec_tests/basic                       OK
+ ForkChoice - minimal/capella/fork_choice/on_block/pyspec_tests/incompatible_justification_ OK
+ ForkChoice - minimal/capella/fork_choice/on_block/pyspec_tests/incompatible_justification_ OK
+ ForkChoice - minimal/capella/fork_choice/on_block/pyspec_tests/justification_update_beginn OK
+ ForkChoice - minimal/capella/fork_choice/on_block/pyspec_tests/justification_update_end_of OK
+ ForkChoice - minimal/capella/fork_choice/on_block/pyspec_tests/justification_withholding   OK
+ ForkChoice - minimal/capella/fork_choice/on_block/pyspec_tests/justification_withholding_r OK
+ ForkChoice - minimal/capella/fork_choice/on_block/pyspec_tests/justified_update_always_if_ OK
+ ForkChoice - minimal/capella/fork_choice/on_block/pyspec_tests/justified_update_monotonic  OK
+ ForkChoice - minimal/capella/fork_choice/on_block/pyspec_tests/justified_update_not_realiz OK
+ ForkChoice - minimal/capella/fork_choice/on_block/pyspec_tests/new_finalized_slot_is_justi OK
+ ForkChoice - minimal/capella/fork_choice/on_block/pyspec_tests/not_pull_up_current_epoch_b OK
+ ForkChoice - minimal/capella/fork_choice/on_block/pyspec_tests/on_block_bad_parent_root    OK
+ ForkChoice - minimal/capella/fork_choice/on_block/pyspec_tests/on_block_before_finalized   OK
+ ForkChoice - minimal/capella/fork_choice/on_block/pyspec_tests/on_block_checkpoints        OK
+ ForkChoice - minimal/capella/fork_choice/on_block/pyspec_tests/on_block_finalized_skip_slo OK
+ ForkChoice - minimal/capella/fork_choice/on_block/pyspec_tests/on_block_finalized_skip_slo OK
  ForkChoice - minimal/capella/fork_choice/on_block/pyspec_tests/on_block_future_block       Skip
+ ForkChoice - minimal/capella/fork_choice/on_block/pyspec_tests/proposer_boost              OK
+ ForkChoice - minimal/capella/fork_choice/on_block/pyspec_tests/proposer_boost_is_first_blo OK
+ ForkChoice - minimal/capella/fork_choice/on_block/pyspec_tests/proposer_boost_root_same_sl OK
+ ForkChoice - minimal/capella/fork_choice/on_block/pyspec_tests/pull_up_on_tick             OK
+ ForkChoice - minimal/capella/fork_choice/on_block/pyspec_tests/pull_up_past_epoch_block    OK
+ ForkChoice - minimal/capella/fork_choice/reorg/pyspec_tests/delayed_justification_current_ OK
+ ForkChoice - minimal/capella/fork_choice/reorg/pyspec_tests/delayed_justification_previous OK
+ ForkChoice - minimal/capella/fork_choice/reorg/pyspec_tests/include_votes_another_empty_ch OK
+ ForkChoice - minimal/capella/fork_choice/reorg/pyspec_tests/include_votes_another_empty_ch OK
+ ForkChoice - minimal/capella/fork_choice/reorg/pyspec_tests/include_votes_another_empty_ch OK
+ ForkChoice - minimal/capella/fork_choice/reorg/pyspec_tests/simple_attempted_reorg_delayed OK
+ ForkChoice - minimal/capella/fork_choice/reorg/pyspec_tests/simple_attempted_reorg_delayed OK
+ ForkChoice - minimal/capella/fork_choice/reorg/pyspec_tests/simple_attempted_reorg_without OK
  ForkChoice - minimal/capella/fork_choice/should_override_forkchoice_update/pyspec_tests/sh Skip
  ForkChoice - minimal/capella/fork_choice/should_override_forkchoice_update/pyspec_tests/sh Skip
+ ForkChoice - minimal/capella/fork_choice/withholding/pyspec_tests/withholding_attack       OK
+ ForkChoice - minimal/capella/fork_choice/withholding/pyspec_tests/withholding_attack_unvia OK
+ ForkChoice - minimal/deneb/fork_choice/ex_ante/pyspec_tests/ex_ante_sandwich_with_honest_a OK
+ ForkChoice - minimal/deneb/fork_choice/ex_ante/pyspec_tests/ex_ante_sandwich_without_attes OK
+ ForkChoice - minimal/deneb/fork_choice/ex_ante/pyspec_tests/ex_ante_vanilla                OK
+ ForkChoice - minimal/deneb/fork_choice/get_head/pyspec_tests/chain_no_attestations         OK
+ ForkChoice - minimal/deneb/fork_choice/get_head/pyspec_tests/discard_equivocations_on_atte OK
+ ForkChoice - minimal/deneb/fork_choice/get_head/pyspec_tests/discard_equivocations_slashed OK
+ ForkChoice - minimal/deneb/fork_choice/get_head/pyspec_tests/filtered_block_tree           OK
+ ForkChoice - minimal/deneb/fork_choice/get_head/pyspec_tests/genesis                       OK
+ ForkChoice - minimal/deneb/fork_choice/get_head/pyspec_tests/proposer_boost_correct_head   OK
+ ForkChoice - minimal/deneb/fork_choice/get_head/pyspec_tests/shorter_chain_but_heavier_wei OK
+ ForkChoice - minimal/deneb/fork_choice/get_head/pyspec_tests/split_tie_breaker_no_attestat OK
+ ForkChoice - minimal/deneb/fork_choice/get_head/pyspec_tests/voting_source_beyond_two_epoc OK
+ ForkChoice - minimal/deneb/fork_choice/get_head/pyspec_tests/voting_source_within_two_epoc OK
  ForkChoice - minimal/deneb/fork_choice/get_proposer_head/pyspec_tests/basic_is_head_root   Skip
  ForkChoice - minimal/deneb/fork_choice/get_proposer_head/pyspec_tests/basic_is_parent_root Skip
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/basic                         OK
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/incompatible_justification_up OK
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/incompatible_justification_up OK
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/invalid_data_unavailable      OK
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/invalid_incorrect_proof       OK
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/invalid_wrong_blobs_length    OK
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/invalid_wrong_proofs_length   OK
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/justification_update_beginnin OK
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/justification_update_end_of_e OK
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/justification_withholding     OK
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/justification_withholding_rev OK
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/justified_update_always_if_be OK
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/justified_update_monotonic    OK
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/justified_update_not_realized OK
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/new_finalized_slot_is_justifi OK
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/not_pull_up_current_epoch_blo OK
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/on_block_bad_parent_root      OK
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/on_block_before_finalized     OK
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/on_block_checkpoints          OK
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/on_block_finalized_skip_slots OK
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/on_block_finalized_skip_slots OK
  ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/on_block_future_block         Skip
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/proposer_boost                OK
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/proposer_boost_is_first_block OK
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/proposer_boost_root_same_slot OK
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/pull_up_on_tick               OK
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/pull_up_past_epoch_block      OK
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/simple_blob_data              OK
+ ForkChoice - minimal/deneb/fork_choice/reorg/pyspec_tests/delayed_justification_current_ep OK
+ ForkChoice - minimal/deneb/fork_choice/reorg/pyspec_tests/delayed_justification_previous_e OK
+ ForkChoice - minimal/deneb/fork_choice/reorg/pyspec_tests/include_votes_another_empty_chai OK
+ ForkChoice - minimal/deneb/fork_choice/reorg/pyspec_tests/include_votes_another_empty_chai OK
+ ForkChoice - minimal/deneb/fork_choice/reorg/pyspec_tests/include_votes_another_empty_chai OK
+ ForkChoice - minimal/deneb/fork_choice/reorg/pyspec_tests/simple_attempted_reorg_delayed_j OK
+ ForkChoice - minimal/deneb/fork_choice/reorg/pyspec_tests/simple_attempted_reorg_delayed_j OK
+ ForkChoice - minimal/deneb/fork_choice/reorg/pyspec_tests/simple_attempted_reorg_without_e OK
  ForkChoice - minimal/deneb/fork_choice/should_override_forkchoice_update/pyspec_tests/shou Skip
  ForkChoice - minimal/deneb/fork_choice/should_override_forkchoice_update/pyspec_tests/shou Skip
+ ForkChoice - minimal/deneb/fork_choice/withholding/pyspec_tests/withholding_attack         OK
+ ForkChoice - minimal/deneb/fork_choice/withholding/pyspec_tests/withholding_attack_unviabl OK
```
OK: 185/207 Fail: 0/207 Skip: 22/207
## Sync
```diff
+ Sync - minimal/bellatrix/sync/optimistic/pyspec_tests/from_syncing_to_invalid              OK
+ Sync - minimal/capella/sync/optimistic/pyspec_tests/from_syncing_to_invalid                OK
+ Sync - minimal/deneb/sync/optimistic/pyspec_tests/from_syncing_to_invalid                  OK
```
OK: 3/3 Fail: 0/3 Skip: 0/3

---TOTAL---
OK: 2581/2603 Fail: 0/2603 Skip: 22/2603
