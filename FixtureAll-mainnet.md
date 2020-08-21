FixtureAll-mainnet
===
## Official - Epoch Processing - Final updates [Preset: mainnet]
```diff
+ Final updates - effective_balance_hysteresis [Preset: mainnet]                             OK
+ Final updates - eth1_vote_no_reset [Preset: mainnet]                                       OK
+ Final updates - eth1_vote_reset [Preset: mainnet]                                          OK
+ Final updates - historical_root_accumulator [Preset: mainnet]                              OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
## Official - Epoch Processing - Justification & Finalization [Preset: mainnet]
```diff
+ Justification & Finalization - 123_ok_support [Preset: mainnet]                            OK
+ Justification & Finalization - 123_poor_support [Preset: mainnet]                          OK
+ Justification & Finalization - 12_ok_support [Preset: mainnet]                             OK
+ Justification & Finalization - 12_ok_support_messed_target [Preset: mainnet]               OK
+ Justification & Finalization - 12_poor_support [Preset: mainnet]                           OK
+ Justification & Finalization - 234_ok_support [Preset: mainnet]                            OK
+ Justification & Finalization - 234_poor_support [Preset: mainnet]                          OK
+ Justification & Finalization - 23_ok_support [Preset: mainnet]                             OK
+ Justification & Finalization - 23_poor_support [Preset: mainnet]                           OK
```
OK: 9/9 Fail: 0/9 Skip: 0/9
## Official - Epoch Processing - Registry updates [Preset: mainnet]
```diff
+ Registry updates - activation_queue_activation_and_ejection [Preset: mainnet]              OK
+ Registry updates - activation_queue_efficiency [Preset: mainnet]                           OK
+ Registry updates - activation_queue_no_activation_no_finality [Preset: mainnet]            OK
+ Registry updates - activation_queue_sorting [Preset: mainnet]                              OK
+ Registry updates - activation_queue_to_activated_if_finalized [Preset: mainnet]            OK
+ Registry updates - add_to_activation_queue [Preset: mainnet]                               OK
+ Registry updates - ejection [Preset: mainnet]                                              OK
+ Registry updates - ejection_past_churn_limit [Preset: mainnet]                             OK
```
OK: 8/8 Fail: 0/8 Skip: 0/8
## Official - Epoch Processing - Slashings [Preset: mainnet]
```diff
+ Slashings - max_penalties [Preset: mainnet]                                                OK
+ Slashings - scaled_penalties [Preset: mainnet]                                             OK
+ Slashings - small_penalty [Preset: mainnet]                                                OK
```
OK: 3/3 Fail: 0/3 Skip: 0/3
## Official - Finality  [Preset: mainnet]
```diff
+ [Valid]   Official - Finality - finality_no_updates_at_genesis [Preset: mainnet]           OK
+ [Valid]   Official - Finality - finality_rule_1 [Preset: mainnet]                          OK
+ [Valid]   Official - Finality - finality_rule_2 [Preset: mainnet]                          OK
+ [Valid]   Official - Finality - finality_rule_3 [Preset: mainnet]                          OK
+ [Valid]   Official - Finality - finality_rule_4 [Preset: mainnet]                          OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5
## Official - Operations - Attestations  [Preset: mainnet]
```diff
+ [Invalid] after_epoch_slots                                                                OK
+ [Invalid] bad_source_root                                                                  OK
+ [Invalid] before_inclusion_delay                                                           OK
+ [Invalid] empty_participants_seemingly_valid_sig                                           OK
+ [Invalid] empty_participants_zeroes_sig                                                    OK
+ [Invalid] future_target_epoch                                                              OK
+ [Invalid] invalid_attestation_signature                                                    OK
+ [Invalid] invalid_current_source_root                                                      OK
+ [Invalid] invalid_index                                                                    OK
+ [Invalid] mismatched_target_and_slot                                                       OK
+ [Invalid] new_source_epoch                                                                 OK
+ [Invalid] old_source_epoch                                                                 OK
+ [Invalid] old_target_epoch                                                                 OK
+ [Invalid] source_root_is_target_root                                                       OK
+ [Invalid] too_few_aggregation_bits                                                         OK
+ [Invalid] too_many_aggregation_bits                                                        OK
+ [Invalid] wrong_index_for_committee_signature                                              OK
+ [Invalid] wrong_index_for_slot                                                             OK
+ [Valid]   success                                                                          OK
+ [Valid]   success_multi_proposer_index_iterations                                          OK
+ [Valid]   success_previous_epoch                                                           OK
```
OK: 21/21 Fail: 0/21 Skip: 0/21
## Official - Operations - Attester slashing  [Preset: mainnet]
```diff
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
+ [Invalid] invalid_sig_1                                                                    OK
+ [Invalid] invalid_sig_1_and_2                                                              OK
+ [Invalid] invalid_sig_2                                                                    OK
+ [Invalid] no_double_or_surround                                                            OK
+ [Invalid] participants_already_slashed                                                     OK
+ [Invalid] same_data                                                                        OK
+ [Invalid] unsorted_att_1                                                                   OK
+ [Invalid] unsorted_att_2                                                                   OK
+ [Valid]   success_already_exited_long_ago                                                  OK
+ [Valid]   success_already_exited_recent                                                    OK
+ [Valid]   success_double                                                                   OK
+ [Valid]   success_surround                                                                 OK
```
OK: 25/25 Fail: 0/25 Skip: 0/25
## Official - Operations - Block header  [Preset: mainnet]
```diff
+ [Invalid] invalid_multiple_blocks_single_slot                                              OK
+ [Invalid] invalid_parent_root                                                              OK
+ [Invalid] invalid_proposer_index                                                           OK
+ [Invalid] invalid_slot_block_header                                                        OK
+ [Invalid] proposer_slashed                                                                 OK
+ [Valid]   success_block_header                                                             OK
```
OK: 6/6 Fail: 0/6 Skip: 0/6
## Official - Operations - Deposits  [Preset: mainnet]
```diff
+ [Invalid]  bad_merkle_proof                                                                OK
+ [Invalid]  wrong_deposit_for_deposit_count                                                 OK
+ [Valid]    invalid_sig_new_deposit                                                         OK
+ [Valid]    invalid_sig_other_version                                                       OK
+ [Valid]    invalid_sig_top_up                                                              OK
+ [Valid]    invalid_withdrawal_credentials_top_up                                           OK
+ [Valid]    new_deposit_max                                                                 OK
+ [Valid]    new_deposit_over_max                                                            OK
+ [Valid]    new_deposit_under_max                                                           OK
+ [Valid]    success_top_up                                                                  OK
+ [Valid]    valid_sig_but_forked_state                                                      OK
```
OK: 11/11 Fail: 0/11 Skip: 0/11
## Official - Operations - Proposer slashing  [Preset: mainnet]
```diff
+ [Invalid] identifier                                                                       OK
+ [Valid]   identifier                                                                       OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## Official - Operations - Voluntary exit  [Preset: mainnet]
```diff
+ [Invalid] invalid_signature                                                                OK
+ [Invalid] validator_already_exited                                                         OK
+ [Invalid] validator_exit_in_future                                                         OK
+ [Invalid] validator_invalid_validator_index                                                OK
+ [Invalid] validator_not_active                                                             OK
+ [Invalid] validator_not_active_long_enough                                                 OK
+ [Valid]   default_exit_epoch_subsequent_exit                                               OK
+ [Valid]   success                                                                          OK
+ [Valid]   success_exit_queue                                                               OK
```
OK: 9/9 Fail: 0/9 Skip: 0/9
## Official - Rewards  [Preset: mainnet]
```diff
+ Rewards - all_balances_too_low_for_reward [Preset: mainnet]                                OK
+ Rewards - duplicate_attestations_at_later_slots [Preset: mainnet]                          OK
+ Rewards - empty [Preset: mainnet]                                                          OK
+ Rewards - empty_leak [Preset: mainnet]                                                     OK
+ Rewards - full_all_correct [Preset: mainnet]                                               OK
+ Rewards - full_but_partial_participation [Preset: mainnet]                                 OK
+ Rewards - full_but_partial_participation_leak [Preset: mainnet]                            OK
+ Rewards - full_correct_target_incorrect_head [Preset: mainnet]                             OK
+ Rewards - full_correct_target_incorrect_head_leak [Preset: mainnet]                        OK
+ Rewards - full_delay_max_slots [Preset: mainnet]                                           OK
+ Rewards - full_delay_one_slot [Preset: mainnet]                                            OK
+ Rewards - full_half_correct_target_incorrect_head [Preset: mainnet]                        OK
+ Rewards - full_half_correct_target_incorrect_head_leak [Preset: mainnet]                   OK
+ Rewards - full_half_incorrect_target_correct_head [Preset: mainnet]                        OK
+ Rewards - full_half_incorrect_target_correct_head_leak [Preset: mainnet]                   OK
+ Rewards - full_half_incorrect_target_incorrect_head [Preset: mainnet]                      OK
+ Rewards - full_half_incorrect_target_incorrect_head_leak [Preset: mainnet]                 OK
+ Rewards - full_leak [Preset: mainnet]                                                      OK
+ Rewards - full_mixed_delay [Preset: mainnet]                                               OK
+ Rewards - full_random_0 [Preset: mainnet]                                                  OK
+ Rewards - full_random_1 [Preset: mainnet]                                                  OK
+ Rewards - full_random_2 [Preset: mainnet]                                                  OK
+ Rewards - full_random_five_epoch_leak [Preset: mainnet]                                    OK
+ Rewards - full_random_leak [Preset: mainnet]                                               OK
+ Rewards - full_random_low_balances [Preset: mainnet]                                       OK
+ Rewards - full_random_misc_balances [Preset: mainnet]                                      OK
+ Rewards - full_random_ten_epoch_leak [Preset: mainnet]                                     OK
+ Rewards - half_full [Preset: mainnet]                                                      OK
+ Rewards - half_full_leak [Preset: mainnet]                                                 OK
+ Rewards - one_attestation_one_correct [Preset: mainnet]                                    OK
+ Rewards - one_attestation_one_correct_leak [Preset: mainnet]                               OK
+ Rewards - proposer_not_in_attestations [Preset: mainnet]                                   OK
+ Rewards - quarter_full [Preset: mainnet]                                                   OK
+ Rewards - quarter_full_leak [Preset: mainnet]                                              OK
+ Rewards - some_very_low_effective_balances_that_attested [Preset: mainnet]                 OK
+ Rewards - some_very_low_effective_balances_that_attested_leak [Preset: mainnet]            OK
+ Rewards - some_very_low_effective_balances_that_did_not_attest [Preset: mainnet]           OK
+ Rewards - some_very_low_effective_balances_that_did_not_attest_leak [Preset: mainnet]      OK
+ Rewards - with_exited_validators [Preset: mainnet]                                         OK
+ Rewards - with_exited_validators_leak [Preset: mainnet]                                    OK
+ Rewards - with_not_yet_activated_validators [Preset: mainnet]                              OK
+ Rewards - with_not_yet_activated_validators_leak [Preset: mainnet]                         OK
+ Rewards - with_slashed_validators [Preset: mainnet]                                        OK
+ Rewards - with_slashed_validators_leak [Preset: mainnet]                                   OK
```
OK: 44/44 Fail: 0/44 Skip: 0/44
## Official - Sanity - Blocks  [Preset: mainnet]
```diff
+ [Invalid] Official - Sanity - Blocks - double_same_proposer_slashings_same_block [Preset:  OK
+ [Invalid] Official - Sanity - Blocks - double_similar_proposer_slashings_same_block [Prese OK
+ [Invalid] Official - Sanity - Blocks - double_validator_exit_same_block [Preset: mainnet]  OK
+ [Invalid] Official - Sanity - Blocks - duplicate_attester_slashing [Preset: mainnet]       OK
+ [Invalid] Official - Sanity - Blocks - expected_deposit_in_block [Preset: mainnet]         OK
+ [Invalid] Official - Sanity - Blocks - invalid_block_sig [Preset: mainnet]                 OK
+ [Invalid] Official - Sanity - Blocks - invalid_proposer_index_sig_from_expected_proposer [ OK
+ [Invalid] Official - Sanity - Blocks - invalid_proposer_index_sig_from_proposer_index [Pre OK
+ [Invalid] Official - Sanity - Blocks - invalid_state_root [Preset: mainnet]                OK
+ [Invalid] Official - Sanity - Blocks - parent_from_same_slot [Preset: mainnet]             OK
+ [Invalid] Official - Sanity - Blocks - prev_slot_block_transition [Preset: mainnet]        OK
+ [Invalid] Official - Sanity - Blocks - proposal_for_genesis_slot [Preset: mainnet]         OK
+ [Invalid] Official - Sanity - Blocks - same_slot_block_transition [Preset: mainnet]        OK
+ [Invalid] Official - Sanity - Blocks - zero_block_sig [Preset: mainnet]                    OK
+ [Valid]   Official - Sanity - Blocks - attestation [Preset: mainnet]                       OK
+ [Valid]   Official - Sanity - Blocks - attester_slashing [Preset: mainnet]                 OK
+ [Valid]   Official - Sanity - Blocks - balance_driven_status_transitions [Preset: mainnet] OK
+ [Valid]   Official - Sanity - Blocks - deposit_in_block [Preset: mainnet]                  OK
+ [Valid]   Official - Sanity - Blocks - deposit_top_up [Preset: mainnet]                    OK
+ [Valid]   Official - Sanity - Blocks - empty_block_transition [Preset: mainnet]            OK
+ [Valid]   Official - Sanity - Blocks - empty_epoch_transition [Preset: mainnet]            OK
+ [Valid]   Official - Sanity - Blocks - high_proposer_index [Preset: mainnet]               OK
+ [Valid]   Official - Sanity - Blocks - historical_batch [Preset: mainnet]                  OK
+ [Valid]   Official - Sanity - Blocks - multiple_attester_slashings_no_overlap [Preset: mai OK
+ [Valid]   Official - Sanity - Blocks - multiple_attester_slashings_partial_overlap [Preset OK
+ [Valid]   Official - Sanity - Blocks - multiple_different_proposer_slashings_same_block [P OK
+ [Valid]   Official - Sanity - Blocks - multiple_different_validator_exits_same_block [Pres OK
+ [Valid]   Official - Sanity - Blocks - proposer_after_inactive_index [Preset: mainnet]     OK
+ [Valid]   Official - Sanity - Blocks - proposer_self_slashing [Preset: mainnet]            OK
+ [Valid]   Official - Sanity - Blocks - proposer_slashing [Preset: mainnet]                 OK
+ [Valid]   Official - Sanity - Blocks - skipped_slots [Preset: mainnet]                     OK
+ [Valid]   Official - Sanity - Blocks - voluntary_exit [Preset: mainnet]                    OK
```
OK: 32/32 Fail: 0/32 Skip: 0/32
## Official - Sanity - Slots  [Preset: mainnet]
```diff
+ Slots - double_empty_epoch                                                                 OK
+ Slots - empty_epoch                                                                        OK
+ Slots - over_epoch_boundary                                                                OK
+ Slots - slots_1                                                                            OK
+ Slots - slots_2                                                                            OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5

---TOTAL---
OK: 184/184 Fail: 0/184 Skip: 0/184
