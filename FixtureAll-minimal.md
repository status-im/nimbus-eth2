FixtureAll-minimal
===
## Official - Epoch Processing - Final updates [Preset: minimal]
```diff
+ Final updates - effective_balance_hysteresis [Preset: minimal]                             OK
+ Final updates - eth1_vote_no_reset [Preset: minimal]                                       OK
+ Final updates - eth1_vote_reset [Preset: minimal]                                          OK
+ Final updates - historical_root_accumulator [Preset: minimal]                              OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
## Official - Epoch Processing - Justification & Finalization [Preset: minimal]
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
```
OK: 9/9 Fail: 0/9 Skip: 0/9
## Official - Epoch Processing - Registry updates [Preset: minimal]
```diff
+ Registry updates - activation_queue_activation_and_ejection [Preset: minimal]              OK
+ Registry updates - activation_queue_efficiency [Preset: minimal]                           OK
+ Registry updates - activation_queue_no_activation_no_finality [Preset: minimal]            OK
+ Registry updates - activation_queue_sorting [Preset: minimal]                              OK
+ Registry updates - activation_queue_to_activated_if_finalized [Preset: minimal]            OK
+ Registry updates - add_to_activation_queue [Preset: minimal]                               OK
+ Registry updates - ejection [Preset: minimal]                                              OK
+ Registry updates - ejection_past_churn_limit [Preset: minimal]                             OK
```
OK: 8/8 Fail: 0/8 Skip: 0/8
## Official - Epoch Processing - Slashings [Preset: minimal]
```diff
+ Slashings - max_penalties [Preset: minimal]                                                OK
+ Slashings - scaled_penalties [Preset: minimal]                                             OK
+ Slashings - small_penalty [Preset: minimal]                                                OK
```
OK: 3/3 Fail: 0/3 Skip: 0/3
## Official - Operations - Attestations  [Preset: minimal]
```diff
+ [Invalid] after_epoch_slots                                                                OK
+ [Invalid] bad_source_root                                                                  OK
+ [Invalid] before_inclusion_delay                                                           OK
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
+ [Valid]   empty_aggregation_bits                                                           OK
+ [Valid]   success                                                                          OK
+ [Valid]   success_multi_proposer_index_iterations                                          OK
+ [Valid]   success_previous_epoch                                                           OK
```
OK: 20/20 Fail: 0/20 Skip: 0/20
## Official - Operations - Attester slashing  [Preset: minimal]
```diff
+ [Invalid] att1_bad_extra_index                                                             OK
+ [Invalid] att1_bad_replaced_index                                                          OK
+ [Invalid] att1_duplicate_index_normal_signed                                               OK
+ [Invalid] att2_bad_extra_index                                                             OK
+ [Invalid] att2_bad_replaced_index                                                          OK
+ [Invalid] att2_duplicate_index_normal_signed                                               OK
+ [Invalid] invalid_sig_1                                                                    OK
+ [Invalid] invalid_sig_1_and_2                                                              OK
+ [Invalid] invalid_sig_2                                                                    OK
+ [Invalid] no_double_or_surround                                                            OK
+ [Invalid] participants_already_slashed                                                     OK
+ [Invalid] same_data                                                                        OK
+ [Invalid] unsorted_att_1                                                                   OK
+ [Invalid] unsorted_att_2                                                                   OK
+ [Valid]   success_double                                                                   OK
+ [Valid]   success_surround                                                                 OK
```
OK: 16/16 Fail: 0/16 Skip: 0/16
## Official - Operations - Block header  [Preset: minimal]
```diff
+ [Invalid] invalid_parent_root                                                              OK
+ [Invalid] invalid_slot_block_header                                                        OK
+ [Invalid] proposer_slashed                                                                 OK
+ [Valid]   success_block_header                                                             OK
```
OK: 4/4 Fail: 0/4 Skip: 0/4
## Official - Operations - Deposits  [Preset: minimal]
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
```
OK: 10/10 Fail: 0/10 Skip: 0/10
## Official - Operations - Proposer slashing  [Preset: minimal]
```diff
+ [Invalid] identifier                                                                       OK
+ [Valid]   identifier                                                                       OK
```
OK: 2/2 Fail: 0/2 Skip: 0/2
## Official - Operations - Voluntary exit  [Preset: minimal]
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
## Official - Sanity - Blocks  [Preset: minimal]
```diff
+ [Invalid] invalid_block_sig                                                                OK
+ [Invalid] invalid_state_root                                                               OK
+ [Invalid] prev_slot_block_transition                                                       OK
+ [Invalid] zero_block_sig                                                                   OK
+ [Valid]   attestation                                                                      OK
+ [Valid]   balance_driven_status_transitions                                                OK
+ [Valid]   deposit_in_block                                                                 OK
+ [Valid]   deposit_top_up                                                                   OK
+ [Valid]   empty_block_transition                                                           OK
+ [Valid]   empty_epoch_transition                                                           OK
+ [Valid]   empty_epoch_transition_not_finalizing                                            OK
+ [Valid]   eth1_data_votes_consensus                                                        OK
+ [Valid]   eth1_data_votes_no_consensus                                                     OK
+ [Valid]   high_proposer_index                                                              OK
+ [Valid]   historical_batch                                                                 OK
+ [Valid]   proposer_after_inactive_index                                                    OK
+ [Valid]   proposer_slashing                                                                OK
+ [Valid]   same_slot_block_transition                                                       OK
+ [Valid]   skipped_slots                                                                    OK
+ [Valid]   voluntary_exit                                                                   OK
```
OK: 20/20 Fail: 0/20 Skip: 0/20
## Official - Sanity - Slots  [Preset: minimal]
```diff
+ Slots - double_empty_epoch                                                                 OK
+ Slots - empty_epoch                                                                        OK
+ Slots - over_epoch_boundary                                                                OK
+ Slots - slots_1                                                                            OK
+ Slots - slots_2                                                                            OK
```
OK: 5/5 Fail: 0/5 Skip: 0/5

---TOTAL---
OK: 110/110 Fail: 0/110 Skip: 0/110
