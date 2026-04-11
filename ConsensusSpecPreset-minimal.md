ConsensusSpecPreset-minimal
===
## EF - Altair - Fork  [Preset: minimal]
```diff
+ EF - Altair - Fork - after_fork_deactivate_validators_from_phase0_to_altair [Preset: minim OK
+ EF - Altair - Fork - after_fork_deactivate_validators_wo_block_from_phase0_to_altair [Pres OK
+ EF - Altair - Fork - after_fork_new_validator_active_from_phase0_to_altair [Preset: minima OK
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
## EF - Altair - Operations - Block Header  [Preset: minimal]
```diff
+ [Invalid] EF - Altair - Operations - Block Header - invalid_multiple_blocks_single_slot    OK
+ [Invalid] EF - Altair - Operations - Block Header - invalid_parent_root                    OK
+ [Invalid] EF - Altair - Operations - Block Header - invalid_proposer_index                 OK
+ [Invalid] EF - Altair - Operations - Block Header - invalid_proposer_slashed               OK
+ [Invalid] EF - Altair - Operations - Block Header - invalid_slot_block_header              OK
+ [Valid]   EF - Altair - Operations - Block Header - basic_block_header                     OK
```
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
+ [Invalid] EF - Altair - Operations - Proposer Slashing - invalid_proposer_withdrawable_cur OK
+ [Invalid] EF - Altair - Operations - Proposer Slashing - invalid_slots_of_different_epochs OK
+ [Invalid] EF - Altair - Operations - Proposer Slashing - invalid_slots_same_epoch_differen OK
+ [Valid]   EF - Altair - Operations - Proposer Slashing - basic                             OK
+ [Valid]   EF - Altair - Operations - Proposer Slashing - block_header_from_future          OK
+ [Valid]   EF - Altair - Operations - Proposer Slashing - block_header_from_past            OK
+ [Valid]   EF - Altair - Operations - Proposer Slashing - header_slot_at_epoch_end          OK
+ [Valid]   EF - Altair - Operations - Proposer Slashing - header_slot_at_epoch_start        OK
+ [Valid]   EF - Altair - Operations - Proposer Slashing - headers_differ_multiple_roots     OK
+ [Valid]   EF - Altair - Operations - Proposer Slashing - headers_differ_only_body_root     OK
+ [Valid]   EF - Altair - Operations - Proposer Slashing - headers_differ_only_state_root    OK
+ [Valid]   EF - Altair - Operations - Proposer Slashing - proposer_activated_current_epoch  OK
+ [Valid]   EF - Altair - Operations - Proposer Slashing - proposer_index_last               OK
+ [Valid]   EF - Altair - Operations - Proposer Slashing - proposer_index_zero               OK
+ [Valid]   EF - Altair - Operations - Proposer Slashing - proposer_withdrawable_next_epoch  OK
+ [Valid]   EF - Altair - Operations - Proposer Slashing - self_slashing_future_slot         OK
+ [Valid]   EF - Altair - Operations - Proposer Slashing - slashed_and_proposer_index_the_sa OK
```
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
## EF - Altair - Sanity - Slots  [Preset: minimal]
```diff
+ EF - Altair - Slots - balance_change_affects_proposer [Preset: minimal]                    OK
+ EF - Altair - Slots - double_empty_epoch [Preset: minimal]                                 OK
+ EF - Altair - Slots - empty_epoch [Preset: minimal]                                        OK
+ EF - Altair - Slots - historical_accumulator [Preset: minimal]                             OK
+ EF - Altair - Slots - over_epoch_boundary [Preset: minimal]                                OK
+ EF - Altair - Slots - slots_1 [Preset: minimal]                                            OK
+ EF - Altair - Slots - slots_2 [Preset: minimal]                                            OK
```
## EF - Altair - Transition  [Preset: minimal]
```diff
+ EF - Altair - Transition - non_empty_historical_roots [Preset: minimal]                    OK
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
## EF - Altair - Unittests - Light client - Sync protocol [Preset: minimal]
```diff
+ process_light_client_update_finality_updated                                               OK
+ process_light_client_update_timeout                                                        OK
+ test_process_light_client_update_at_period_boundary                                        OK
+ test_process_light_client_update_not_timeout                                               OK
```
## EF - Bellatrix - Fork  [Preset: minimal]
```diff
+ EF - Bellatrix - Fork - after_fork_deactivate_validators_from_altair_to_bellatrix [Preset: OK
+ EF - Bellatrix - Fork - after_fork_deactivate_validators_wo_block_from_altair_to_bellatrix OK
+ EF - Bellatrix - Fork - after_fork_new_validator_active_from_altair_to_bellatrix [Preset:  OK
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
## EF - Bellatrix - Operations - Block Header  [Preset: minimal]
```diff
+ [Invalid] EF - Bellatrix - Operations - Block Header - invalid_multiple_blocks_single_slot OK
+ [Invalid] EF - Bellatrix - Operations - Block Header - invalid_parent_root                 OK
+ [Invalid] EF - Bellatrix - Operations - Block Header - invalid_proposer_index              OK
+ [Invalid] EF - Bellatrix - Operations - Block Header - invalid_proposer_slashed            OK
+ [Invalid] EF - Bellatrix - Operations - Block Header - invalid_slot_block_header           OK
+ [Valid]   EF - Bellatrix - Operations - Block Header - basic_block_header                  OK
```
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
+ [Invalid] EF - Bellatrix - Operations - Proposer Slashing - invalid_proposer_withdrawable_ OK
+ [Invalid] EF - Bellatrix - Operations - Proposer Slashing - invalid_slots_of_different_epo OK
+ [Invalid] EF - Bellatrix - Operations - Proposer Slashing - invalid_slots_same_epoch_diffe OK
+ [Valid]   EF - Bellatrix - Operations - Proposer Slashing - basic                          OK
+ [Valid]   EF - Bellatrix - Operations - Proposer Slashing - block_header_from_future       OK
+ [Valid]   EF - Bellatrix - Operations - Proposer Slashing - block_header_from_past         OK
+ [Valid]   EF - Bellatrix - Operations - Proposer Slashing - header_slot_at_epoch_end       OK
+ [Valid]   EF - Bellatrix - Operations - Proposer Slashing - header_slot_at_epoch_start     OK
+ [Valid]   EF - Bellatrix - Operations - Proposer Slashing - headers_differ_multiple_roots  OK
+ [Valid]   EF - Bellatrix - Operations - Proposer Slashing - headers_differ_only_body_root  OK
+ [Valid]   EF - Bellatrix - Operations - Proposer Slashing - headers_differ_only_state_root OK
+ [Valid]   EF - Bellatrix - Operations - Proposer Slashing - proposer_activated_current_epo OK
+ [Valid]   EF - Bellatrix - Operations - Proposer Slashing - proposer_index_last            OK
+ [Valid]   EF - Bellatrix - Operations - Proposer Slashing - proposer_index_zero            OK
+ [Valid]   EF - Bellatrix - Operations - Proposer Slashing - proposer_withdrawable_next_epo OK
+ [Valid]   EF - Bellatrix - Operations - Proposer Slashing - self_slashing_future_slot      OK
+ [Valid]   EF - Bellatrix - Operations - Proposer Slashing - slashed_and_proposer_index_the OK
```
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
## EF - Bellatrix - Sanity - Slots  [Preset: minimal]
```diff
+ EF - Bellatrix - Slots - balance_change_affects_proposer [Preset: minimal]                 OK
+ EF - Bellatrix - Slots - double_empty_epoch [Preset: minimal]                              OK
+ EF - Bellatrix - Slots - empty_epoch [Preset: minimal]                                     OK
+ EF - Bellatrix - Slots - historical_accumulator [Preset: minimal]                          OK
+ EF - Bellatrix - Slots - over_epoch_boundary [Preset: minimal]                             OK
+ EF - Bellatrix - Slots - slots_1 [Preset: minimal]                                         OK
+ EF - Bellatrix - Slots - slots_2 [Preset: minimal]                                         OK
```
## EF - Bellatrix - Transition  [Preset: minimal]
```diff
+ EF - Bellatrix - Transition - non_empty_historical_roots [Preset: minimal]                 OK
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
## EF - Capella - Fork  [Preset: minimal]
```diff
+ EF - Capella - Fork - after_fork_deactivate_validators_from_bellatrix_to_capella [Preset:  OK
+ EF - Capella - Fork - after_fork_deactivate_validators_wo_block_from_bellatrix_to_capella  OK
+ EF - Capella - Fork - after_fork_new_validator_active_from_bellatrix_to_capella [Preset: m OK
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
## EF - Capella - Operations - Block Header  [Preset: minimal]
```diff
+ [Invalid] EF - Capella - Operations - Block Header - invalid_multiple_blocks_single_slot   OK
+ [Invalid] EF - Capella - Operations - Block Header - invalid_parent_root                   OK
+ [Invalid] EF - Capella - Operations - Block Header - invalid_proposer_index                OK
+ [Invalid] EF - Capella - Operations - Block Header - invalid_proposer_slashed              OK
+ [Invalid] EF - Capella - Operations - Block Header - invalid_slot_block_header             OK
+ [Valid]   EF - Capella - Operations - Block Header - basic_block_header                    OK
```
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
+ [Invalid] EF - Capella - Operations - Proposer Slashing - invalid_proposer_withdrawable_cu OK
+ [Invalid] EF - Capella - Operations - Proposer Slashing - invalid_slots_of_different_epoch OK
+ [Invalid] EF - Capella - Operations - Proposer Slashing - invalid_slots_same_epoch_differe OK
+ [Valid]   EF - Capella - Operations - Proposer Slashing - basic                            OK
+ [Valid]   EF - Capella - Operations - Proposer Slashing - block_header_from_future         OK
+ [Valid]   EF - Capella - Operations - Proposer Slashing - block_header_from_past           OK
+ [Valid]   EF - Capella - Operations - Proposer Slashing - header_slot_at_epoch_end         OK
+ [Valid]   EF - Capella - Operations - Proposer Slashing - header_slot_at_epoch_start       OK
+ [Valid]   EF - Capella - Operations - Proposer Slashing - headers_differ_multiple_roots    OK
+ [Valid]   EF - Capella - Operations - Proposer Slashing - headers_differ_only_body_root    OK
+ [Valid]   EF - Capella - Operations - Proposer Slashing - headers_differ_only_state_root   OK
+ [Valid]   EF - Capella - Operations - Proposer Slashing - proposer_activated_current_epoch OK
+ [Valid]   EF - Capella - Operations - Proposer Slashing - proposer_index_last              OK
+ [Valid]   EF - Capella - Operations - Proposer Slashing - proposer_index_zero              OK
+ [Valid]   EF - Capella - Operations - Proposer Slashing - proposer_withdrawable_next_epoch OK
+ [Valid]   EF - Capella - Operations - Proposer Slashing - self_slashing_future_slot        OK
+ [Valid]   EF - Capella - Operations - Proposer Slashing - slashed_and_proposer_index_the_s OK
```
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
+ [Valid]   EF - Capella - Operations - Withdrawals - partially_withdrawable_validator_legac OK
+ [Valid]   EF - Capella - Operations - Withdrawals - partially_withdrawable_validator_legac OK
+ [Valid]   EF - Capella - Operations - Withdrawals - partially_withdrawable_validator_legac OK
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
## EF - Capella - Sanity - Slots  [Preset: minimal]
```diff
+ EF - Capella - Slots - balance_change_affects_proposer [Preset: minimal]                   OK
+ EF - Capella - Slots - double_empty_epoch [Preset: minimal]                                OK
+ EF - Capella - Slots - empty_epoch [Preset: minimal]                                       OK
+ EF - Capella - Slots - historical_accumulator [Preset: minimal]                            OK
+ EF - Capella - Slots - over_epoch_boundary [Preset: minimal]                               OK
+ EF - Capella - Slots - slots_1 [Preset: minimal]                                           OK
+ EF - Capella - Slots - slots_2 [Preset: minimal]                                           OK
```
## EF - Capella - Transition  [Preset: minimal]
```diff
+ EF - Capella - Transition - non_empty_historical_roots [Preset: minimal]                   OK
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
## EF - Capella - Unittests - Light client - Sync protocol [Preset: minimal]
```diff
+ process_light_client_update_finality_updated                                               OK
+ process_light_client_update_timeout                                                        OK
+ test_process_light_client_update_at_period_boundary                                        OK
+ test_process_light_client_update_not_timeout                                               OK
```
## EF - Deneb - Fork  [Preset: minimal]
```diff
+ EF - Deneb - Fork - after_fork_deactivate_validators_from_capella_to_deneb [Preset: minima OK
+ EF - Deneb - Fork - after_fork_deactivate_validators_wo_block_from_capella_to_deneb [Prese OK
+ EF - Deneb - Fork - after_fork_new_validator_active_from_capella_to_deneb [Preset: minimal OK
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
## EF - Deneb - Operations - Block Header  [Preset: minimal]
```diff
+ [Invalid] EF - Deneb - Operations - Block Header - invalid_multiple_blocks_single_slot     OK
+ [Invalid] EF - Deneb - Operations - Block Header - invalid_parent_root                     OK
+ [Invalid] EF - Deneb - Operations - Block Header - invalid_proposer_index                  OK
+ [Invalid] EF - Deneb - Operations - Block Header - invalid_proposer_slashed                OK
+ [Invalid] EF - Deneb - Operations - Block Header - invalid_slot_block_header               OK
+ [Valid]   EF - Deneb - Operations - Block Header - basic_block_header                      OK
```
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
+ [Valid]   EF - Deneb - Operations - Execution Payload - incorrect_transaction_no_blobs_but OK
+ [Valid]   EF - Deneb - Operations - Execution Payload - no_commitments_for_transactions    OK
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
+ [Invalid] EF - Deneb - Operations - Proposer Slashing - invalid_proposer_withdrawable_curr OK
+ [Invalid] EF - Deneb - Operations - Proposer Slashing - invalid_slots_of_different_epochs  OK
+ [Invalid] EF - Deneb - Operations - Proposer Slashing - invalid_slots_same_epoch_different OK
+ [Valid]   EF - Deneb - Operations - Proposer Slashing - basic                              OK
+ [Valid]   EF - Deneb - Operations - Proposer Slashing - block_header_from_future           OK
+ [Valid]   EF - Deneb - Operations - Proposer Slashing - block_header_from_past             OK
+ [Valid]   EF - Deneb - Operations - Proposer Slashing - header_slot_at_epoch_end           OK
+ [Valid]   EF - Deneb - Operations - Proposer Slashing - header_slot_at_epoch_start         OK
+ [Valid]   EF - Deneb - Operations - Proposer Slashing - headers_differ_multiple_roots      OK
+ [Valid]   EF - Deneb - Operations - Proposer Slashing - headers_differ_only_body_root      OK
+ [Valid]   EF - Deneb - Operations - Proposer Slashing - headers_differ_only_state_root     OK
+ [Valid]   EF - Deneb - Operations - Proposer Slashing - proposer_activated_current_epoch   OK
+ [Valid]   EF - Deneb - Operations - Proposer Slashing - proposer_index_last                OK
+ [Valid]   EF - Deneb - Operations - Proposer Slashing - proposer_index_zero                OK
+ [Valid]   EF - Deneb - Operations - Proposer Slashing - proposer_withdrawable_next_epoch   OK
+ [Valid]   EF - Deneb - Operations - Proposer Slashing - self_slashing_future_slot          OK
+ [Valid]   EF - Deneb - Operations - Proposer Slashing - slashed_and_proposer_index_the_sam OK
```
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
+ [Valid]   EF - Deneb - Operations - Withdrawals - partially_withdrawable_validator_legacy_ OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - partially_withdrawable_validator_legacy_ OK
+ [Valid]   EF - Deneb - Operations - Withdrawals - partially_withdrawable_validator_legacy_ OK
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
## EF - Deneb - Sanity - Slots  [Preset: minimal]
```diff
+ EF - Deneb - Slots - balance_change_affects_proposer [Preset: minimal]                     OK
+ EF - Deneb - Slots - double_empty_epoch [Preset: minimal]                                  OK
+ EF - Deneb - Slots - empty_epoch [Preset: minimal]                                         OK
+ EF - Deneb - Slots - historical_accumulator [Preset: minimal]                              OK
+ EF - Deneb - Slots - over_epoch_boundary [Preset: minimal]                                 OK
+ EF - Deneb - Slots - slots_1 [Preset: minimal]                                             OK
+ EF - Deneb - Slots - slots_2 [Preset: minimal]                                             OK
```
## EF - Deneb - Transition  [Preset: minimal]
```diff
+ EF - Deneb - Transition - higher_churn_limit_to_lower [Preset: minimal]                    OK
+ EF - Deneb - Transition - non_empty_historical_roots [Preset: minimal]                     OK
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
## EF - Deneb - Unittests - Light client - Sync protocol [Preset: minimal]
```diff
+ process_light_client_update_finality_updated                                               OK
+ process_light_client_update_timeout                                                        OK
+ test_process_light_client_update_at_period_boundary                                        OK
+ test_process_light_client_update_not_timeout                                               OK
```
## EF - Electra - Fork  [Preset: minimal]
```diff
+ EF - Electra - Fork - after_fork_deactivate_validators_from_deneb_to_electra [Preset: mini OK
+ EF - Electra - Fork - after_fork_deactivate_validators_wo_block_from_deneb_to_electra [Pre OK
+ EF - Electra - Fork - after_fork_new_validator_active_from_deneb_to_electra [Preset: minim OK
+ EF - Electra - Fork - electra_fork_random_0 [Preset: minimal]                              OK
+ EF - Electra - Fork - electra_fork_random_1 [Preset: minimal]                              OK
+ EF - Electra - Fork - electra_fork_random_2 [Preset: minimal]                              OK
+ EF - Electra - Fork - electra_fork_random_3 [Preset: minimal]                              OK
+ EF - Electra - Fork - electra_fork_random_large_validator_set [Preset: minimal]            OK
+ EF - Electra - Fork - electra_fork_random_low_balances [Preset: minimal]                   OK
+ EF - Electra - Fork - electra_fork_random_misc_balances [Preset: minimal]                  OK
+ EF - Electra - Fork - fork_base_state [Preset: minimal]                                    OK
+ EF - Electra - Fork - fork_earliest_exit_epoch_is_max_validator_exit_epoch [Preset: minima OK
+ EF - Electra - Fork - fork_earliest_exit_epoch_less_than_current_epoch [Preset: minimal]   OK
+ EF - Electra - Fork - fork_earliest_exit_epoch_no_validator_exits [Preset: minimal]        OK
+ EF - Electra - Fork - fork_has_compounding_withdrawal_credential [Preset: minimal]         OK
+ EF - Electra - Fork - fork_inactive_compounding_validator_with_excess_balance [Preset: min OK
+ EF - Electra - Fork - fork_many_next_epoch [Preset: minimal]                               OK
+ EF - Electra - Fork - fork_next_epoch [Preset: minimal]                                    OK
+ EF - Electra - Fork - fork_next_epoch_with_block [Preset: minimal]                         OK
+ EF - Electra - Fork - fork_pending_deposits_are_sorted [Preset: minimal]                   OK
+ EF - Electra - Fork - fork_pre_activation [Preset: minimal]                                OK
+ EF - Electra - Fork - fork_random_large_validator_set [Preset: minimal]                    OK
+ EF - Electra - Fork - fork_random_low_balances [Preset: minimal]                           OK
+ EF - Electra - Fork - fork_random_misc_balances [Preset: minimal]                          OK
```
## EF - Electra - Operations - Attestation  [Preset: minimal]
```diff
+ [Invalid] EF - Electra - Operations - Attestation - invalid_after_max_inclusion_slot       OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_attestation_data_index_not_zer OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_attestation_signature          OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_bad_source_root                OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_before_inclusion_delay         OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_committee_index                OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_correct_attestation_included_a OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_current_source_root            OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_empty_participants_seemingly_v OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_empty_participants_zeroes_sig  OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_future_target_epoch            OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_incorrect_head_and_target_incl OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_incorrect_head_included_after_ OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_incorrect_target_included_afte OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_index                          OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_mismatched_target_and_slot     OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_new_source_epoch               OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_nonset_bits_for_one_committee  OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_nonset_committee_bits          OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_nonset_multiple_committee_bits OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_old_source_epoch               OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_old_target_epoch               OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_previous_source_root           OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_source_root_is_target_root     OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_too_few_aggregation_bits       OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_too_many_aggregation_bits      OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_too_many_committee_bits        OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_wrong_index_for_committee_sign OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_wrong_index_for_slot_0         OK
+ [Invalid] EF - Electra - Operations - Attestation - invalid_wrong_index_for_slot_1         OK
+ [Valid]   EF - Electra - Operations - Attestation - at_max_inclusion_slot                  OK
+ [Valid]   EF - Electra - Operations - Attestation - correct_attestation_included_at_max_in OK
+ [Valid]   EF - Electra - Operations - Attestation - correct_attestation_included_at_min_in OK
+ [Valid]   EF - Electra - Operations - Attestation - correct_attestation_included_at_one_ep OK
+ [Valid]   EF - Electra - Operations - Attestation - correct_attestation_included_at_sqrt_e OK
+ [Valid]   EF - Electra - Operations - Attestation - incorrect_head_and_target_included_at_ OK
+ [Valid]   EF - Electra - Operations - Attestation - incorrect_head_and_target_included_at_ OK
+ [Valid]   EF - Electra - Operations - Attestation - incorrect_head_and_target_min_inclusio OK
+ [Valid]   EF - Electra - Operations - Attestation - incorrect_head_included_at_max_inclusi OK
+ [Valid]   EF - Electra - Operations - Attestation - incorrect_head_included_at_min_inclusi OK
+ [Valid]   EF - Electra - Operations - Attestation - incorrect_head_included_at_sqrt_epoch_ OK
+ [Valid]   EF - Electra - Operations - Attestation - incorrect_target_included_at_epoch_del OK
+ [Valid]   EF - Electra - Operations - Attestation - incorrect_target_included_at_min_inclu OK
+ [Valid]   EF - Electra - Operations - Attestation - incorrect_target_included_at_sqrt_epoc OK
+ [Valid]   EF - Electra - Operations - Attestation - multi_proposer_index_iterations        OK
+ [Valid]   EF - Electra - Operations - Attestation - multiple_committees                    OK
+ [Valid]   EF - Electra - Operations - Attestation - one_basic_attestation                  OK
+ [Valid]   EF - Electra - Operations - Attestation - one_committee_with_gap                 OK
+ [Valid]   EF - Electra - Operations - Attestation - previous_epoch                         OK
```
## EF - Electra - Operations - Attester Slashing  [Preset: minimal]
```diff
+ [Invalid] EF - Electra - Operations - Attester Slashing - invalid_all_empty_indices        OK
+ [Invalid] EF - Electra - Operations - Attester Slashing - invalid_att1_bad_extra_index     OK
+ [Invalid] EF - Electra - Operations - Attester Slashing - invalid_att1_bad_replaced_index  OK
+ [Invalid] EF - Electra - Operations - Attester Slashing - invalid_att1_duplicate_index_dou OK
+ [Invalid] EF - Electra - Operations - Attester Slashing - invalid_att1_duplicate_index_nor OK
+ [Invalid] EF - Electra - Operations - Attester Slashing - invalid_att1_empty_indices       OK
+ [Invalid] EF - Electra - Operations - Attester Slashing - invalid_att1_high_index          OK
+ [Invalid] EF - Electra - Operations - Attester Slashing - invalid_att2_bad_extra_index     OK
+ [Invalid] EF - Electra - Operations - Attester Slashing - invalid_att2_bad_replaced_index  OK
+ [Invalid] EF - Electra - Operations - Attester Slashing - invalid_att2_duplicate_index_dou OK
+ [Invalid] EF - Electra - Operations - Attester Slashing - invalid_att2_duplicate_index_nor OK
+ [Invalid] EF - Electra - Operations - Attester Slashing - invalid_att2_empty_indices       OK
+ [Invalid] EF - Electra - Operations - Attester Slashing - invalid_att2_high_index          OK
+ [Invalid] EF - Electra - Operations - Attester Slashing - invalid_incorrect_sig_1          OK
+ [Invalid] EF - Electra - Operations - Attester Slashing - invalid_incorrect_sig_1_and_2    OK
+ [Invalid] EF - Electra - Operations - Attester Slashing - invalid_incorrect_sig_2          OK
+ [Invalid] EF - Electra - Operations - Attester Slashing - invalid_no_double_or_surround    OK
+ [Invalid] EF - Electra - Operations - Attester Slashing - invalid_participants_already_sla OK
+ [Invalid] EF - Electra - Operations - Attester Slashing - invalid_same_data                OK
+ [Invalid] EF - Electra - Operations - Attester Slashing - invalid_unsorted_att_1           OK
+ [Invalid] EF - Electra - Operations - Attester Slashing - invalid_unsorted_att_2           OK
+ [Valid]   EF - Electra - Operations - Attester Slashing - already_exited_long_ago          OK
+ [Valid]   EF - Electra - Operations - Attester Slashing - already_exited_recent            OK
+ [Valid]   EF - Electra - Operations - Attester Slashing - attestation_from_future          OK
+ [Valid]   EF - Electra - Operations - Attester Slashing - basic_double                     OK
+ [Valid]   EF - Electra - Operations - Attester Slashing - basic_surround                   OK
+ [Valid]   EF - Electra - Operations - Attester Slashing - low_balances                     OK
+ [Valid]   EF - Electra - Operations - Attester Slashing - misc_balances                    OK
+ [Valid]   EF - Electra - Operations - Attester Slashing - proposer_index_slashed           OK
+ [Valid]   EF - Electra - Operations - Attester Slashing - with_effective_balance_disparity OK
```
## EF - Electra - Operations - BLS to execution change  [Preset: minimal]
```diff
+ [Invalid] EF - Electra - Operations - BLS to execution change - invalid_already_0x01       OK
+ [Invalid] EF - Electra - Operations - BLS to execution change - invalid_bad_signature      OK
+ [Invalid] EF - Electra - Operations - BLS to execution change - invalid_current_fork_versi OK
+ [Invalid] EF - Electra - Operations - BLS to execution change - invalid_genesis_validators OK
+ [Invalid] EF - Electra - Operations - BLS to execution change - invalid_incorrect_from_bls OK
+ [Invalid] EF - Electra - Operations - BLS to execution change - invalid_previous_fork_vers OK
+ [Invalid] EF - Electra - Operations - BLS to execution change - invalid_val_index_out_of_r OK
+ [Valid]   EF - Electra - Operations - BLS to execution change - genesis_fork_version       OK
+ [Valid]   EF - Electra - Operations - BLS to execution change - success                    OK
+ [Valid]   EF - Electra - Operations - BLS to execution change - success_exited             OK
+ [Valid]   EF - Electra - Operations - BLS to execution change - success_in_activation_queu OK
+ [Valid]   EF - Electra - Operations - BLS to execution change - success_in_exit_queue      OK
+ [Valid]   EF - Electra - Operations - BLS to execution change - success_not_activated      OK
+ [Valid]   EF - Electra - Operations - BLS to execution change - success_withdrawable       OK
```
## EF - Electra - Operations - Block Header  [Preset: minimal]
```diff
+ [Invalid] EF - Electra - Operations - Block Header - invalid_multiple_blocks_single_slot   OK
+ [Invalid] EF - Electra - Operations - Block Header - invalid_parent_root                   OK
+ [Invalid] EF - Electra - Operations - Block Header - invalid_proposer_index                OK
+ [Invalid] EF - Electra - Operations - Block Header - invalid_proposer_slashed              OK
+ [Invalid] EF - Electra - Operations - Block Header - invalid_slot_block_header             OK
+ [Valid]   EF - Electra - Operations - Block Header - basic_block_header                    OK
```
## EF - Electra - Operations - Consolidation Request  [Preset: minimal]
```diff
+ [Valid]   EF - Electra - Operations - Consolidation Request - basic_consolidation_in_curre OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - basic_consolidation_in_new_c OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - basic_consolidation_source_h OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - basic_consolidation_target_h OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - basic_consolidation_with_com OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - basic_consolidation_with_exc OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - basic_consolidation_with_ins OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - basic_consolidation_with_pre OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - basic_switch_to_compounding  OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - consolidation_balance_larger OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - consolidation_balance_throug OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - consolidation_churn_limit_ba OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - incorrect_exceed_pending_con OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - incorrect_exited_source      OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - incorrect_exited_target      OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - incorrect_inactive_source    OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - incorrect_inactive_target    OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - incorrect_no_source_executio OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - incorrect_not_enough_consoli OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - incorrect_same_source_target OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - incorrect_source_address     OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - incorrect_source_has_pending OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - incorrect_source_not_active_ OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - incorrect_source_pubkey_is_t OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - incorrect_source_with_bls_cr OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - incorrect_target_with_bls_cr OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - incorrect_target_with_eth1_c OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - incorrect_unknown_source_pub OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - incorrect_unknown_target_pub OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - switch_to_compounding_exited OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - switch_to_compounding_inacti OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - switch_to_compounding_not_au OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - switch_to_compounding_source OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - switch_to_compounding_source OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - switch_to_compounding_unknow OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - switch_to_compounding_with_e OK
+ [Valid]   EF - Electra - Operations - Consolidation Request - switch_to_compounding_with_p OK
```
## EF - Electra - Operations - Deposit  [Preset: minimal]
```diff
+ [Invalid] EF - Electra - Operations - Deposit - invalid_bad_merkle_proof                   OK
+ [Invalid] EF - Electra - Operations - Deposit - invalid_wrong_deposit_for_deposit_count    OK
+ [Valid]   EF - Electra - Operations - Deposit - correct_sig_but_forked_state               OK
+ [Valid]   EF - Electra - Operations - Deposit - effective_deposit_with_genesis_fork_versio OK
+ [Valid]   EF - Electra - Operations - Deposit - incorrect_sig_new_deposit                  OK
+ [Valid]   EF - Electra - Operations - Deposit - incorrect_sig_top_up                       OK
+ [Valid]   EF - Electra - Operations - Deposit - incorrect_withdrawal_credentials_top_up    OK
+ [Valid]   EF - Electra - Operations - Deposit - ineffective_deposit_with_bad_fork_version  OK
+ [Valid]   EF - Electra - Operations - Deposit - ineffective_deposit_with_current_fork_vers OK
+ [Valid]   EF - Electra - Operations - Deposit - ineffective_deposit_with_previous_fork_ver OK
+ [Valid]   EF - Electra - Operations - Deposit - key_validate_invalid_decompression         OK
+ [Valid]   EF - Electra - Operations - Deposit - key_validate_invalid_subgroup              OK
+ [Valid]   EF - Electra - Operations - Deposit - new_deposit_eth1_withdrawal_credentials    OK
+ [Valid]   EF - Electra - Operations - Deposit - new_deposit_max                            OK
+ [Valid]   EF - Electra - Operations - Deposit - new_deposit_non_versioned_withdrawal_crede OK
+ [Valid]   EF - Electra - Operations - Deposit - new_deposit_over_max                       OK
+ [Valid]   EF - Electra - Operations - Deposit - new_deposit_under_max                      OK
+ [Valid]   EF - Electra - Operations - Deposit - success_top_up_to_withdrawn_validator      OK
+ [Valid]   EF - Electra - Operations - Deposit - top_up__less_effective_balance             OK
+ [Valid]   EF - Electra - Operations - Deposit - top_up__max_effective_balance              OK
+ [Valid]   EF - Electra - Operations - Deposit - top_up__zero_balance                       OK
```
## EF - Electra - Operations - Deposit Request  [Preset: minimal]
```diff
+ [Valid]   EF - Electra - Operations - Deposit Request - process_deposit_request_eth1_crede OK
+ [Valid]   EF - Electra - Operations - Deposit Request - process_deposit_request_extra_gwei OK
+ [Valid]   EF - Electra - Operations - Deposit Request - process_deposit_request_greater_th OK
+ [Valid]   EF - Electra - Operations - Deposit Request - process_deposit_request_invalid_si OK
+ [Valid]   EF - Electra - Operations - Deposit Request - process_deposit_request_max_effect OK
+ [Valid]   EF - Electra - Operations - Deposit Request - process_deposit_request_min_activa OK
+ [Valid]   EF - Electra - Operations - Deposit Request - process_deposit_request_pending_de OK
+ [Valid]   EF - Electra - Operations - Deposit Request - process_deposit_request_set_start_ OK
+ [Valid]   EF - Electra - Operations - Deposit Request - process_deposit_request_set_start_ OK
+ [Valid]   EF - Electra - Operations - Deposit Request - process_deposit_request_top_up_inv OK
+ [Valid]   EF - Electra - Operations - Deposit Request - process_deposit_request_top_up_max OK
+ [Valid]   EF - Electra - Operations - Deposit Request - process_deposit_request_top_up_min OK
+ [Valid]   EF - Electra - Operations - Deposit Request - process_deposit_request_top_up_sti OK
+ [Valid]   EF - Electra - Operations - Deposit Request - process_deposit_request_undefined_ OK
```
## EF - Electra - Operations - Execution Payload  [Preset: minimal]
```diff
+ [Invalid] EF - Electra - Operations - Execution Payload - invalid_bad_everything_first_pay OK
+ [Invalid] EF - Electra - Operations - Execution Payload - invalid_bad_everything_regular_p OK
+ [Invalid] EF - Electra - Operations - Execution Payload - invalid_bad_execution_first_payl OK
+ [Invalid] EF - Electra - Operations - Execution Payload - invalid_bad_execution_regular_pa OK
+ [Invalid] EF - Electra - Operations - Execution Payload - invalid_bad_parent_hash_first_pa OK
+ [Invalid] EF - Electra - Operations - Execution Payload - invalid_bad_parent_hash_regular_ OK
+ [Invalid] EF - Electra - Operations - Execution Payload - invalid_bad_pre_randao_regular_p OK
+ [Invalid] EF - Electra - Operations - Execution Payload - invalid_bad_prev_randao_first_pa OK
+ [Invalid] EF - Electra - Operations - Execution Payload - invalid_correct_input__execution OK
+ [Invalid] EF - Electra - Operations - Execution Payload - invalid_future_timestamp_first_p OK
+ [Invalid] EF - Electra - Operations - Execution Payload - invalid_future_timestamp_regular OK
+ [Invalid] EF - Electra - Operations - Execution Payload - invalid_past_timestamp_first_pay OK
+ [Invalid] EF - Electra - Operations - Execution Payload - invalid_past_timestamp_regular_p OK
+ [Invalid] EF - Electra - Operations - Execution Payload - invalid_randomized_non_validated OK
+ [Invalid] EF - Electra - Operations - Execution Payload - invalid_randomized_non_validated OK
+ [Valid]   EF - Electra - Operations - Execution Payload - incorrect_blob_tx_type           OK
+ [Valid]   EF - Electra - Operations - Execution Payload - incorrect_block_hash             OK
+ [Valid]   EF - Electra - Operations - Execution Payload - incorrect_commitment             OK
+ [Valid]   EF - Electra - Operations - Execution Payload - incorrect_commitments_order      OK
+ [Valid]   EF - Electra - Operations - Execution Payload - incorrect_transaction_length_1_b OK
+ [Valid]   EF - Electra - Operations - Execution Payload - incorrect_transaction_length_1_e OK
+ [Valid]   EF - Electra - Operations - Execution Payload - incorrect_transaction_length_32_ OK
+ [Valid]   EF - Electra - Operations - Execution Payload - incorrect_transaction_length_emp OK
+ [Valid]   EF - Electra - Operations - Execution Payload - incorrect_transaction_no_blobs_b OK
+ [Valid]   EF - Electra - Operations - Execution Payload - no_commitments_for_transactions  OK
+ [Valid]   EF - Electra - Operations - Execution Payload - no_transactions_with_commitments OK
+ [Valid]   EF - Electra - Operations - Execution Payload - non_empty_extra_data_first_paylo OK
+ [Valid]   EF - Electra - Operations - Execution Payload - non_empty_extra_data_regular_pay OK
+ [Valid]   EF - Electra - Operations - Execution Payload - non_empty_transactions_first_pay OK
+ [Valid]   EF - Electra - Operations - Execution Payload - non_empty_transactions_regular_p OK
+ [Valid]   EF - Electra - Operations - Execution Payload - randomized_non_validated_executi OK
+ [Valid]   EF - Electra - Operations - Execution Payload - randomized_non_validated_executi OK
+ [Valid]   EF - Electra - Operations - Execution Payload - success_first_payload            OK
+ [Valid]   EF - Electra - Operations - Execution Payload - success_first_payload_with_gap_s OK
+ [Valid]   EF - Electra - Operations - Execution Payload - success_regular_payload          OK
+ [Valid]   EF - Electra - Operations - Execution Payload - success_regular_payload_with_gap OK
+ [Valid]   EF - Electra - Operations - Execution Payload - zero_length_transaction_first_pa OK
+ [Valid]   EF - Electra - Operations - Execution Payload - zero_length_transaction_regular_ OK
+ [Valid]   EF - Electra - Operations - Execution Payload - zeroed_commitment                OK
```
## EF - Electra - Operations - Proposer Slashing  [Preset: minimal]
```diff
+ [Invalid] EF - Electra - Operations - Proposer Slashing - invalid_different_proposer_indic OK
+ [Invalid] EF - Electra - Operations - Proposer Slashing - invalid_headers_are_same_sigs_ar OK
+ [Invalid] EF - Electra - Operations - Proposer Slashing - invalid_headers_are_same_sigs_ar OK
+ [Invalid] EF - Electra - Operations - Proposer Slashing - invalid_incorrect_proposer_index OK
+ [Invalid] EF - Electra - Operations - Proposer Slashing - invalid_incorrect_sig_1          OK
+ [Invalid] EF - Electra - Operations - Proposer Slashing - invalid_incorrect_sig_1_and_2    OK
+ [Invalid] EF - Electra - Operations - Proposer Slashing - invalid_incorrect_sig_1_and_2_sw OK
+ [Invalid] EF - Electra - Operations - Proposer Slashing - invalid_incorrect_sig_2          OK
+ [Invalid] EF - Electra - Operations - Proposer Slashing - invalid_proposer_is_not_activate OK
+ [Invalid] EF - Electra - Operations - Proposer Slashing - invalid_proposer_is_slashed      OK
+ [Invalid] EF - Electra - Operations - Proposer Slashing - invalid_proposer_is_withdrawn    OK
+ [Invalid] EF - Electra - Operations - Proposer Slashing - invalid_proposer_withdrawable_cu OK
+ [Invalid] EF - Electra - Operations - Proposer Slashing - invalid_slots_of_different_epoch OK
+ [Invalid] EF - Electra - Operations - Proposer Slashing - invalid_slots_same_epoch_differe OK
+ [Valid]   EF - Electra - Operations - Proposer Slashing - basic                            OK
+ [Valid]   EF - Electra - Operations - Proposer Slashing - block_header_from_future         OK
+ [Valid]   EF - Electra - Operations - Proposer Slashing - block_header_from_past           OK
+ [Valid]   EF - Electra - Operations - Proposer Slashing - header_slot_at_epoch_end         OK
+ [Valid]   EF - Electra - Operations - Proposer Slashing - header_slot_at_epoch_start       OK
+ [Valid]   EF - Electra - Operations - Proposer Slashing - headers_differ_multiple_roots    OK
+ [Valid]   EF - Electra - Operations - Proposer Slashing - headers_differ_only_body_root    OK
+ [Valid]   EF - Electra - Operations - Proposer Slashing - headers_differ_only_state_root   OK
+ [Valid]   EF - Electra - Operations - Proposer Slashing - proposer_activated_current_epoch OK
+ [Valid]   EF - Electra - Operations - Proposer Slashing - proposer_index_last              OK
+ [Valid]   EF - Electra - Operations - Proposer Slashing - proposer_index_zero              OK
+ [Valid]   EF - Electra - Operations - Proposer Slashing - proposer_withdrawable_next_epoch OK
+ [Valid]   EF - Electra - Operations - Proposer Slashing - self_slashing_future_slot        OK
+ [Valid]   EF - Electra - Operations - Proposer Slashing - slashed_and_proposer_index_the_s OK
```
## EF - Electra - Operations - Sync Aggregate  [Preset: minimal]
```diff
+ [Invalid] EF - Electra - Operations - Sync Aggregate - invalid_signature_bad_domain        OK
+ [Invalid] EF - Electra - Operations - Sync Aggregate - invalid_signature_extra_participant OK
+ [Invalid] EF - Electra - Operations - Sync Aggregate - invalid_signature_infinite_signatur OK
+ [Invalid] EF - Electra - Operations - Sync Aggregate - invalid_signature_infinite_signatur OK
+ [Invalid] EF - Electra - Operations - Sync Aggregate - invalid_signature_missing_participa OK
+ [Invalid] EF - Electra - Operations - Sync Aggregate - invalid_signature_no_participants   OK
+ [Invalid] EF - Electra - Operations - Sync Aggregate - invalid_signature_past_block        OK
+ [Invalid] EF - Electra - Operations - Sync Aggregate - invalid_signature_previous_committe OK
+ [Valid]   EF - Electra - Operations - Sync Aggregate - proposer_in_committee_with_particip OK
+ [Valid]   EF - Electra - Operations - Sync Aggregate - proposer_in_committee_without_parti OK
+ [Valid]   EF - Electra - Operations - Sync Aggregate - random_all_but_one_participating_wi OK
+ [Valid]   EF - Electra - Operations - Sync Aggregate - random_high_participation_without_d OK
+ [Valid]   EF - Electra - Operations - Sync Aggregate - random_low_participation_without_du OK
+ [Valid]   EF - Electra - Operations - Sync Aggregate - random_misc_balances_and_half_parti OK
+ [Valid]   EF - Electra - Operations - Sync Aggregate - random_only_one_participant_without OK
+ [Valid]   EF - Electra - Operations - Sync Aggregate - random_with_exits_without_duplicate OK
+ [Valid]   EF - Electra - Operations - Sync Aggregate - sync_committee_rewards_empty_partic OK
+ [Valid]   EF - Electra - Operations - Sync Aggregate - sync_committee_rewards_nonduplicate OK
+ [Valid]   EF - Electra - Operations - Sync Aggregate - sync_committee_rewards_not_full_par OK
+ [Valid]   EF - Electra - Operations - Sync Aggregate - sync_committee_with_nonparticipatin OK
+ [Valid]   EF - Electra - Operations - Sync Aggregate - sync_committee_with_nonparticipatin OK
+ [Valid]   EF - Electra - Operations - Sync Aggregate - sync_committee_with_participating_e OK
+ [Valid]   EF - Electra - Operations - Sync Aggregate - sync_committee_with_participating_w OK
+ [Valid]   EF - Electra - Operations - Sync Aggregate - valid_signature_future_committee    OK
```
## EF - Electra - Operations - Voluntary Exit  [Preset: minimal]
```diff
+ [Invalid] EF - Electra - Operations - Voluntary Exit - invalid_incorrect_signature         OK
+ [Invalid] EF - Electra - Operations - Voluntary Exit - invalid_validator_already_exited    OK
+ [Invalid] EF - Electra - Operations - Voluntary Exit - invalid_validator_exit_in_future    OK
+ [Invalid] EF - Electra - Operations - Voluntary Exit - invalid_validator_has_pending_withd OK
+ [Invalid] EF - Electra - Operations - Voluntary Exit - invalid_validator_incorrect_validat OK
+ [Invalid] EF - Electra - Operations - Voluntary Exit - invalid_validator_not_active        OK
+ [Invalid] EF - Electra - Operations - Voluntary Exit - invalid_validator_not_active_long_e OK
+ [Invalid] EF - Electra - Operations - Voluntary Exit - invalid_voluntary_exit_with_current OK
+ [Invalid] EF - Electra - Operations - Voluntary Exit - invalid_voluntary_exit_with_current OK
+ [Invalid] EF - Electra - Operations - Voluntary Exit - invalid_voluntary_exit_with_genesis OK
+ [Invalid] EF - Electra - Operations - Voluntary Exit - invalid_voluntary_exit_with_genesis OK
+ [Invalid] EF - Electra - Operations - Voluntary Exit - voluntary_exit_with_previous_fork_v OK
+ [Invalid] EF - Electra - Operations - Voluntary Exit - voluntary_exit_with_previous_fork_v OK
+ [Valid]   EF - Electra - Operations - Voluntary Exit - basic                               OK
+ [Valid]   EF - Electra - Operations - Voluntary Exit - default_exit_epoch_subsequent_exit  OK
+ [Valid]   EF - Electra - Operations - Voluntary Exit - min_balance_exit                    OK
+ [Valid]   EF - Electra - Operations - Voluntary Exit - min_balance_exits_above_churn       OK
+ [Valid]   EF - Electra - Operations - Voluntary Exit - min_balance_exits_up_to_churn       OK
+ [Valid]   EF - Electra - Operations - Voluntary Exit - success_exit_queue__min_churn       OK
+ [Valid]   EF - Electra - Operations - Voluntary Exit - success_exit_queue__scaled_churn    OK
+ [Valid]   EF - Electra - Operations - Voluntary Exit - voluntary_exit_with_pending_deposit OK
```
## EF - Electra - Operations - Withdrawal Request  [Preset: minimal]
```diff
+ [Valid]   EF - Electra - Operations - Withdrawal Request - activation_epoch_less_than_shar OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - basic_partial_withdrawal_reques OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - basic_partial_withdrawal_reques OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - basic_partial_withdrawal_reques OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - basic_withdrawal_request        OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - basic_withdrawal_request_with_c OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - basic_withdrawal_request_with_f OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - basic_withdrawal_request_with_f OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - full_exit_request_has_partial_w OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - incorrect_inactive_validator    OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - incorrect_source_address        OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - incorrect_withdrawal_credential OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - insufficient_balance            OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - insufficient_effective_balance  OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - no_compounding_credentials      OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - no_excess_balance               OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - on_withdrawal_request_initiated OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - partial_withdrawal_activation_e OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - partial_withdrawal_incorrect_so OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - partial_withdrawal_incorrect_wi OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - partial_withdrawal_on_exit_init OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - partial_withdrawal_queue_full   OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - partial_withdrawal_request_with OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - partial_withdrawal_request_with OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - partial_withdrawal_request_with OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - partial_withdrawal_request_with OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - partial_withdrawal_request_with OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - pending_withdrawals_consume_all OK
+ [Valid]   EF - Electra - Operations - Withdrawal Request - unknown_pubkey                  OK
```
## EF - Electra - Operations - Withdrawals  [Preset: minimal]
```diff
+ [Invalid] EF - Electra - Operations - Withdrawals - invalid_a_lot_fully_withdrawable_too_f OK
+ [Invalid] EF - Electra - Operations - Withdrawals - invalid_a_lot_mixed_withdrawable_in_qu OK
+ [Invalid] EF - Electra - Operations - Withdrawals - invalid_a_lot_partially_withdrawable_t OK
+ [Invalid] EF - Electra - Operations - Withdrawals - invalid_incorrect_address_full         OK
+ [Invalid] EF - Electra - Operations - Withdrawals - invalid_incorrect_address_partial      OK
+ [Invalid] EF - Electra - Operations - Withdrawals - invalid_incorrect_amount_full          OK
+ [Invalid] EF - Electra - Operations - Withdrawals - invalid_incorrect_amount_partial       OK
+ [Invalid] EF - Electra - Operations - Withdrawals - invalid_incorrect_withdrawal_index     OK
+ [Invalid] EF - Electra - Operations - Withdrawals - invalid_many_incorrectly_full          OK
+ [Invalid] EF - Electra - Operations - Withdrawals - invalid_many_incorrectly_partial       OK
+ [Invalid] EF - Electra - Operations - Withdrawals - invalid_max_per_slot_full_withdrawals_ OK
+ [Invalid] EF - Electra - Operations - Withdrawals - invalid_max_per_slot_partial_withdrawa OK
+ [Invalid] EF - Electra - Operations - Withdrawals - invalid_non_withdrawable_non_empty_wit OK
+ [Invalid] EF - Electra - Operations - Withdrawals - invalid_one_expected_full_withdrawal_a OK
+ [Invalid] EF - Electra - Operations - Withdrawals - invalid_one_expected_full_withdrawal_a OK
+ [Invalid] EF - Electra - Operations - Withdrawals - invalid_one_expected_partial_withdrawa OK
+ [Invalid] EF - Electra - Operations - Withdrawals - invalid_one_of_many_incorrectly_full   OK
+ [Invalid] EF - Electra - Operations - Withdrawals - invalid_one_of_many_incorrectly_partia OK
+ [Invalid] EF - Electra - Operations - Withdrawals - invalid_two_expected_partial_withdrawa OK
+ [Valid]   EF - Electra - Operations - Withdrawals - all_withdrawal                         OK
+ [Valid]   EF - Electra - Operations - Withdrawals - full_pending_withdrawals_but_first_ski OK
+ [Valid]   EF - Electra - Operations - Withdrawals - full_pending_withdrawals_but_first_ski OK
+ [Valid]   EF - Electra - Operations - Withdrawals - full_pending_withdrawals_but_first_ski OK
+ [Valid]   EF - Electra - Operations - Withdrawals - no_withdrawals_but_some_next_epoch     OK
+ [Valid]   EF - Electra - Operations - Withdrawals - partially_withdrawable_validator_compo OK
+ [Valid]   EF - Electra - Operations - Withdrawals - partially_withdrawable_validator_compo OK
+ [Valid]   EF - Electra - Operations - Withdrawals - partially_withdrawable_validator_compo OK
+ [Valid]   EF - Electra - Operations - Withdrawals - partially_withdrawable_validator_compo OK
+ [Valid]   EF - Electra - Operations - Withdrawals - partially_withdrawable_validator_compo OK
+ [Valid]   EF - Electra - Operations - Withdrawals - partially_withdrawable_validator_compo OK
+ [Valid]   EF - Electra - Operations - Withdrawals - partially_withdrawable_validator_legac OK
+ [Valid]   EF - Electra - Operations - Withdrawals - partially_withdrawable_validator_legac OK
+ [Valid]   EF - Electra - Operations - Withdrawals - partially_withdrawable_validator_legac OK
+ [Valid]   EF - Electra - Operations - Withdrawals - pending_withdrawals_at_max             OK
+ [Valid]   EF - Electra - Operations - Withdrawals - pending_withdrawals_at_max_mixed_with_ OK
+ [Valid]   EF - Electra - Operations - Withdrawals - pending_withdrawals_exiting_validator  OK
+ [Valid]   EF - Electra - Operations - Withdrawals - pending_withdrawals_low_effective_bala OK
+ [Valid]   EF - Electra - Operations - Withdrawals - pending_withdrawals_mixed_with_sweep_a OK
+ [Valid]   EF - Electra - Operations - Withdrawals - pending_withdrawals_next_epoch         OK
+ [Valid]   EF - Electra - Operations - Withdrawals - pending_withdrawals_no_excess_balance  OK
+ [Valid]   EF - Electra - Operations - Withdrawals - pending_withdrawals_one_skipped_one_ef OK
+ [Valid]   EF - Electra - Operations - Withdrawals - pending_withdrawals_two_partial_withdr OK
+ [Valid]   EF - Electra - Operations - Withdrawals - pending_withdrawals_two_partial_withdr OK
+ [Valid]   EF - Electra - Operations - Withdrawals - pending_withdrawals_with_effective_swe OK
+ [Valid]   EF - Electra - Operations - Withdrawals - pending_withdrawals_with_ineffective_s OK
+ [Valid]   EF - Electra - Operations - Withdrawals - pending_withdrawals_with_ineffective_s OK
+ [Valid]   EF - Electra - Operations - Withdrawals - pending_withdrawals_with_sweep_differe OK
+ [Valid]   EF - Electra - Operations - Withdrawals - random_0                               OK
+ [Valid]   EF - Electra - Operations - Withdrawals - random_full_withdrawals_0              OK
+ [Valid]   EF - Electra - Operations - Withdrawals - random_full_withdrawals_1              OK
+ [Valid]   EF - Electra - Operations - Withdrawals - random_full_withdrawals_2              OK
+ [Valid]   EF - Electra - Operations - Withdrawals - random_full_withdrawals_3              OK
+ [Valid]   EF - Electra - Operations - Withdrawals - random_partial_withdrawals_1           OK
+ [Valid]   EF - Electra - Operations - Withdrawals - random_partial_withdrawals_2           OK
+ [Valid]   EF - Electra - Operations - Withdrawals - random_partial_withdrawals_3           OK
+ [Valid]   EF - Electra - Operations - Withdrawals - random_partial_withdrawals_4           OK
+ [Valid]   EF - Electra - Operations - Withdrawals - random_partial_withdrawals_5           OK
+ [Valid]   EF - Electra - Operations - Withdrawals - success_all_fully_withdrawable         OK
+ [Valid]   EF - Electra - Operations - Withdrawals - success_all_partially_withdrawable     OK
+ [Valid]   EF - Electra - Operations - Withdrawals - success_excess_balance_but_no_max_effe OK
+ [Valid]   EF - Electra - Operations - Withdrawals - success_excess_balance_but_no_max_effe OK
+ [Valid]   EF - Electra - Operations - Withdrawals - success_max_partial_withdrawable       OK
+ [Valid]   EF - Electra - Operations - Withdrawals - success_max_plus_one_withdrawable      OK
+ [Valid]   EF - Electra - Operations - Withdrawals - success_mixed_fully_and_partial_withdr OK
+ [Valid]   EF - Electra - Operations - Withdrawals - success_mixed_fully_and_partial_withdr OK
+ [Valid]   EF - Electra - Operations - Withdrawals - success_no_excess_balance              OK
+ [Valid]   EF - Electra - Operations - Withdrawals - success_no_excess_balance_compounding  OK
+ [Valid]   EF - Electra - Operations - Withdrawals - success_no_max_effective_balance       OK
+ [Valid]   EF - Electra - Operations - Withdrawals - success_no_max_effective_balance_compo OK
+ [Valid]   EF - Electra - Operations - Withdrawals - success_one_full_withdrawal            OK
+ [Valid]   EF - Electra - Operations - Withdrawals - success_one_partial_withdrawable_activ OK
+ [Valid]   EF - Electra - Operations - Withdrawals - success_one_partial_withdrawable_exite OK
+ [Valid]   EF - Electra - Operations - Withdrawals - success_one_partial_withdrawable_exite OK
+ [Valid]   EF - Electra - Operations - Withdrawals - success_one_partial_withdrawable_in_ex OK
+ [Valid]   EF - Electra - Operations - Withdrawals - success_one_partial_withdrawable_not_y OK
+ [Valid]   EF - Electra - Operations - Withdrawals - success_one_partial_withdrawal         OK
+ [Valid]   EF - Electra - Operations - Withdrawals - success_two_partial_withdrawable       OK
+ [Valid]   EF - Electra - Operations - Withdrawals - success_zero_expected_withdrawals      OK
+ [Valid]   EF - Electra - Operations - Withdrawals - withdrawable_epoch_but_0_balance       OK
+ [Valid]   EF - Electra - Operations - Withdrawals - withdrawable_epoch_but_0_effective_bal OK
+ [Valid]   EF - Electra - Operations - Withdrawals - withdrawable_epoch_but_0_effective_bal OK
```
## EF - Electra - SSZ consensus objects  [Preset: minimal]
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
+   Testing    ConsolidationRequest                                                          OK
+   Testing    ContributionAndProof                                                          OK
+   Testing    Deposit                                                                       OK
+   Testing    DepositData                                                                   OK
+   Testing    DepositMessage                                                                OK
+   Testing    DepositRequest                                                                OK
+   Testing    Eth1Block                                                                     OK
+   Testing    Eth1Data                                                                      OK
+   Testing    ExecutionPayload                                                              OK
+   Testing    ExecutionPayloadHeader                                                        OK
+   Testing    ExecutionRequests                                                             OK
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
+   Testing    PendingConsolidation                                                          OK
+   Testing    PendingDeposit                                                                OK
+   Testing    PendingPartialWithdrawal                                                      OK
+   Testing    PowBlock                                                                      OK
+   Testing    ProposerSlashing                                                              OK
+   Testing    SignedAggregateAndProof                                                       OK
+   Testing    SignedBLSToExecutionChange                                                    OK
+   Testing    SignedBeaconBlock                                                             OK
+   Testing    SignedBeaconBlockHeader                                                       OK
+   Testing    SignedContributionAndProof                                                    OK
+   Testing    SignedVoluntaryExit                                                           OK
+   Testing    SigningData                                                                   OK
+   Testing    SingleAttestation                                                             OK
+   Testing    SyncAggregate                                                                 OK
+   Testing    SyncAggregatorSelectionData                                                   OK
+   Testing    SyncCommittee                                                                 OK
+   Testing    SyncCommitteeContribution                                                     OK
+   Testing    SyncCommitteeMessage                                                          OK
+   Testing    Validator                                                                     OK
+   Testing    VoluntaryExit                                                                 OK
+   Testing    Withdrawal                                                                    OK
+   Testing    WithdrawalRequest                                                             OK
```
## EF - Electra - Sanity - Slots  [Preset: minimal]
```diff
+ EF - Electra - Slots - balance_change_affects_proposer [Preset: minimal]                   OK
+ EF - Electra - Slots - double_empty_epoch [Preset: minimal]                                OK
+ EF - Electra - Slots - effective_decrease_balance_updates_lookahead [Preset: minimal]      OK
+ EF - Electra - Slots - empty_epoch [Preset: minimal]                                       OK
+ EF - Electra - Slots - historical_accumulator [Preset: minimal]                            OK
+ EF - Electra - Slots - multiple_pending_deposits_same_pubkey [Preset: minimal]             OK
+ EF - Electra - Slots - multiple_pending_deposits_same_pubkey_above_upward_threshold [Prese OK
+ EF - Electra - Slots - multiple_pending_deposits_same_pubkey_below_upward_threshold [Prese OK
+ EF - Electra - Slots - multiple_pending_deposits_same_pubkey_compounding [Preset: minimal] OK
+ EF - Electra - Slots - multiple_pending_deposits_same_pubkey_different_signature [Preset:  OK
+ EF - Electra - Slots - over_epoch_boundary [Preset: minimal]                               OK
+ EF - Electra - Slots - pending_consolidation [Preset: minimal]                             OK
+ EF - Electra - Slots - pending_deposit_extra_gwei [Preset: minimal]                        OK
+ EF - Electra - Slots - slots_1 [Preset: minimal]                                           OK
+ EF - Electra - Slots - slots_2 [Preset: minimal]                                           OK
```
## EF - Electra - Transition  [Preset: minimal]
```diff
+ EF - Electra - Transition - higher_churn_limit_to_lower [Preset: minimal]                  OK
+ EF - Electra - Transition - non_empty_historical_roots [Preset: minimal]                   OK
+ EF - Electra - Transition - normal_transition [Preset: minimal]                            OK
+ EF - Electra - Transition - simple_transition [Preset: minimal]                            OK
+ EF - Electra - Transition - transition_attestation_from_previous_fork_with_new_range [Pres OK
+ EF - Electra - Transition - transition_missing_first_post_block [Preset: minimal]          OK
+ EF - Electra - Transition - transition_missing_last_pre_fork_block [Preset: minimal]       OK
+ EF - Electra - Transition - transition_only_blocks_post_fork [Preset: minimal]             OK
+ EF - Electra - Transition - transition_randomized_state [Preset: minimal]                  OK
+ EF - Electra - Transition - transition_with_activation_at_fork_epoch [Preset: minimal]     OK
+ EF - Electra - Transition - transition_with_attester_slashing_right_after_fork [Preset: mi OK
+ EF - Electra - Transition - transition_with_attester_slashing_right_before_fork [Preset: m OK
+ EF - Electra - Transition - transition_with_btec_right_after_fork [Preset: minimal]        OK
+ EF - Electra - Transition - transition_with_btec_right_before_fork [Preset: minimal]       OK
+ EF - Electra - Transition - transition_with_consolidation_request_right_after_fork [Preset OK
+ EF - Electra - Transition - transition_with_deposit_request_right_after_fork [Preset: mini OK
+ EF - Electra - Transition - transition_with_deposit_right_after_fork [Preset: minimal]     OK
+ EF - Electra - Transition - transition_with_deposit_right_before_fork [Preset: minimal]    OK
+ EF - Electra - Transition - transition_with_finality [Preset: minimal]                     OK
+ EF - Electra - Transition - transition_with_full_withdrawal_request_right_after_fork [Pres OK
+ EF - Electra - Transition - transition_with_leaking_at_fork [Preset: minimal]              OK
+ EF - Electra - Transition - transition_with_leaking_pre_fork [Preset: minimal]             OK
+ EF - Electra - Transition - transition_with_no_attestations_until_after_fork [Preset: mini OK
+ EF - Electra - Transition - transition_with_non_empty_activation_queue [Preset: minimal]   OK
+ EF - Electra - Transition - transition_with_one_fourth_exiting_validators_exit_at_fork [Pr OK
+ EF - Electra - Transition - transition_with_one_fourth_exiting_validators_exit_post_fork [ OK
+ EF - Electra - Transition - transition_with_one_fourth_slashed_active_validators_pre_fork  OK
+ EF - Electra - Transition - transition_with_proposer_slashing_right_after_fork [Preset: mi OK
+ EF - Electra - Transition - transition_with_proposer_slashing_right_before_fork [Preset: m OK
+ EF - Electra - Transition - transition_with_random_half_participation [Preset: minimal]    OK
+ EF - Electra - Transition - transition_with_random_three_quarters_participation [Preset: m OK
+ EF - Electra - Transition - transition_with_voluntary_exit_right_after_fork [Preset: minim OK
+ EF - Electra - Transition - transition_with_voluntary_exit_right_before_fork [Preset: mini OK
```
## EF - Electra - Unittests - Light client - Sync protocol [Preset: minimal]
```diff
+ process_light_client_update_finality_updated                                               OK
+ process_light_client_update_timeout                                                        OK
+ test_process_light_client_update_at_period_boundary                                        OK
+ test_process_light_client_update_not_timeout                                               OK
```
## EF - Fulu - Fork  [Preset: minimal]
```diff
+ EF - Fulu - Fork - after_fork_deactivate_validators_from_electra_to_fulu [Preset: minimal] OK
+ EF - Fulu - Fork - after_fork_deactivate_validators_wo_block_from_electra_to_fulu [Preset: OK
+ EF - Fulu - Fork - after_fork_new_validator_active_from_electra_to_fulu [Preset: minimal]  OK
+ EF - Fulu - Fork - fork_base_state [Preset: minimal]                                       OK
+ EF - Fulu - Fork - fork_many_next_epoch [Preset: minimal]                                  OK
+ EF - Fulu - Fork - fork_next_epoch [Preset: minimal]                                       OK
+ EF - Fulu - Fork - fork_next_epoch_with_block [Preset: minimal]                            OK
+ EF - Fulu - Fork - fork_random_large_validator_set [Preset: minimal]                       OK
+ EF - Fulu - Fork - fork_random_low_balances [Preset: minimal]                              OK
+ EF - Fulu - Fork - fork_random_misc_balances [Preset: minimal]                             OK
+ EF - Fulu - Fork - fulu_fork_random_0 [Preset: minimal]                                    OK
+ EF - Fulu - Fork - fulu_fork_random_1 [Preset: minimal]                                    OK
+ EF - Fulu - Fork - fulu_fork_random_2 [Preset: minimal]                                    OK
+ EF - Fulu - Fork - fulu_fork_random_3 [Preset: minimal]                                    OK
+ EF - Fulu - Fork - fulu_fork_random_large_validator_set [Preset: minimal]                  OK
+ EF - Fulu - Fork - fulu_fork_random_low_balances [Preset: minimal]                         OK
+ EF - Fulu - Fork - fulu_fork_random_misc_balances [Preset: minimal]                        OK
+ EF - Fulu - Fork - lookahead_consistency_at_fork [Preset: minimal]                         OK
+ EF - Fulu - Fork - lookahead_consistency_with_effective_balance_change_at_fork [Preset: mi OK
+ EF - Fulu - Fork - proposer_lookahead_init_at_fork_only_contains_active_validators [Preset OK
```
## EF - Fulu - Operations - Attestation  [Preset: minimal]
```diff
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_after_max_inclusion_slot          OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_attestation_data_index_not_zero   OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_attestation_signature             OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_bad_source_root                   OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_before_inclusion_delay            OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_committee_index                   OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_correct_attestation_included_afte OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_current_source_root               OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_empty_participants_seemingly_vali OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_empty_participants_zeroes_sig     OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_future_target_epoch               OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_incorrect_head_and_target_include OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_incorrect_head_included_after_max OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_incorrect_target_included_after_m OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_index                             OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_mismatched_target_and_slot        OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_new_source_epoch                  OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_nonset_bits_for_one_committee     OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_nonset_committee_bits             OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_nonset_multiple_committee_bits    OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_old_source_epoch                  OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_old_target_epoch                  OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_previous_source_root              OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_source_root_is_target_root        OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_too_few_aggregation_bits          OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_too_many_aggregation_bits         OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_too_many_committee_bits           OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_wrong_index_for_committee_signatu OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_wrong_index_for_slot_0            OK
+ [Invalid] EF - Fulu - Operations - Attestation - invalid_wrong_index_for_slot_1            OK
+ [Valid]   EF - Fulu - Operations - Attestation - at_max_inclusion_slot                     OK
+ [Valid]   EF - Fulu - Operations - Attestation - correct_attestation_included_at_max_inclu OK
+ [Valid]   EF - Fulu - Operations - Attestation - correct_attestation_included_at_min_inclu OK
+ [Valid]   EF - Fulu - Operations - Attestation - correct_attestation_included_at_one_epoch OK
+ [Valid]   EF - Fulu - Operations - Attestation - correct_attestation_included_at_sqrt_epoc OK
+ [Valid]   EF - Fulu - Operations - Attestation - incorrect_head_and_target_included_at_epo OK
+ [Valid]   EF - Fulu - Operations - Attestation - incorrect_head_and_target_included_at_sqr OK
+ [Valid]   EF - Fulu - Operations - Attestation - incorrect_head_and_target_min_inclusion_d OK
+ [Valid]   EF - Fulu - Operations - Attestation - incorrect_head_included_at_max_inclusion_ OK
+ [Valid]   EF - Fulu - Operations - Attestation - incorrect_head_included_at_min_inclusion_ OK
+ [Valid]   EF - Fulu - Operations - Attestation - incorrect_head_included_at_sqrt_epoch_del OK
+ [Valid]   EF - Fulu - Operations - Attestation - incorrect_target_included_at_epoch_delay  OK
+ [Valid]   EF - Fulu - Operations - Attestation - incorrect_target_included_at_min_inclusio OK
+ [Valid]   EF - Fulu - Operations - Attestation - incorrect_target_included_at_sqrt_epoch_d OK
+ [Valid]   EF - Fulu - Operations - Attestation - multi_proposer_index_iterations           OK
+ [Valid]   EF - Fulu - Operations - Attestation - multiple_committees                       OK
+ [Valid]   EF - Fulu - Operations - Attestation - one_basic_attestation                     OK
+ [Valid]   EF - Fulu - Operations - Attestation - one_committee_with_gap                    OK
+ [Valid]   EF - Fulu - Operations - Attestation - previous_epoch                            OK
```
## EF - Fulu - Operations - Attester Slashing  [Preset: minimal]
```diff
+ [Invalid] EF - Fulu - Operations - Attester Slashing - invalid_all_empty_indices           OK
+ [Invalid] EF - Fulu - Operations - Attester Slashing - invalid_att1_bad_extra_index        OK
+ [Invalid] EF - Fulu - Operations - Attester Slashing - invalid_att1_bad_replaced_index     OK
+ [Invalid] EF - Fulu - Operations - Attester Slashing - invalid_att1_duplicate_index_double OK
+ [Invalid] EF - Fulu - Operations - Attester Slashing - invalid_att1_duplicate_index_normal OK
+ [Invalid] EF - Fulu - Operations - Attester Slashing - invalid_att1_empty_indices          OK
+ [Invalid] EF - Fulu - Operations - Attester Slashing - invalid_att1_high_index             OK
+ [Invalid] EF - Fulu - Operations - Attester Slashing - invalid_att2_bad_extra_index        OK
+ [Invalid] EF - Fulu - Operations - Attester Slashing - invalid_att2_bad_replaced_index     OK
+ [Invalid] EF - Fulu - Operations - Attester Slashing - invalid_att2_duplicate_index_double OK
+ [Invalid] EF - Fulu - Operations - Attester Slashing - invalid_att2_duplicate_index_normal OK
+ [Invalid] EF - Fulu - Operations - Attester Slashing - invalid_att2_empty_indices          OK
+ [Invalid] EF - Fulu - Operations - Attester Slashing - invalid_att2_high_index             OK
+ [Invalid] EF - Fulu - Operations - Attester Slashing - invalid_incorrect_sig_1             OK
+ [Invalid] EF - Fulu - Operations - Attester Slashing - invalid_incorrect_sig_1_and_2       OK
+ [Invalid] EF - Fulu - Operations - Attester Slashing - invalid_incorrect_sig_2             OK
+ [Invalid] EF - Fulu - Operations - Attester Slashing - invalid_no_double_or_surround       OK
+ [Invalid] EF - Fulu - Operations - Attester Slashing - invalid_participants_already_slashe OK
+ [Invalid] EF - Fulu - Operations - Attester Slashing - invalid_same_data                   OK
+ [Invalid] EF - Fulu - Operations - Attester Slashing - invalid_unsorted_att_1              OK
+ [Invalid] EF - Fulu - Operations - Attester Slashing - invalid_unsorted_att_2              OK
+ [Valid]   EF - Fulu - Operations - Attester Slashing - already_exited_long_ago             OK
+ [Valid]   EF - Fulu - Operations - Attester Slashing - already_exited_recent               OK
+ [Valid]   EF - Fulu - Operations - Attester Slashing - attestation_from_future             OK
+ [Valid]   EF - Fulu - Operations - Attester Slashing - basic_double                        OK
+ [Valid]   EF - Fulu - Operations - Attester Slashing - basic_surround                      OK
+ [Valid]   EF - Fulu - Operations - Attester Slashing - low_balances                        OK
+ [Valid]   EF - Fulu - Operations - Attester Slashing - misc_balances                       OK
+ [Valid]   EF - Fulu - Operations - Attester Slashing - proposer_index_slashed              OK
+ [Valid]   EF - Fulu - Operations - Attester Slashing - with_effective_balance_disparity    OK
```
## EF - Fulu - Operations - BLS to execution change  [Preset: minimal]
```diff
+ [Invalid] EF - Fulu - Operations - BLS to execution change - invalid_already_0x01          OK
+ [Invalid] EF - Fulu - Operations - BLS to execution change - invalid_bad_signature         OK
+ [Invalid] EF - Fulu - Operations - BLS to execution change - invalid_current_fork_version  OK
+ [Invalid] EF - Fulu - Operations - BLS to execution change - invalid_genesis_validators_ro OK
+ [Invalid] EF - Fulu - Operations - BLS to execution change - invalid_incorrect_from_bls_pu OK
+ [Invalid] EF - Fulu - Operations - BLS to execution change - invalid_previous_fork_version OK
+ [Invalid] EF - Fulu - Operations - BLS to execution change - invalid_val_index_out_of_rang OK
+ [Valid]   EF - Fulu - Operations - BLS to execution change - genesis_fork_version          OK
+ [Valid]   EF - Fulu - Operations - BLS to execution change - success                       OK
+ [Valid]   EF - Fulu - Operations - BLS to execution change - success_exited                OK
+ [Valid]   EF - Fulu - Operations - BLS to execution change - success_in_activation_queue   OK
+ [Valid]   EF - Fulu - Operations - BLS to execution change - success_in_exit_queue         OK
+ [Valid]   EF - Fulu - Operations - BLS to execution change - success_not_activated         OK
+ [Valid]   EF - Fulu - Operations - BLS to execution change - success_withdrawable          OK
```
## EF - Fulu - Operations - Block Header  [Preset: minimal]
```diff
+ [Invalid] EF - Fulu - Operations - Block Header - invalid_multiple_blocks_single_slot      OK
+ [Invalid] EF - Fulu - Operations - Block Header - invalid_parent_root                      OK
+ [Invalid] EF - Fulu - Operations - Block Header - invalid_proposer_index                   OK
+ [Invalid] EF - Fulu - Operations - Block Header - invalid_proposer_slashed                 OK
+ [Invalid] EF - Fulu - Operations - Block Header - invalid_slot_block_header                OK
+ [Valid]   EF - Fulu - Operations - Block Header - basic_block_header                       OK
```
## EF - Fulu - Operations - Consolidation Request  [Preset: minimal]
```diff
+ [Valid]   EF - Fulu - Operations - Consolidation Request - basic_consolidation_in_current_ OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - basic_consolidation_in_new_cons OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - basic_consolidation_source_has_ OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - basic_consolidation_target_has_ OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - basic_consolidation_with_compou OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - basic_consolidation_with_excess OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - basic_consolidation_with_insuff OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - basic_consolidation_with_preexi OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - basic_switch_to_compounding     OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - consolidation_balance_larger_th OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - consolidation_balance_through_t OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - consolidation_churn_limit_balan OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - incorrect_exceed_pending_consol OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - incorrect_exited_source         OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - incorrect_exited_target         OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - incorrect_inactive_source       OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - incorrect_inactive_target       OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - incorrect_no_source_execution_w OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - incorrect_not_enough_consolidat OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - incorrect_same_source_target    OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - incorrect_source_address        OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - incorrect_source_has_pending_wi OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - incorrect_source_not_active_lon OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - incorrect_source_pubkey_is_targ OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - incorrect_source_with_bls_crede OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - incorrect_target_with_bls_crede OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - incorrect_target_with_eth1_cred OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - incorrect_unknown_source_pubkey OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - incorrect_unknown_target_pubkey OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - switch_to_compounding_exited_so OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - switch_to_compounding_inactive_ OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - switch_to_compounding_not_autho OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - switch_to_compounding_source_bl OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - switch_to_compounding_source_co OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - switch_to_compounding_unknown_s OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - switch_to_compounding_with_exce OK
+ [Valid]   EF - Fulu - Operations - Consolidation Request - switch_to_compounding_with_pend OK
```
## EF - Fulu - Operations - Deposit  [Preset: minimal]
```diff
+ [Invalid] EF - Fulu - Operations - Deposit - invalid_bad_merkle_proof                      OK
+ [Invalid] EF - Fulu - Operations - Deposit - invalid_wrong_deposit_for_deposit_count       OK
+ [Valid]   EF - Fulu - Operations - Deposit - correct_sig_but_forked_state                  OK
+ [Valid]   EF - Fulu - Operations - Deposit - effective_deposit_with_genesis_fork_version   OK
+ [Valid]   EF - Fulu - Operations - Deposit - incorrect_sig_new_deposit                     OK
+ [Valid]   EF - Fulu - Operations - Deposit - incorrect_sig_top_up                          OK
+ [Valid]   EF - Fulu - Operations - Deposit - incorrect_withdrawal_credentials_top_up       OK
+ [Valid]   EF - Fulu - Operations - Deposit - ineffective_deposit_with_bad_fork_version     OK
+ [Valid]   EF - Fulu - Operations - Deposit - ineffective_deposit_with_current_fork_version OK
+ [Valid]   EF - Fulu - Operations - Deposit - ineffective_deposit_with_previous_fork_versio OK
+ [Valid]   EF - Fulu - Operations - Deposit - key_validate_invalid_decompression            OK
+ [Valid]   EF - Fulu - Operations - Deposit - key_validate_invalid_subgroup                 OK
+ [Valid]   EF - Fulu - Operations - Deposit - new_deposit_eth1_withdrawal_credentials       OK
+ [Valid]   EF - Fulu - Operations - Deposit - new_deposit_max                               OK
+ [Valid]   EF - Fulu - Operations - Deposit - new_deposit_non_versioned_withdrawal_credenti OK
+ [Valid]   EF - Fulu - Operations - Deposit - new_deposit_over_max                          OK
+ [Valid]   EF - Fulu - Operations - Deposit - new_deposit_under_max                         OK
+ [Valid]   EF - Fulu - Operations - Deposit - success_top_up_to_withdrawn_validator         OK
+ [Valid]   EF - Fulu - Operations - Deposit - top_up__less_effective_balance                OK
+ [Valid]   EF - Fulu - Operations - Deposit - top_up__max_effective_balance                 OK
+ [Valid]   EF - Fulu - Operations - Deposit - top_up__zero_balance                          OK
```
## EF - Fulu - Operations - Deposit Request  [Preset: minimal]
```diff
+ [Valid]   EF - Fulu - Operations - Deposit Request - process_deposit_request_eth1_credenti OK
+ [Valid]   EF - Fulu - Operations - Deposit Request - process_deposit_request_extra_gwei    OK
+ [Valid]   EF - Fulu - Operations - Deposit Request - process_deposit_request_greater_than_ OK
+ [Valid]   EF - Fulu - Operations - Deposit Request - process_deposit_request_invalid_sig   OK
+ [Valid]   EF - Fulu - Operations - Deposit Request - process_deposit_request_max_effective OK
+ [Valid]   EF - Fulu - Operations - Deposit Request - process_deposit_request_min_activatio OK
+ [Valid]   EF - Fulu - Operations - Deposit Request - process_deposit_request_pending_depos OK
+ [Valid]   EF - Fulu - Operations - Deposit Request - process_deposit_request_set_start_ind OK
+ [Valid]   EF - Fulu - Operations - Deposit Request - process_deposit_request_set_start_ind OK
+ [Valid]   EF - Fulu - Operations - Deposit Request - process_deposit_request_top_up_invali OK
+ [Valid]   EF - Fulu - Operations - Deposit Request - process_deposit_request_top_up_max_ef OK
+ [Valid]   EF - Fulu - Operations - Deposit Request - process_deposit_request_top_up_min_ac OK
+ [Valid]   EF - Fulu - Operations - Deposit Request - process_deposit_request_top_up_still_ OK
+ [Valid]   EF - Fulu - Operations - Deposit Request - process_deposit_request_undefined_cre OK
```
## EF - Fulu - Operations - Execution Payload  [Preset: minimal]
```diff
+ [Invalid] EF - Fulu - Operations - Execution Payload - invalid_bad_everything_first_payloa OK
+ [Invalid] EF - Fulu - Operations - Execution Payload - invalid_bad_everything_regular_payl OK
+ [Invalid] EF - Fulu - Operations - Execution Payload - invalid_bad_execution_first_payload OK
+ [Invalid] EF - Fulu - Operations - Execution Payload - invalid_bad_execution_regular_paylo OK
+ [Invalid] EF - Fulu - Operations - Execution Payload - invalid_bad_parent_hash_first_paylo OK
+ [Invalid] EF - Fulu - Operations - Execution Payload - invalid_bad_parent_hash_regular_pay OK
+ [Invalid] EF - Fulu - Operations - Execution Payload - invalid_bad_pre_randao_regular_payl OK
+ [Invalid] EF - Fulu - Operations - Execution Payload - invalid_bad_prev_randao_first_paylo OK
+ [Invalid] EF - Fulu - Operations - Execution Payload - invalid_correct_input__execution_in OK
+ [Invalid] EF - Fulu - Operations - Execution Payload - invalid_future_timestamp_first_payl OK
+ [Invalid] EF - Fulu - Operations - Execution Payload - invalid_future_timestamp_regular_pa OK
+ [Invalid] EF - Fulu - Operations - Execution Payload - invalid_past_timestamp_first_payloa OK
+ [Invalid] EF - Fulu - Operations - Execution Payload - invalid_past_timestamp_regular_payl OK
+ [Invalid] EF - Fulu - Operations - Execution Payload - invalid_randomized_non_validated_ex OK
+ [Invalid] EF - Fulu - Operations - Execution Payload - invalid_randomized_non_validated_ex OK
+ [Valid]   EF - Fulu - Operations - Execution Payload - incorrect_blob_tx_type              OK
+ [Valid]   EF - Fulu - Operations - Execution Payload - incorrect_block_hash                OK
+ [Valid]   EF - Fulu - Operations - Execution Payload - incorrect_commitment                OK
+ [Valid]   EF - Fulu - Operations - Execution Payload - incorrect_commitments_order         OK
+ [Valid]   EF - Fulu - Operations - Execution Payload - incorrect_transaction_length_1_byte OK
+ [Valid]   EF - Fulu - Operations - Execution Payload - incorrect_transaction_length_1_extr OK
+ [Valid]   EF - Fulu - Operations - Execution Payload - incorrect_transaction_length_32_ext OK
+ [Valid]   EF - Fulu - Operations - Execution Payload - incorrect_transaction_length_empty  OK
+ [Valid]   EF - Fulu - Operations - Execution Payload - incorrect_transaction_no_blobs_but_ OK
+ [Valid]   EF - Fulu - Operations - Execution Payload - no_commitments_for_transactions     OK
+ [Valid]   EF - Fulu - Operations - Execution Payload - no_transactions_with_commitments    OK
+ [Valid]   EF - Fulu - Operations - Execution Payload - non_empty_extra_data_first_payload  OK
+ [Valid]   EF - Fulu - Operations - Execution Payload - non_empty_extra_data_regular_payloa OK
+ [Valid]   EF - Fulu - Operations - Execution Payload - non_empty_transactions_first_payloa OK
+ [Valid]   EF - Fulu - Operations - Execution Payload - non_empty_transactions_regular_payl OK
+ [Valid]   EF - Fulu - Operations - Execution Payload - randomized_non_validated_execution_ OK
+ [Valid]   EF - Fulu - Operations - Execution Payload - randomized_non_validated_execution_ OK
+ [Valid]   EF - Fulu - Operations - Execution Payload - success_first_payload               OK
+ [Valid]   EF - Fulu - Operations - Execution Payload - success_first_payload_with_gap_slot OK
+ [Valid]   EF - Fulu - Operations - Execution Payload - success_regular_payload             OK
+ [Valid]   EF - Fulu - Operations - Execution Payload - success_regular_payload_with_gap_sl OK
+ [Valid]   EF - Fulu - Operations - Execution Payload - zero_length_transaction_first_paylo OK
+ [Valid]   EF - Fulu - Operations - Execution Payload - zero_length_transaction_regular_pay OK
+ [Valid]   EF - Fulu - Operations - Execution Payload - zeroed_commitment                   OK
```
## EF - Fulu - Operations - Proposer Slashing  [Preset: minimal]
```diff
+ [Invalid] EF - Fulu - Operations - Proposer Slashing - invalid_different_proposer_indices  OK
+ [Invalid] EF - Fulu - Operations - Proposer Slashing - invalid_headers_are_same_sigs_are_d OK
+ [Invalid] EF - Fulu - Operations - Proposer Slashing - invalid_headers_are_same_sigs_are_s OK
+ [Invalid] EF - Fulu - Operations - Proposer Slashing - invalid_incorrect_proposer_index    OK
+ [Invalid] EF - Fulu - Operations - Proposer Slashing - invalid_incorrect_sig_1             OK
+ [Invalid] EF - Fulu - Operations - Proposer Slashing - invalid_incorrect_sig_1_and_2       OK
+ [Invalid] EF - Fulu - Operations - Proposer Slashing - invalid_incorrect_sig_1_and_2_swap  OK
+ [Invalid] EF - Fulu - Operations - Proposer Slashing - invalid_incorrect_sig_2             OK
+ [Invalid] EF - Fulu - Operations - Proposer Slashing - invalid_proposer_is_not_activated   OK
+ [Invalid] EF - Fulu - Operations - Proposer Slashing - invalid_proposer_is_slashed         OK
+ [Invalid] EF - Fulu - Operations - Proposer Slashing - invalid_proposer_is_withdrawn       OK
+ [Invalid] EF - Fulu - Operations - Proposer Slashing - invalid_proposer_withdrawable_curre OK
+ [Invalid] EF - Fulu - Operations - Proposer Slashing - invalid_slots_of_different_epochs   OK
+ [Invalid] EF - Fulu - Operations - Proposer Slashing - invalid_slots_same_epoch_different_ OK
+ [Valid]   EF - Fulu - Operations - Proposer Slashing - basic                               OK
+ [Valid]   EF - Fulu - Operations - Proposer Slashing - block_header_from_future            OK
+ [Valid]   EF - Fulu - Operations - Proposer Slashing - block_header_from_past              OK
+ [Valid]   EF - Fulu - Operations - Proposer Slashing - header_slot_at_epoch_end            OK
+ [Valid]   EF - Fulu - Operations - Proposer Slashing - header_slot_at_epoch_start          OK
+ [Valid]   EF - Fulu - Operations - Proposer Slashing - headers_differ_multiple_roots       OK
+ [Valid]   EF - Fulu - Operations - Proposer Slashing - headers_differ_only_body_root       OK
+ [Valid]   EF - Fulu - Operations - Proposer Slashing - headers_differ_only_state_root      OK
+ [Valid]   EF - Fulu - Operations - Proposer Slashing - proposer_activated_current_epoch    OK
+ [Valid]   EF - Fulu - Operations - Proposer Slashing - proposer_index_last                 OK
+ [Valid]   EF - Fulu - Operations - Proposer Slashing - proposer_index_zero                 OK
+ [Valid]   EF - Fulu - Operations - Proposer Slashing - proposer_withdrawable_next_epoch    OK
+ [Valid]   EF - Fulu - Operations - Proposer Slashing - self_slashing_future_slot           OK
+ [Valid]   EF - Fulu - Operations - Proposer Slashing - slashed_and_proposer_index_the_same OK
```
## EF - Fulu - Operations - Sync Aggregate  [Preset: minimal]
```diff
+ [Invalid] EF - Fulu - Operations - Sync Aggregate - invalid_signature_bad_domain           OK
+ [Invalid] EF - Fulu - Operations - Sync Aggregate - invalid_signature_extra_participant    OK
+ [Invalid] EF - Fulu - Operations - Sync Aggregate - invalid_signature_infinite_signature_w OK
+ [Invalid] EF - Fulu - Operations - Sync Aggregate - invalid_signature_infinite_signature_w OK
+ [Invalid] EF - Fulu - Operations - Sync Aggregate - invalid_signature_missing_participant  OK
+ [Invalid] EF - Fulu - Operations - Sync Aggregate - invalid_signature_no_participants      OK
+ [Invalid] EF - Fulu - Operations - Sync Aggregate - invalid_signature_past_block           OK
+ [Invalid] EF - Fulu - Operations - Sync Aggregate - invalid_signature_previous_committee   OK
+ [Valid]   EF - Fulu - Operations - Sync Aggregate - proposer_in_committee_with_participati OK
+ [Valid]   EF - Fulu - Operations - Sync Aggregate - proposer_in_committee_without_particip OK
+ [Valid]   EF - Fulu - Operations - Sync Aggregate - random_all_but_one_participating_witho OK
+ [Valid]   EF - Fulu - Operations - Sync Aggregate - random_high_participation_without_dupl OK
+ [Valid]   EF - Fulu - Operations - Sync Aggregate - random_low_participation_without_dupli OK
+ [Valid]   EF - Fulu - Operations - Sync Aggregate - random_misc_balances_and_half_particip OK
+ [Valid]   EF - Fulu - Operations - Sync Aggregate - random_only_one_participant_without_du OK
+ [Valid]   EF - Fulu - Operations - Sync Aggregate - random_with_exits_without_duplicates   OK
+ [Valid]   EF - Fulu - Operations - Sync Aggregate - sync_committee_rewards_empty_participa OK
+ [Valid]   EF - Fulu - Operations - Sync Aggregate - sync_committee_rewards_nonduplicate_co OK
+ [Valid]   EF - Fulu - Operations - Sync Aggregate - sync_committee_rewards_not_full_partic OK
+ [Valid]   EF - Fulu - Operations - Sync Aggregate - sync_committee_with_nonparticipating_e OK
+ [Valid]   EF - Fulu - Operations - Sync Aggregate - sync_committee_with_nonparticipating_w OK
+ [Valid]   EF - Fulu - Operations - Sync Aggregate - sync_committee_with_participating_exit OK
+ [Valid]   EF - Fulu - Operations - Sync Aggregate - sync_committee_with_participating_with OK
+ [Valid]   EF - Fulu - Operations - Sync Aggregate - valid_signature_future_committee       OK
```
## EF - Fulu - Operations - Voluntary Exit  [Preset: minimal]
```diff
+ [Invalid] EF - Fulu - Operations - Voluntary Exit - invalid_incorrect_signature            OK
+ [Invalid] EF - Fulu - Operations - Voluntary Exit - invalid_validator_already_exited       OK
+ [Invalid] EF - Fulu - Operations - Voluntary Exit - invalid_validator_exit_in_future       OK
+ [Invalid] EF - Fulu - Operations - Voluntary Exit - invalid_validator_has_pending_withdraw OK
+ [Invalid] EF - Fulu - Operations - Voluntary Exit - invalid_validator_incorrect_validator_ OK
+ [Invalid] EF - Fulu - Operations - Voluntary Exit - invalid_validator_not_active           OK
+ [Invalid] EF - Fulu - Operations - Voluntary Exit - invalid_validator_not_active_long_enou OK
+ [Invalid] EF - Fulu - Operations - Voluntary Exit - invalid_voluntary_exit_with_current_fo OK
+ [Invalid] EF - Fulu - Operations - Voluntary Exit - invalid_voluntary_exit_with_current_fo OK
+ [Invalid] EF - Fulu - Operations - Voluntary Exit - invalid_voluntary_exit_with_genesis_fo OK
+ [Invalid] EF - Fulu - Operations - Voluntary Exit - invalid_voluntary_exit_with_genesis_fo OK
+ [Invalid] EF - Fulu - Operations - Voluntary Exit - voluntary_exit_with_previous_fork_vers OK
+ [Invalid] EF - Fulu - Operations - Voluntary Exit - voluntary_exit_with_previous_fork_vers OK
+ [Valid]   EF - Fulu - Operations - Voluntary Exit - basic                                  OK
+ [Valid]   EF - Fulu - Operations - Voluntary Exit - default_exit_epoch_subsequent_exit     OK
+ [Valid]   EF - Fulu - Operations - Voluntary Exit - min_balance_exit                       OK
+ [Valid]   EF - Fulu - Operations - Voluntary Exit - min_balance_exits_above_churn          OK
+ [Valid]   EF - Fulu - Operations - Voluntary Exit - min_balance_exits_up_to_churn          OK
+ [Valid]   EF - Fulu - Operations - Voluntary Exit - success_exit_queue__min_churn          OK
+ [Valid]   EF - Fulu - Operations - Voluntary Exit - success_exit_queue__scaled_churn       OK
+ [Valid]   EF - Fulu - Operations - Voluntary Exit - voluntary_exit_with_pending_deposit    OK
```
## EF - Fulu - Operations - Withdrawal Request  [Preset: minimal]
```diff
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - activation_epoch_less_than_shard_c OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - basic_partial_withdrawal_request   OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - basic_partial_withdrawal_request_h OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - basic_partial_withdrawal_request_l OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - basic_withdrawal_request           OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - basic_withdrawal_request_with_comp OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - basic_withdrawal_request_with_firs OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - basic_withdrawal_request_with_full OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - full_exit_request_has_partial_with OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - incorrect_inactive_validator       OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - incorrect_source_address           OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - incorrect_withdrawal_credential_pr OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - insufficient_balance               OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - insufficient_effective_balance     OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - no_compounding_credentials         OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - no_excess_balance                  OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - on_withdrawal_request_initiated_ex OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - partial_withdrawal_activation_epoc OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - partial_withdrawal_incorrect_sourc OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - partial_withdrawal_incorrect_withd OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - partial_withdrawal_on_exit_initiat OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - partial_withdrawal_queue_full      OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - partial_withdrawal_request_with_hi OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - partial_withdrawal_request_with_hi OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - partial_withdrawal_request_with_lo OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - partial_withdrawal_request_with_pe OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - partial_withdrawal_request_with_pe OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - pending_withdrawals_consume_all_ex OK
+ [Valid]   EF - Fulu - Operations - Withdrawal Request - unknown_pubkey                     OK
```
## EF - Fulu - Operations - Withdrawals  [Preset: minimal]
```diff
+ [Invalid] EF - Fulu - Operations - Withdrawals - invalid_a_lot_fully_withdrawable_too_few_ OK
+ [Invalid] EF - Fulu - Operations - Withdrawals - invalid_a_lot_mixed_withdrawable_in_queue OK
+ [Invalid] EF - Fulu - Operations - Withdrawals - invalid_a_lot_partially_withdrawable_too_ OK
+ [Invalid] EF - Fulu - Operations - Withdrawals - invalid_incorrect_address_full            OK
+ [Invalid] EF - Fulu - Operations - Withdrawals - invalid_incorrect_address_partial         OK
+ [Invalid] EF - Fulu - Operations - Withdrawals - invalid_incorrect_amount_full             OK
+ [Invalid] EF - Fulu - Operations - Withdrawals - invalid_incorrect_amount_partial          OK
+ [Invalid] EF - Fulu - Operations - Withdrawals - invalid_incorrect_withdrawal_index        OK
+ [Invalid] EF - Fulu - Operations - Withdrawals - invalid_many_incorrectly_full             OK
+ [Invalid] EF - Fulu - Operations - Withdrawals - invalid_many_incorrectly_partial          OK
+ [Invalid] EF - Fulu - Operations - Withdrawals - invalid_max_per_slot_full_withdrawals_and OK
+ [Invalid] EF - Fulu - Operations - Withdrawals - invalid_max_per_slot_partial_withdrawals_ OK
+ [Invalid] EF - Fulu - Operations - Withdrawals - invalid_non_withdrawable_non_empty_withdr OK
+ [Invalid] EF - Fulu - Operations - Withdrawals - invalid_one_expected_full_withdrawal_and_ OK
+ [Invalid] EF - Fulu - Operations - Withdrawals - invalid_one_expected_full_withdrawal_and_ OK
+ [Invalid] EF - Fulu - Operations - Withdrawals - invalid_one_expected_partial_withdrawal_a OK
+ [Invalid] EF - Fulu - Operations - Withdrawals - invalid_one_of_many_incorrectly_full      OK
+ [Invalid] EF - Fulu - Operations - Withdrawals - invalid_one_of_many_incorrectly_partial   OK
+ [Invalid] EF - Fulu - Operations - Withdrawals - invalid_two_expected_partial_withdrawal_a OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - all_withdrawal                            OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - full_pending_withdrawals_but_first_skippe OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - full_pending_withdrawals_but_first_skippe OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - full_pending_withdrawals_but_first_skippe OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - no_withdrawals_but_some_next_epoch        OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - partially_withdrawable_validator_compound OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - partially_withdrawable_validator_compound OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - partially_withdrawable_validator_compound OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - partially_withdrawable_validator_compound OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - partially_withdrawable_validator_compound OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - partially_withdrawable_validator_compound OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - partially_withdrawable_validator_legacy_e OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - partially_withdrawable_validator_legacy_m OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - partially_withdrawable_validator_legacy_m OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - pending_withdrawals_at_max                OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - pending_withdrawals_at_max_mixed_with_swe OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - pending_withdrawals_exiting_validator     OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - pending_withdrawals_low_effective_balance OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - pending_withdrawals_mixed_with_sweep_and_ OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - pending_withdrawals_next_epoch            OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - pending_withdrawals_no_excess_balance     OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - pending_withdrawals_one_skipped_one_effec OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - pending_withdrawals_two_partial_withdrawa OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - pending_withdrawals_two_partial_withdrawa OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - pending_withdrawals_with_effective_sweep_ OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - pending_withdrawals_with_ineffective_swee OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - pending_withdrawals_with_ineffective_swee OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - pending_withdrawals_with_sweep_different_ OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - random_0                                  OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - random_full_withdrawals_0                 OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - random_full_withdrawals_1                 OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - random_full_withdrawals_2                 OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - random_full_withdrawals_3                 OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - random_partial_withdrawals_1              OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - random_partial_withdrawals_2              OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - random_partial_withdrawals_3              OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - random_partial_withdrawals_4              OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - random_partial_withdrawals_5              OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - success_all_fully_withdrawable            OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - success_all_partially_withdrawable        OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - success_excess_balance_but_no_max_effecti OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - success_excess_balance_but_no_max_effecti OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - success_max_partial_withdrawable          OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - success_max_plus_one_withdrawable         OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - success_mixed_fully_and_partial_withdrawa OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - success_mixed_fully_and_partial_withdrawa OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - success_no_excess_balance                 OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - success_no_excess_balance_compounding     OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - success_no_max_effective_balance          OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - success_no_max_effective_balance_compound OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - success_one_full_withdrawal               OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - success_one_partial_withdrawable_active_a OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - success_one_partial_withdrawable_exited   OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - success_one_partial_withdrawable_exited_a OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - success_one_partial_withdrawable_in_exit_ OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - success_one_partial_withdrawable_not_yet_ OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - success_one_partial_withdrawal            OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - success_two_partial_withdrawable          OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - success_zero_expected_withdrawals         OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - withdrawable_epoch_but_0_balance          OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - withdrawable_epoch_but_0_effective_balanc OK
+ [Valid]   EF - Fulu - Operations - Withdrawals - withdrawable_epoch_but_0_effective_balanc OK
```
## EF - Fulu - SSZ consensus objects  [Preset: minimal]
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
+   Testing    ConsolidationRequest                                                          OK
+   Testing    ContributionAndProof                                                          OK
+   Testing    DataColumnSidecar                                                             OK
+   Testing    DataColumnsByRootIdentifier                                                   OK
+   Testing    Deposit                                                                       OK
+   Testing    DepositData                                                                   OK
+   Testing    DepositMessage                                                                OK
+   Testing    DepositRequest                                                                OK
+   Testing    Eth1Block                                                                     OK
+   Testing    Eth1Data                                                                      OK
+   Testing    ExecutionPayload                                                              OK
+   Testing    ExecutionPayloadHeader                                                        OK
+   Testing    ExecutionRequests                                                             OK
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
+   Testing    MatrixEntry                                                                   OK
+   Testing    PartialDataColumnHeader                                                       OK
+   Testing    PartialDataColumnPartsMetadata                                                OK
+   Testing    PartialDataColumnSidecar                                                      OK
+   Testing    PendingAttestation                                                            OK
+   Testing    PendingConsolidation                                                          OK
+   Testing    PendingDeposit                                                                OK
+   Testing    PendingPartialWithdrawal                                                      OK
+   Testing    PowBlock                                                                      OK
+   Testing    ProposerSlashing                                                              OK
+   Testing    SignedAggregateAndProof                                                       OK
+   Testing    SignedBLSToExecutionChange                                                    OK
+   Testing    SignedBeaconBlock                                                             OK
+   Testing    SignedBeaconBlockHeader                                                       OK
+   Testing    SignedContributionAndProof                                                    OK
+   Testing    SignedVoluntaryExit                                                           OK
+   Testing    SigningData                                                                   OK
+   Testing    SingleAttestation                                                             OK
+   Testing    SyncAggregate                                                                 OK
+   Testing    SyncAggregatorSelectionData                                                   OK
+   Testing    SyncCommittee                                                                 OK
+   Testing    SyncCommitteeContribution                                                     OK
+   Testing    SyncCommitteeMessage                                                          OK
+   Testing    Validator                                                                     OK
+   Testing    VoluntaryExit                                                                 OK
+   Testing    Withdrawal                                                                    OK
+   Testing    WithdrawalRequest                                                             OK
```
## EF - Fulu - Sanity - Slots  [Preset: minimal]
```diff
+ EF - Fulu - Slots - balance_change_affects_proposer [Preset: minimal]                      OK
+ EF - Fulu - Slots - double_empty_epoch [Preset: minimal]                                   OK
+ EF - Fulu - Slots - effective_decrease_balance_updates_lookahead [Preset: minimal]         OK
+ EF - Fulu - Slots - empty_epoch [Preset: minimal]                                          OK
+ EF - Fulu - Slots - historical_accumulator [Preset: minimal]                               OK
+ EF - Fulu - Slots - multiple_pending_deposits_same_pubkey [Preset: minimal]                OK
+ EF - Fulu - Slots - multiple_pending_deposits_same_pubkey_above_upward_threshold [Preset:  OK
+ EF - Fulu - Slots - multiple_pending_deposits_same_pubkey_below_upward_threshold [Preset:  OK
+ EF - Fulu - Slots - multiple_pending_deposits_same_pubkey_compounding [Preset: minimal]    OK
+ EF - Fulu - Slots - multiple_pending_deposits_same_pubkey_different_signature [Preset: min OK
+ EF - Fulu - Slots - over_epoch_boundary [Preset: minimal]                                  OK
+ EF - Fulu - Slots - pending_consolidation [Preset: minimal]                                OK
+ EF - Fulu - Slots - pending_deposit_extra_gwei [Preset: minimal]                           OK
+ EF - Fulu - Slots - slots_1 [Preset: minimal]                                              OK
+ EF - Fulu - Slots - slots_2 [Preset: minimal]                                              OK
```
## EF - Fulu - Transition  [Preset: minimal]
```diff
+ EF - Fulu - Transition - higher_churn_limit_to_lower [Preset: minimal]                     OK
+ EF - Fulu - Transition - non_empty_historical_roots [Preset: minimal]                      OK
+ EF - Fulu - Transition - normal_transition [Preset: minimal]                               OK
+ EF - Fulu - Transition - simple_transition [Preset: minimal]                               OK
+ EF - Fulu - Transition - transition_attestation_from_previous_fork_with_new_range [Preset: OK
+ EF - Fulu - Transition - transition_missing_first_post_block [Preset: minimal]             OK
+ EF - Fulu - Transition - transition_missing_last_pre_fork_block [Preset: minimal]          OK
+ EF - Fulu - Transition - transition_only_blocks_post_fork [Preset: minimal]                OK
+ EF - Fulu - Transition - transition_randomized_state [Preset: minimal]                     OK
+ EF - Fulu - Transition - transition_with_activation_at_fork_epoch [Preset: minimal]        OK
+ EF - Fulu - Transition - transition_with_attester_slashing_right_after_fork [Preset: minim OK
+ EF - Fulu - Transition - transition_with_attester_slashing_right_before_fork [Preset: mini OK
+ EF - Fulu - Transition - transition_with_btec_right_after_fork [Preset: minimal]           OK
+ EF - Fulu - Transition - transition_with_btec_right_before_fork [Preset: minimal]          OK
+ EF - Fulu - Transition - transition_with_consolidation_request_right_after_fork [Preset: m OK
+ EF - Fulu - Transition - transition_with_deposit_request_right_after_fork [Preset: minimal OK
+ EF - Fulu - Transition - transition_with_deposit_right_after_fork [Preset: minimal]        OK
+ EF - Fulu - Transition - transition_with_deposit_right_before_fork [Preset: minimal]       OK
+ EF - Fulu - Transition - transition_with_finality [Preset: minimal]                        OK
+ EF - Fulu - Transition - transition_with_full_withdrawal_request_right_after_fork [Preset: OK
+ EF - Fulu - Transition - transition_with_leaking_at_fork [Preset: minimal]                 OK
+ EF - Fulu - Transition - transition_with_leaking_pre_fork [Preset: minimal]                OK
+ EF - Fulu - Transition - transition_with_no_attestations_until_after_fork [Preset: minimal OK
+ EF - Fulu - Transition - transition_with_non_empty_activation_queue [Preset: minimal]      OK
+ EF - Fulu - Transition - transition_with_one_fourth_exiting_validators_exit_at_fork [Prese OK
+ EF - Fulu - Transition - transition_with_one_fourth_exiting_validators_exit_post_fork [Pre OK
+ EF - Fulu - Transition - transition_with_one_fourth_slashed_active_validators_pre_fork [Pr OK
+ EF - Fulu - Transition - transition_with_proposer_slashing_right_after_fork [Preset: minim OK
+ EF - Fulu - Transition - transition_with_proposer_slashing_right_before_fork [Preset: mini OK
+ EF - Fulu - Transition - transition_with_random_half_participation [Preset: minimal]       OK
+ EF - Fulu - Transition - transition_with_random_three_quarters_participation [Preset: mini OK
+ EF - Fulu - Transition - transition_with_voluntary_exit_right_after_fork [Preset: minimal] OK
+ EF - Fulu - Transition - transition_with_voluntary_exit_right_before_fork [Preset: minimal OK
```
## EF - Gloas - Fork  [Preset: minimal]
```diff
+ EF - Gloas - Fork - after_fork_deactivate_validators_from_fulu_to_gloas [Preset: minimal]  OK
+ EF - Gloas - Fork - after_fork_deactivate_validators_wo_block_from_fulu_to_gloas [Preset:  OK
+ EF - Gloas - Fork - after_fork_new_validator_active_from_fulu_to_gloas [Preset: minimal]   OK
+ EF - Gloas - Fork - fork_base_state [Preset: minimal]                                      OK
+ EF - Gloas - Fork - fork_builder_deposit_followed_by_non_builder_credentials [Preset: mini OK
+ EF - Gloas - Fork - fork_builder_deposit_uses_deposit_slot_epoch [Preset: minimal]         OK
+ EF - Gloas - Fork - fork_builder_deposit_with_existing_validator_pubkey_builder_creds [Pre OK
+ EF - Gloas - Fork - fork_invalid_builder_deposit_followed_by_valid_builder_deposit [Preset OK
+ EF - Gloas - Fork - fork_invalid_validator_deposit_followed_by_builder_credentials [Preset OK
+ EF - Gloas - Fork - fork_many_next_epoch [Preset: minimal]                                 OK
+ EF - Gloas - Fork - fork_mixed_pending_deposits [Preset: minimal]                          OK
+ EF - Gloas - Fork - fork_multiple_builder_deposits [Preset: minimal]                       OK
+ EF - Gloas - Fork - fork_multiple_deposits_same_builder [Preset: minimal]                  OK
+ EF - Gloas - Fork - fork_next_epoch [Preset: minimal]                                      OK
+ EF - Gloas - Fork - fork_next_epoch_with_block [Preset: minimal]                           OK
+ EF - Gloas - Fork - fork_no_pending_deposits [Preset: minimal]                             OK
+ EF - Gloas - Fork - fork_pending_deposit_for_existing_validator [Preset: minimal]          OK
+ EF - Gloas - Fork - fork_pending_deposit_validator_credentials [Preset: minimal]           OK
+ EF - Gloas - Fork - fork_random_large_validator_set [Preset: minimal]                      OK
+ EF - Gloas - Fork - fork_random_low_balances [Preset: minimal]                             OK
+ EF - Gloas - Fork - fork_random_misc_balances [Preset: minimal]                            OK
+ EF - Gloas - Fork - fork_single_builder_deposit [Preset: minimal]                          OK
+ EF - Gloas - Fork - fork_valid_builder_deposit_followed_by_invalid_builder_deposit [Preset OK
+ EF - Gloas - Fork - fork_validator_deposit_followed_by_builder_credentials [Preset: minima OK
+ EF - Gloas - Fork - gloas_fork_random_0 [Preset: minimal]                                  OK
+ EF - Gloas - Fork - gloas_fork_random_1 [Preset: minimal]                                  OK
+ EF - Gloas - Fork - gloas_fork_random_2 [Preset: minimal]                                  OK
+ EF - Gloas - Fork - gloas_fork_random_3 [Preset: minimal]                                  OK
+ EF - Gloas - Fork - gloas_fork_random_large_validator_set [Preset: minimal]                OK
+ EF - Gloas - Fork - gloas_fork_random_low_balances [Preset: minimal]                       OK
+ EF - Gloas - Fork - gloas_fork_random_misc_balances [Preset: minimal]                      OK
```
## EF - Gloas - Operations - Attestation  [Preset: minimal]
```diff
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_after_max_inclusion_slot         OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_attestation_data_index_not_zero  OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_attestation_data_index_too_high  OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_attestation_signature            OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_bad_source_root                  OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_before_inclusion_delay           OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_committee_index                  OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_correct_attestation_included_aft OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_current_source_root              OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_empty_participants_seemingly_val OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_empty_participants_zeroes_sig    OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_future_target_epoch              OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_incorrect_head_and_target_includ OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_incorrect_head_included_after_ma OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_incorrect_target_included_after_ OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_index                            OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_mismatched_target_and_slot       OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_new_source_epoch                 OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_nonset_bits_for_one_committee    OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_nonset_committee_bits            OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_nonset_multiple_committee_bits   OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_old_source_epoch                 OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_old_target_epoch                 OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_previous_source_root             OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_same_slot_attestation_index_one  OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_source_root_is_target_root       OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_too_few_aggregation_bits         OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_too_many_aggregation_bits        OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_too_many_committee_bits          OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_wrong_index_for_committee_signat OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_wrong_index_for_slot_0           OK
+ [Invalid] EF - Gloas - Operations - Attestation - invalid_wrong_index_for_slot_1           OK
+ [Valid]   EF - Gloas - Operations - Attestation - at_max_inclusion_slot                    OK
+ [Valid]   EF - Gloas - Operations - Attestation - builder_payment_weight_no_double_countin OK
+ [Valid]   EF - Gloas - Operations - Attestation - builder_payment_weight_tracking          OK
+ [Valid]   EF - Gloas - Operations - Attestation - correct_attestation_included_at_max_incl OK
+ [Valid]   EF - Gloas - Operations - Attestation - correct_attestation_included_at_min_incl OK
+ [Valid]   EF - Gloas - Operations - Attestation - correct_attestation_included_at_one_epoc OK
+ [Valid]   EF - Gloas - Operations - Attestation - correct_attestation_included_at_sqrt_epo OK
+ [Valid]   EF - Gloas - Operations - Attestation - incorrect_head_and_target_included_at_ep OK
+ [Valid]   EF - Gloas - Operations - Attestation - incorrect_head_and_target_included_at_sq OK
+ [Valid]   EF - Gloas - Operations - Attestation - incorrect_head_and_target_min_inclusion_ OK
+ [Valid]   EF - Gloas - Operations - Attestation - incorrect_head_included_at_max_inclusion OK
+ [Valid]   EF - Gloas - Operations - Attestation - incorrect_head_included_at_min_inclusion OK
+ [Valid]   EF - Gloas - Operations - Attestation - incorrect_head_included_at_sqrt_epoch_de OK
+ [Valid]   EF - Gloas - Operations - Attestation - incorrect_target_included_at_epoch_delay OK
+ [Valid]   EF - Gloas - Operations - Attestation - incorrect_target_included_at_min_inclusi OK
+ [Valid]   EF - Gloas - Operations - Attestation - incorrect_target_included_at_sqrt_epoch_ OK
+ [Valid]   EF - Gloas - Operations - Attestation - matching_payload_false_historical_slot   OK
+ [Valid]   EF - Gloas - Operations - Attestation - matching_payload_gets_head_flag          OK
+ [Valid]   EF - Gloas - Operations - Attestation - matching_payload_true_historical_slot    OK
+ [Valid]   EF - Gloas - Operations - Attestation - matching_payload_true_same_slot          OK
+ [Valid]   EF - Gloas - Operations - Attestation - mismatched_payload_no_head_flag          OK
+ [Valid]   EF - Gloas - Operations - Attestation - multi_proposer_index_iterations          OK
+ [Valid]   EF - Gloas - Operations - Attestation - multiple_committees                      OK
+ [Valid]   EF - Gloas - Operations - Attestation - one_basic_attestation                    OK
+ [Valid]   EF - Gloas - Operations - Attestation - one_committee_with_gap                   OK
+ [Valid]   EF - Gloas - Operations - Attestation - previous_epoch                           OK
+ [Valid]   EF - Gloas - Operations - Attestation - valid_attestation_data_index_one_previou OK
+ [Valid]   EF - Gloas - Operations - Attestation - valid_attestation_data_index_one_previou OK
+ [Valid]   EF - Gloas - Operations - Attestation - valid_attestation_data_index_zero_previo OK
+ [Valid]   EF - Gloas - Operations - Attestation - valid_same_slot_attestation_index_zero   OK
```
## EF - Gloas - Operations - Attester Slashing  [Preset: minimal]
```diff
+ [Invalid] EF - Gloas - Operations - Attester Slashing - invalid_all_empty_indices          OK
+ [Invalid] EF - Gloas - Operations - Attester Slashing - invalid_att1_bad_extra_index       OK
+ [Invalid] EF - Gloas - Operations - Attester Slashing - invalid_att1_bad_replaced_index    OK
+ [Invalid] EF - Gloas - Operations - Attester Slashing - invalid_att1_duplicate_index_doubl OK
+ [Invalid] EF - Gloas - Operations - Attester Slashing - invalid_att1_duplicate_index_norma OK
+ [Invalid] EF - Gloas - Operations - Attester Slashing - invalid_att1_empty_indices         OK
+ [Invalid] EF - Gloas - Operations - Attester Slashing - invalid_att1_high_index            OK
+ [Invalid] EF - Gloas - Operations - Attester Slashing - invalid_att2_bad_extra_index       OK
+ [Invalid] EF - Gloas - Operations - Attester Slashing - invalid_att2_bad_replaced_index    OK
+ [Invalid] EF - Gloas - Operations - Attester Slashing - invalid_att2_duplicate_index_doubl OK
+ [Invalid] EF - Gloas - Operations - Attester Slashing - invalid_att2_duplicate_index_norma OK
+ [Invalid] EF - Gloas - Operations - Attester Slashing - invalid_att2_empty_indices         OK
+ [Invalid] EF - Gloas - Operations - Attester Slashing - invalid_att2_high_index            OK
+ [Invalid] EF - Gloas - Operations - Attester Slashing - invalid_incorrect_sig_1            OK
+ [Invalid] EF - Gloas - Operations - Attester Slashing - invalid_incorrect_sig_1_and_2      OK
+ [Invalid] EF - Gloas - Operations - Attester Slashing - invalid_incorrect_sig_2            OK
+ [Invalid] EF - Gloas - Operations - Attester Slashing - invalid_no_double_or_surround      OK
+ [Invalid] EF - Gloas - Operations - Attester Slashing - invalid_participants_already_slash OK
+ [Invalid] EF - Gloas - Operations - Attester Slashing - invalid_same_data                  OK
+ [Invalid] EF - Gloas - Operations - Attester Slashing - invalid_unsorted_att_1             OK
+ [Invalid] EF - Gloas - Operations - Attester Slashing - invalid_unsorted_att_2             OK
+ [Valid]   EF - Gloas - Operations - Attester Slashing - already_exited_long_ago            OK
+ [Valid]   EF - Gloas - Operations - Attester Slashing - already_exited_recent              OK
+ [Valid]   EF - Gloas - Operations - Attester Slashing - attestation_from_future            OK
+ [Valid]   EF - Gloas - Operations - Attester Slashing - basic_double                       OK
+ [Valid]   EF - Gloas - Operations - Attester Slashing - basic_surround                     OK
+ [Valid]   EF - Gloas - Operations - Attester Slashing - low_balances                       OK
+ [Valid]   EF - Gloas - Operations - Attester Slashing - misc_balances                      OK
+ [Valid]   EF - Gloas - Operations - Attester Slashing - proposer_index_slashed             OK
+ [Valid]   EF - Gloas - Operations - Attester Slashing - with_effective_balance_disparity   OK
```
## EF - Gloas - Operations - BLS to execution change  [Preset: minimal]
```diff
+ [Invalid] EF - Gloas - Operations - BLS to execution change - invalid_already_0x01         OK
+ [Invalid] EF - Gloas - Operations - BLS to execution change - invalid_bad_signature        OK
+ [Invalid] EF - Gloas - Operations - BLS to execution change - invalid_current_fork_version OK
+ [Invalid] EF - Gloas - Operations - BLS to execution change - invalid_genesis_validators_r OK
+ [Invalid] EF - Gloas - Operations - BLS to execution change - invalid_incorrect_from_bls_p OK
+ [Invalid] EF - Gloas - Operations - BLS to execution change - invalid_previous_fork_versio OK
+ [Invalid] EF - Gloas - Operations - BLS to execution change - invalid_val_index_out_of_ran OK
+ [Valid]   EF - Gloas - Operations - BLS to execution change - genesis_fork_version         OK
+ [Valid]   EF - Gloas - Operations - BLS to execution change - success                      OK
+ [Valid]   EF - Gloas - Operations - BLS to execution change - success_exited               OK
+ [Valid]   EF - Gloas - Operations - BLS to execution change - success_in_activation_queue  OK
+ [Valid]   EF - Gloas - Operations - BLS to execution change - success_in_exit_queue        OK
+ [Valid]   EF - Gloas - Operations - BLS to execution change - success_not_activated        OK
+ [Valid]   EF - Gloas - Operations - BLS to execution change - success_withdrawable         OK
```
## EF - Gloas - Operations - Block Header  [Preset: minimal]
```diff
+ [Invalid] EF - Gloas - Operations - Block Header - invalid_multiple_blocks_single_slot     OK
+ [Invalid] EF - Gloas - Operations - Block Header - invalid_parent_root                     OK
+ [Invalid] EF - Gloas - Operations - Block Header - invalid_proposer_index                  OK
+ [Invalid] EF - Gloas - Operations - Block Header - invalid_proposer_slashed                OK
+ [Invalid] EF - Gloas - Operations - Block Header - invalid_slot_block_header               OK
+ [Valid]   EF - Gloas - Operations - Block Header - basic_block_header                      OK
```
## EF - Gloas - Operations - Consolidation Request  [Preset: minimal]
```diff
+ [Valid]   EF - Gloas - Operations - Consolidation Request - basic_consolidation_in_current OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - basic_consolidation_in_new_con OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - basic_consolidation_source_has OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - basic_consolidation_target_has OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - basic_consolidation_with_compo OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - basic_consolidation_with_exces OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - basic_consolidation_with_insuf OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - basic_consolidation_with_preex OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - basic_switch_to_compounding    OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - consolidation_balance_larger_t OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - consolidation_balance_through_ OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - consolidation_churn_limit_bala OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - incorrect_exceed_pending_conso OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - incorrect_exited_source        OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - incorrect_exited_target        OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - incorrect_inactive_source      OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - incorrect_inactive_target      OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - incorrect_no_source_execution_ OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - incorrect_not_enough_consolida OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - incorrect_same_source_target   OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - incorrect_source_address       OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - incorrect_source_has_pending_w OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - incorrect_source_not_active_lo OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - incorrect_source_pubkey_is_tar OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - incorrect_source_with_bls_cred OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - incorrect_target_with_bls_cred OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - incorrect_target_with_eth1_cre OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - incorrect_unknown_source_pubke OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - incorrect_unknown_target_pubke OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - switch_to_compounding_exited_s OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - switch_to_compounding_inactive OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - switch_to_compounding_not_auth OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - switch_to_compounding_source_b OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - switch_to_compounding_source_c OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - switch_to_compounding_unknown_ OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - switch_to_compounding_with_exc OK
+ [Valid]   EF - Gloas - Operations - Consolidation Request - switch_to_compounding_with_pen OK
```
## EF - Gloas - Operations - Deposit  [Preset: minimal]
```diff
+ [Invalid] EF - Gloas - Operations - Deposit - invalid_bad_merkle_proof                     OK
+ [Invalid] EF - Gloas - Operations - Deposit - invalid_wrong_deposit_for_deposit_count      OK
+ [Valid]   EF - Gloas - Operations - Deposit - correct_sig_but_forked_state                 OK
+ [Valid]   EF - Gloas - Operations - Deposit - effective_deposit_with_genesis_fork_version  OK
+ [Valid]   EF - Gloas - Operations - Deposit - incorrect_sig_new_deposit                    OK
+ [Valid]   EF - Gloas - Operations - Deposit - incorrect_sig_top_up                         OK
+ [Valid]   EF - Gloas - Operations - Deposit - incorrect_withdrawal_credentials_top_up      OK
+ [Valid]   EF - Gloas - Operations - Deposit - ineffective_deposit_with_bad_fork_version    OK
+ [Valid]   EF - Gloas - Operations - Deposit - ineffective_deposit_with_current_fork_versio OK
+ [Valid]   EF - Gloas - Operations - Deposit - ineffective_deposit_with_previous_fork_versi OK
+ [Valid]   EF - Gloas - Operations - Deposit - key_validate_invalid_decompression           OK
+ [Valid]   EF - Gloas - Operations - Deposit - key_validate_invalid_subgroup                OK
+ [Valid]   EF - Gloas - Operations - Deposit - new_deposit_eth1_withdrawal_credentials      OK
+ [Valid]   EF - Gloas - Operations - Deposit - new_deposit_max                              OK
+ [Valid]   EF - Gloas - Operations - Deposit - new_deposit_non_versioned_withdrawal_credent OK
+ [Valid]   EF - Gloas - Operations - Deposit - new_deposit_over_max                         OK
+ [Valid]   EF - Gloas - Operations - Deposit - new_deposit_under_max                        OK
+ [Valid]   EF - Gloas - Operations - Deposit - top_up__less_effective_balance               OK
+ [Valid]   EF - Gloas - Operations - Deposit - top_up__max_effective_balance                OK
+ [Valid]   EF - Gloas - Operations - Deposit - top_up__zero_balance                         OK
```
## EF - Gloas - Operations - Deposit Request  [Preset: minimal]
```diff
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__builder_top OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__builder_top OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__builder_top OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__builder_top OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__builder_top OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__new_builder OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__new_builder OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__new_builder OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__new_builder OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__new_builder OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__new_builder OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__new_builder OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__no_reuse_fu OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__no_reuse_no OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__nonstandard OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__reuses_exit OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__reuses_firs OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__reuses_slot OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__routing__bu OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__routing__ne OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__routing__ne OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__routing__ne OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__routing__pe OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__routing__pe OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__routing__pe OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__routing__pe OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__routing__va OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request__routing__va OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request_eth1_credent OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request_extra_gwei   OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request_greater_than OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request_invalid_sig  OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request_max_effectiv OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request_min_activati OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request_pending_depo OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request_set_start_in OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request_top_up_inval OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request_top_up_max_e OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request_top_up_min_a OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request_top_up_still OK
+ [Valid]   EF - Gloas - Operations - Deposit Request - process_deposit_request_undefined_cr OK
```
## EF - Gloas - Operations - Execution Payload  [Preset: minimal]
```diff
+ [Invalid] EF - Gloas - Operations - Execution Payload - invalid_bad_everything_first_paylo OK
+ [Invalid] EF - Gloas - Operations - Execution Payload - invalid_bad_everything_regular_pay OK
+ [Invalid] EF - Gloas - Operations - Execution Payload - invalid_bad_parent_hash_first_payl OK
+ [Invalid] EF - Gloas - Operations - Execution Payload - invalid_bad_parent_hash_regular_pa OK
+ [Invalid] EF - Gloas - Operations - Execution Payload - invalid_bad_pre_randao_regular_pay OK
+ [Invalid] EF - Gloas - Operations - Execution Payload - invalid_bad_prev_randao_first_payl OK
+ [Invalid] EF - Gloas - Operations - Execution Payload - invalid_correct_input__execution_i OK
+ [Invalid] EF - Gloas - Operations - Execution Payload - invalid_future_timestamp_first_pay OK
+ [Invalid] EF - Gloas - Operations - Execution Payload - invalid_future_timestamp_regular_p OK
+ [Invalid] EF - Gloas - Operations - Execution Payload - invalid_past_timestamp_first_paylo OK
+ [Invalid] EF - Gloas - Operations - Execution Payload - invalid_past_timestamp_regular_pay OK
+ [Invalid] EF - Gloas - Operations - Execution Payload - process_execution_payload_bid_prev OK
+ [Invalid] EF - Gloas - Operations - Execution Payload - process_execution_payload_executio OK
+ [Invalid] EF - Gloas - Operations - Execution Payload - process_execution_payload_invalid_ OK
+ [Invalid] EF - Gloas - Operations - Execution Payload - process_execution_payload_missing_ OK
+ [Invalid] EF - Gloas - Operations - Execution Payload - process_execution_payload_wrong_be OK
+ [Invalid] EF - Gloas - Operations - Execution Payload - process_execution_payload_wrong_bl OK
+ [Invalid] EF - Gloas - Operations - Execution Payload - process_execution_payload_wrong_bu OK
+ [Invalid] EF - Gloas - Operations - Execution Payload - process_execution_payload_wrong_ga OK
+ [Invalid] EF - Gloas - Operations - Execution Payload - process_execution_payload_wrong_pa OK
+ [Invalid] EF - Gloas - Operations - Execution Payload - process_execution_payload_wrong_pr OK
+ [Invalid] EF - Gloas - Operations - Execution Payload - process_execution_payload_wrong_sl OK
+ [Invalid] EF - Gloas - Operations - Execution Payload - process_execution_payload_wrong_ti OK
+ [Valid]   EF - Gloas - Operations - Execution Payload - incorrect_blob_tx_type             OK
+ [Valid]   EF - Gloas - Operations - Execution Payload - incorrect_block_hash               OK
+ [Valid]   EF - Gloas - Operations - Execution Payload - incorrect_commitment               OK
+ [Valid]   EF - Gloas - Operations - Execution Payload - incorrect_commitments_order        OK
+ [Valid]   EF - Gloas - Operations - Execution Payload - incorrect_transaction_length_1_byt OK
+ [Valid]   EF - Gloas - Operations - Execution Payload - incorrect_transaction_length_1_ext OK
+ [Valid]   EF - Gloas - Operations - Execution Payload - incorrect_transaction_length_32_ex OK
+ [Valid]   EF - Gloas - Operations - Execution Payload - incorrect_transaction_length_empty OK
+ [Valid]   EF - Gloas - Operations - Execution Payload - incorrect_transaction_no_blobs_but OK
+ [Valid]   EF - Gloas - Operations - Execution Payload - no_commitments_for_transactions    OK
+ [Valid]   EF - Gloas - Operations - Execution Payload - no_transactions_with_commitments   OK
+ [Valid]   EF - Gloas - Operations - Execution Payload - process_execution_payload_large_pa OK
+ [Valid]   EF - Gloas - Operations - Execution Payload - process_execution_payload_self_bui OK
+ [Valid]   EF - Gloas - Operations - Execution Payload - process_execution_payload_valid    OK
+ [Valid]   EF - Gloas - Operations - Execution Payload - process_execution_payload_with_blo OK
+ [Valid]   EF - Gloas - Operations - Execution Payload - process_execution_payload_with_exe OK
+ [Valid]   EF - Gloas - Operations - Execution Payload - zeroed_commitment                  OK
```
## EF - Gloas - Operations - Execution Payload Bid  [Preset: minimal]
```diff
+ [Invalid] EF - Gloas - Operations - Execution Payload Bid - process_execution_payload_bid_ OK
+ [Invalid] EF - Gloas - Operations - Execution Payload Bid - process_execution_payload_bid_ OK
+ [Invalid] EF - Gloas - Operations - Execution Payload Bid - process_execution_payload_bid_ OK
+ [Invalid] EF - Gloas - Operations - Execution Payload Bid - process_execution_payload_bid_ OK
+ [Invalid] EF - Gloas - Operations - Execution Payload Bid - process_execution_payload_bid_ OK
+ [Invalid] EF - Gloas - Operations - Execution Payload Bid - process_execution_payload_bid_ OK
+ [Invalid] EF - Gloas - Operations - Execution Payload Bid - process_execution_payload_bid_ OK
+ [Invalid] EF - Gloas - Operations - Execution Payload Bid - process_execution_payload_bid_ OK
+ [Invalid] EF - Gloas - Operations - Execution Payload Bid - process_execution_payload_bid_ OK
+ [Invalid] EF - Gloas - Operations - Execution Payload Bid - process_execution_payload_bid_ OK
+ [Invalid] EF - Gloas - Operations - Execution Payload Bid - process_execution_payload_bid_ OK
+ [Invalid] EF - Gloas - Operations - Execution Payload Bid - process_execution_payload_bid_ OK
+ [Valid]   EF - Gloas - Operations - Execution Payload Bid - process_execution_payload_bid_ OK
+ [Valid]   EF - Gloas - Operations - Execution Payload Bid - process_execution_payload_bid_ OK
+ [Valid]   EF - Gloas - Operations - Execution Payload Bid - process_execution_payload_bid_ OK
+ [Valid]   EF - Gloas - Operations - Execution Payload Bid - process_execution_payload_bid_ OK
+ [Valid]   EF - Gloas - Operations - Execution Payload Bid - process_execution_payload_bid_ OK
```
## EF - Gloas - Operations - Payload Attestation  [Preset: minimal]
```diff
+ [Invalid] EF - Gloas - Operations - Payload Attestation - process_payload_attestation_cros OK
+ [Invalid] EF - Gloas - Operations - Payload Attestation - process_payload_attestation_futu OK
+ [Invalid] EF - Gloas - Operations - Payload Attestation - process_payload_attestation_inva OK
+ [Invalid] EF - Gloas - Operations - Payload Attestation - process_payload_attestation_inva OK
+ [Invalid] EF - Gloas - Operations - Payload Attestation - process_payload_attestation_no_a OK
+ [Invalid] EF - Gloas - Operations - Payload Attestation - process_payload_attestation_too_ OK
+ [Valid]   EF - Gloas - Operations - Payload Attestation - process_payload_attestation_part OK
+ [Valid]   EF - Gloas - Operations - Payload Attestation - process_payload_attestation_payl OK
+ [Valid]   EF - Gloas - Operations - Payload Attestation - process_payload_attestation_payl OK
+ [Valid]   EF - Gloas - Operations - Payload Attestation - process_payload_attestation_samp OK
+ [Valid]   EF - Gloas - Operations - Payload Attestation - process_payload_attestation_uses OK
```
## EF - Gloas - Operations - Proposer Slashing  [Preset: minimal]
```diff
+ [Invalid] EF - Gloas - Operations - Proposer Slashing - invalid_different_proposer_indices OK
+ [Invalid] EF - Gloas - Operations - Proposer Slashing - invalid_headers_are_same_sigs_are_ OK
+ [Invalid] EF - Gloas - Operations - Proposer Slashing - invalid_headers_are_same_sigs_are_ OK
+ [Invalid] EF - Gloas - Operations - Proposer Slashing - invalid_incorrect_proposer_index   OK
+ [Invalid] EF - Gloas - Operations - Proposer Slashing - invalid_incorrect_sig_1            OK
+ [Invalid] EF - Gloas - Operations - Proposer Slashing - invalid_incorrect_sig_1_and_2      OK
+ [Invalid] EF - Gloas - Operations - Proposer Slashing - invalid_incorrect_sig_1_and_2_swap OK
+ [Invalid] EF - Gloas - Operations - Proposer Slashing - invalid_incorrect_sig_2            OK
+ [Invalid] EF - Gloas - Operations - Proposer Slashing - invalid_proposer_is_not_activated  OK
+ [Invalid] EF - Gloas - Operations - Proposer Slashing - invalid_proposer_is_slashed        OK
+ [Invalid] EF - Gloas - Operations - Proposer Slashing - invalid_proposer_is_withdrawn      OK
+ [Invalid] EF - Gloas - Operations - Proposer Slashing - invalid_proposer_withdrawable_curr OK
+ [Invalid] EF - Gloas - Operations - Proposer Slashing - invalid_slots_of_different_epochs  OK
+ [Invalid] EF - Gloas - Operations - Proposer Slashing - invalid_slots_same_epoch_different OK
+ [Valid]   EF - Gloas - Operations - Proposer Slashing - basic                              OK
+ [Valid]   EF - Gloas - Operations - Proposer Slashing - block_header_from_future           OK
+ [Valid]   EF - Gloas - Operations - Proposer Slashing - block_header_from_past             OK
+ [Valid]   EF - Gloas - Operations - Proposer Slashing - builder_payment_deletion_current_e OK
+ [Valid]   EF - Gloas - Operations - Proposer Slashing - builder_payment_deletion_current_e OK
+ [Valid]   EF - Gloas - Operations - Proposer Slashing - builder_payment_deletion_current_e OK
+ [Valid]   EF - Gloas - Operations - Proposer Slashing - builder_payment_deletion_previous_ OK
+ [Valid]   EF - Gloas - Operations - Proposer Slashing - builder_payment_deletion_previous_ OK
+ [Valid]   EF - Gloas - Operations - Proposer Slashing - builder_payment_deletion_previous_ OK
+ [Valid]   EF - Gloas - Operations - Proposer Slashing - builder_payment_deletion_too_late  OK
+ [Valid]   EF - Gloas - Operations - Proposer Slashing - builder_payment_empty_current_epoc OK
+ [Valid]   EF - Gloas - Operations - Proposer Slashing - builder_payment_empty_old_epoch    OK
+ [Valid]   EF - Gloas - Operations - Proposer Slashing - builder_payment_empty_previous_epo OK
+ [Valid]   EF - Gloas - Operations - Proposer Slashing - header_slot_at_epoch_end           OK
+ [Valid]   EF - Gloas - Operations - Proposer Slashing - header_slot_at_epoch_start         OK
+ [Valid]   EF - Gloas - Operations - Proposer Slashing - headers_differ_multiple_roots      OK
+ [Valid]   EF - Gloas - Operations - Proposer Slashing - headers_differ_only_body_root      OK
+ [Valid]   EF - Gloas - Operations - Proposer Slashing - headers_differ_only_state_root     OK
+ [Valid]   EF - Gloas - Operations - Proposer Slashing - proposer_activated_current_epoch   OK
+ [Valid]   EF - Gloas - Operations - Proposer Slashing - proposer_index_last                OK
+ [Valid]   EF - Gloas - Operations - Proposer Slashing - proposer_index_zero                OK
+ [Valid]   EF - Gloas - Operations - Proposer Slashing - proposer_withdrawable_next_epoch   OK
+ [Valid]   EF - Gloas - Operations - Proposer Slashing - self_slashing_future_slot          OK
+ [Valid]   EF - Gloas - Operations - Proposer Slashing - slashed_and_proposer_index_the_sam OK
```
## EF - Gloas - Operations - Sync Aggregate  [Preset: minimal]
```diff
+ [Invalid] EF - Gloas - Operations - Sync Aggregate - invalid_signature_bad_domain          OK
+ [Invalid] EF - Gloas - Operations - Sync Aggregate - invalid_signature_extra_participant   OK
+ [Invalid] EF - Gloas - Operations - Sync Aggregate - invalid_signature_infinite_signature_ OK
+ [Invalid] EF - Gloas - Operations - Sync Aggregate - invalid_signature_infinite_signature_ OK
+ [Invalid] EF - Gloas - Operations - Sync Aggregate - invalid_signature_missing_participant OK
+ [Invalid] EF - Gloas - Operations - Sync Aggregate - invalid_signature_no_participants     OK
+ [Invalid] EF - Gloas - Operations - Sync Aggregate - invalid_signature_past_block          OK
+ [Invalid] EF - Gloas - Operations - Sync Aggregate - invalid_signature_previous_committee  OK
+ [Valid]   EF - Gloas - Operations - Sync Aggregate - proposer_in_committee_with_participat OK
+ [Valid]   EF - Gloas - Operations - Sync Aggregate - proposer_in_committee_without_partici OK
+ [Valid]   EF - Gloas - Operations - Sync Aggregate - random_all_but_one_participating_with OK
+ [Valid]   EF - Gloas - Operations - Sync Aggregate - random_high_participation_without_dup OK
+ [Valid]   EF - Gloas - Operations - Sync Aggregate - random_low_participation_without_dupl OK
+ [Valid]   EF - Gloas - Operations - Sync Aggregate - random_misc_balances_and_half_partici OK
+ [Valid]   EF - Gloas - Operations - Sync Aggregate - random_only_one_participant_without_d OK
+ [Valid]   EF - Gloas - Operations - Sync Aggregate - random_with_exits_without_duplicates  OK
+ [Valid]   EF - Gloas - Operations - Sync Aggregate - sync_committee_rewards_empty_particip OK
+ [Valid]   EF - Gloas - Operations - Sync Aggregate - sync_committee_rewards_nonduplicate_c OK
+ [Valid]   EF - Gloas - Operations - Sync Aggregate - sync_committee_rewards_not_full_parti OK
+ [Valid]   EF - Gloas - Operations - Sync Aggregate - sync_committee_with_nonparticipating_ OK
+ [Valid]   EF - Gloas - Operations - Sync Aggregate - sync_committee_with_nonparticipating_ OK
+ [Valid]   EF - Gloas - Operations - Sync Aggregate - sync_committee_with_participating_exi OK
+ [Valid]   EF - Gloas - Operations - Sync Aggregate - sync_committee_with_participating_wit OK
+ [Valid]   EF - Gloas - Operations - Sync Aggregate - valid_signature_future_committee      OK
```
## EF - Gloas - Operations - Voluntary Exit  [Preset: minimal]
```diff
+ [Invalid] EF - Gloas - Operations - Voluntary Exit - builder_voluntary_exit__invalid__bad_ OK
+ [Invalid] EF - Gloas - Operations - Voluntary Exit - builder_voluntary_exit__invalid__inac OK
+ [Invalid] EF - Gloas - Operations - Voluntary Exit - builder_voluntary_exit__invalid__inac OK
+ [Invalid] EF - Gloas - Operations - Voluntary Exit - builder_voluntary_exit__invalid__pend OK
+ [Invalid] EF - Gloas - Operations - Voluntary Exit - builder_voluntary_exit__invalid__pend OK
+ [Invalid] EF - Gloas - Operations - Voluntary Exit - invalid_incorrect_signature           OK
+ [Invalid] EF - Gloas - Operations - Voluntary Exit - invalid_validator_already_exited      OK
+ [Invalid] EF - Gloas - Operations - Voluntary Exit - invalid_validator_exit_in_future      OK
+ [Invalid] EF - Gloas - Operations - Voluntary Exit - invalid_validator_has_pending_withdra OK
+ [Invalid] EF - Gloas - Operations - Voluntary Exit - invalid_validator_incorrect_validator OK
+ [Invalid] EF - Gloas - Operations - Voluntary Exit - invalid_validator_not_active          OK
+ [Invalid] EF - Gloas - Operations - Voluntary Exit - invalid_validator_not_active_long_eno OK
+ [Invalid] EF - Gloas - Operations - Voluntary Exit - invalid_voluntary_exit_with_current_f OK
+ [Invalid] EF - Gloas - Operations - Voluntary Exit - invalid_voluntary_exit_with_current_f OK
+ [Invalid] EF - Gloas - Operations - Voluntary Exit - invalid_voluntary_exit_with_genesis_f OK
+ [Invalid] EF - Gloas - Operations - Voluntary Exit - invalid_voluntary_exit_with_genesis_f OK
+ [Invalid] EF - Gloas - Operations - Voluntary Exit - voluntary_exit_with_previous_fork_ver OK
+ [Invalid] EF - Gloas - Operations - Voluntary Exit - voluntary_exit_with_previous_fork_ver OK
+ [Valid]   EF - Gloas - Operations - Voluntary Exit - basic                                 OK
+ [Valid]   EF - Gloas - Operations - Voluntary Exit - builder_voluntary_exit__success       OK
+ [Valid]   EF - Gloas - Operations - Voluntary Exit - default_exit_epoch_subsequent_exit    OK
+ [Valid]   EF - Gloas - Operations - Voluntary Exit - min_balance_exit                      OK
+ [Valid]   EF - Gloas - Operations - Voluntary Exit - min_balance_exits_above_churn         OK
+ [Valid]   EF - Gloas - Operations - Voluntary Exit - min_balance_exits_up_to_churn         OK
+ [Valid]   EF - Gloas - Operations - Voluntary Exit - success_exit_queue__min_churn         OK
+ [Valid]   EF - Gloas - Operations - Voluntary Exit - success_exit_queue__scaled_churn      OK
+ [Valid]   EF - Gloas - Operations - Voluntary Exit - voluntary_exit_with_pending_deposit   OK
```
## EF - Gloas - Operations - Withdrawal Request  [Preset: minimal]
```diff
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - activation_epoch_less_than_shard_ OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - basic_partial_withdrawal_request  OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - basic_partial_withdrawal_request_ OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - basic_partial_withdrawal_request_ OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - basic_withdrawal_request          OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - basic_withdrawal_request_with_com OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - basic_withdrawal_request_with_fir OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - basic_withdrawal_request_with_ful OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - full_exit_request_has_partial_wit OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - incorrect_inactive_validator      OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - incorrect_source_address          OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - incorrect_withdrawal_credential_p OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - insufficient_balance              OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - insufficient_effective_balance    OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - no_compounding_credentials        OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - no_excess_balance                 OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - on_withdrawal_request_initiated_e OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - partial_withdrawal_activation_epo OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - partial_withdrawal_incorrect_sour OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - partial_withdrawal_incorrect_with OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - partial_withdrawal_on_exit_initia OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - partial_withdrawal_queue_full     OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - partial_withdrawal_request_with_h OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - partial_withdrawal_request_with_h OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - partial_withdrawal_request_with_l OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - partial_withdrawal_request_with_p OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - partial_withdrawal_request_with_p OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - pending_withdrawals_consume_all_e OK
+ [Valid]   EF - Gloas - Operations - Withdrawal Request - unknown_pubkey                    OK
```
## EF - Gloas - Operations - Withdrawals  [Preset: minimal]
```diff
+ [Valid]   EF - Gloas - Operations - Withdrawals - all_builder_withdrawals_zero_balance     OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - builder_and_pending_leave_room_for_sweep OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - builder_max_minus_one_plus_one_regular   OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - builder_payments_exceed_limit_blocks_oth OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - builder_sweep_index_wrap_around          OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - builder_sweep_not_withdrawable_skipped   OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - builder_sweep_zero_balance_skipped       OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - builder_uses_fee_recipient_address       OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - builder_withdrawal_insufficient_balance  OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - builder_withdrawal_insufficient_balance_ OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - builder_withdrawals_processed_order      OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - builder_zero_withdrawal_amount           OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - compounding_validator_partial_withdrawal OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - duplicate_builder_index_in_pending_withd OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - early_return_empty_parent_block          OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - full_builder_payload_reserves_sweep_slot OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - full_pending_withdrawals_but_first_skipp OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - full_pending_withdrawals_but_first_skipp OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - full_pending_withdrawals_but_first_skipp OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - maximum_withdrawals_per_payload_limit    OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - multiple_builder_sweep_withdrawals       OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - multiple_builder_withdrawals             OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - no_builders_max_pending_with_sweep_spill OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - no_builders_no_pending_max_sweep_withdra OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - partially_withdrawable_validator_compoun OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - partially_withdrawable_validator_compoun OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - partially_withdrawable_validator_compoun OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - partially_withdrawable_validator_compoun OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - partially_withdrawable_validator_compoun OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - partially_withdrawable_validator_compoun OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - partially_withdrawable_validator_legacy_ OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - partially_withdrawable_validator_legacy_ OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - partially_withdrawable_validator_legacy_ OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - pending_withdrawals_at_max               OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - pending_withdrawals_at_max_mixed_with_sw OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - pending_withdrawals_exiting_validator    OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - pending_withdrawals_low_effective_balanc OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - pending_withdrawals_mixed_with_sweep_and OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - pending_withdrawals_next_epoch           OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - pending_withdrawals_no_excess_balance    OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - pending_withdrawals_one_skipped_one_effe OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - pending_withdrawals_processing           OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - pending_withdrawals_processing_exceeds_l OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - pending_withdrawals_two_partial_withdraw OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - pending_withdrawals_two_partial_withdraw OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - pending_withdrawals_with_effective_sweep OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - pending_withdrawals_with_ineffective_swe OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - pending_withdrawals_with_ineffective_swe OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - pending_withdrawals_with_sweep_different OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - random_0                                 OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - random_partial_withdrawals_1             OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - random_partial_withdrawals_2             OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - random_partial_withdrawals_3             OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - random_partial_withdrawals_4             OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - random_partial_withdrawals_5             OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - single_builder_sweep_withdrawal          OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - single_builder_withdrawal                OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - success_excess_balance_but_no_max_effect OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - success_excess_balance_but_no_max_effect OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - success_max_partial_withdrawable         OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - success_max_plus_one_withdrawable        OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - success_mixed_fully_and_partial_withdraw OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - success_mixed_fully_and_partial_withdraw OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - success_no_excess_balance                OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - success_no_excess_balance_compounding    OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - success_no_max_effective_balance         OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - success_no_max_effective_balance_compoun OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - success_one_full_withdrawal              OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - success_one_partial_withdrawable_active_ OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - success_one_partial_withdrawable_exited  OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - success_one_partial_withdrawable_exited_ OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - success_one_partial_withdrawable_in_exit OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - success_one_partial_withdrawable_not_yet OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - success_one_partial_withdrawal           OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - success_two_partial_withdrawable         OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - success_zero_expected_withdrawals        OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - withdrawable_epoch_but_0_balance         OK
+ [Valid]   EF - Gloas - Operations - Withdrawals - withdrawable_epoch_but_0_effective_balan OK
```
## EF - Gloas - SSZ consensus objects  [Preset: minimal]
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
+   Testing    Builder                                                                       OK
+   Testing    BuilderPendingPayment                                                         OK
+   Testing    BuilderPendingWithdrawal                                                      OK
+   Testing    Checkpoint                                                                    OK
+   Testing    ConsolidationRequest                                                          OK
+   Testing    ContributionAndProof                                                          OK
+   Testing    DataColumnSidecar                                                             OK
+   Testing    DataColumnsByRootIdentifier                                                   OK
+   Testing    Deposit                                                                       OK
+   Testing    DepositData                                                                   OK
+   Testing    DepositMessage                                                                OK
+   Testing    DepositRequest                                                                OK
+   Testing    Eth1Block                                                                     OK
+   Testing    Eth1Data                                                                      OK
+   Testing    ExecutionPayload                                                              OK
+   Testing    ExecutionPayloadBid                                                           OK
+   Testing    ExecutionPayloadEnvelope                                                      OK
+   Testing    ExecutionPayloadHeader                                                        OK
+   Testing    ExecutionRequests                                                             OK
+   Testing    Fork                                                                          OK
+   Testing    ForkChoiceNode                                                                OK
+   Testing    ForkData                                                                      OK
+   Testing    HistoricalBatch                                                               OK
+   Testing    HistoricalSummary                                                             OK
+   Testing    IndexedAttestation                                                            OK
+   Testing    IndexedPayloadAttestation                                                     OK
+   Testing    LightClientBootstrap                                                          OK
+   Testing    LightClientFinalityUpdate                                                     OK
+   Testing    LightClientHeader                                                             OK
+   Testing    LightClientOptimisticUpdate                                                   OK
+   Testing    LightClientUpdate                                                             OK
+   Testing    MatrixEntry                                                                   OK
+   Testing    PartialDataColumnHeader                                                       OK
+   Testing    PartialDataColumnPartsMetadata                                                OK
+   Testing    PartialDataColumnSidecar                                                      OK
+   Testing    PayloadAttestation                                                            OK
+   Testing    PayloadAttestationData                                                        OK
+   Testing    PayloadAttestationMessage                                                     OK
+   Testing    PendingAttestation                                                            OK
+   Testing    PendingConsolidation                                                          OK
+   Testing    PendingDeposit                                                                OK
+   Testing    PendingPartialWithdrawal                                                      OK
+   Testing    PowBlock                                                                      OK
+   Testing    ProposerPreferences                                                           OK
+   Testing    ProposerSlashing                                                              OK
+   Testing    SignedAggregateAndProof                                                       OK
+   Testing    SignedBLSToExecutionChange                                                    OK
+   Testing    SignedBeaconBlock                                                             OK
+   Testing    SignedBeaconBlockHeader                                                       OK
+   Testing    SignedContributionAndProof                                                    OK
+   Testing    SignedExecutionPayloadBid                                                     OK
+   Testing    SignedExecutionPayloadEnvelope                                                OK
+   Testing    SignedProposerPreferences                                                     OK
+   Testing    SignedVoluntaryExit                                                           OK
+   Testing    SigningData                                                                   OK
+   Testing    SingleAttestation                                                             OK
+   Testing    SyncAggregate                                                                 OK
+   Testing    SyncAggregatorSelectionData                                                   OK
+   Testing    SyncCommittee                                                                 OK
+   Testing    SyncCommitteeContribution                                                     OK
+   Testing    SyncCommitteeMessage                                                          OK
+   Testing    Validator                                                                     OK
+   Testing    VoluntaryExit                                                                 OK
+   Testing    Withdrawal                                                                    OK
+   Testing    WithdrawalRequest                                                             OK
```
## EF - Gloas - Sanity - Slots  [Preset: minimal]
```diff
+ EF - Gloas - Slots - balance_change_affects_proposer [Preset: minimal]                     OK
+ EF - Gloas - Slots - double_empty_epoch [Preset: minimal]                                  OK
+ EF - Gloas - Slots - effective_decrease_balance_updates_lookahead [Preset: minimal]        OK
+ EF - Gloas - Slots - empty_epoch [Preset: minimal]                                         OK
+ EF - Gloas - Slots - execution_payload_availability_reset_from_set [Preset: minimal]       OK
+ EF - Gloas - Slots - execution_payload_availability_reset_from_unset [Preset: minimal]     OK
+ EF - Gloas - Slots - historical_accumulator [Preset: minimal]                              OK
+ EF - Gloas - Slots - multiple_pending_deposits_same_pubkey [Preset: minimal]               OK
+ EF - Gloas - Slots - multiple_pending_deposits_same_pubkey_above_upward_threshold [Preset: OK
+ EF - Gloas - Slots - multiple_pending_deposits_same_pubkey_below_upward_threshold [Preset: OK
+ EF - Gloas - Slots - multiple_pending_deposits_same_pubkey_compounding [Preset: minimal]   OK
+ EF - Gloas - Slots - multiple_pending_deposits_same_pubkey_different_signature [Preset: mi OK
+ EF - Gloas - Slots - over_epoch_boundary [Preset: minimal]                                 OK
+ EF - Gloas - Slots - pending_consolidation [Preset: minimal]                               OK
+ EF - Gloas - Slots - pending_deposit_extra_gwei [Preset: minimal]                          OK
+ EF - Gloas - Slots - slots_1 [Preset: minimal]                                             OK
+ EF - Gloas - Slots - slots_2 [Preset: minimal]                                             OK
```
## EF - Gloas - Transition  [Preset: minimal]
```diff
+ EF - Gloas - Transition - higher_churn_limit_to_lower [Preset: minimal]                    OK
+ EF - Gloas - Transition - non_empty_historical_roots [Preset: minimal]                     OK
+ EF - Gloas - Transition - normal_transition [Preset: minimal]                              OK
+ EF - Gloas - Transition - simple_transition [Preset: minimal]                              OK
+ EF - Gloas - Transition - transition_attestation_from_previous_fork_with_new_range [Preset OK
+ EF - Gloas - Transition - transition_missing_first_post_block [Preset: minimal]            OK
+ EF - Gloas - Transition - transition_missing_last_pre_fork_block [Preset: minimal]         OK
+ EF - Gloas - Transition - transition_only_blocks_post_fork [Preset: minimal]               OK
+ EF - Gloas - Transition - transition_randomized_state [Preset: minimal]                    OK
+ EF - Gloas - Transition - transition_with_activation_at_fork_epoch [Preset: minimal]       OK
+ EF - Gloas - Transition - transition_with_attester_slashing_right_after_fork [Preset: mini OK
+ EF - Gloas - Transition - transition_with_attester_slashing_right_before_fork [Preset: min OK
+ EF - Gloas - Transition - transition_with_btec_right_after_fork [Preset: minimal]          OK
+ EF - Gloas - Transition - transition_with_btec_right_before_fork [Preset: minimal]         OK
+ EF - Gloas - Transition - transition_with_deposit_right_after_fork [Preset: minimal]       OK
+ EF - Gloas - Transition - transition_with_deposit_right_before_fork [Preset: minimal]      OK
+ EF - Gloas - Transition - transition_with_finality [Preset: minimal]                       OK
+ EF - Gloas - Transition - transition_with_leaking_at_fork [Preset: minimal]                OK
+ EF - Gloas - Transition - transition_with_leaking_pre_fork [Preset: minimal]               OK
+ EF - Gloas - Transition - transition_with_no_attestations_until_after_fork [Preset: minima OK
+ EF - Gloas - Transition - transition_with_non_empty_activation_queue [Preset: minimal]     OK
+ EF - Gloas - Transition - transition_with_one_fourth_exiting_validators_exit_at_fork [Pres OK
+ EF - Gloas - Transition - transition_with_one_fourth_exiting_validators_exit_post_fork [Pr OK
+ EF - Gloas - Transition - transition_with_one_fourth_slashed_active_validators_pre_fork [P OK
+ EF - Gloas - Transition - transition_with_proposer_slashing_right_after_fork [Preset: mini OK
+ EF - Gloas - Transition - transition_with_proposer_slashing_right_before_fork [Preset: min OK
+ EF - Gloas - Transition - transition_with_random_half_participation [Preset: minimal]      OK
+ EF - Gloas - Transition - transition_with_random_three_quarters_participation [Preset: min OK
+ EF - Gloas - Transition - transition_with_voluntary_exit_right_after_fork [Preset: minimal OK
+ EF - Gloas - Transition - transition_with_voluntary_exit_right_before_fork [Preset: minima OK
```
## EF - Heze - Fork  [Preset: minimal]
```diff
+ EF - Heze - Fork - after_fork_deactivate_validators_from_gloas_to_heze [Preset: minimal]   OK
+ EF - Heze - Fork - after_fork_deactivate_validators_wo_block_from_gloas_to_heze [Preset: m OK
```
## EF - Heze - Operations - Attestation  [Preset: minimal]
```diff
+ [Invalid] EF - Heze - Operations - Attestation - invalid_after_max_inclusion_slot          OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_attestation_data_index_not_zero   OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_attestation_data_index_too_high   OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_attestation_signature             OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_bad_source_root                   OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_before_inclusion_delay            OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_committee_index                   OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_correct_attestation_included_afte OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_current_source_root               OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_empty_participants_seemingly_vali OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_empty_participants_zeroes_sig     OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_future_target_epoch               OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_incorrect_head_and_target_include OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_incorrect_head_included_after_max OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_incorrect_target_included_after_m OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_index                             OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_mismatched_target_and_slot        OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_new_source_epoch                  OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_nonset_bits_for_one_committee     OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_nonset_committee_bits             OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_nonset_multiple_committee_bits    OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_old_source_epoch                  OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_old_target_epoch                  OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_previous_source_root              OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_same_slot_attestation_index_one   OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_source_root_is_target_root        OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_too_few_aggregation_bits          OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_too_many_aggregation_bits         OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_too_many_committee_bits           OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_wrong_index_for_committee_signatu OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_wrong_index_for_slot_0            OK
+ [Invalid] EF - Heze - Operations - Attestation - invalid_wrong_index_for_slot_1            OK
+ [Valid]   EF - Heze - Operations - Attestation - at_max_inclusion_slot                     OK
+ [Valid]   EF - Heze - Operations - Attestation - builder_payment_weight_no_double_counting OK
+ [Valid]   EF - Heze - Operations - Attestation - builder_payment_weight_tracking           OK
+ [Valid]   EF - Heze - Operations - Attestation - correct_attestation_included_at_max_inclu OK
+ [Valid]   EF - Heze - Operations - Attestation - correct_attestation_included_at_min_inclu OK
+ [Valid]   EF - Heze - Operations - Attestation - correct_attestation_included_at_one_epoch OK
+ [Valid]   EF - Heze - Operations - Attestation - correct_attestation_included_at_sqrt_epoc OK
+ [Valid]   EF - Heze - Operations - Attestation - incorrect_head_and_target_included_at_epo OK
+ [Valid]   EF - Heze - Operations - Attestation - incorrect_head_and_target_included_at_sqr OK
+ [Valid]   EF - Heze - Operations - Attestation - incorrect_head_and_target_min_inclusion_d OK
+ [Valid]   EF - Heze - Operations - Attestation - incorrect_head_included_at_max_inclusion_ OK
+ [Valid]   EF - Heze - Operations - Attestation - incorrect_head_included_at_min_inclusion_ OK
+ [Valid]   EF - Heze - Operations - Attestation - incorrect_head_included_at_sqrt_epoch_del OK
+ [Valid]   EF - Heze - Operations - Attestation - incorrect_target_included_at_epoch_delay  OK
+ [Valid]   EF - Heze - Operations - Attestation - incorrect_target_included_at_min_inclusio OK
+ [Valid]   EF - Heze - Operations - Attestation - incorrect_target_included_at_sqrt_epoch_d OK
+ [Valid]   EF - Heze - Operations - Attestation - matching_payload_false_historical_slot    OK
+ [Valid]   EF - Heze - Operations - Attestation - matching_payload_gets_head_flag           OK
+ [Valid]   EF - Heze - Operations - Attestation - matching_payload_true_historical_slot     OK
+ [Valid]   EF - Heze - Operations - Attestation - matching_payload_true_same_slot           OK
+ [Valid]   EF - Heze - Operations - Attestation - mismatched_payload_no_head_flag           OK
+ [Valid]   EF - Heze - Operations - Attestation - multi_proposer_index_iterations           OK
+ [Valid]   EF - Heze - Operations - Attestation - multiple_committees                       OK
+ [Valid]   EF - Heze - Operations - Attestation - one_basic_attestation                     OK
+ [Valid]   EF - Heze - Operations - Attestation - one_committee_with_gap                    OK
+ [Valid]   EF - Heze - Operations - Attestation - previous_epoch                            OK
+ [Valid]   EF - Heze - Operations - Attestation - valid_attestation_data_index_one_previous OK
+ [Valid]   EF - Heze - Operations - Attestation - valid_attestation_data_index_one_previous OK
+ [Valid]   EF - Heze - Operations - Attestation - valid_attestation_data_index_zero_previou OK
+ [Valid]   EF - Heze - Operations - Attestation - valid_same_slot_attestation_index_zero    OK
```
## EF - Heze - Operations - Attester Slashing  [Preset: minimal]
```diff
+ [Invalid] EF - Heze - Operations - Attester Slashing - invalid_all_empty_indices           OK
+ [Invalid] EF - Heze - Operations - Attester Slashing - invalid_att1_bad_extra_index        OK
+ [Invalid] EF - Heze - Operations - Attester Slashing - invalid_att1_bad_replaced_index     OK
+ [Invalid] EF - Heze - Operations - Attester Slashing - invalid_att1_duplicate_index_double OK
+ [Invalid] EF - Heze - Operations - Attester Slashing - invalid_att1_duplicate_index_normal OK
+ [Invalid] EF - Heze - Operations - Attester Slashing - invalid_att1_empty_indices          OK
+ [Invalid] EF - Heze - Operations - Attester Slashing - invalid_att1_high_index             OK
+ [Invalid] EF - Heze - Operations - Attester Slashing - invalid_att2_bad_extra_index        OK
+ [Invalid] EF - Heze - Operations - Attester Slashing - invalid_att2_bad_replaced_index     OK
+ [Invalid] EF - Heze - Operations - Attester Slashing - invalid_att2_duplicate_index_double OK
+ [Invalid] EF - Heze - Operations - Attester Slashing - invalid_att2_duplicate_index_normal OK
+ [Invalid] EF - Heze - Operations - Attester Slashing - invalid_att2_empty_indices          OK
+ [Invalid] EF - Heze - Operations - Attester Slashing - invalid_att2_high_index             OK
+ [Invalid] EF - Heze - Operations - Attester Slashing - invalid_incorrect_sig_1             OK
+ [Invalid] EF - Heze - Operations - Attester Slashing - invalid_incorrect_sig_1_and_2       OK
+ [Invalid] EF - Heze - Operations - Attester Slashing - invalid_incorrect_sig_2             OK
+ [Invalid] EF - Heze - Operations - Attester Slashing - invalid_no_double_or_surround       OK
+ [Invalid] EF - Heze - Operations - Attester Slashing - invalid_participants_already_slashe OK
+ [Invalid] EF - Heze - Operations - Attester Slashing - invalid_same_data                   OK
+ [Invalid] EF - Heze - Operations - Attester Slashing - invalid_unsorted_att_1              OK
+ [Invalid] EF - Heze - Operations - Attester Slashing - invalid_unsorted_att_2              OK
+ [Valid]   EF - Heze - Operations - Attester Slashing - already_exited_long_ago             OK
+ [Valid]   EF - Heze - Operations - Attester Slashing - already_exited_recent               OK
+ [Valid]   EF - Heze - Operations - Attester Slashing - attestation_from_future             OK
+ [Valid]   EF - Heze - Operations - Attester Slashing - basic_double                        OK
+ [Valid]   EF - Heze - Operations - Attester Slashing - basic_surround                      OK
+ [Valid]   EF - Heze - Operations - Attester Slashing - low_balances                        OK
+ [Valid]   EF - Heze - Operations - Attester Slashing - misc_balances                       OK
+ [Valid]   EF - Heze - Operations - Attester Slashing - proposer_index_slashed              OK
+ [Valid]   EF - Heze - Operations - Attester Slashing - with_effective_balance_disparity    OK
```
## EF - Heze - Operations - BLS to execution change  [Preset: minimal]
```diff
+ [Invalid] EF - Heze - Operations - BLS to execution change - invalid_already_0x01          OK
+ [Invalid] EF - Heze - Operations - BLS to execution change - invalid_bad_signature         OK
+ [Invalid] EF - Heze - Operations - BLS to execution change - invalid_current_fork_version  OK
+ [Invalid] EF - Heze - Operations - BLS to execution change - invalid_genesis_validators_ro OK
+ [Invalid] EF - Heze - Operations - BLS to execution change - invalid_incorrect_from_bls_pu OK
+ [Invalid] EF - Heze - Operations - BLS to execution change - invalid_previous_fork_version OK
+ [Invalid] EF - Heze - Operations - BLS to execution change - invalid_val_index_out_of_rang OK
+ [Valid]   EF - Heze - Operations - BLS to execution change - genesis_fork_version          OK
+ [Valid]   EF - Heze - Operations - BLS to execution change - success                       OK
+ [Valid]   EF - Heze - Operations - BLS to execution change - success_exited                OK
+ [Valid]   EF - Heze - Operations - BLS to execution change - success_in_activation_queue   OK
+ [Valid]   EF - Heze - Operations - BLS to execution change - success_in_exit_queue         OK
+ [Valid]   EF - Heze - Operations - BLS to execution change - success_not_activated         OK
+ [Valid]   EF - Heze - Operations - BLS to execution change - success_withdrawable          OK
```
## EF - Heze - Operations - Block Header  [Preset: minimal]
```diff
+ [Invalid] EF - Heze - Operations - Block Header - invalid_multiple_blocks_single_slot      OK
+ [Invalid] EF - Heze - Operations - Block Header - invalid_parent_root                      OK
+ [Invalid] EF - Heze - Operations - Block Header - invalid_proposer_index                   OK
+ [Invalid] EF - Heze - Operations - Block Header - invalid_proposer_slashed                 OK
+ [Invalid] EF - Heze - Operations - Block Header - invalid_slot_block_header                OK
+ [Valid]   EF - Heze - Operations - Block Header - basic_block_header                       OK
```
## EF - Heze - Operations - Consolidation Request  [Preset: minimal]
```diff
+ [Valid]   EF - Heze - Operations - Consolidation Request - basic_consolidation_in_current_ OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - basic_consolidation_in_new_cons OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - basic_consolidation_source_has_ OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - basic_consolidation_target_has_ OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - basic_consolidation_with_compou OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - basic_consolidation_with_excess OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - basic_consolidation_with_insuff OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - basic_consolidation_with_preexi OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - basic_switch_to_compounding     OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - consolidation_balance_larger_th OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - consolidation_balance_through_t OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - consolidation_churn_limit_balan OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - incorrect_exceed_pending_consol OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - incorrect_exited_source         OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - incorrect_exited_target         OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - incorrect_inactive_source       OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - incorrect_inactive_target       OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - incorrect_no_source_execution_w OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - incorrect_not_enough_consolidat OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - incorrect_same_source_target    OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - incorrect_source_address        OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - incorrect_source_has_pending_wi OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - incorrect_source_not_active_lon OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - incorrect_source_pubkey_is_targ OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - incorrect_source_with_bls_crede OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - incorrect_target_with_bls_crede OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - incorrect_target_with_eth1_cred OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - incorrect_unknown_source_pubkey OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - incorrect_unknown_target_pubkey OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - switch_to_compounding_exited_so OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - switch_to_compounding_inactive_ OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - switch_to_compounding_not_autho OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - switch_to_compounding_source_bl OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - switch_to_compounding_source_co OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - switch_to_compounding_unknown_s OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - switch_to_compounding_with_exce OK
+ [Valid]   EF - Heze - Operations - Consolidation Request - switch_to_compounding_with_pend OK
```
## EF - Heze - Operations - Deposit  [Preset: minimal]
```diff
+ [Invalid] EF - Heze - Operations - Deposit - invalid_bad_merkle_proof                      OK
+ [Invalid] EF - Heze - Operations - Deposit - invalid_wrong_deposit_for_deposit_count       OK
+ [Valid]   EF - Heze - Operations - Deposit - correct_sig_but_forked_state                  OK
+ [Valid]   EF - Heze - Operations - Deposit - effective_deposit_with_genesis_fork_version   OK
+ [Valid]   EF - Heze - Operations - Deposit - incorrect_sig_new_deposit                     OK
+ [Valid]   EF - Heze - Operations - Deposit - incorrect_sig_top_up                          OK
+ [Valid]   EF - Heze - Operations - Deposit - incorrect_withdrawal_credentials_top_up       OK
+ [Valid]   EF - Heze - Operations - Deposit - ineffective_deposit_with_bad_fork_version     OK
+ [Valid]   EF - Heze - Operations - Deposit - ineffective_deposit_with_current_fork_version OK
+ [Valid]   EF - Heze - Operations - Deposit - ineffective_deposit_with_previous_fork_versio OK
+ [Valid]   EF - Heze - Operations - Deposit - key_validate_invalid_decompression            OK
+ [Valid]   EF - Heze - Operations - Deposit - key_validate_invalid_subgroup                 OK
+ [Valid]   EF - Heze - Operations - Deposit - new_deposit_eth1_withdrawal_credentials       OK
+ [Valid]   EF - Heze - Operations - Deposit - new_deposit_max                               OK
+ [Valid]   EF - Heze - Operations - Deposit - new_deposit_non_versioned_withdrawal_credenti OK
+ [Valid]   EF - Heze - Operations - Deposit - new_deposit_over_max                          OK
+ [Valid]   EF - Heze - Operations - Deposit - new_deposit_under_max                         OK
+ [Valid]   EF - Heze - Operations - Deposit - top_up__less_effective_balance                OK
+ [Valid]   EF - Heze - Operations - Deposit - top_up__max_effective_balance                 OK
+ [Valid]   EF - Heze - Operations - Deposit - top_up__zero_balance                          OK
```
## EF - Heze - Operations - Deposit Request  [Preset: minimal]
```diff
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__builder_top_ OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__builder_top_ OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__builder_top_ OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__builder_top_ OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__builder_top_ OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__new_builder  OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__new_builder_ OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__new_builder_ OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__new_builder_ OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__new_builder_ OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__new_builder_ OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__new_builder_ OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__no_reuse_fut OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__no_reuse_non OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__nonstandard_ OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__reuses_exite OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__reuses_first OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__reuses_slot_ OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__routing__bui OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__routing__new OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__routing__new OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__routing__new OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__routing__pen OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__routing__pen OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__routing__pen OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__routing__pen OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__routing__val OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request__routing__val OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request_eth1_credenti OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request_extra_gwei    OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request_greater_than_ OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request_invalid_sig   OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request_max_effective OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request_min_activatio OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request_pending_depos OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request_set_start_ind OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request_top_up_invali OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request_top_up_max_ef OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request_top_up_min_ac OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request_top_up_still_ OK
+ [Valid]   EF - Heze - Operations - Deposit Request - process_deposit_request_undefined_cre OK
```
## EF - Heze - Operations - Execution Payload  [Preset: minimal]
```diff
+ [Invalid] EF - Heze - Operations - Execution Payload - invalid_bad_everything_first_payloa OK
+ [Invalid] EF - Heze - Operations - Execution Payload - invalid_bad_everything_regular_payl OK
+ [Invalid] EF - Heze - Operations - Execution Payload - invalid_bad_parent_hash_first_paylo OK
+ [Invalid] EF - Heze - Operations - Execution Payload - invalid_bad_parent_hash_regular_pay OK
+ [Invalid] EF - Heze - Operations - Execution Payload - invalid_bad_pre_randao_regular_payl OK
+ [Invalid] EF - Heze - Operations - Execution Payload - invalid_bad_prev_randao_first_paylo OK
+ [Invalid] EF - Heze - Operations - Execution Payload - invalid_correct_input__execution_in OK
+ [Invalid] EF - Heze - Operations - Execution Payload - invalid_future_timestamp_first_payl OK
+ [Invalid] EF - Heze - Operations - Execution Payload - invalid_future_timestamp_regular_pa OK
+ [Invalid] EF - Heze - Operations - Execution Payload - invalid_past_timestamp_first_payloa OK
+ [Invalid] EF - Heze - Operations - Execution Payload - invalid_past_timestamp_regular_payl OK
+ [Invalid] EF - Heze - Operations - Execution Payload - process_execution_payload_bid_prev_ OK
+ [Invalid] EF - Heze - Operations - Execution Payload - process_execution_payload_execution OK
+ [Invalid] EF - Heze - Operations - Execution Payload - process_execution_payload_invalid_s OK
+ [Invalid] EF - Heze - Operations - Execution Payload - process_execution_payload_missing_e OK
+ [Invalid] EF - Heze - Operations - Execution Payload - process_execution_payload_wrong_bea OK
+ [Invalid] EF - Heze - Operations - Execution Payload - process_execution_payload_wrong_blo OK
+ [Invalid] EF - Heze - Operations - Execution Payload - process_execution_payload_wrong_bui OK
+ [Invalid] EF - Heze - Operations - Execution Payload - process_execution_payload_wrong_gas OK
+ [Invalid] EF - Heze - Operations - Execution Payload - process_execution_payload_wrong_par OK
+ [Invalid] EF - Heze - Operations - Execution Payload - process_execution_payload_wrong_pre OK
+ [Invalid] EF - Heze - Operations - Execution Payload - process_execution_payload_wrong_slo OK
+ [Invalid] EF - Heze - Operations - Execution Payload - process_execution_payload_wrong_tim OK
+ [Valid]   EF - Heze - Operations - Execution Payload - incorrect_blob_tx_type              OK
+ [Valid]   EF - Heze - Operations - Execution Payload - incorrect_block_hash                OK
+ [Valid]   EF - Heze - Operations - Execution Payload - incorrect_commitment                OK
+ [Valid]   EF - Heze - Operations - Execution Payload - incorrect_commitments_order         OK
+ [Valid]   EF - Heze - Operations - Execution Payload - incorrect_transaction_length_1_byte OK
+ [Valid]   EF - Heze - Operations - Execution Payload - incorrect_transaction_length_1_extr OK
+ [Valid]   EF - Heze - Operations - Execution Payload - incorrect_transaction_length_32_ext OK
+ [Valid]   EF - Heze - Operations - Execution Payload - incorrect_transaction_length_empty  OK
+ [Valid]   EF - Heze - Operations - Execution Payload - incorrect_transaction_no_blobs_but_ OK
+ [Valid]   EF - Heze - Operations - Execution Payload - no_commitments_for_transactions     OK
+ [Valid]   EF - Heze - Operations - Execution Payload - no_transactions_with_commitments    OK
+ [Valid]   EF - Heze - Operations - Execution Payload - process_execution_payload_large_pay OK
+ [Valid]   EF - Heze - Operations - Execution Payload - process_execution_payload_self_buil OK
+ [Valid]   EF - Heze - Operations - Execution Payload - process_execution_payload_valid     OK
+ [Valid]   EF - Heze - Operations - Execution Payload - process_execution_payload_with_blob OK
+ [Valid]   EF - Heze - Operations - Execution Payload - process_execution_payload_with_exec OK
+ [Valid]   EF - Heze - Operations - Execution Payload - zeroed_commitment                   OK
```
## EF - Heze - Operations - Execution Payload Bid  [Preset: minimal]
```diff
+ [Invalid] EF - Heze - Operations - Execution Payload Bid - process_execution_payload_bid_b OK
+ [Invalid] EF - Heze - Operations - Execution Payload Bid - process_execution_payload_bid_i OK
+ [Invalid] EF - Heze - Operations - Execution Payload Bid - process_execution_payload_bid_i OK
+ [Invalid] EF - Heze - Operations - Execution Payload Bid - process_execution_payload_bid_i OK
+ [Invalid] EF - Heze - Operations - Execution Payload Bid - process_execution_payload_bid_i OK
+ [Invalid] EF - Heze - Operations - Execution Payload Bid - process_execution_payload_bid_i OK
+ [Invalid] EF - Heze - Operations - Execution Payload Bid - process_execution_payload_bid_i OK
+ [Invalid] EF - Heze - Operations - Execution Payload Bid - process_execution_payload_bid_s OK
+ [Invalid] EF - Heze - Operations - Execution Payload Bid - process_execution_payload_bid_w OK
+ [Invalid] EF - Heze - Operations - Execution Payload Bid - process_execution_payload_bid_w OK
+ [Invalid] EF - Heze - Operations - Execution Payload Bid - process_execution_payload_bid_w OK
+ [Invalid] EF - Heze - Operations - Execution Payload Bid - process_execution_payload_bid_w OK
+ [Valid]   EF - Heze - Operations - Execution Payload Bid - process_execution_payload_bid_b OK
+ [Valid]   EF - Heze - Operations - Execution Payload Bid - process_execution_payload_bid_s OK
+ [Valid]   EF - Heze - Operations - Execution Payload Bid - process_execution_payload_bid_s OK
+ [Valid]   EF - Heze - Operations - Execution Payload Bid - process_execution_payload_bid_v OK
+ [Valid]   EF - Heze - Operations - Execution Payload Bid - process_execution_payload_bid_v OK
```
## EF - Heze - Operations - Payload Attestation  [Preset: minimal]
```diff
+ [Invalid] EF - Heze - Operations - Payload Attestation - process_payload_attestation_cross OK
+ [Invalid] EF - Heze - Operations - Payload Attestation - process_payload_attestation_futur OK
+ [Invalid] EF - Heze - Operations - Payload Attestation - process_payload_attestation_inval OK
+ [Invalid] EF - Heze - Operations - Payload Attestation - process_payload_attestation_inval OK
+ [Invalid] EF - Heze - Operations - Payload Attestation - process_payload_attestation_no_at OK
+ [Invalid] EF - Heze - Operations - Payload Attestation - process_payload_attestation_too_o OK
+ [Valid]   EF - Heze - Operations - Payload Attestation - process_payload_attestation_parti OK
+ [Valid]   EF - Heze - Operations - Payload Attestation - process_payload_attestation_paylo OK
+ [Valid]   EF - Heze - Operations - Payload Attestation - process_payload_attestation_paylo OK
+ [Valid]   EF - Heze - Operations - Payload Attestation - process_payload_attestation_sampl OK
+ [Valid]   EF - Heze - Operations - Payload Attestation - process_payload_attestation_uses_ OK
```
## EF - Heze - Operations - Proposer Slashing  [Preset: minimal]
```diff
+ [Invalid] EF - Heze - Operations - Proposer Slashing - invalid_different_proposer_indices  OK
+ [Invalid] EF - Heze - Operations - Proposer Slashing - invalid_headers_are_same_sigs_are_d OK
+ [Invalid] EF - Heze - Operations - Proposer Slashing - invalid_headers_are_same_sigs_are_s OK
+ [Invalid] EF - Heze - Operations - Proposer Slashing - invalid_incorrect_proposer_index    OK
+ [Invalid] EF - Heze - Operations - Proposer Slashing - invalid_incorrect_sig_1             OK
+ [Invalid] EF - Heze - Operations - Proposer Slashing - invalid_incorrect_sig_1_and_2       OK
+ [Invalid] EF - Heze - Operations - Proposer Slashing - invalid_incorrect_sig_1_and_2_swap  OK
+ [Invalid] EF - Heze - Operations - Proposer Slashing - invalid_incorrect_sig_2             OK
+ [Invalid] EF - Heze - Operations - Proposer Slashing - invalid_proposer_is_not_activated   OK
+ [Invalid] EF - Heze - Operations - Proposer Slashing - invalid_proposer_is_slashed         OK
+ [Invalid] EF - Heze - Operations - Proposer Slashing - invalid_proposer_is_withdrawn       OK
+ [Invalid] EF - Heze - Operations - Proposer Slashing - invalid_proposer_withdrawable_curre OK
+ [Invalid] EF - Heze - Operations - Proposer Slashing - invalid_slots_of_different_epochs   OK
+ [Invalid] EF - Heze - Operations - Proposer Slashing - invalid_slots_same_epoch_different_ OK
+ [Valid]   EF - Heze - Operations - Proposer Slashing - basic                               OK
+ [Valid]   EF - Heze - Operations - Proposer Slashing - block_header_from_future            OK
+ [Valid]   EF - Heze - Operations - Proposer Slashing - block_header_from_past              OK
+ [Valid]   EF - Heze - Operations - Proposer Slashing - builder_payment_deletion_current_ep OK
+ [Valid]   EF - Heze - Operations - Proposer Slashing - builder_payment_deletion_current_ep OK
+ [Valid]   EF - Heze - Operations - Proposer Slashing - builder_payment_deletion_current_ep OK
+ [Valid]   EF - Heze - Operations - Proposer Slashing - builder_payment_deletion_previous_e OK
+ [Valid]   EF - Heze - Operations - Proposer Slashing - builder_payment_deletion_previous_e OK
+ [Valid]   EF - Heze - Operations - Proposer Slashing - builder_payment_deletion_previous_e OK
+ [Valid]   EF - Heze - Operations - Proposer Slashing - builder_payment_deletion_too_late   OK
+ [Valid]   EF - Heze - Operations - Proposer Slashing - builder_payment_empty_current_epoch OK
+ [Valid]   EF - Heze - Operations - Proposer Slashing - builder_payment_empty_old_epoch     OK
+ [Valid]   EF - Heze - Operations - Proposer Slashing - builder_payment_empty_previous_epoc OK
+ [Valid]   EF - Heze - Operations - Proposer Slashing - header_slot_at_epoch_end            OK
+ [Valid]   EF - Heze - Operations - Proposer Slashing - header_slot_at_epoch_start          OK
+ [Valid]   EF - Heze - Operations - Proposer Slashing - headers_differ_multiple_roots       OK
+ [Valid]   EF - Heze - Operations - Proposer Slashing - headers_differ_only_body_root       OK
+ [Valid]   EF - Heze - Operations - Proposer Slashing - headers_differ_only_state_root      OK
+ [Valid]   EF - Heze - Operations - Proposer Slashing - proposer_activated_current_epoch    OK
+ [Valid]   EF - Heze - Operations - Proposer Slashing - proposer_index_last                 OK
+ [Valid]   EF - Heze - Operations - Proposer Slashing - proposer_index_zero                 OK
+ [Valid]   EF - Heze - Operations - Proposer Slashing - proposer_withdrawable_next_epoch    OK
+ [Valid]   EF - Heze - Operations - Proposer Slashing - self_slashing_future_slot           OK
+ [Valid]   EF - Heze - Operations - Proposer Slashing - slashed_and_proposer_index_the_same OK
```
## EF - Heze - Operations - Sync Aggregate  [Preset: minimal]
```diff
+ [Invalid] EF - Heze - Operations - Sync Aggregate - invalid_signature_bad_domain           OK
+ [Invalid] EF - Heze - Operations - Sync Aggregate - invalid_signature_extra_participant    OK
+ [Invalid] EF - Heze - Operations - Sync Aggregate - invalid_signature_infinite_signature_w OK
+ [Invalid] EF - Heze - Operations - Sync Aggregate - invalid_signature_infinite_signature_w OK
+ [Invalid] EF - Heze - Operations - Sync Aggregate - invalid_signature_missing_participant  OK
+ [Invalid] EF - Heze - Operations - Sync Aggregate - invalid_signature_no_participants      OK
+ [Invalid] EF - Heze - Operations - Sync Aggregate - invalid_signature_past_block           OK
+ [Invalid] EF - Heze - Operations - Sync Aggregate - invalid_signature_previous_committee   OK
+ [Valid]   EF - Heze - Operations - Sync Aggregate - proposer_in_committee_with_participati OK
+ [Valid]   EF - Heze - Operations - Sync Aggregate - proposer_in_committee_without_particip OK
+ [Valid]   EF - Heze - Operations - Sync Aggregate - random_all_but_one_participating_witho OK
+ [Valid]   EF - Heze - Operations - Sync Aggregate - random_high_participation_without_dupl OK
+ [Valid]   EF - Heze - Operations - Sync Aggregate - random_low_participation_without_dupli OK
+ [Valid]   EF - Heze - Operations - Sync Aggregate - random_misc_balances_and_half_particip OK
+ [Valid]   EF - Heze - Operations - Sync Aggregate - random_only_one_participant_without_du OK
+ [Valid]   EF - Heze - Operations - Sync Aggregate - random_with_exits_without_duplicates   OK
+ [Valid]   EF - Heze - Operations - Sync Aggregate - sync_committee_rewards_empty_participa OK
+ [Valid]   EF - Heze - Operations - Sync Aggregate - sync_committee_rewards_nonduplicate_co OK
+ [Valid]   EF - Heze - Operations - Sync Aggregate - sync_committee_rewards_not_full_partic OK
+ [Valid]   EF - Heze - Operations - Sync Aggregate - sync_committee_with_nonparticipating_e OK
+ [Valid]   EF - Heze - Operations - Sync Aggregate - sync_committee_with_nonparticipating_w OK
+ [Valid]   EF - Heze - Operations - Sync Aggregate - sync_committee_with_participating_exit OK
+ [Valid]   EF - Heze - Operations - Sync Aggregate - sync_committee_with_participating_with OK
+ [Valid]   EF - Heze - Operations - Sync Aggregate - valid_signature_future_committee       OK
```
## EF - Heze - Operations - Voluntary Exit  [Preset: minimal]
```diff
+ [Invalid] EF - Heze - Operations - Voluntary Exit - builder_voluntary_exit__invalid__bad_s OK
+ [Invalid] EF - Heze - Operations - Voluntary Exit - builder_voluntary_exit__invalid__inact OK
+ [Invalid] EF - Heze - Operations - Voluntary Exit - builder_voluntary_exit__invalid__inact OK
+ [Invalid] EF - Heze - Operations - Voluntary Exit - builder_voluntary_exit__invalid__pendi OK
+ [Invalid] EF - Heze - Operations - Voluntary Exit - builder_voluntary_exit__invalid__pendi OK
+ [Invalid] EF - Heze - Operations - Voluntary Exit - invalid_incorrect_signature            OK
+ [Invalid] EF - Heze - Operations - Voluntary Exit - invalid_validator_already_exited       OK
+ [Invalid] EF - Heze - Operations - Voluntary Exit - invalid_validator_exit_in_future       OK
+ [Invalid] EF - Heze - Operations - Voluntary Exit - invalid_validator_has_pending_withdraw OK
+ [Invalid] EF - Heze - Operations - Voluntary Exit - invalid_validator_incorrect_validator_ OK
+ [Invalid] EF - Heze - Operations - Voluntary Exit - invalid_validator_not_active           OK
+ [Invalid] EF - Heze - Operations - Voluntary Exit - invalid_validator_not_active_long_enou OK
+ [Invalid] EF - Heze - Operations - Voluntary Exit - invalid_voluntary_exit_with_current_fo OK
+ [Invalid] EF - Heze - Operations - Voluntary Exit - invalid_voluntary_exit_with_current_fo OK
+ [Invalid] EF - Heze - Operations - Voluntary Exit - invalid_voluntary_exit_with_genesis_fo OK
+ [Invalid] EF - Heze - Operations - Voluntary Exit - invalid_voluntary_exit_with_genesis_fo OK
+ [Invalid] EF - Heze - Operations - Voluntary Exit - voluntary_exit_with_previous_fork_vers OK
+ [Invalid] EF - Heze - Operations - Voluntary Exit - voluntary_exit_with_previous_fork_vers OK
+ [Valid]   EF - Heze - Operations - Voluntary Exit - basic                                  OK
+ [Valid]   EF - Heze - Operations - Voluntary Exit - builder_voluntary_exit__success        OK
+ [Valid]   EF - Heze - Operations - Voluntary Exit - default_exit_epoch_subsequent_exit     OK
+ [Valid]   EF - Heze - Operations - Voluntary Exit - min_balance_exit                       OK
+ [Valid]   EF - Heze - Operations - Voluntary Exit - min_balance_exits_above_churn          OK
+ [Valid]   EF - Heze - Operations - Voluntary Exit - min_balance_exits_up_to_churn          OK
+ [Valid]   EF - Heze - Operations - Voluntary Exit - success_exit_queue__min_churn          OK
+ [Valid]   EF - Heze - Operations - Voluntary Exit - success_exit_queue__scaled_churn       OK
+ [Valid]   EF - Heze - Operations - Voluntary Exit - voluntary_exit_with_pending_deposit    OK
```
## EF - Heze - Operations - Withdrawal Request  [Preset: minimal]
```diff
+ [Valid]   EF - Heze - Operations - Withdrawal Request - activation_epoch_less_than_shard_c OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - basic_partial_withdrawal_request   OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - basic_partial_withdrawal_request_h OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - basic_partial_withdrawal_request_l OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - basic_withdrawal_request           OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - basic_withdrawal_request_with_comp OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - basic_withdrawal_request_with_firs OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - basic_withdrawal_request_with_full OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - full_exit_request_has_partial_with OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - incorrect_inactive_validator       OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - incorrect_source_address           OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - incorrect_withdrawal_credential_pr OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - insufficient_balance               OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - insufficient_effective_balance     OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - no_compounding_credentials         OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - no_excess_balance                  OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - on_withdrawal_request_initiated_ex OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - partial_withdrawal_activation_epoc OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - partial_withdrawal_incorrect_sourc OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - partial_withdrawal_incorrect_withd OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - partial_withdrawal_on_exit_initiat OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - partial_withdrawal_queue_full      OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - partial_withdrawal_request_with_hi OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - partial_withdrawal_request_with_hi OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - partial_withdrawal_request_with_lo OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - partial_withdrawal_request_with_pe OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - partial_withdrawal_request_with_pe OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - pending_withdrawals_consume_all_ex OK
+ [Valid]   EF - Heze - Operations - Withdrawal Request - unknown_pubkey                     OK
```
## EF - Heze - Operations - Withdrawals  [Preset: minimal]
```diff
+ [Valid]   EF - Heze - Operations - Withdrawals - all_builder_withdrawals_zero_balance      OK
+ [Valid]   EF - Heze - Operations - Withdrawals - builder_and_pending_leave_room_for_sweep  OK
+ [Valid]   EF - Heze - Operations - Withdrawals - builder_max_minus_one_plus_one_regular    OK
+ [Valid]   EF - Heze - Operations - Withdrawals - builder_payments_exceed_limit_blocks_othe OK
+ [Valid]   EF - Heze - Operations - Withdrawals - builder_sweep_index_wrap_around           OK
+ [Valid]   EF - Heze - Operations - Withdrawals - builder_sweep_not_withdrawable_skipped    OK
+ [Valid]   EF - Heze - Operations - Withdrawals - builder_sweep_zero_balance_skipped        OK
+ [Valid]   EF - Heze - Operations - Withdrawals - builder_uses_fee_recipient_address        OK
+ [Valid]   EF - Heze - Operations - Withdrawals - builder_withdrawal_insufficient_balance   OK
+ [Valid]   EF - Heze - Operations - Withdrawals - builder_withdrawal_insufficient_balance_r OK
+ [Valid]   EF - Heze - Operations - Withdrawals - builder_withdrawals_processed_order       OK
+ [Valid]   EF - Heze - Operations - Withdrawals - builder_zero_withdrawal_amount            OK
+ [Valid]   EF - Heze - Operations - Withdrawals - compounding_validator_partial_withdrawal  OK
+ [Valid]   EF - Heze - Operations - Withdrawals - duplicate_builder_index_in_pending_withdr OK
+ [Valid]   EF - Heze - Operations - Withdrawals - early_return_empty_parent_block           OK
+ [Valid]   EF - Heze - Operations - Withdrawals - full_builder_payload_reserves_sweep_slot  OK
+ [Valid]   EF - Heze - Operations - Withdrawals - full_pending_withdrawals_but_first_skippe OK
+ [Valid]   EF - Heze - Operations - Withdrawals - full_pending_withdrawals_but_first_skippe OK
+ [Valid]   EF - Heze - Operations - Withdrawals - full_pending_withdrawals_but_first_skippe OK
+ [Valid]   EF - Heze - Operations - Withdrawals - maximum_withdrawals_per_payload_limit     OK
+ [Valid]   EF - Heze - Operations - Withdrawals - multiple_builder_sweep_withdrawals        OK
+ [Valid]   EF - Heze - Operations - Withdrawals - multiple_builder_withdrawals              OK
+ [Valid]   EF - Heze - Operations - Withdrawals - no_builders_max_pending_with_sweep_spillo OK
+ [Valid]   EF - Heze - Operations - Withdrawals - no_builders_no_pending_max_sweep_withdraw OK
+ [Valid]   EF - Heze - Operations - Withdrawals - partially_withdrawable_validator_compound OK
+ [Valid]   EF - Heze - Operations - Withdrawals - partially_withdrawable_validator_compound OK
+ [Valid]   EF - Heze - Operations - Withdrawals - partially_withdrawable_validator_compound OK
+ [Valid]   EF - Heze - Operations - Withdrawals - partially_withdrawable_validator_compound OK
+ [Valid]   EF - Heze - Operations - Withdrawals - partially_withdrawable_validator_compound OK
+ [Valid]   EF - Heze - Operations - Withdrawals - partially_withdrawable_validator_compound OK
+ [Valid]   EF - Heze - Operations - Withdrawals - partially_withdrawable_validator_legacy_e OK
+ [Valid]   EF - Heze - Operations - Withdrawals - partially_withdrawable_validator_legacy_m OK
+ [Valid]   EF - Heze - Operations - Withdrawals - partially_withdrawable_validator_legacy_m OK
+ [Valid]   EF - Heze - Operations - Withdrawals - pending_withdrawals_at_max                OK
+ [Valid]   EF - Heze - Operations - Withdrawals - pending_withdrawals_at_max_mixed_with_swe OK
+ [Valid]   EF - Heze - Operations - Withdrawals - pending_withdrawals_exiting_validator     OK
+ [Valid]   EF - Heze - Operations - Withdrawals - pending_withdrawals_low_effective_balance OK
+ [Valid]   EF - Heze - Operations - Withdrawals - pending_withdrawals_mixed_with_sweep_and_ OK
+ [Valid]   EF - Heze - Operations - Withdrawals - pending_withdrawals_next_epoch            OK
+ [Valid]   EF - Heze - Operations - Withdrawals - pending_withdrawals_no_excess_balance     OK
+ [Valid]   EF - Heze - Operations - Withdrawals - pending_withdrawals_one_skipped_one_effec OK
+ [Valid]   EF - Heze - Operations - Withdrawals - pending_withdrawals_processing            OK
+ [Valid]   EF - Heze - Operations - Withdrawals - pending_withdrawals_processing_exceeds_li OK
+ [Valid]   EF - Heze - Operations - Withdrawals - pending_withdrawals_two_partial_withdrawa OK
+ [Valid]   EF - Heze - Operations - Withdrawals - pending_withdrawals_two_partial_withdrawa OK
+ [Valid]   EF - Heze - Operations - Withdrawals - pending_withdrawals_with_effective_sweep_ OK
+ [Valid]   EF - Heze - Operations - Withdrawals - pending_withdrawals_with_ineffective_swee OK
+ [Valid]   EF - Heze - Operations - Withdrawals - pending_withdrawals_with_ineffective_swee OK
+ [Valid]   EF - Heze - Operations - Withdrawals - pending_withdrawals_with_sweep_different_ OK
+ [Valid]   EF - Heze - Operations - Withdrawals - random_0                                  OK
+ [Valid]   EF - Heze - Operations - Withdrawals - random_partial_withdrawals_1              OK
+ [Valid]   EF - Heze - Operations - Withdrawals - random_partial_withdrawals_2              OK
+ [Valid]   EF - Heze - Operations - Withdrawals - random_partial_withdrawals_3              OK
+ [Valid]   EF - Heze - Operations - Withdrawals - random_partial_withdrawals_4              OK
+ [Valid]   EF - Heze - Operations - Withdrawals - random_partial_withdrawals_5              OK
+ [Valid]   EF - Heze - Operations - Withdrawals - single_builder_sweep_withdrawal           OK
+ [Valid]   EF - Heze - Operations - Withdrawals - single_builder_withdrawal                 OK
+ [Valid]   EF - Heze - Operations - Withdrawals - success_excess_balance_but_no_max_effecti OK
+ [Valid]   EF - Heze - Operations - Withdrawals - success_excess_balance_but_no_max_effecti OK
+ [Valid]   EF - Heze - Operations - Withdrawals - success_max_partial_withdrawable          OK
+ [Valid]   EF - Heze - Operations - Withdrawals - success_max_plus_one_withdrawable         OK
+ [Valid]   EF - Heze - Operations - Withdrawals - success_mixed_fully_and_partial_withdrawa OK
+ [Valid]   EF - Heze - Operations - Withdrawals - success_mixed_fully_and_partial_withdrawa OK
+ [Valid]   EF - Heze - Operations - Withdrawals - success_no_excess_balance                 OK
+ [Valid]   EF - Heze - Operations - Withdrawals - success_no_excess_balance_compounding     OK
+ [Valid]   EF - Heze - Operations - Withdrawals - success_no_max_effective_balance          OK
+ [Valid]   EF - Heze - Operations - Withdrawals - success_no_max_effective_balance_compound OK
+ [Valid]   EF - Heze - Operations - Withdrawals - success_one_full_withdrawal               OK
+ [Valid]   EF - Heze - Operations - Withdrawals - success_one_partial_withdrawable_active_a OK
+ [Valid]   EF - Heze - Operations - Withdrawals - success_one_partial_withdrawable_exited   OK
+ [Valid]   EF - Heze - Operations - Withdrawals - success_one_partial_withdrawable_exited_a OK
+ [Valid]   EF - Heze - Operations - Withdrawals - success_one_partial_withdrawable_in_exit_ OK
+ [Valid]   EF - Heze - Operations - Withdrawals - success_one_partial_withdrawable_not_yet_ OK
+ [Valid]   EF - Heze - Operations - Withdrawals - success_one_partial_withdrawal            OK
+ [Valid]   EF - Heze - Operations - Withdrawals - success_two_partial_withdrawable          OK
+ [Valid]   EF - Heze - Operations - Withdrawals - success_zero_expected_withdrawals         OK
+ [Valid]   EF - Heze - Operations - Withdrawals - withdrawable_epoch_but_0_balance          OK
+ [Valid]   EF - Heze - Operations - Withdrawals - withdrawable_epoch_but_0_effective_balanc OK
```
## EF - Heze - SSZ consensus objects  [Preset: minimal]
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
+   Testing    Builder                                                                       OK
+   Testing    BuilderPendingPayment                                                         OK
+   Testing    BuilderPendingWithdrawal                                                      OK
+   Testing    Checkpoint                                                                    OK
+   Testing    ConsolidationRequest                                                          OK
+   Testing    ContributionAndProof                                                          OK
+   Testing    DataColumnSidecar                                                             OK
+   Testing    DataColumnsByRootIdentifier                                                   OK
+   Testing    Deposit                                                                       OK
+   Testing    DepositData                                                                   OK
+   Testing    DepositMessage                                                                OK
+   Testing    DepositRequest                                                                OK
+   Testing    Eth1Block                                                                     OK
+   Testing    Eth1Data                                                                      OK
+   Testing    ExecutionPayload                                                              OK
+   Testing    ExecutionPayloadBid                                                           OK
+   Testing    ExecutionPayloadEnvelope                                                      OK
+   Testing    ExecutionPayloadHeader                                                        OK
+   Testing    ExecutionRequests                                                             OK
+   Testing    Fork                                                                          OK
+   Testing    ForkChoiceNode                                                                OK
+   Testing    ForkData                                                                      OK
+   Testing    HistoricalBatch                                                               OK
+   Testing    HistoricalSummary                                                             OK
+   Testing    InclusionList                                                                 OK
+   Testing    IndexedAttestation                                                            OK
+   Testing    IndexedPayloadAttestation                                                     OK
+   Testing    LightClientBootstrap                                                          OK
+   Testing    LightClientFinalityUpdate                                                     OK
+   Testing    LightClientHeader                                                             OK
+   Testing    LightClientOptimisticUpdate                                                   OK
+   Testing    LightClientUpdate                                                             OK
+   Testing    MatrixEntry                                                                   OK
+   Testing    PartialDataColumnHeader                                                       OK
+   Testing    PartialDataColumnPartsMetadata                                                OK
+   Testing    PartialDataColumnSidecar                                                      OK
+   Testing    PayloadAttestation                                                            OK
+   Testing    PayloadAttestationData                                                        OK
+   Testing    PayloadAttestationMessage                                                     OK
+   Testing    PendingAttestation                                                            OK
+   Testing    PendingConsolidation                                                          OK
+   Testing    PendingDeposit                                                                OK
+   Testing    PendingPartialWithdrawal                                                      OK
+   Testing    PowBlock                                                                      OK
+   Testing    ProposerPreferences                                                           OK
+   Testing    ProposerSlashing                                                              OK
+   Testing    SignedAggregateAndProof                                                       OK
+   Testing    SignedBLSToExecutionChange                                                    OK
+   Testing    SignedBeaconBlock                                                             OK
+   Testing    SignedBeaconBlockHeader                                                       OK
+   Testing    SignedContributionAndProof                                                    OK
+   Testing    SignedExecutionPayloadBid                                                     OK
+   Testing    SignedExecutionPayloadEnvelope                                                OK
+   Testing    SignedInclusionList                                                           OK
+   Testing    SignedProposerPreferences                                                     OK
+   Testing    SignedVoluntaryExit                                                           OK
+   Testing    SigningData                                                                   OK
+   Testing    SingleAttestation                                                             OK
+   Testing    SyncAggregate                                                                 OK
+   Testing    SyncAggregatorSelectionData                                                   OK
+   Testing    SyncCommittee                                                                 OK
+   Testing    SyncCommitteeContribution                                                     OK
+   Testing    SyncCommitteeMessage                                                          OK
+   Testing    Validator                                                                     OK
+   Testing    VoluntaryExit                                                                 OK
+   Testing    Withdrawal                                                                    OK
+   Testing    WithdrawalRequest                                                             OK
```
## EF - Heze - Sanity - Slots  [Preset: minimal]
```diff
+ EF - Heze - Slots - balance_change_affects_proposer [Preset: minimal]                      OK
+ EF - Heze - Slots - double_empty_epoch [Preset: minimal]                                   OK
+ EF - Heze - Slots - effective_decrease_balance_updates_lookahead [Preset: minimal]         OK
+ EF - Heze - Slots - empty_epoch [Preset: minimal]                                          OK
+ EF - Heze - Slots - execution_payload_availability_reset_from_set [Preset: minimal]        OK
+ EF - Heze - Slots - execution_payload_availability_reset_from_unset [Preset: minimal]      OK
+ EF - Heze - Slots - historical_accumulator [Preset: minimal]                               OK
+ EF - Heze - Slots - multiple_pending_deposits_same_pubkey [Preset: minimal]                OK
+ EF - Heze - Slots - multiple_pending_deposits_same_pubkey_above_upward_threshold [Preset:  OK
+ EF - Heze - Slots - multiple_pending_deposits_same_pubkey_below_upward_threshold [Preset:  OK
+ EF - Heze - Slots - multiple_pending_deposits_same_pubkey_compounding [Preset: minimal]    OK
+ EF - Heze - Slots - multiple_pending_deposits_same_pubkey_different_signature [Preset: min OK
+ EF - Heze - Slots - over_epoch_boundary [Preset: minimal]                                  OK
+ EF - Heze - Slots - pending_consolidation [Preset: minimal]                                OK
+ EF - Heze - Slots - pending_deposit_extra_gwei [Preset: minimal]                           OK
+ EF - Heze - Slots - slots_1 [Preset: minimal]                                              OK
+ EF - Heze - Slots - slots_2 [Preset: minimal]                                              OK
```
## EF - Heze - Transition  [Preset: minimal]
```diff
+ EF - Heze - Transition - higher_churn_limit_to_lower [Preset: minimal]                     OK
+ EF - Heze - Transition - non_empty_historical_roots [Preset: minimal]                      OK
+ EF - Heze - Transition - normal_transition [Preset: minimal]                               OK
+ EF - Heze - Transition - simple_transition [Preset: minimal]                               OK
+ EF - Heze - Transition - transition_attestation_from_previous_fork_with_new_range [Preset: OK
+ EF - Heze - Transition - transition_missing_first_post_block [Preset: minimal]             OK
+ EF - Heze - Transition - transition_missing_last_pre_fork_block [Preset: minimal]          OK
+ EF - Heze - Transition - transition_only_blocks_post_fork [Preset: minimal]                OK
+ EF - Heze - Transition - transition_randomized_state [Preset: minimal]                     OK
+ EF - Heze - Transition - transition_with_activation_at_fork_epoch [Preset: minimal]        OK
+ EF - Heze - Transition - transition_with_attester_slashing_right_after_fork [Preset: minim OK
+ EF - Heze - Transition - transition_with_attester_slashing_right_before_fork [Preset: mini OK
+ EF - Heze - Transition - transition_with_btec_right_after_fork [Preset: minimal]           OK
+ EF - Heze - Transition - transition_with_btec_right_before_fork [Preset: minimal]          OK
+ EF - Heze - Transition - transition_with_deposit_right_after_fork [Preset: minimal]        OK
+ EF - Heze - Transition - transition_with_deposit_right_before_fork [Preset: minimal]       OK
+ EF - Heze - Transition - transition_with_finality [Preset: minimal]                        OK
+ EF - Heze - Transition - transition_with_leaking_at_fork [Preset: minimal]                 OK
+ EF - Heze - Transition - transition_with_leaking_pre_fork [Preset: minimal]                OK
+ EF - Heze - Transition - transition_with_no_attestations_until_after_fork [Preset: minimal OK
+ EF - Heze - Transition - transition_with_non_empty_activation_queue [Preset: minimal]      OK
+ EF - Heze - Transition - transition_with_one_fourth_exiting_validators_exit_at_fork [Prese OK
+ EF - Heze - Transition - transition_with_one_fourth_exiting_validators_exit_post_fork [Pre OK
+ EF - Heze - Transition - transition_with_one_fourth_slashed_active_validators_pre_fork [Pr OK
+ EF - Heze - Transition - transition_with_proposer_slashing_right_after_fork [Preset: minim OK
+ EF - Heze - Transition - transition_with_proposer_slashing_right_before_fork [Preset: mini OK
+ EF - Heze - Transition - transition_with_random_half_participation [Preset: minimal]       OK
+ EF - Heze - Transition - transition_with_random_three_quarters_participation [Preset: mini OK
+ EF - Heze - Transition - transition_with_voluntary_exit_right_after_fork [Preset: minimal] OK
+ EF - Heze - Transition - transition_with_voluntary_exit_right_before_fork [Preset: minimal OK
```
## EF - Light client - Data collection [Preset: minimal]
```diff
+ Light client - Data collection - minimal/altair/light_client/data_collection/pyspec_tests/ OK
+ Light client - Data collection - minimal/bellatrix/light_client/data_collection/pyspec_tes OK
+ Light client - Data collection - minimal/bellatrix/light_client/data_collection/pyspec_tes OK
+ Light client - Data collection - minimal/bellatrix/light_client/data_collection/pyspec_tes OK
+ Light client - Data collection - minimal/capella/light_client/data_collection/pyspec_tests OK
+ Light client - Data collection - minimal/capella/light_client/data_collection/pyspec_tests OK
+ Light client - Data collection - minimal/capella/light_client/data_collection/pyspec_tests OK
+ Light client - Data collection - minimal/deneb/light_client/data_collection/pyspec_tests/l OK
+ Light client - Data collection - minimal/electra/light_client/data_collection/pyspec_tests OK
+ Light client - Data collection - minimal/fulu/light_client/data_collection/pyspec_tests/li OK
```
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
+ Light client - Single merkle proof - minimal/electra/light_client/single_merkle_proof/Beac OK
+ Light client - Single merkle proof - minimal/electra/light_client/single_merkle_proof/Beac OK
+ Light client - Single merkle proof - minimal/electra/light_client/single_merkle_proof/Beac OK
+ Light client - Single merkle proof - minimal/electra/light_client/single_merkle_proof/Beac OK
+ Light client - Single merkle proof - minimal/fulu/light_client/single_merkle_proof/BeaconB OK
+ Light client - Single merkle proof - minimal/fulu/light_client/single_merkle_proof/BeaconS OK
+ Light client - Single merkle proof - minimal/fulu/light_client/single_merkle_proof/BeaconS OK
+ Light client - Single merkle proof - minimal/fulu/light_client/single_merkle_proof/BeaconS OK
```
## EF - Light client - Sync [Preset: minimal]
```diff
+ Light client - Sync - minimal/altair/light_client/sync/pyspec_tests/advance_finality_witho OK
+ Light client - Sync - minimal/altair/light_client/sync/pyspec_tests/capella_store_with_leg OK
+ Light client - Sync - minimal/altair/light_client/sync/pyspec_tests/deneb_store_with_legac OK
+ Light client - Sync - minimal/altair/light_client/sync/pyspec_tests/electra_store_with_leg OK
+ Light client - Sync - minimal/altair/light_client/sync/pyspec_tests/light_client_sync      OK
+ Light client - Sync - minimal/altair/light_client/sync/pyspec_tests/light_client_sync_no_f OK
+ Light client - Sync - minimal/altair/light_client/sync/pyspec_tests/supply_sync_committee_ OK
+ Light client - Sync - minimal/bellatrix/light_client/sync/pyspec_tests/advance_finality_wi OK
+ Light client - Sync - minimal/bellatrix/light_client/sync/pyspec_tests/capella_deneb_fork  OK
+ Light client - Sync - minimal/bellatrix/light_client/sync/pyspec_tests/capella_electra_for OK
+ Light client - Sync - minimal/bellatrix/light_client/sync/pyspec_tests/capella_fork        OK
+ Light client - Sync - minimal/bellatrix/light_client/sync/pyspec_tests/capella_store_with_ OK
+ Light client - Sync - minimal/bellatrix/light_client/sync/pyspec_tests/deneb_store_with_le OK
+ Light client - Sync - minimal/bellatrix/light_client/sync/pyspec_tests/electra_store_with_ OK
+ Light client - Sync - minimal/bellatrix/light_client/sync/pyspec_tests/light_client_sync   OK
+ Light client - Sync - minimal/bellatrix/light_client/sync/pyspec_tests/light_client_sync_n OK
+ Light client - Sync - minimal/bellatrix/light_client/sync/pyspec_tests/supply_sync_committ OK
+ Light client - Sync - minimal/capella/light_client/sync/pyspec_tests/advance_finality_with OK
+ Light client - Sync - minimal/capella/light_client/sync/pyspec_tests/deneb_electra_fork    OK
+ Light client - Sync - minimal/capella/light_client/sync/pyspec_tests/deneb_fork            OK
+ Light client - Sync - minimal/capella/light_client/sync/pyspec_tests/deneb_store_with_lega OK
+ Light client - Sync - minimal/capella/light_client/sync/pyspec_tests/electra_store_with_le OK
+ Light client - Sync - minimal/capella/light_client/sync/pyspec_tests/light_client_sync     OK
+ Light client - Sync - minimal/capella/light_client/sync/pyspec_tests/light_client_sync_no_ OK
+ Light client - Sync - minimal/capella/light_client/sync/pyspec_tests/supply_sync_committee OK
+ Light client - Sync - minimal/deneb/light_client/sync/pyspec_tests/advance_finality_withou OK
+ Light client - Sync - minimal/deneb/light_client/sync/pyspec_tests/electra_fork            OK
+ Light client - Sync - minimal/deneb/light_client/sync/pyspec_tests/electra_store_with_lega OK
+ Light client - Sync - minimal/deneb/light_client/sync/pyspec_tests/light_client_sync       OK
+ Light client - Sync - minimal/deneb/light_client/sync/pyspec_tests/light_client_sync_no_fo OK
+ Light client - Sync - minimal/deneb/light_client/sync/pyspec_tests/supply_sync_committee_f OK
+ Light client - Sync - minimal/electra/light_client/sync/pyspec_tests/advance_finality_with OK
+ Light client - Sync - minimal/electra/light_client/sync/pyspec_tests/light_client_sync     OK
+ Light client - Sync - minimal/electra/light_client/sync/pyspec_tests/light_client_sync_no_ OK
+ Light client - Sync - minimal/electra/light_client/sync/pyspec_tests/supply_sync_committee OK
+ Light client - Sync - minimal/fulu/light_client/sync/pyspec_tests/advance_finality_without OK
+ Light client - Sync - minimal/fulu/light_client/sync/pyspec_tests/light_client_sync        OK
+ Light client - Sync - minimal/fulu/light_client/sync/pyspec_tests/light_client_sync_no_for OK
+ Light client - Sync - minimal/fulu/light_client/sync/pyspec_tests/supply_sync_committee_fr OK
```
## EF - Light client - Update ranking [Preset: minimal]
```diff
+ Light client - Update ranking - minimal/altair/light_client/update_ranking/pyspec_tests/up OK
+ Light client - Update ranking - minimal/bellatrix/light_client/update_ranking/pyspec_tests OK
+ Light client - Update ranking - minimal/capella/light_client/update_ranking/pyspec_tests/u OK
+ Light client - Update ranking - minimal/deneb/light_client/update_ranking/pyspec_tests/upd OK
+ Light client - Update ranking - minimal/electra/light_client/update_ranking/pyspec_tests/u OK
+ Light client - Update ranking - minimal/fulu/light_client/update_ranking/pyspec_tests/upda OK
```
## EF - Merkle proof [Preset: minimal]
```diff
+ Merkle proof - Single merkle proof - minimal/deneb/merkle_proof/single_merkle_proof/Beacon OK
+ Merkle proof - Single merkle proof - minimal/deneb/merkle_proof/single_merkle_proof/Beacon OK
+ Merkle proof - Single merkle proof - minimal/deneb/merkle_proof/single_merkle_proof/Beacon OK
+ Merkle proof - Single merkle proof - minimal/deneb/merkle_proof/single_merkle_proof/Beacon OK
+ Merkle proof - Single merkle proof - minimal/electra/merkle_proof/single_merkle_proof/Beac OK
+ Merkle proof - Single merkle proof - minimal/electra/merkle_proof/single_merkle_proof/Beac OK
+ Merkle proof - Single merkle proof - minimal/electra/merkle_proof/single_merkle_proof/Beac OK
+ Merkle proof - Single merkle proof - minimal/electra/merkle_proof/single_merkle_proof/Beac OK
+ Merkle proof - Single merkle proof - minimal/fulu/merkle_proof/single_merkle_proof/BeaconB OK
+ Merkle proof - Single merkle proof - minimal/fulu/merkle_proof/single_merkle_proof/BeaconB OK
+ Merkle proof - Single merkle proof - minimal/fulu/merkle_proof/single_merkle_proof/BeaconB OK
+ Merkle proof - Single merkle proof - minimal/fulu/merkle_proof/single_merkle_proof/BeaconB OK
```
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
## EF - Phase 0 - Operations - Block Header  [Preset: minimal]
```diff
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Block Header  [Preset: m OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Block Header  [Preset: m OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Block Header  [Preset: m OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Block Header  [Preset: m OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Block Header  [Preset: m OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Block Header  [Preset: m OK
```
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
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Invalid] EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
+ [Valid]   EF - Phase 0 - Operations - EF - Phase 0 - Operations - Proposer Slashing  [Pres OK
```
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
## EF - Phase 0 - Sanity - Slots  [Preset: minimal]
```diff
+ EF - Phase 0 - Slots - balance_change_affects_proposer [Preset: minimal]                   OK
+ EF - Phase 0 - Slots - double_empty_epoch [Preset: minimal]                                OK
+ EF - Phase 0 - Slots - empty_epoch [Preset: minimal]                                       OK
+ EF - Phase 0 - Slots - historical_accumulator [Preset: minimal]                            OK
+ EF - Phase 0 - Slots - over_epoch_boundary [Preset: minimal]                               OK
+ EF - Phase 0 - Slots - slots_1 [Preset: minimal]                                           OK
+ EF - Phase 0 - Slots - slots_2 [Preset: minimal]                                           OK
```
## EF - altair - Epoch Processing - Effective balance updates [Preset: minimal]
```diff
+ Effective balance updates - effective_balance_hysteresis [Preset: minimal]                 OK
```
## EF - altair - Epoch Processing - Eth1 data reset [Preset: minimal]
```diff
+ Eth1 data reset - eth1_vote_no_reset [Preset: minimal]                                     OK
+ Eth1 data reset - eth1_vote_reset [Preset: minimal]                                        OK
```
## EF - altair - Epoch Processing - Historical roots update [Preset: minimal]
```diff
+ Historical roots update - historical_root_accumulator [Preset: minimal]                    OK
```
## EF - altair - Epoch Processing - Inactivity [Preset: minimal]
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
## EF - altair - Epoch Processing - Justification & Finalization [Preset: minimal]
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
## EF - altair - Epoch Processing - Participation flag updates [Preset: minimal]
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
## EF - altair - Epoch Processing - RANDAO mixes reset [Preset: minimal]
```diff
+ RANDAO mixes reset - updated_randao_mixes [Preset: minimal]                                OK
```
## EF - altair - Epoch Processing - Registry updates [Preset: minimal]
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
## EF - altair - Epoch Processing - Rewards and penalties [Preset: minimal]
```diff
+ Rewards and penalties - almost_empty_attestations [Preset: minimal]                        OK
+ Rewards and penalties - almost_empty_attestations_with_leak [Preset: minimal]              OK
+ Rewards and penalties - almost_full_attestations [Preset: minimal]                         OK
+ Rewards and penalties - almost_full_attestations_with_leak [Preset: minimal]               OK
+ Rewards and penalties - attestations_some_slashed [Preset: minimal]                        OK
+ Rewards and penalties - duplicate_attestation [Preset: minimal]                            OK
+ Rewards and penalties - full_attestation_participation [Preset: minimal]                   OK
+ Rewards and penalties - full_attestation_participation_with_leak [Preset: minimal]         OK
+ Rewards and penalties - full_attestations_default_balances_except_a_validator_with_one_gwe OK
+ Rewards and penalties - full_attestations_misc_balances [Preset: minimal]                  OK
+ Rewards and penalties - genesis_epoch_full_attestations_no_rewards [Preset: minimal]       OK
+ Rewards and penalties - genesis_epoch_no_attestations_no_penalties [Preset: minimal]       OK
+ Rewards and penalties - no_attestations_all_penalties [Preset: minimal]                    OK
+ Rewards and penalties - random_fill_attestations [Preset: minimal]                         OK
+ Rewards and penalties - random_fill_attestations_with_leak [Preset: minimal]               OK
```
## EF - altair - Epoch Processing - Slashings [Preset: minimal]
```diff
+ Slashings - low_penalty [Preset: minimal]                                                  OK
+ Slashings - max_penalties [Preset: minimal]                                                OK
+ Slashings - minimal_penalty [Preset: minimal]                                              OK
+ Slashings - scaled_penalties [Preset: minimal]                                             OK
+ Slashings - slashings_with_random_state [Preset: minimal]                                  OK
```
## EF - altair - Epoch Processing - Slashings reset [Preset: minimal]
```diff
+ Slashings reset - flush_slashings [Preset: minimal]                                        OK
```
## EF - altair - Epoch Processing - Sync committee updates [Preset: minimal]
```diff
+ Sync committee updates - sync_committees_no_progress_not_at_period_boundary [Preset: minim OK
+ Sync committee updates - sync_committees_progress_genesis [Preset: minimal]                OK
+ Sync committee updates - sync_committees_progress_misc_balances_genesis [Preset: minimal]  OK
+ Sync committee updates - sync_committees_progress_misc_balances_not_genesis [Preset: minim OK
+ Sync committee updates - sync_committees_progress_not_genesis [Preset: minimal]            OK
```
## EF - altair - Finality  [Preset: minimal]
```diff
+ [Valid]   EF - altair - Finality - finality_no_updates_at_genesis [Preset: minimal]        OK
+ [Valid]   EF - altair - Finality - finality_rule_1 [Preset: minimal]                       OK
+ [Valid]   EF - altair - Finality - finality_rule_2 [Preset: minimal]                       OK
+ [Valid]   EF - altair - Finality - finality_rule_3 [Preset: minimal]                       OK
+ [Valid]   EF - altair - Finality - finality_rule_4 [Preset: minimal]                       OK
```
## EF - altair - Random  [Preset: minimal]
```diff
+ [Valid]   EF - altair - Random - randomized_0 [Preset: minimal]                            OK
+ [Valid]   EF - altair - Random - randomized_1 [Preset: minimal]                            OK
+ [Valid]   EF - altair - Random - randomized_10 [Preset: minimal]                           OK
+ [Valid]   EF - altair - Random - randomized_11 [Preset: minimal]                           OK
+ [Valid]   EF - altair - Random - randomized_12 [Preset: minimal]                           OK
+ [Valid]   EF - altair - Random - randomized_13 [Preset: minimal]                           OK
+ [Valid]   EF - altair - Random - randomized_14 [Preset: minimal]                           OK
+ [Valid]   EF - altair - Random - randomized_15 [Preset: minimal]                           OK
+ [Valid]   EF - altair - Random - randomized_2 [Preset: minimal]                            OK
+ [Valid]   EF - altair - Random - randomized_3 [Preset: minimal]                            OK
+ [Valid]   EF - altair - Random - randomized_4 [Preset: minimal]                            OK
+ [Valid]   EF - altair - Random - randomized_5 [Preset: minimal]                            OK
+ [Valid]   EF - altair - Random - randomized_6 [Preset: minimal]                            OK
+ [Valid]   EF - altair - Random - randomized_7 [Preset: minimal]                            OK
+ [Valid]   EF - altair - Random - randomized_8 [Preset: minimal]                            OK
+ [Valid]   EF - altair - Random - randomized_9 [Preset: minimal]                            OK
```
## EF - altair - Rewards  [Preset: minimal]
```diff
+ EF - altair - Rewards - all_balances_too_low_for_reward [Preset: minimal]                  OK
+ EF - altair - Rewards - empty [Preset: minimal]                                            OK
+ EF - altair - Rewards - empty_leak [Preset: minimal]                                       OK
+ EF - altair - Rewards - full_all_correct [Preset: minimal]                                 OK
+ EF - altair - Rewards - full_but_partial_participation [Preset: minimal]                   OK
+ EF - altair - Rewards - full_but_partial_participation_leak [Preset: minimal]              OK
+ EF - altair - Rewards - full_leak [Preset: minimal]                                        OK
+ EF - altair - Rewards - full_random_0 [Preset: minimal]                                    OK
+ EF - altair - Rewards - full_random_1 [Preset: minimal]                                    OK
+ EF - altair - Rewards - full_random_2 [Preset: minimal]                                    OK
+ EF - altair - Rewards - full_random_3 [Preset: minimal]                                    OK
+ EF - altair - Rewards - full_random_4 [Preset: minimal]                                    OK
+ EF - altair - Rewards - full_random_leak [Preset: minimal]                                 OK
+ EF - altair - Rewards - full_random_low_balances_0 [Preset: minimal]                       OK
+ EF - altair - Rewards - full_random_low_balances_1 [Preset: minimal]                       OK
+ EF - altair - Rewards - full_random_misc_balances [Preset: minimal]                        OK
+ EF - altair - Rewards - full_random_seven_epoch_leak [Preset: minimal]                     OK
+ EF - altair - Rewards - full_random_ten_epoch_leak [Preset: minimal]                       OK
+ EF - altair - Rewards - full_random_without_leak_0 [Preset: minimal]                       OK
+ EF - altair - Rewards - full_random_without_leak_and_current_exit_0 [Preset: minimal]      OK
+ EF - altair - Rewards - half_full [Preset: minimal]                                        OK
+ EF - altair - Rewards - half_full_leak [Preset: minimal]                                   OK
+ EF - altair - Rewards - quarter_full [Preset: minimal]                                     OK
+ EF - altair - Rewards - quarter_full_leak [Preset: minimal]                                OK
+ EF - altair - Rewards - some_very_low_effective_balances_that_attested [Preset: minimal]   OK
+ EF - altair - Rewards - some_very_low_effective_balances_that_attested_leak [Preset: minim OK
+ EF - altair - Rewards - some_very_low_effective_balances_that_did_not_attest [Preset: mini OK
+ EF - altair - Rewards - some_very_low_effective_balances_that_did_not_attest_leak [Preset: OK
+ EF - altair - Rewards - with_exited_validators [Preset: minimal]                           OK
+ EF - altair - Rewards - with_exited_validators_leak [Preset: minimal]                      OK
+ EF - altair - Rewards - with_not_yet_activated_validators [Preset: minimal]                OK
+ EF - altair - Rewards - with_not_yet_activated_validators_leak [Preset: minimal]           OK
+ EF - altair - Rewards - with_slashed_validators [Preset: minimal]                          OK
+ EF - altair - Rewards - with_slashed_validators_leak [Preset: minimal]                     OK
```
## EF - altair - Sanity - Blocks  [Preset: minimal]
```diff
+ [Invalid] EF - altair - Sanity - Blocks - invalid_all_zeroed_sig [Preset: minimal]         OK
+ [Invalid] EF - altair - Sanity - Blocks - invalid_duplicate_attester_slashing_same_block [ OK
+ [Invalid] EF - altair - Sanity - Blocks - invalid_duplicate_deposit_same_block [Preset: mi OK
+ [Invalid] EF - altair - Sanity - Blocks - invalid_duplicate_proposer_slashings_same_block  OK
+ [Invalid] EF - altair - Sanity - Blocks - invalid_duplicate_validator_exit_same_block [Pre OK
+ [Invalid] EF - altair - Sanity - Blocks - invalid_incorrect_block_sig [Preset: minimal]    OK
+ [Invalid] EF - altair - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_expect OK
+ [Invalid] EF - altair - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_propos OK
+ [Invalid] EF - altair - Sanity - Blocks - invalid_incorrect_state_root [Preset: minimal]   OK
+ [Invalid] EF - altair - Sanity - Blocks - invalid_only_increase_deposit_count [Preset: min OK
+ [Invalid] EF - altair - Sanity - Blocks - invalid_parent_from_same_slot [Preset: minimal]  OK
+ [Invalid] EF - altair - Sanity - Blocks - invalid_prev_slot_block_transition [Preset: mini OK
+ [Invalid] EF - altair - Sanity - Blocks - invalid_same_slot_block_transition [Preset: mini OK
+ [Invalid] EF - altair - Sanity - Blocks - invalid_similar_proposer_slashings_same_block [P OK
+ [Invalid] EF - altair - Sanity - Blocks - slash_and_exit_same_index [Preset: minimal]      OK
+ [Valid]   EF - altair - Sanity - Blocks - attestation [Preset: minimal]                    OK
+ [Valid]   EF - altair - Sanity - Blocks - attester_slashing [Preset: minimal]              OK
+ [Valid]   EF - altair - Sanity - Blocks - balance_driven_status_transitions [Preset: minim OK
+ [Valid]   EF - altair - Sanity - Blocks - deposit_in_block [Preset: minimal]               OK
+ [Valid]   EF - altair - Sanity - Blocks - deposit_top_up [Preset: minimal]                 OK
+ [Valid]   EF - altair - Sanity - Blocks - duplicate_attestation_same_block [Preset: minima OK
+ [Valid]   EF - altair - Sanity - Blocks - empty_block_transition [Preset: minimal]         OK
+ [Valid]   EF - altair - Sanity - Blocks - empty_block_transition_large_validator_set [Pres OK
+ [Valid]   EF - altair - Sanity - Blocks - empty_epoch_transition [Preset: minimal]         OK
+ [Valid]   EF - altair - Sanity - Blocks - empty_epoch_transition_large_validator_set [Pres OK
+ [Valid]   EF - altair - Sanity - Blocks - empty_epoch_transition_not_finalizing [Preset: m OK
+ [Valid]   EF - altair - Sanity - Blocks - eth1_data_votes_consensus [Preset: minimal]      OK
+ [Valid]   EF - altair - Sanity - Blocks - eth1_data_votes_no_consensus [Preset: minimal]   OK
+ [Valid]   EF - altair - Sanity - Blocks - full_random_operations_0 [Preset: minimal]       OK
+ [Valid]   EF - altair - Sanity - Blocks - full_random_operations_1 [Preset: minimal]       OK
+ [Valid]   EF - altair - Sanity - Blocks - full_random_operations_2 [Preset: minimal]       OK
+ [Valid]   EF - altair - Sanity - Blocks - full_random_operations_3 [Preset: minimal]       OK
+ [Valid]   EF - altair - Sanity - Blocks - high_proposer_index [Preset: minimal]            OK
+ [Valid]   EF - altair - Sanity - Blocks - historical_batch [Preset: minimal]               OK
+ [Valid]   EF - altair - Sanity - Blocks - inactivity_scores_full_participation_leaking [Pr OK
+ [Valid]   EF - altair - Sanity - Blocks - inactivity_scores_leaking [Preset: minimal]      OK
+ [Valid]   EF - altair - Sanity - Blocks - multiple_attester_slashings_no_overlap [Preset:  OK
+ [Valid]   EF - altair - Sanity - Blocks - multiple_attester_slashings_partial_overlap [Pre OK
+ [Valid]   EF - altair - Sanity - Blocks - multiple_different_proposer_slashings_same_block OK
+ [Valid]   EF - altair - Sanity - Blocks - multiple_different_validator_exits_same_block [P OK
+ [Valid]   EF - altair - Sanity - Blocks - proposer_after_inactive_index [Preset: minimal]  OK
+ [Valid]   EF - altair - Sanity - Blocks - proposer_self_slashing [Preset: minimal]         OK
+ [Valid]   EF - altair - Sanity - Blocks - proposer_slashing [Preset: minimal]              OK
+ [Valid]   EF - altair - Sanity - Blocks - skipped_slots [Preset: minimal]                  OK
+ [Valid]   EF - altair - Sanity - Blocks - slash_and_exit_diff_index [Preset: minimal]      OK
+ [Valid]   EF - altair - Sanity - Blocks - sync_committee_committee__empty [Preset: minimal OK
+ [Valid]   EF - altair - Sanity - Blocks - sync_committee_committee__full [Preset: minimal] OK
+ [Valid]   EF - altair - Sanity - Blocks - sync_committee_committee__half [Preset: minimal] OK
+ [Valid]   EF - altair - Sanity - Blocks - sync_committee_committee_genesis__empty [Preset: OK
+ [Valid]   EF - altair - Sanity - Blocks - sync_committee_committee_genesis__full [Preset:  OK
+ [Valid]   EF - altair - Sanity - Blocks - sync_committee_committee_genesis__half [Preset:  OK
+ [Valid]   EF - altair - Sanity - Blocks - voluntary_exit [Preset: minimal]                 OK
```
## EF - bellatrix - Epoch Processing - Effective balance updates [Preset: minimal]
```diff
+ Effective balance updates - effective_balance_hysteresis [Preset: minimal]                 OK
```
## EF - bellatrix - Epoch Processing - Eth1 data reset [Preset: minimal]
```diff
+ Eth1 data reset - eth1_vote_no_reset [Preset: minimal]                                     OK
+ Eth1 data reset - eth1_vote_reset [Preset: minimal]                                        OK
```
## EF - bellatrix - Epoch Processing - Historical roots update [Preset: minimal]
```diff
+ Historical roots update - historical_root_accumulator [Preset: minimal]                    OK
```
## EF - bellatrix - Epoch Processing - Inactivity [Preset: minimal]
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
## EF - bellatrix - Epoch Processing - Justification & Finalization [Preset: minimal]
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
## EF - bellatrix - Epoch Processing - Participation flag updates [Preset: minimal]
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
## EF - bellatrix - Epoch Processing - RANDAO mixes reset [Preset: minimal]
```diff
+ RANDAO mixes reset - updated_randao_mixes [Preset: minimal]                                OK
```
## EF - bellatrix - Epoch Processing - Registry updates [Preset: minimal]
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
## EF - bellatrix - Epoch Processing - Rewards and penalties [Preset: minimal]
```diff
+ Rewards and penalties - almost_empty_attestations [Preset: minimal]                        OK
+ Rewards and penalties - almost_empty_attestations_with_leak [Preset: minimal]              OK
+ Rewards and penalties - almost_full_attestations [Preset: minimal]                         OK
+ Rewards and penalties - almost_full_attestations_with_leak [Preset: minimal]               OK
+ Rewards and penalties - attestations_some_slashed [Preset: minimal]                        OK
+ Rewards and penalties - duplicate_attestation [Preset: minimal]                            OK
+ Rewards and penalties - full_attestation_participation [Preset: minimal]                   OK
+ Rewards and penalties - full_attestation_participation_with_leak [Preset: minimal]         OK
+ Rewards and penalties - full_attestations_default_balances_except_a_validator_with_one_gwe OK
+ Rewards and penalties - full_attestations_misc_balances [Preset: minimal]                  OK
+ Rewards and penalties - genesis_epoch_full_attestations_no_rewards [Preset: minimal]       OK
+ Rewards and penalties - genesis_epoch_no_attestations_no_penalties [Preset: minimal]       OK
+ Rewards and penalties - no_attestations_all_penalties [Preset: minimal]                    OK
+ Rewards and penalties - random_fill_attestations [Preset: minimal]                         OK
+ Rewards and penalties - random_fill_attestations_with_leak [Preset: minimal]               OK
```
## EF - bellatrix - Epoch Processing - Slashings [Preset: minimal]
```diff
+ Slashings - low_penalty [Preset: minimal]                                                  OK
+ Slashings - max_penalties [Preset: minimal]                                                OK
+ Slashings - minimal_penalty [Preset: minimal]                                              OK
+ Slashings - scaled_penalties [Preset: minimal]                                             OK
+ Slashings - slashings_with_random_state [Preset: minimal]                                  OK
```
## EF - bellatrix - Epoch Processing - Slashings reset [Preset: minimal]
```diff
+ Slashings reset - flush_slashings [Preset: minimal]                                        OK
```
## EF - bellatrix - Epoch Processing - Sync committee updates [Preset: minimal]
```diff
+ Sync committee updates - sync_committees_no_progress_not_at_period_boundary [Preset: minim OK
+ Sync committee updates - sync_committees_progress_genesis [Preset: minimal]                OK
+ Sync committee updates - sync_committees_progress_misc_balances_genesis [Preset: minimal]  OK
+ Sync committee updates - sync_committees_progress_misc_balances_not_genesis [Preset: minim OK
+ Sync committee updates - sync_committees_progress_not_genesis [Preset: minimal]            OK
```
## EF - bellatrix - Finality  [Preset: minimal]
```diff
+ [Valid]   EF - bellatrix - Finality - finality_no_updates_at_genesis [Preset: minimal]     OK
+ [Valid]   EF - bellatrix - Finality - finality_rule_1 [Preset: minimal]                    OK
+ [Valid]   EF - bellatrix - Finality - finality_rule_2 [Preset: minimal]                    OK
+ [Valid]   EF - bellatrix - Finality - finality_rule_3 [Preset: minimal]                    OK
+ [Valid]   EF - bellatrix - Finality - finality_rule_4 [Preset: minimal]                    OK
```
## EF - bellatrix - Random  [Preset: minimal]
```diff
+ [Valid]   EF - bellatrix - Random - randomized_0 [Preset: minimal]                         OK
+ [Valid]   EF - bellatrix - Random - randomized_1 [Preset: minimal]                         OK
+ [Valid]   EF - bellatrix - Random - randomized_10 [Preset: minimal]                        OK
+ [Valid]   EF - bellatrix - Random - randomized_11 [Preset: minimal]                        OK
+ [Valid]   EF - bellatrix - Random - randomized_12 [Preset: minimal]                        OK
+ [Valid]   EF - bellatrix - Random - randomized_13 [Preset: minimal]                        OK
+ [Valid]   EF - bellatrix - Random - randomized_14 [Preset: minimal]                        OK
+ [Valid]   EF - bellatrix - Random - randomized_15 [Preset: minimal]                        OK
+ [Valid]   EF - bellatrix - Random - randomized_2 [Preset: minimal]                         OK
+ [Valid]   EF - bellatrix - Random - randomized_3 [Preset: minimal]                         OK
+ [Valid]   EF - bellatrix - Random - randomized_4 [Preset: minimal]                         OK
+ [Valid]   EF - bellatrix - Random - randomized_5 [Preset: minimal]                         OK
+ [Valid]   EF - bellatrix - Random - randomized_6 [Preset: minimal]                         OK
+ [Valid]   EF - bellatrix - Random - randomized_7 [Preset: minimal]                         OK
+ [Valid]   EF - bellatrix - Random - randomized_8 [Preset: minimal]                         OK
+ [Valid]   EF - bellatrix - Random - randomized_9 [Preset: minimal]                         OK
```
## EF - bellatrix - Rewards  [Preset: minimal]
```diff
+ EF - bellatrix - Rewards - all_balances_too_low_for_reward [Preset: minimal]               OK
+ EF - bellatrix - Rewards - empty [Preset: minimal]                                         OK
+ EF - bellatrix - Rewards - empty_leak [Preset: minimal]                                    OK
+ EF - bellatrix - Rewards - full_all_correct [Preset: minimal]                              OK
+ EF - bellatrix - Rewards - full_but_partial_participation [Preset: minimal]                OK
+ EF - bellatrix - Rewards - full_but_partial_participation_leak [Preset: minimal]           OK
+ EF - bellatrix - Rewards - full_leak [Preset: minimal]                                     OK
+ EF - bellatrix - Rewards - full_random_0 [Preset: minimal]                                 OK
+ EF - bellatrix - Rewards - full_random_1 [Preset: minimal]                                 OK
+ EF - bellatrix - Rewards - full_random_2 [Preset: minimal]                                 OK
+ EF - bellatrix - Rewards - full_random_3 [Preset: minimal]                                 OK
+ EF - bellatrix - Rewards - full_random_4 [Preset: minimal]                                 OK
+ EF - bellatrix - Rewards - full_random_leak [Preset: minimal]                              OK
+ EF - bellatrix - Rewards - full_random_low_balances_0 [Preset: minimal]                    OK
+ EF - bellatrix - Rewards - full_random_low_balances_1 [Preset: minimal]                    OK
+ EF - bellatrix - Rewards - full_random_misc_balances [Preset: minimal]                     OK
+ EF - bellatrix - Rewards - full_random_seven_epoch_leak [Preset: minimal]                  OK
+ EF - bellatrix - Rewards - full_random_ten_epoch_leak [Preset: minimal]                    OK
+ EF - bellatrix - Rewards - full_random_without_leak_0 [Preset: minimal]                    OK
+ EF - bellatrix - Rewards - full_random_without_leak_and_current_exit_0 [Preset: minimal]   OK
+ EF - bellatrix - Rewards - half_full [Preset: minimal]                                     OK
+ EF - bellatrix - Rewards - half_full_leak [Preset: minimal]                                OK
+ EF - bellatrix - Rewards - quarter_full [Preset: minimal]                                  OK
+ EF - bellatrix - Rewards - quarter_full_leak [Preset: minimal]                             OK
+ EF - bellatrix - Rewards - some_very_low_effective_balances_that_attested [Preset: minimal OK
+ EF - bellatrix - Rewards - some_very_low_effective_balances_that_attested_leak [Preset: mi OK
+ EF - bellatrix - Rewards - some_very_low_effective_balances_that_did_not_attest [Preset: m OK
+ EF - bellatrix - Rewards - some_very_low_effective_balances_that_did_not_attest_leak [Pres OK
+ EF - bellatrix - Rewards - with_exited_validators [Preset: minimal]                        OK
+ EF - bellatrix - Rewards - with_exited_validators_leak [Preset: minimal]                   OK
+ EF - bellatrix - Rewards - with_not_yet_activated_validators [Preset: minimal]             OK
+ EF - bellatrix - Rewards - with_not_yet_activated_validators_leak [Preset: minimal]        OK
+ EF - bellatrix - Rewards - with_slashed_validators [Preset: minimal]                       OK
+ EF - bellatrix - Rewards - with_slashed_validators_leak [Preset: minimal]                  OK
```
## EF - bellatrix - Sanity - Blocks  [Preset: minimal]
```diff
+ [Invalid] EF - bellatrix - Sanity - Blocks - invalid_all_zeroed_sig [Preset: minimal]      OK
+ [Invalid] EF - bellatrix - Sanity - Blocks - invalid_duplicate_attester_slashing_same_bloc OK
+ [Invalid] EF - bellatrix - Sanity - Blocks - invalid_duplicate_deposit_same_block [Preset: OK
+ [Invalid] EF - bellatrix - Sanity - Blocks - invalid_duplicate_proposer_slashings_same_blo OK
+ [Invalid] EF - bellatrix - Sanity - Blocks - invalid_duplicate_validator_exit_same_block [ OK
+ [Invalid] EF - bellatrix - Sanity - Blocks - invalid_incorrect_block_sig [Preset: minimal] OK
+ [Invalid] EF - bellatrix - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_exp OK
+ [Invalid] EF - bellatrix - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_pro OK
+ [Invalid] EF - bellatrix - Sanity - Blocks - invalid_incorrect_state_root [Preset: minimal OK
+ [Invalid] EF - bellatrix - Sanity - Blocks - invalid_only_increase_deposit_count [Preset:  OK
+ [Invalid] EF - bellatrix - Sanity - Blocks - invalid_parent_from_same_slot [Preset: minima OK
+ [Invalid] EF - bellatrix - Sanity - Blocks - invalid_prev_slot_block_transition [Preset: m OK
+ [Invalid] EF - bellatrix - Sanity - Blocks - invalid_same_slot_block_transition [Preset: m OK
+ [Invalid] EF - bellatrix - Sanity - Blocks - invalid_similar_proposer_slashings_same_block OK
+ [Invalid] EF - bellatrix - Sanity - Blocks - slash_and_exit_same_index [Preset: minimal]   OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - attestation [Preset: minimal]                 OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - attester_slashing [Preset: minimal]           OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - balance_driven_status_transitions [Preset: mi OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - block_transition_randomized_payload [Preset:  OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - deposit_in_block [Preset: minimal]            OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - deposit_top_up [Preset: minimal]              OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - duplicate_attestation_same_block [Preset: min OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - empty_block_transition [Preset: minimal]      OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - empty_block_transition_large_validator_set [P OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - empty_block_transition_no_tx [Preset: minimal OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - empty_epoch_transition [Preset: minimal]      OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - empty_epoch_transition_large_validator_set [P OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - empty_epoch_transition_not_finalizing [Preset OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - eth1_data_votes_consensus [Preset: minimal]   OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - eth1_data_votes_no_consensus [Preset: minimal OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - full_random_operations_0 [Preset: minimal]    OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - full_random_operations_1 [Preset: minimal]    OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - full_random_operations_2 [Preset: minimal]    OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - full_random_operations_3 [Preset: minimal]    OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - high_proposer_index [Preset: minimal]         OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - historical_batch [Preset: minimal]            OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - inactivity_scores_full_participation_leaking  OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - inactivity_scores_leaking [Preset: minimal]   OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - is_execution_enabled_false [Preset: minimal]  OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - multiple_attester_slashings_no_overlap [Prese OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - multiple_attester_slashings_partial_overlap [ OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - multiple_different_proposer_slashings_same_bl OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - multiple_different_validator_exits_same_block OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - proposer_after_inactive_index [Preset: minima OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - proposer_self_slashing [Preset: minimal]      OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - proposer_slashing [Preset: minimal]           OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - skipped_slots [Preset: minimal]               OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - slash_and_exit_diff_index [Preset: minimal]   OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - sync_committee_committee__empty [Preset: mini OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - sync_committee_committee__full [Preset: minim OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - sync_committee_committee__half [Preset: minim OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - sync_committee_committee_genesis__empty [Pres OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - sync_committee_committee_genesis__full [Prese OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - sync_committee_committee_genesis__half [Prese OK
+ [Valid]   EF - bellatrix - Sanity - Blocks - voluntary_exit [Preset: minimal]              OK
```
## EF - capella - Epoch Processing - Effective balance updates [Preset: minimal]
```diff
+ Effective balance updates - effective_balance_hysteresis [Preset: minimal]                 OK
```
## EF - capella - Epoch Processing - Eth1 data reset [Preset: minimal]
```diff
+ Eth1 data reset - eth1_vote_no_reset [Preset: minimal]                                     OK
+ Eth1 data reset - eth1_vote_reset [Preset: minimal]                                        OK
```
## EF - capella - Epoch Processing - Historical summaries update [Preset: minimal]
```diff
+ Historical summaries update - historical_summaries_accumulator [Preset: minimal]           OK
```
## EF - capella - Epoch Processing - Inactivity [Preset: minimal]
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
## EF - capella - Epoch Processing - Justification & Finalization [Preset: minimal]
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
## EF - capella - Epoch Processing - Participation flag updates [Preset: minimal]
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
## EF - capella - Epoch Processing - RANDAO mixes reset [Preset: minimal]
```diff
+ RANDAO mixes reset - updated_randao_mixes [Preset: minimal]                                OK
```
## EF - capella - Epoch Processing - Registry updates [Preset: minimal]
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
## EF - capella - Epoch Processing - Rewards and penalties [Preset: minimal]
```diff
+ Rewards and penalties - almost_empty_attestations [Preset: minimal]                        OK
+ Rewards and penalties - almost_empty_attestations_with_leak [Preset: minimal]              OK
+ Rewards and penalties - almost_full_attestations [Preset: minimal]                         OK
+ Rewards and penalties - almost_full_attestations_with_leak [Preset: minimal]               OK
+ Rewards and penalties - attestations_some_slashed [Preset: minimal]                        OK
+ Rewards and penalties - duplicate_attestation [Preset: minimal]                            OK
+ Rewards and penalties - full_attestation_participation [Preset: minimal]                   OK
+ Rewards and penalties - full_attestation_participation_with_leak [Preset: minimal]         OK
+ Rewards and penalties - full_attestations_default_balances_except_a_validator_with_one_gwe OK
+ Rewards and penalties - full_attestations_misc_balances [Preset: minimal]                  OK
+ Rewards and penalties - genesis_epoch_full_attestations_no_rewards [Preset: minimal]       OK
+ Rewards and penalties - genesis_epoch_no_attestations_no_penalties [Preset: minimal]       OK
+ Rewards and penalties - no_attestations_all_penalties [Preset: minimal]                    OK
+ Rewards and penalties - random_fill_attestations [Preset: minimal]                         OK
+ Rewards and penalties - random_fill_attestations_with_leak [Preset: minimal]               OK
```
## EF - capella - Epoch Processing - Slashings [Preset: minimal]
```diff
+ Slashings - low_penalty [Preset: minimal]                                                  OK
+ Slashings - max_penalties [Preset: minimal]                                                OK
+ Slashings - minimal_penalty [Preset: minimal]                                              OK
+ Slashings - scaled_penalties [Preset: minimal]                                             OK
+ Slashings - slashings_with_random_state [Preset: minimal]                                  OK
```
## EF - capella - Epoch Processing - Slashings reset [Preset: minimal]
```diff
+ Slashings reset - flush_slashings [Preset: minimal]                                        OK
```
## EF - capella - Epoch Processing - Sync committee updates [Preset: minimal]
```diff
+ Sync committee updates - sync_committees_no_progress_not_at_period_boundary [Preset: minim OK
+ Sync committee updates - sync_committees_progress_genesis [Preset: minimal]                OK
+ Sync committee updates - sync_committees_progress_misc_balances_genesis [Preset: minimal]  OK
+ Sync committee updates - sync_committees_progress_misc_balances_not_genesis [Preset: minim OK
+ Sync committee updates - sync_committees_progress_not_genesis [Preset: minimal]            OK
```
## EF - capella - Finality  [Preset: minimal]
```diff
+ [Valid]   EF - capella - Finality - finality_no_updates_at_genesis [Preset: minimal]       OK
+ [Valid]   EF - capella - Finality - finality_rule_1 [Preset: minimal]                      OK
+ [Valid]   EF - capella - Finality - finality_rule_2 [Preset: minimal]                      OK
+ [Valid]   EF - capella - Finality - finality_rule_3 [Preset: minimal]                      OK
+ [Valid]   EF - capella - Finality - finality_rule_4 [Preset: minimal]                      OK
```
## EF - capella - Random  [Preset: minimal]
```diff
+ [Valid]   EF - capella - Random - randomized_0 [Preset: minimal]                           OK
+ [Valid]   EF - capella - Random - randomized_1 [Preset: minimal]                           OK
+ [Valid]   EF - capella - Random - randomized_10 [Preset: minimal]                          OK
+ [Valid]   EF - capella - Random - randomized_11 [Preset: minimal]                          OK
+ [Valid]   EF - capella - Random - randomized_12 [Preset: minimal]                          OK
+ [Valid]   EF - capella - Random - randomized_13 [Preset: minimal]                          OK
+ [Valid]   EF - capella - Random - randomized_14 [Preset: minimal]                          OK
+ [Valid]   EF - capella - Random - randomized_15 [Preset: minimal]                          OK
+ [Valid]   EF - capella - Random - randomized_2 [Preset: minimal]                           OK
+ [Valid]   EF - capella - Random - randomized_3 [Preset: minimal]                           OK
+ [Valid]   EF - capella - Random - randomized_4 [Preset: minimal]                           OK
+ [Valid]   EF - capella - Random - randomized_5 [Preset: minimal]                           OK
+ [Valid]   EF - capella - Random - randomized_6 [Preset: minimal]                           OK
+ [Valid]   EF - capella - Random - randomized_7 [Preset: minimal]                           OK
+ [Valid]   EF - capella - Random - randomized_8 [Preset: minimal]                           OK
+ [Valid]   EF - capella - Random - randomized_9 [Preset: minimal]                           OK
```
## EF - capella - Rewards  [Preset: minimal]
```diff
+ EF - capella - Rewards - all_balances_too_low_for_reward [Preset: minimal]                 OK
+ EF - capella - Rewards - empty [Preset: minimal]                                           OK
+ EF - capella - Rewards - empty_leak [Preset: minimal]                                      OK
+ EF - capella - Rewards - full_all_correct [Preset: minimal]                                OK
+ EF - capella - Rewards - full_but_partial_participation [Preset: minimal]                  OK
+ EF - capella - Rewards - full_but_partial_participation_leak [Preset: minimal]             OK
+ EF - capella - Rewards - full_leak [Preset: minimal]                                       OK
+ EF - capella - Rewards - full_random_0 [Preset: minimal]                                   OK
+ EF - capella - Rewards - full_random_1 [Preset: minimal]                                   OK
+ EF - capella - Rewards - full_random_2 [Preset: minimal]                                   OK
+ EF - capella - Rewards - full_random_3 [Preset: minimal]                                   OK
+ EF - capella - Rewards - full_random_4 [Preset: minimal]                                   OK
+ EF - capella - Rewards - full_random_leak [Preset: minimal]                                OK
+ EF - capella - Rewards - full_random_low_balances_0 [Preset: minimal]                      OK
+ EF - capella - Rewards - full_random_low_balances_1 [Preset: minimal]                      OK
+ EF - capella - Rewards - full_random_misc_balances [Preset: minimal]                       OK
+ EF - capella - Rewards - full_random_seven_epoch_leak [Preset: minimal]                    OK
+ EF - capella - Rewards - full_random_ten_epoch_leak [Preset: minimal]                      OK
+ EF - capella - Rewards - full_random_without_leak_0 [Preset: minimal]                      OK
+ EF - capella - Rewards - full_random_without_leak_and_current_exit_0 [Preset: minimal]     OK
+ EF - capella - Rewards - half_full [Preset: minimal]                                       OK
+ EF - capella - Rewards - half_full_leak [Preset: minimal]                                  OK
+ EF - capella - Rewards - quarter_full [Preset: minimal]                                    OK
+ EF - capella - Rewards - quarter_full_leak [Preset: minimal]                               OK
+ EF - capella - Rewards - some_very_low_effective_balances_that_attested [Preset: minimal]  OK
+ EF - capella - Rewards - some_very_low_effective_balances_that_attested_leak [Preset: mini OK
+ EF - capella - Rewards - some_very_low_effective_balances_that_did_not_attest [Preset: min OK
+ EF - capella - Rewards - some_very_low_effective_balances_that_did_not_attest_leak [Preset OK
+ EF - capella - Rewards - with_exited_validators [Preset: minimal]                          OK
+ EF - capella - Rewards - with_exited_validators_leak [Preset: minimal]                     OK
+ EF - capella - Rewards - with_not_yet_activated_validators [Preset: minimal]               OK
+ EF - capella - Rewards - with_not_yet_activated_validators_leak [Preset: minimal]          OK
+ EF - capella - Rewards - with_slashed_validators [Preset: minimal]                         OK
+ EF - capella - Rewards - with_slashed_validators_leak [Preset: minimal]                    OK
```
## EF - capella - Sanity - Blocks  [Preset: minimal]
```diff
+ [Invalid] EF - capella - Sanity - Blocks - invalid_all_zeroed_sig [Preset: minimal]        OK
+ [Invalid] EF - capella - Sanity - Blocks - invalid_duplicate_attester_slashing_same_block  OK
+ [Invalid] EF - capella - Sanity - Blocks - invalid_duplicate_bls_changes_same_block [Prese OK
+ [Invalid] EF - capella - Sanity - Blocks - invalid_duplicate_deposit_same_block [Preset: m OK
+ [Invalid] EF - capella - Sanity - Blocks - invalid_duplicate_proposer_slashings_same_block OK
+ [Invalid] EF - capella - Sanity - Blocks - invalid_duplicate_validator_exit_same_block [Pr OK
+ [Invalid] EF - capella - Sanity - Blocks - invalid_incorrect_block_sig [Preset: minimal]   OK
+ [Invalid] EF - capella - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_expec OK
+ [Invalid] EF - capella - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_propo OK
+ [Invalid] EF - capella - Sanity - Blocks - invalid_incorrect_state_root [Preset: minimal]  OK
+ [Invalid] EF - capella - Sanity - Blocks - invalid_is_execution_enabled_false [Preset: min OK
+ [Invalid] EF - capella - Sanity - Blocks - invalid_only_increase_deposit_count [Preset: mi OK
+ [Invalid] EF - capella - Sanity - Blocks - invalid_parent_from_same_slot [Preset: minimal] OK
+ [Invalid] EF - capella - Sanity - Blocks - invalid_prev_slot_block_transition [Preset: min OK
+ [Invalid] EF - capella - Sanity - Blocks - invalid_same_slot_block_transition [Preset: min OK
+ [Invalid] EF - capella - Sanity - Blocks - invalid_similar_proposer_slashings_same_block [ OK
+ [Invalid] EF - capella - Sanity - Blocks - invalid_two_bls_changes_of_different_addresses_ OK
+ [Invalid] EF - capella - Sanity - Blocks - invalid_withdrawal_fail_second_block_payload_is OK
+ [Invalid] EF - capella - Sanity - Blocks - slash_and_exit_same_index [Preset: minimal]     OK
+ [Valid]   EF - capella - Sanity - Blocks - activate_and_partial_withdrawal_max_effective_b OK
+ [Valid]   EF - capella - Sanity - Blocks - activate_and_partial_withdrawal_overdeposit [Pr OK
+ [Valid]   EF - capella - Sanity - Blocks - attestation [Preset: minimal]                   OK
+ [Valid]   EF - capella - Sanity - Blocks - attester_slashing [Preset: minimal]             OK
+ [Valid]   EF - capella - Sanity - Blocks - balance_driven_status_transitions [Preset: mini OK
+ [Valid]   EF - capella - Sanity - Blocks - block_transition_randomized_payload [Preset: mi OK
+ [Valid]   EF - capella - Sanity - Blocks - bls_change [Preset: minimal]                    OK
+ [Valid]   EF - capella - Sanity - Blocks - deposit_and_bls_change [Preset: minimal]        OK
+ [Valid]   EF - capella - Sanity - Blocks - deposit_in_block [Preset: minimal]              OK
+ [Valid]   EF - capella - Sanity - Blocks - deposit_top_up [Preset: minimal]                OK
+ [Valid]   EF - capella - Sanity - Blocks - duplicate_attestation_same_block [Preset: minim OK
+ [Valid]   EF - capella - Sanity - Blocks - empty_block_transition [Preset: minimal]        OK
+ [Valid]   EF - capella - Sanity - Blocks - empty_block_transition_large_validator_set [Pre OK
+ [Valid]   EF - capella - Sanity - Blocks - empty_block_transition_no_tx [Preset: minimal]  OK
+ [Valid]   EF - capella - Sanity - Blocks - empty_epoch_transition [Preset: minimal]        OK
+ [Valid]   EF - capella - Sanity - Blocks - empty_epoch_transition_large_validator_set [Pre OK
+ [Valid]   EF - capella - Sanity - Blocks - empty_epoch_transition_not_finalizing [Preset:  OK
+ [Valid]   EF - capella - Sanity - Blocks - eth1_data_votes_consensus [Preset: minimal]     OK
+ [Valid]   EF - capella - Sanity - Blocks - eth1_data_votes_no_consensus [Preset: minimal]  OK
+ [Valid]   EF - capella - Sanity - Blocks - exit_and_bls_change [Preset: minimal]           OK
+ [Valid]   EF - capella - Sanity - Blocks - full_random_operations_0 [Preset: minimal]      OK
+ [Valid]   EF - capella - Sanity - Blocks - full_random_operations_1 [Preset: minimal]      OK
+ [Valid]   EF - capella - Sanity - Blocks - full_random_operations_2 [Preset: minimal]      OK
+ [Valid]   EF - capella - Sanity - Blocks - full_random_operations_3 [Preset: minimal]      OK
+ [Valid]   EF - capella - Sanity - Blocks - full_withdrawal_in_epoch_transition [Preset: mi OK
+ [Valid]   EF - capella - Sanity - Blocks - high_proposer_index [Preset: minimal]           OK
+ [Valid]   EF - capella - Sanity - Blocks - historical_batch [Preset: minimal]              OK
+ [Valid]   EF - capella - Sanity - Blocks - inactivity_scores_full_participation_leaking [P OK
+ [Valid]   EF - capella - Sanity - Blocks - inactivity_scores_leaking [Preset: minimal]     OK
+ [Valid]   EF - capella - Sanity - Blocks - many_partial_withdrawals_in_epoch_transition [P OK
+ [Valid]   EF - capella - Sanity - Blocks - multiple_attester_slashings_no_overlap [Preset: OK
+ [Valid]   EF - capella - Sanity - Blocks - multiple_attester_slashings_partial_overlap [Pr OK
+ [Valid]   EF - capella - Sanity - Blocks - multiple_different_proposer_slashings_same_bloc OK
+ [Valid]   EF - capella - Sanity - Blocks - multiple_different_validator_exits_same_block [ OK
+ [Valid]   EF - capella - Sanity - Blocks - partial_withdrawal_in_epoch_transition [Preset: OK
+ [Valid]   EF - capella - Sanity - Blocks - proposer_after_inactive_index [Preset: minimal] OK
+ [Valid]   EF - capella - Sanity - Blocks - proposer_self_slashing [Preset: minimal]        OK
+ [Valid]   EF - capella - Sanity - Blocks - proposer_slashing [Preset: minimal]             OK
+ [Valid]   EF - capella - Sanity - Blocks - skipped_slots [Preset: minimal]                 OK
+ [Valid]   EF - capella - Sanity - Blocks - slash_and_exit_diff_index [Preset: minimal]     OK
+ [Valid]   EF - capella - Sanity - Blocks - sync_committee_committee__empty [Preset: minima OK
+ [Valid]   EF - capella - Sanity - Blocks - sync_committee_committee__full [Preset: minimal OK
+ [Valid]   EF - capella - Sanity - Blocks - sync_committee_committee__half [Preset: minimal OK
+ [Valid]   EF - capella - Sanity - Blocks - sync_committee_committee_genesis__empty [Preset OK
+ [Valid]   EF - capella - Sanity - Blocks - sync_committee_committee_genesis__full [Preset: OK
+ [Valid]   EF - capella - Sanity - Blocks - sync_committee_committee_genesis__half [Preset: OK
+ [Valid]   EF - capella - Sanity - Blocks - top_up_and_partial_withdrawable_validator [Pres OK
+ [Valid]   EF - capella - Sanity - Blocks - top_up_to_fully_withdrawn_validator [Preset: mi OK
+ [Valid]   EF - capella - Sanity - Blocks - voluntary_exit [Preset: minimal]                OK
+ [Valid]   EF - capella - Sanity - Blocks - withdrawal_success_two_blocks [Preset: minimal] OK
```
## EF - deneb - Epoch Processing - Effective balance updates [Preset: minimal]
```diff
+ Effective balance updates - effective_balance_hysteresis [Preset: minimal]                 OK
```
## EF - deneb - Epoch Processing - Eth1 data reset [Preset: minimal]
```diff
+ Eth1 data reset - eth1_vote_no_reset [Preset: minimal]                                     OK
+ Eth1 data reset - eth1_vote_reset [Preset: minimal]                                        OK
```
## EF - deneb - Epoch Processing - Historical summaries update [Preset: minimal]
```diff
+ Historical summaries update - historical_summaries_accumulator [Preset: minimal]           OK
```
## EF - deneb - Epoch Processing - Inactivity [Preset: minimal]
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
## EF - deneb - Epoch Processing - Justification & Finalization [Preset: minimal]
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
## EF - deneb - Epoch Processing - Participation flag updates [Preset: minimal]
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
## EF - deneb - Epoch Processing - RANDAO mixes reset [Preset: minimal]
```diff
+ RANDAO mixes reset - updated_randao_mixes [Preset: minimal]                                OK
```
## EF - deneb - Epoch Processing - Registry updates [Preset: minimal]
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
## EF - deneb - Epoch Processing - Rewards and penalties [Preset: minimal]
```diff
+ Rewards and penalties - almost_empty_attestations [Preset: minimal]                        OK
+ Rewards and penalties - almost_empty_attestations_with_leak [Preset: minimal]              OK
+ Rewards and penalties - almost_full_attestations [Preset: minimal]                         OK
+ Rewards and penalties - almost_full_attestations_with_leak [Preset: minimal]               OK
+ Rewards and penalties - attestations_some_slashed [Preset: minimal]                        OK
+ Rewards and penalties - duplicate_attestation [Preset: minimal]                            OK
+ Rewards and penalties - full_attestation_participation [Preset: minimal]                   OK
+ Rewards and penalties - full_attestation_participation_with_leak [Preset: minimal]         OK
+ Rewards and penalties - full_attestations_default_balances_except_a_validator_with_one_gwe OK
+ Rewards and penalties - full_attestations_misc_balances [Preset: minimal]                  OK
+ Rewards and penalties - genesis_epoch_full_attestations_no_rewards [Preset: minimal]       OK
+ Rewards and penalties - genesis_epoch_no_attestations_no_penalties [Preset: minimal]       OK
+ Rewards and penalties - no_attestations_all_penalties [Preset: minimal]                    OK
+ Rewards and penalties - random_fill_attestations [Preset: minimal]                         OK
+ Rewards and penalties - random_fill_attestations_with_leak [Preset: minimal]               OK
```
## EF - deneb - Epoch Processing - Slashings [Preset: minimal]
```diff
+ Slashings - low_penalty [Preset: minimal]                                                  OK
+ Slashings - max_penalties [Preset: minimal]                                                OK
+ Slashings - minimal_penalty [Preset: minimal]                                              OK
+ Slashings - scaled_penalties [Preset: minimal]                                             OK
+ Slashings - slashings_with_random_state [Preset: minimal]                                  OK
```
## EF - deneb - Epoch Processing - Slashings reset [Preset: minimal]
```diff
+ Slashings reset - flush_slashings [Preset: minimal]                                        OK
```
## EF - deneb - Epoch Processing - Sync committee updates [Preset: minimal]
```diff
+ Sync committee updates - sync_committees_no_progress_not_at_period_boundary [Preset: minim OK
+ Sync committee updates - sync_committees_progress_genesis [Preset: minimal]                OK
+ Sync committee updates - sync_committees_progress_misc_balances_genesis [Preset: minimal]  OK
+ Sync committee updates - sync_committees_progress_misc_balances_not_genesis [Preset: minim OK
+ Sync committee updates - sync_committees_progress_not_genesis [Preset: minimal]            OK
```
## EF - deneb - Finality  [Preset: minimal]
```diff
+ [Valid]   EF - deneb - Finality - finality_no_updates_at_genesis [Preset: minimal]         OK
+ [Valid]   EF - deneb - Finality - finality_rule_1 [Preset: minimal]                        OK
+ [Valid]   EF - deneb - Finality - finality_rule_2 [Preset: minimal]                        OK
+ [Valid]   EF - deneb - Finality - finality_rule_3 [Preset: minimal]                        OK
+ [Valid]   EF - deneb - Finality - finality_rule_4 [Preset: minimal]                        OK
```
## EF - deneb - Random  [Preset: minimal]
```diff
+ [Valid]   EF - deneb - Random - randomized_0 [Preset: minimal]                             OK
+ [Valid]   EF - deneb - Random - randomized_1 [Preset: minimal]                             OK
+ [Valid]   EF - deneb - Random - randomized_10 [Preset: minimal]                            OK
+ [Valid]   EF - deneb - Random - randomized_11 [Preset: minimal]                            OK
+ [Valid]   EF - deneb - Random - randomized_12 [Preset: minimal]                            OK
+ [Valid]   EF - deneb - Random - randomized_13 [Preset: minimal]                            OK
+ [Valid]   EF - deneb - Random - randomized_14 [Preset: minimal]                            OK
+ [Valid]   EF - deneb - Random - randomized_15 [Preset: minimal]                            OK
+ [Valid]   EF - deneb - Random - randomized_2 [Preset: minimal]                             OK
+ [Valid]   EF - deneb - Random - randomized_3 [Preset: minimal]                             OK
+ [Valid]   EF - deneb - Random - randomized_4 [Preset: minimal]                             OK
+ [Valid]   EF - deneb - Random - randomized_5 [Preset: minimal]                             OK
+ [Valid]   EF - deneb - Random - randomized_6 [Preset: minimal]                             OK
+ [Valid]   EF - deneb - Random - randomized_7 [Preset: minimal]                             OK
+ [Valid]   EF - deneb - Random - randomized_8 [Preset: minimal]                             OK
+ [Valid]   EF - deneb - Random - randomized_9 [Preset: minimal]                             OK
```
## EF - deneb - Rewards  [Preset: minimal]
```diff
+ EF - deneb - Rewards - all_balances_too_low_for_reward [Preset: minimal]                   OK
+ EF - deneb - Rewards - empty [Preset: minimal]                                             OK
+ EF - deneb - Rewards - empty_leak [Preset: minimal]                                        OK
+ EF - deneb - Rewards - full_all_correct [Preset: minimal]                                  OK
+ EF - deneb - Rewards - full_but_partial_participation [Preset: minimal]                    OK
+ EF - deneb - Rewards - full_but_partial_participation_leak [Preset: minimal]               OK
+ EF - deneb - Rewards - full_leak [Preset: minimal]                                         OK
+ EF - deneb - Rewards - full_random_0 [Preset: minimal]                                     OK
+ EF - deneb - Rewards - full_random_1 [Preset: minimal]                                     OK
+ EF - deneb - Rewards - full_random_2 [Preset: minimal]                                     OK
+ EF - deneb - Rewards - full_random_3 [Preset: minimal]                                     OK
+ EF - deneb - Rewards - full_random_4 [Preset: minimal]                                     OK
+ EF - deneb - Rewards - full_random_leak [Preset: minimal]                                  OK
+ EF - deneb - Rewards - full_random_low_balances_0 [Preset: minimal]                        OK
+ EF - deneb - Rewards - full_random_low_balances_1 [Preset: minimal]                        OK
+ EF - deneb - Rewards - full_random_misc_balances [Preset: minimal]                         OK
+ EF - deneb - Rewards - full_random_seven_epoch_leak [Preset: minimal]                      OK
+ EF - deneb - Rewards - full_random_ten_epoch_leak [Preset: minimal]                        OK
+ EF - deneb - Rewards - full_random_without_leak_0 [Preset: minimal]                        OK
+ EF - deneb - Rewards - full_random_without_leak_and_current_exit_0 [Preset: minimal]       OK
+ EF - deneb - Rewards - half_full [Preset: minimal]                                         OK
+ EF - deneb - Rewards - half_full_leak [Preset: minimal]                                    OK
+ EF - deneb - Rewards - quarter_full [Preset: minimal]                                      OK
+ EF - deneb - Rewards - quarter_full_leak [Preset: minimal]                                 OK
+ EF - deneb - Rewards - some_very_low_effective_balances_that_attested [Preset: minimal]    OK
+ EF - deneb - Rewards - some_very_low_effective_balances_that_attested_leak [Preset: minima OK
+ EF - deneb - Rewards - some_very_low_effective_balances_that_did_not_attest [Preset: minim OK
+ EF - deneb - Rewards - some_very_low_effective_balances_that_did_not_attest_leak [Preset:  OK
+ EF - deneb - Rewards - with_exited_validators [Preset: minimal]                            OK
+ EF - deneb - Rewards - with_exited_validators_leak [Preset: minimal]                       OK
+ EF - deneb - Rewards - with_not_yet_activated_validators [Preset: minimal]                 OK
+ EF - deneb - Rewards - with_not_yet_activated_validators_leak [Preset: minimal]            OK
+ EF - deneb - Rewards - with_slashed_validators [Preset: minimal]                           OK
+ EF - deneb - Rewards - with_slashed_validators_leak [Preset: minimal]                      OK
```
## EF - deneb - Sanity - Blocks  [Preset: minimal]
```diff
+ [Invalid] EF - deneb - Sanity - Blocks - invalid_all_zeroed_sig [Preset: minimal]          OK
+ [Invalid] EF - deneb - Sanity - Blocks - invalid_duplicate_attester_slashing_same_block [P OK
+ [Invalid] EF - deneb - Sanity - Blocks - invalid_duplicate_bls_changes_same_block [Preset: OK
+ [Invalid] EF - deneb - Sanity - Blocks - invalid_duplicate_deposit_same_block [Preset: min OK
+ [Invalid] EF - deneb - Sanity - Blocks - invalid_duplicate_proposer_slashings_same_block [ OK
+ [Invalid] EF - deneb - Sanity - Blocks - invalid_duplicate_validator_exit_same_block [Pres OK
+ [Invalid] EF - deneb - Sanity - Blocks - invalid_exceed_max_blobs_per_block [Preset: minim OK
+ [Invalid] EF - deneb - Sanity - Blocks - invalid_incorrect_block_sig [Preset: minimal]     OK
+ [Invalid] EF - deneb - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_expecte OK
+ [Invalid] EF - deneb - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_propose OK
+ [Invalid] EF - deneb - Sanity - Blocks - invalid_incorrect_state_root [Preset: minimal]    OK
+ [Invalid] EF - deneb - Sanity - Blocks - invalid_is_execution_enabled_false [Preset: minim OK
+ [Invalid] EF - deneb - Sanity - Blocks - invalid_max_blobs_per_block_two_txs [Preset: mini OK
+ [Invalid] EF - deneb - Sanity - Blocks - invalid_one_blob_max_plus_one_txs [Preset: minima OK
+ [Invalid] EF - deneb - Sanity - Blocks - invalid_only_increase_deposit_count [Preset: mini OK
+ [Invalid] EF - deneb - Sanity - Blocks - invalid_parent_from_same_slot [Preset: minimal]   OK
+ [Invalid] EF - deneb - Sanity - Blocks - invalid_prev_slot_block_transition [Preset: minim OK
+ [Invalid] EF - deneb - Sanity - Blocks - invalid_same_slot_block_transition [Preset: minim OK
+ [Invalid] EF - deneb - Sanity - Blocks - invalid_similar_proposer_slashings_same_block [Pr OK
+ [Invalid] EF - deneb - Sanity - Blocks - invalid_two_bls_changes_of_different_addresses_sa OK
+ [Invalid] EF - deneb - Sanity - Blocks - invalid_withdrawal_fail_second_block_payload_isnt OK
+ [Invalid] EF - deneb - Sanity - Blocks - slash_and_exit_same_index [Preset: minimal]       OK
+ [Valid]   EF - deneb - Sanity - Blocks - activate_and_partial_withdrawal_max_effective_bal OK
+ [Valid]   EF - deneb - Sanity - Blocks - activate_and_partial_withdrawal_overdeposit [Pres OK
+ [Valid]   EF - deneb - Sanity - Blocks - attestation [Preset: minimal]                     OK
+ [Valid]   EF - deneb - Sanity - Blocks - attester_slashing [Preset: minimal]               OK
+ [Valid]   EF - deneb - Sanity - Blocks - balance_driven_status_transitions [Preset: minima OK
+ [Valid]   EF - deneb - Sanity - Blocks - block_transition_randomized_payload [Preset: mini OK
+ [Valid]   EF - deneb - Sanity - Blocks - bls_change [Preset: minimal]                      OK
+ [Valid]   EF - deneb - Sanity - Blocks - deposit_and_bls_change [Preset: minimal]          OK
+ [Valid]   EF - deneb - Sanity - Blocks - deposit_in_block [Preset: minimal]                OK
+ [Valid]   EF - deneb - Sanity - Blocks - deposit_top_up [Preset: minimal]                  OK
+ [Valid]   EF - deneb - Sanity - Blocks - duplicate_attestation_same_block [Preset: minimal OK
+ [Valid]   EF - deneb - Sanity - Blocks - empty_block_transition [Preset: minimal]          OK
+ [Valid]   EF - deneb - Sanity - Blocks - empty_block_transition_large_validator_set [Prese OK
+ [Valid]   EF - deneb - Sanity - Blocks - empty_block_transition_no_tx [Preset: minimal]    OK
+ [Valid]   EF - deneb - Sanity - Blocks - empty_epoch_transition [Preset: minimal]          OK
+ [Valid]   EF - deneb - Sanity - Blocks - empty_epoch_transition_large_validator_set [Prese OK
+ [Valid]   EF - deneb - Sanity - Blocks - empty_epoch_transition_not_finalizing [Preset: mi OK
+ [Valid]   EF - deneb - Sanity - Blocks - eth1_data_votes_consensus [Preset: minimal]       OK
+ [Valid]   EF - deneb - Sanity - Blocks - eth1_data_votes_no_consensus [Preset: minimal]    OK
+ [Valid]   EF - deneb - Sanity - Blocks - exit_and_bls_change [Preset: minimal]             OK
+ [Valid]   EF - deneb - Sanity - Blocks - full_random_operations_0 [Preset: minimal]        OK
+ [Valid]   EF - deneb - Sanity - Blocks - full_random_operations_1 [Preset: minimal]        OK
+ [Valid]   EF - deneb - Sanity - Blocks - full_random_operations_2 [Preset: minimal]        OK
+ [Valid]   EF - deneb - Sanity - Blocks - full_random_operations_3 [Preset: minimal]        OK
+ [Valid]   EF - deneb - Sanity - Blocks - full_withdrawal_in_epoch_transition [Preset: mini OK
+ [Valid]   EF - deneb - Sanity - Blocks - high_proposer_index [Preset: minimal]             OK
+ [Valid]   EF - deneb - Sanity - Blocks - historical_batch [Preset: minimal]                OK
+ [Valid]   EF - deneb - Sanity - Blocks - inactivity_scores_full_participation_leaking [Pre OK
+ [Valid]   EF - deneb - Sanity - Blocks - inactivity_scores_leaking [Preset: minimal]       OK
+ [Valid]   EF - deneb - Sanity - Blocks - many_partial_withdrawals_in_epoch_transition [Pre OK
+ [Valid]   EF - deneb - Sanity - Blocks - max_blobs_per_block [Preset: minimal]             OK
+ [Valid]   EF - deneb - Sanity - Blocks - mix_blob_tx_and_non_blob_tx [Preset: minimal]     OK
+ [Valid]   EF - deneb - Sanity - Blocks - multiple_attester_slashings_no_overlap [Preset: m OK
+ [Valid]   EF - deneb - Sanity - Blocks - multiple_attester_slashings_partial_overlap [Pres OK
+ [Valid]   EF - deneb - Sanity - Blocks - multiple_different_proposer_slashings_same_block  OK
+ [Valid]   EF - deneb - Sanity - Blocks - multiple_different_validator_exits_same_block [Pr OK
+ [Valid]   EF - deneb - Sanity - Blocks - one_blob [Preset: minimal]                        OK
+ [Valid]   EF - deneb - Sanity - Blocks - one_blob_max_txs [Preset: minimal]                OK
+ [Valid]   EF - deneb - Sanity - Blocks - one_blob_two_txs [Preset: minimal]                OK
+ [Valid]   EF - deneb - Sanity - Blocks - partial_withdrawal_in_epoch_transition [Preset: m OK
+ [Valid]   EF - deneb - Sanity - Blocks - proposer_after_inactive_index [Preset: minimal]   OK
+ [Valid]   EF - deneb - Sanity - Blocks - proposer_self_slashing [Preset: minimal]          OK
+ [Valid]   EF - deneb - Sanity - Blocks - proposer_slashing [Preset: minimal]               OK
+ [Valid]   EF - deneb - Sanity - Blocks - skipped_slots [Preset: minimal]                   OK
+ [Valid]   EF - deneb - Sanity - Blocks - slash_and_exit_diff_index [Preset: minimal]       OK
+ [Valid]   EF - deneb - Sanity - Blocks - sync_committee_committee__empty [Preset: minimal] OK
+ [Valid]   EF - deneb - Sanity - Blocks - sync_committee_committee__full [Preset: minimal]  OK
+ [Valid]   EF - deneb - Sanity - Blocks - sync_committee_committee__half [Preset: minimal]  OK
+ [Valid]   EF - deneb - Sanity - Blocks - sync_committee_committee_genesis__empty [Preset:  OK
+ [Valid]   EF - deneb - Sanity - Blocks - sync_committee_committee_genesis__full [Preset: m OK
+ [Valid]   EF - deneb - Sanity - Blocks - sync_committee_committee_genesis__half [Preset: m OK
+ [Valid]   EF - deneb - Sanity - Blocks - top_up_and_partial_withdrawable_validator [Preset OK
+ [Valid]   EF - deneb - Sanity - Blocks - top_up_to_fully_withdrawn_validator [Preset: mini OK
+ [Valid]   EF - deneb - Sanity - Blocks - voluntary_exit [Preset: minimal]                  OK
+ [Valid]   EF - deneb - Sanity - Blocks - withdrawal_success_two_blocks [Preset: minimal]   OK
+ [Valid]   EF - deneb - Sanity - Blocks - zero_blob [Preset: minimal]                       OK
```
## EF - electra - Epoch Processing - Effective balance updates [Preset: minimal]
```diff
+ Effective balance updates - effective_balance_hysteresis [Preset: minimal]                 OK
+ Effective balance updates - effective_balance_hysteresis_with_compounding_credentials [Pre OK
```
## EF - electra - Epoch Processing - Eth1 data reset [Preset: minimal]
```diff
+ Eth1 data reset - eth1_vote_no_reset [Preset: minimal]                                     OK
+ Eth1 data reset - eth1_vote_reset [Preset: minimal]                                        OK
```
## EF - electra - Epoch Processing - Historical summaries update [Preset: minimal]
```diff
+ Historical summaries update - historical_summaries_accumulator [Preset: minimal]           OK
```
## EF - electra - Epoch Processing - Inactivity [Preset: minimal]
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
## EF - electra - Epoch Processing - Justification & Finalization [Preset: minimal]
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
## EF - electra - Epoch Processing - Participation flag updates [Preset: minimal]
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
## EF - electra - Epoch Processing - Pending consolidations [Preset: minimal]
```diff
+ Pending consolidations - all_consolidation_cases_together [Preset: minimal]                OK
+ Pending consolidations - basic_pending_consolidation [Preset: minimal]                     OK
+ Pending consolidations - consolidation_not_yet_withdrawable_validator [Preset: minimal]    OK
+ Pending consolidations - pending_consolidation_balance_computation_compounding [Preset: mi OK
+ Pending consolidations - pending_consolidation_balance_computation_eth1 [Preset: minimal]  OK
+ Pending consolidations - pending_consolidation_compounding_creds [Preset: minimal]         OK
+ Pending consolidations - pending_consolidation_future_epoch [Preset: minimal]              OK
+ Pending consolidations - pending_consolidation_source_balance_greater_than_max_effective [ OK
+ Pending consolidations - pending_consolidation_source_balance_greater_than_max_effective_c OK
+ Pending consolidations - pending_consolidation_source_balance_less_than_max_effective [Pre OK
+ Pending consolidations - pending_consolidation_source_balance_less_than_max_effective_comp OK
+ Pending consolidations - pending_consolidation_with_pending_deposit [Preset: minimal]      OK
+ Pending consolidations - skip_consolidation_when_source_slashed [Preset: minimal]          OK
```
## EF - electra - Epoch Processing - Pending deposits [Preset: minimal]
```diff
+ Pending deposits - apply_pending_deposit_compounding_withdrawal_credentials_max [Preset: m OK
+ Pending deposits - apply_pending_deposit_compounding_withdrawal_credentials_over_max [Pres OK
+ Pending deposits - apply_pending_deposit_compounding_withdrawal_credentials_over_max_next_ OK
+ Pending deposits - apply_pending_deposit_compounding_withdrawal_credentials_under_max [Pre OK
+ Pending deposits - apply_pending_deposit_correct_sig_but_forked_state [Preset: minimal]    OK
+ Pending deposits - apply_pending_deposit_effective_deposit_with_genesis_fork_version [Pres OK
+ Pending deposits - apply_pending_deposit_eth1_withdrawal_credentials [Preset: minimal]     OK
+ Pending deposits - apply_pending_deposit_incorrect_sig_new_deposit [Preset: minimal]       OK
+ Pending deposits - apply_pending_deposit_incorrect_sig_top_up [Preset: minimal]            OK
+ Pending deposits - apply_pending_deposit_incorrect_withdrawal_credentials_top_up [Preset:  OK
+ Pending deposits - apply_pending_deposit_ineffective_deposit_with_bad_fork_version [Preset OK
+ Pending deposits - apply_pending_deposit_key_validate_invalid_decompression [Preset: minim OK
+ Pending deposits - apply_pending_deposit_key_validate_invalid_subgroup [Preset: minimal]   OK
+ Pending deposits - apply_pending_deposit_min_activation [Preset: minimal]                  OK
+ Pending deposits - apply_pending_deposit_non_versioned_withdrawal_credentials [Preset: min OK
+ Pending deposits - apply_pending_deposit_non_versioned_withdrawal_credentials_over_min_act OK
+ Pending deposits - apply_pending_deposit_over_min_activation [Preset: minimal]             OK
+ Pending deposits - apply_pending_deposit_over_min_activation_next_increment [Preset: minim OK
+ Pending deposits - apply_pending_deposit_success_top_up_to_withdrawn_validator [Preset: mi OK
+ Pending deposits - apply_pending_deposit_top_up__less_effective_balance [Preset: minimal]  OK
+ Pending deposits - apply_pending_deposit_top_up__max_effective_balance_compounding [Preset OK
+ Pending deposits - apply_pending_deposit_top_up__min_activation_balance [Preset: minimal]  OK
+ Pending deposits - apply_pending_deposit_top_up__min_activation_balance_compounding [Prese OK
+ Pending deposits - apply_pending_deposit_under_min_activation [Preset: minimal]            OK
+ Pending deposits - apply_pending_deposit_with_previous_fork_version [Preset: minimal]      OK
+ Pending deposits - ineffective_deposit_with_current_fork_version [Preset: minimal]         OK
+ Pending deposits - process_pending_deposits_balance_above_churn [Preset: minimal]          OK
+ Pending deposits - process_pending_deposits_balance_equal_churn [Preset: minimal]          OK
+ Pending deposits - process_pending_deposits_eth1_bridge_transition_complete [Preset: minim OK
+ Pending deposits - process_pending_deposits_eth1_bridge_transition_not_applied [Preset: mi OK
+ Pending deposits - process_pending_deposits_eth1_bridge_transition_pending [Preset: minima OK
+ Pending deposits - process_pending_deposits_limit_is_reached [Preset: minimal]             OK
+ Pending deposits - process_pending_deposits_mixture_of_skipped_and_above_churn [Preset: mi OK
+ Pending deposits - process_pending_deposits_multiple_for_new_validator [Preset: minimal]   OK
+ Pending deposits - process_pending_deposits_multiple_pending_deposits_above_churn [Preset: OK
+ Pending deposits - process_pending_deposits_multiple_pending_deposits_below_churn [Preset: OK
+ Pending deposits - process_pending_deposits_multiple_pending_one_skipped [Preset: minimal] OK
+ Pending deposits - process_pending_deposits_multiple_skipped_deposits_exiting_validators [ OK
+ Pending deposits - process_pending_deposits_not_finalized [Preset: minimal]                OK
+ Pending deposits - process_pending_deposits_preexisting_churn [Preset: minimal]            OK
+ Pending deposits - process_pending_deposits_scaled_churn [Preset: minimal]                 OK
+ Pending deposits - process_pending_deposits_skipped_deposit_exiting_validator [Preset: min OK
+ Pending deposits - process_pending_deposits_withdrawable_validator [Preset: minimal]       OK
+ Pending deposits - process_pending_deposits_withdrawable_validator_not_churned [Preset: mi OK
```
## EF - electra - Epoch Processing - RANDAO mixes reset [Preset: minimal]
```diff
+ RANDAO mixes reset - updated_randao_mixes [Preset: minimal]                                OK
```
## EF - electra - Epoch Processing - Registry updates [Preset: minimal]
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
+ Registry updates - activation_queue_eligibility__greater_than_min_activation_balance [Pres OK
+ Registry updates - activation_queue_eligibility__less_than_min_activation_balance [Preset: OK
+ Registry updates - activation_queue_eligibility__min_activation_balance [Preset: minimal]  OK
+ Registry updates - activation_queue_eligibility__min_activation_balance_compounding_creds  OK
+ Registry updates - activation_queue_eligibility__min_activation_balance_eth1_creds [Preset OK
+ Registry updates - activation_queue_no_activation_no_finality [Preset: minimal]            OK
+ Registry updates - activation_queue_sorting [Preset: minimal]                              OK
+ Registry updates - activation_queue_to_activated_if_finalized [Preset: minimal]            OK
+ Registry updates - add_to_activation_queue [Preset: minimal]                               OK
+ Registry updates - ejection [Preset: minimal]                                              OK
+ Registry updates - ejection_past_churn_limit_min [Preset: minimal]                         OK
+ Registry updates - ejection_past_churn_limit_scaled [Preset: minimal]                      OK
+ Registry updates - invalid_large_withdrawable_epoch [Preset: minimal]                      OK
```
## EF - electra - Epoch Processing - Rewards and penalties [Preset: minimal]
```diff
+ Rewards and penalties - almost_empty_attestations [Preset: minimal]                        OK
+ Rewards and penalties - almost_empty_attestations_with_leak [Preset: minimal]              OK
+ Rewards and penalties - almost_full_attestations [Preset: minimal]                         OK
+ Rewards and penalties - almost_full_attestations_with_leak [Preset: minimal]               OK
+ Rewards and penalties - attestations_some_slashed [Preset: minimal]                        OK
+ Rewards and penalties - duplicate_attestation [Preset: minimal]                            OK
+ Rewards and penalties - full_attestation_participation [Preset: minimal]                   OK
+ Rewards and penalties - full_attestation_participation_with_leak [Preset: minimal]         OK
+ Rewards and penalties - full_attestations_default_balances_except_a_validator_with_one_gwe OK
+ Rewards and penalties - full_attestations_misc_balances [Preset: minimal]                  OK
+ Rewards and penalties - genesis_epoch_full_attestations_no_rewards [Preset: minimal]       OK
+ Rewards and penalties - genesis_epoch_no_attestations_no_penalties [Preset: minimal]       OK
+ Rewards and penalties - no_attestations_all_penalties [Preset: minimal]                    OK
+ Rewards and penalties - random_fill_attestations [Preset: minimal]                         OK
+ Rewards and penalties - random_fill_attestations_with_leak [Preset: minimal]               OK
```
## EF - electra - Epoch Processing - Slashings [Preset: minimal]
```diff
+ Slashings - low_penalty [Preset: minimal]                                                  OK
+ Slashings - max_penalties [Preset: minimal]                                                OK
+ Slashings - minimal_penalty [Preset: minimal]                                              OK
+ Slashings - scaled_penalties [Preset: minimal]                                             OK
+ Slashings - slashings_with_random_state [Preset: minimal]                                  OK
```
## EF - electra - Epoch Processing - Slashings reset [Preset: minimal]
```diff
+ Slashings reset - flush_slashings [Preset: minimal]                                        OK
```
## EF - electra - Epoch Processing - Sync committee updates [Preset: minimal]
```diff
+ Sync committee updates - sync_committees_no_progress_not_at_period_boundary [Preset: minim OK
+ Sync committee updates - sync_committees_progress_genesis [Preset: minimal]                OK
+ Sync committee updates - sync_committees_progress_misc_balances_genesis [Preset: minimal]  OK
+ Sync committee updates - sync_committees_progress_misc_balances_not_genesis [Preset: minim OK
+ Sync committee updates - sync_committees_progress_not_genesis [Preset: minimal]            OK
```
## EF - electra - Finality  [Preset: minimal]
```diff
+ [Valid]   EF - electra - Finality - finality_no_updates_at_genesis [Preset: minimal]       OK
+ [Valid]   EF - electra - Finality - finality_rule_1 [Preset: minimal]                      OK
+ [Valid]   EF - electra - Finality - finality_rule_2 [Preset: minimal]                      OK
+ [Valid]   EF - electra - Finality - finality_rule_3 [Preset: minimal]                      OK
+ [Valid]   EF - electra - Finality - finality_rule_4 [Preset: minimal]                      OK
```
## EF - electra - Random  [Preset: minimal]
```diff
+ [Valid]   EF - electra - Random - randomized_0 [Preset: minimal]                           OK
+ [Valid]   EF - electra - Random - randomized_1 [Preset: minimal]                           OK
+ [Valid]   EF - electra - Random - randomized_10 [Preset: minimal]                          OK
+ [Valid]   EF - electra - Random - randomized_11 [Preset: minimal]                          OK
+ [Valid]   EF - electra - Random - randomized_12 [Preset: minimal]                          OK
+ [Valid]   EF - electra - Random - randomized_13 [Preset: minimal]                          OK
+ [Valid]   EF - electra - Random - randomized_14 [Preset: minimal]                          OK
+ [Valid]   EF - electra - Random - randomized_15 [Preset: minimal]                          OK
+ [Valid]   EF - electra - Random - randomized_2 [Preset: minimal]                           OK
+ [Valid]   EF - electra - Random - randomized_3 [Preset: minimal]                           OK
+ [Valid]   EF - electra - Random - randomized_4 [Preset: minimal]                           OK
+ [Valid]   EF - electra - Random - randomized_5 [Preset: minimal]                           OK
+ [Valid]   EF - electra - Random - randomized_6 [Preset: minimal]                           OK
+ [Valid]   EF - electra - Random - randomized_7 [Preset: minimal]                           OK
+ [Valid]   EF - electra - Random - randomized_8 [Preset: minimal]                           OK
+ [Valid]   EF - electra - Random - randomized_9 [Preset: minimal]                           OK
```
## EF - electra - Rewards  [Preset: minimal]
```diff
+ EF - electra - Rewards - all_balances_too_low_for_reward [Preset: minimal]                 OK
+ EF - electra - Rewards - empty [Preset: minimal]                                           OK
+ EF - electra - Rewards - empty_leak [Preset: minimal]                                      OK
+ EF - electra - Rewards - full_all_correct [Preset: minimal]                                OK
+ EF - electra - Rewards - full_but_partial_participation [Preset: minimal]                  OK
+ EF - electra - Rewards - full_but_partial_participation_leak [Preset: minimal]             OK
+ EF - electra - Rewards - full_leak [Preset: minimal]                                       OK
+ EF - electra - Rewards - full_random_0 [Preset: minimal]                                   OK
+ EF - electra - Rewards - full_random_1 [Preset: minimal]                                   OK
+ EF - electra - Rewards - full_random_2 [Preset: minimal]                                   OK
+ EF - electra - Rewards - full_random_3 [Preset: minimal]                                   OK
+ EF - electra - Rewards - full_random_4 [Preset: minimal]                                   OK
+ EF - electra - Rewards - full_random_leak [Preset: minimal]                                OK
+ EF - electra - Rewards - full_random_low_balances_0 [Preset: minimal]                      OK
+ EF - electra - Rewards - full_random_low_balances_1 [Preset: minimal]                      OK
+ EF - electra - Rewards - full_random_misc_balances [Preset: minimal]                       OK
+ EF - electra - Rewards - full_random_seven_epoch_leak [Preset: minimal]                    OK
+ EF - electra - Rewards - full_random_ten_epoch_leak [Preset: minimal]                      OK
+ EF - electra - Rewards - full_random_without_leak_0 [Preset: minimal]                      OK
+ EF - electra - Rewards - full_random_without_leak_and_current_exit_0 [Preset: minimal]     OK
+ EF - electra - Rewards - half_full [Preset: minimal]                                       OK
+ EF - electra - Rewards - half_full_leak [Preset: minimal]                                  OK
+ EF - electra - Rewards - quarter_full [Preset: minimal]                                    OK
+ EF - electra - Rewards - quarter_full_leak [Preset: minimal]                               OK
+ EF - electra - Rewards - some_very_low_effective_balances_that_attested [Preset: minimal]  OK
+ EF - electra - Rewards - some_very_low_effective_balances_that_attested_leak [Preset: mini OK
+ EF - electra - Rewards - some_very_low_effective_balances_that_did_not_attest [Preset: min OK
+ EF - electra - Rewards - some_very_low_effective_balances_that_did_not_attest_leak [Preset OK
+ EF - electra - Rewards - with_exited_validators [Preset: minimal]                          OK
+ EF - electra - Rewards - with_exited_validators_leak [Preset: minimal]                     OK
+ EF - electra - Rewards - with_not_yet_activated_validators [Preset: minimal]               OK
+ EF - electra - Rewards - with_not_yet_activated_validators_leak [Preset: minimal]          OK
+ EF - electra - Rewards - with_slashed_validators [Preset: minimal]                         OK
+ EF - electra - Rewards - with_slashed_validators_leak [Preset: minimal]                    OK
```
## EF - electra - Sanity - Blocks  [Preset: minimal]
```diff
+ [Invalid] EF - electra - Sanity - Blocks - deposit_transition__invalid_eth1_deposits_overl OK
+ [Invalid] EF - electra - Sanity - Blocks - deposit_transition__invalid_not_enough_eth1_dep OK
+ [Invalid] EF - electra - Sanity - Blocks - deposit_transition__invalid_too_many_eth1_depos OK
+ [Invalid] EF - electra - Sanity - Blocks - invalid_all_zeroed_sig [Preset: minimal]        OK
+ [Invalid] EF - electra - Sanity - Blocks - invalid_duplicate_bls_changes_same_block [Prese OK
+ [Invalid] EF - electra - Sanity - Blocks - invalid_duplicate_deposit_same_block [Preset: m OK
+ [Invalid] EF - electra - Sanity - Blocks - invalid_duplicate_proposer_slashings_same_block OK
+ [Invalid] EF - electra - Sanity - Blocks - invalid_duplicate_validator_exit_same_block [Pr OK
+ [Invalid] EF - electra - Sanity - Blocks - invalid_exceed_max_blobs_per_block [Preset: min OK
+ [Invalid] EF - electra - Sanity - Blocks - invalid_incorrect_block_sig [Preset: minimal]   OK
+ [Invalid] EF - electra - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_expec OK
+ [Invalid] EF - electra - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_propo OK
+ [Invalid] EF - electra - Sanity - Blocks - invalid_incorrect_state_root [Preset: minimal]  OK
+ [Invalid] EF - electra - Sanity - Blocks - invalid_is_execution_enabled_false [Preset: min OK
+ [Invalid] EF - electra - Sanity - Blocks - invalid_max_blobs_per_block_two_txs [Preset: mi OK
+ [Invalid] EF - electra - Sanity - Blocks - invalid_one_blob_max_plus_one_txs [Preset: mini OK
+ [Invalid] EF - electra - Sanity - Blocks - invalid_only_increase_deposit_count [Preset: mi OK
+ [Invalid] EF - electra - Sanity - Blocks - invalid_parent_from_same_slot [Preset: minimal] OK
+ [Invalid] EF - electra - Sanity - Blocks - invalid_prev_slot_block_transition [Preset: min OK
+ [Invalid] EF - electra - Sanity - Blocks - invalid_same_slot_block_transition [Preset: min OK
+ [Invalid] EF - electra - Sanity - Blocks - invalid_similar_proposer_slashings_same_block [ OK
+ [Invalid] EF - electra - Sanity - Blocks - invalid_two_bls_changes_of_different_addresses_ OK
+ [Invalid] EF - electra - Sanity - Blocks - invalid_withdrawal_fail_second_block_payload_is OK
+ [Invalid] EF - electra - Sanity - Blocks - slash_and_exit_same_index [Preset: minimal]     OK
+ [Valid]   EF - electra - Sanity - Blocks - activate_and_partial_withdrawal_max_effective_b OK
+ [Valid]   EF - electra - Sanity - Blocks - activate_and_partial_withdrawal_overdeposit [Pr OK
+ [Valid]   EF - electra - Sanity - Blocks - attestation [Preset: minimal]                   OK
+ [Valid]   EF - electra - Sanity - Blocks - attester_slashing [Preset: minimal]             OK
+ [Valid]   EF - electra - Sanity - Blocks - balance_driven_status_transitions [Preset: mini OK
+ [Valid]   EF - electra - Sanity - Blocks - basic_btec_and_el_withdrawal_request_in_same_bl OK
+ [Valid]   EF - electra - Sanity - Blocks - basic_btec_before_el_withdrawal_request [Preset OK
+ [Valid]   EF - electra - Sanity - Blocks - basic_el_withdrawal_request [Preset: minimal]   OK
+ [Valid]   EF - electra - Sanity - Blocks - block_transition_randomized_payload [Preset: mi OK
+ [Valid]   EF - electra - Sanity - Blocks - bls_change [Preset: minimal]                    OK
+ [Valid]   EF - electra - Sanity - Blocks - cl_exit_and_el_withdrawal_request_in_same_block OK
+ [Valid]   EF - electra - Sanity - Blocks - consolidation_requests_when_pending_consolidati OK
+ [Valid]   EF - electra - Sanity - Blocks - deposit_and_bls_change [Preset: minimal]        OK
+ [Valid]   EF - electra - Sanity - Blocks - deposit_in_block [Preset: minimal]              OK
+ [Valid]   EF - electra - Sanity - Blocks - deposit_request_max_per_payload [Preset: minima OK
+ [Valid]   EF - electra - Sanity - Blocks - deposit_request_with_same_pubkey_different_with OK
+ [Valid]   EF - electra - Sanity - Blocks - deposit_top_up [Preset: minimal]                OK
+ [Valid]   EF - electra - Sanity - Blocks - deposit_transition__deposit_and_top_up_same_blo OK
+ [Valid]   EF - electra - Sanity - Blocks - deposit_transition__deposit_with_same_pubkey_di OK
+ [Valid]   EF - electra - Sanity - Blocks - deposit_transition__process_eth1_deposits [Pres OK
+ [Valid]   EF - electra - Sanity - Blocks - deposit_transition__process_eth1_deposits_up_to OK
+ [Valid]   EF - electra - Sanity - Blocks - deposit_transition__process_max_eth1_deposits [ OK
+ [Valid]   EF - electra - Sanity - Blocks - deposit_transition__start_index_is_set [Preset: OK
+ [Valid]   EF - electra - Sanity - Blocks - duplicate_attestation_same_block [Preset: minim OK
+ [Valid]   EF - electra - Sanity - Blocks - effective_balance_increase_changes_lookahead [P OK
+ [Valid]   EF - electra - Sanity - Blocks - empty_block_transition [Preset: minimal]        OK
+ [Valid]   EF - electra - Sanity - Blocks - empty_block_transition_large_validator_set [Pre OK
+ [Valid]   EF - electra - Sanity - Blocks - empty_block_transition_no_tx [Preset: minimal]  OK
+ [Valid]   EF - electra - Sanity - Blocks - empty_epoch_transition [Preset: minimal]        OK
+ [Valid]   EF - electra - Sanity - Blocks - empty_epoch_transition_large_validator_set [Pre OK
+ [Valid]   EF - electra - Sanity - Blocks - empty_epoch_transition_not_finalizing [Preset:  OK
+ [Valid]   EF - electra - Sanity - Blocks - eth1_data_votes_consensus [Preset: minimal]     OK
+ [Valid]   EF - electra - Sanity - Blocks - eth1_data_votes_no_consensus [Preset: minimal]  OK
+ [Valid]   EF - electra - Sanity - Blocks - exit_and_bls_change [Preset: minimal]           OK
+ [Valid]   EF - electra - Sanity - Blocks - full_random_operations_0 [Preset: minimal]      OK
+ [Valid]   EF - electra - Sanity - Blocks - full_random_operations_1 [Preset: minimal]      OK
+ [Valid]   EF - electra - Sanity - Blocks - full_random_operations_2 [Preset: minimal]      OK
+ [Valid]   EF - electra - Sanity - Blocks - full_random_operations_3 [Preset: minimal]      OK
+ [Valid]   EF - electra - Sanity - Blocks - full_withdrawal_in_epoch_transition [Preset: mi OK
+ [Valid]   EF - electra - Sanity - Blocks - high_proposer_index [Preset: minimal]           OK
+ [Valid]   EF - electra - Sanity - Blocks - historical_batch [Preset: minimal]              OK
+ [Valid]   EF - electra - Sanity - Blocks - inactivity_scores_full_participation_leaking [P OK
+ [Valid]   EF - electra - Sanity - Blocks - inactivity_scores_leaking [Preset: minimal]     OK
+ [Valid]   EF - electra - Sanity - Blocks - many_partial_withdrawals_in_epoch_transition [P OK
+ [Valid]   EF - electra - Sanity - Blocks - max_blobs_per_block [Preset: minimal]           OK
+ [Valid]   EF - electra - Sanity - Blocks - mix_blob_tx_and_non_blob_tx [Preset: minimal]   OK
+ [Valid]   EF - electra - Sanity - Blocks - multi_epoch_consolidation_chain [Preset: minima OK
+ [Valid]   EF - electra - Sanity - Blocks - multiple_different_proposer_slashings_same_bloc OK
+ [Valid]   EF - electra - Sanity - Blocks - multiple_different_validator_exits_same_block [ OK
+ [Valid]   EF - electra - Sanity - Blocks - multiple_el_partial_withdrawal_requests_differe OK
+ [Valid]   EF - electra - Sanity - Blocks - multiple_el_partial_withdrawal_requests_same_va OK
+ [Valid]   EF - electra - Sanity - Blocks - one_blob [Preset: minimal]                      OK
+ [Valid]   EF - electra - Sanity - Blocks - one_blob_max_txs [Preset: minimal]              OK
+ [Valid]   EF - electra - Sanity - Blocks - one_blob_two_txs [Preset: minimal]              OK
+ [Valid]   EF - electra - Sanity - Blocks - partial_withdrawal_in_epoch_transition [Preset: OK
+ [Valid]   EF - electra - Sanity - Blocks - proposer_after_inactive_index [Preset: minimal] OK
+ [Valid]   EF - electra - Sanity - Blocks - proposer_self_slashing [Preset: minimal]        OK
+ [Valid]   EF - electra - Sanity - Blocks - proposer_slashing [Preset: minimal]             OK
+ [Valid]   EF - electra - Sanity - Blocks - skipped_slots [Preset: minimal]                 OK
+ [Valid]   EF - electra - Sanity - Blocks - slash_and_exit_diff_index [Preset: minimal]     OK
+ [Valid]   EF - electra - Sanity - Blocks - switch_to_compounding_requests_when_pending_con OK
+ [Valid]   EF - electra - Sanity - Blocks - switch_to_compounding_requests_when_too_little_ OK
+ [Valid]   EF - electra - Sanity - Blocks - sync_committee_committee__empty [Preset: minima OK
+ [Valid]   EF - electra - Sanity - Blocks - sync_committee_committee__full [Preset: minimal OK
+ [Valid]   EF - electra - Sanity - Blocks - sync_committee_committee__half [Preset: minimal OK
+ [Valid]   EF - electra - Sanity - Blocks - sync_committee_committee_genesis__empty [Preset OK
+ [Valid]   EF - electra - Sanity - Blocks - sync_committee_committee_genesis__full [Preset: OK
+ [Valid]   EF - electra - Sanity - Blocks - sync_committee_committee_genesis__half [Preset: OK
+ [Valid]   EF - electra - Sanity - Blocks - top_up_and_partial_withdrawable_validator [Pres OK
+ [Valid]   EF - electra - Sanity - Blocks - top_up_to_fully_withdrawn_validator [Preset: mi OK
+ [Valid]   EF - electra - Sanity - Blocks - voluntary_exit [Preset: minimal]                OK
+ [Valid]   EF - electra - Sanity - Blocks - withdrawal_and_consolidation_effective_balance_ OK
+ [Valid]   EF - electra - Sanity - Blocks - withdrawal_and_switch_to_compounding_request_sa OK
+ [Valid]   EF - electra - Sanity - Blocks - withdrawal_and_withdrawal_request_same_validato OK
+ [Valid]   EF - electra - Sanity - Blocks - withdrawal_requests_when_pending_withdrawal_que OK
+ [Valid]   EF - electra - Sanity - Blocks - withdrawal_success_two_blocks [Preset: minimal] OK
+ [Valid]   EF - electra - Sanity - Blocks - zero_blob [Preset: minimal]                     OK
```
## EF - fulu - Epoch Processing - Effective balance updates [Preset: minimal]
```diff
+ Effective balance updates - effective_balance_hysteresis [Preset: minimal]                 OK
+ Effective balance updates - effective_balance_hysteresis_with_compounding_credentials [Pre OK
```
## EF - fulu - Epoch Processing - Eth1 data reset [Preset: minimal]
```diff
+ Eth1 data reset - eth1_vote_no_reset [Preset: minimal]                                     OK
+ Eth1 data reset - eth1_vote_reset [Preset: minimal]                                        OK
```
## EF - fulu - Epoch Processing - Historical summaries update [Preset: minimal]
```diff
+ Historical summaries update - historical_summaries_accumulator [Preset: minimal]           OK
```
## EF - fulu - Epoch Processing - Inactivity [Preset: minimal]
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
## EF - fulu - Epoch Processing - Justification & Finalization [Preset: minimal]
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
## EF - fulu - Epoch Processing - Participation flag updates [Preset: minimal]
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
## EF - fulu - Epoch Processing - Pending consolidations [Preset: minimal]
```diff
+ Pending consolidations - all_consolidation_cases_together [Preset: minimal]                OK
+ Pending consolidations - basic_pending_consolidation [Preset: minimal]                     OK
+ Pending consolidations - consolidation_not_yet_withdrawable_validator [Preset: minimal]    OK
+ Pending consolidations - pending_consolidation_balance_computation_compounding [Preset: mi OK
+ Pending consolidations - pending_consolidation_balance_computation_eth1 [Preset: minimal]  OK
+ Pending consolidations - pending_consolidation_compounding_creds [Preset: minimal]         OK
+ Pending consolidations - pending_consolidation_future_epoch [Preset: minimal]              OK
+ Pending consolidations - pending_consolidation_source_balance_greater_than_max_effective [ OK
+ Pending consolidations - pending_consolidation_source_balance_greater_than_max_effective_c OK
+ Pending consolidations - pending_consolidation_source_balance_less_than_max_effective [Pre OK
+ Pending consolidations - pending_consolidation_source_balance_less_than_max_effective_comp OK
+ Pending consolidations - pending_consolidation_with_pending_deposit [Preset: minimal]      OK
+ Pending consolidations - skip_consolidation_when_source_slashed [Preset: minimal]          OK
```
## EF - fulu - Epoch Processing - Pending deposits [Preset: minimal]
```diff
+ Pending deposits - apply_pending_deposit_compounding_withdrawal_credentials_max [Preset: m OK
+ Pending deposits - apply_pending_deposit_compounding_withdrawal_credentials_over_max [Pres OK
+ Pending deposits - apply_pending_deposit_compounding_withdrawal_credentials_over_max_next_ OK
+ Pending deposits - apply_pending_deposit_compounding_withdrawal_credentials_under_max [Pre OK
+ Pending deposits - apply_pending_deposit_correct_sig_but_forked_state [Preset: minimal]    OK
+ Pending deposits - apply_pending_deposit_effective_deposit_with_genesis_fork_version [Pres OK
+ Pending deposits - apply_pending_deposit_eth1_withdrawal_credentials [Preset: minimal]     OK
+ Pending deposits - apply_pending_deposit_incorrect_sig_new_deposit [Preset: minimal]       OK
+ Pending deposits - apply_pending_deposit_incorrect_sig_top_up [Preset: minimal]            OK
+ Pending deposits - apply_pending_deposit_incorrect_withdrawal_credentials_top_up [Preset:  OK
+ Pending deposits - apply_pending_deposit_ineffective_deposit_with_bad_fork_version [Preset OK
+ Pending deposits - apply_pending_deposit_key_validate_invalid_decompression [Preset: minim OK
+ Pending deposits - apply_pending_deposit_key_validate_invalid_subgroup [Preset: minimal]   OK
+ Pending deposits - apply_pending_deposit_min_activation [Preset: minimal]                  OK
+ Pending deposits - apply_pending_deposit_non_versioned_withdrawal_credentials [Preset: min OK
+ Pending deposits - apply_pending_deposit_non_versioned_withdrawal_credentials_over_min_act OK
+ Pending deposits - apply_pending_deposit_over_min_activation [Preset: minimal]             OK
+ Pending deposits - apply_pending_deposit_over_min_activation_next_increment [Preset: minim OK
+ Pending deposits - apply_pending_deposit_success_top_up_to_withdrawn_validator [Preset: mi OK
+ Pending deposits - apply_pending_deposit_top_up__less_effective_balance [Preset: minimal]  OK
+ Pending deposits - apply_pending_deposit_top_up__max_effective_balance_compounding [Preset OK
+ Pending deposits - apply_pending_deposit_top_up__min_activation_balance [Preset: minimal]  OK
+ Pending deposits - apply_pending_deposit_top_up__min_activation_balance_compounding [Prese OK
+ Pending deposits - apply_pending_deposit_under_min_activation [Preset: minimal]            OK
+ Pending deposits - apply_pending_deposit_with_previous_fork_version [Preset: minimal]      OK
+ Pending deposits - ineffective_deposit_with_current_fork_version [Preset: minimal]         OK
+ Pending deposits - process_pending_deposits_balance_above_churn [Preset: minimal]          OK
+ Pending deposits - process_pending_deposits_balance_equal_churn [Preset: minimal]          OK
+ Pending deposits - process_pending_deposits_eth1_bridge_transition_complete [Preset: minim OK
+ Pending deposits - process_pending_deposits_eth1_bridge_transition_not_applied [Preset: mi OK
+ Pending deposits - process_pending_deposits_eth1_bridge_transition_pending [Preset: minima OK
+ Pending deposits - process_pending_deposits_limit_is_reached [Preset: minimal]             OK
+ Pending deposits - process_pending_deposits_mixture_of_skipped_and_above_churn [Preset: mi OK
+ Pending deposits - process_pending_deposits_multiple_for_new_validator [Preset: minimal]   OK
+ Pending deposits - process_pending_deposits_multiple_pending_deposits_above_churn [Preset: OK
+ Pending deposits - process_pending_deposits_multiple_pending_deposits_below_churn [Preset: OK
+ Pending deposits - process_pending_deposits_multiple_pending_one_skipped [Preset: minimal] OK
+ Pending deposits - process_pending_deposits_multiple_skipped_deposits_exiting_validators [ OK
+ Pending deposits - process_pending_deposits_not_finalized [Preset: minimal]                OK
+ Pending deposits - process_pending_deposits_preexisting_churn [Preset: minimal]            OK
+ Pending deposits - process_pending_deposits_scaled_churn [Preset: minimal]                 OK
+ Pending deposits - process_pending_deposits_skipped_deposit_exiting_validator [Preset: min OK
+ Pending deposits - process_pending_deposits_withdrawable_validator [Preset: minimal]       OK
+ Pending deposits - process_pending_deposits_withdrawable_validator_not_churned [Preset: mi OK
```
## EF - fulu - Epoch Processing - Proposer lookahead [Preset: minimal]
```diff
+ Proposer lookahead - proposer_lookahead_does_not_contain_exited_validators [Preset: minima OK
+ Proposer lookahead - proposer_lookahead_in_state_matches_computed_lookahead [Preset: minim OK
```
## EF - fulu - Epoch Processing - RANDAO mixes reset [Preset: minimal]
```diff
+ RANDAO mixes reset - updated_randao_mixes [Preset: minimal]                                OK
```
## EF - fulu - Epoch Processing - Registry updates [Preset: minimal]
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
+ Registry updates - activation_queue_eligibility__greater_than_min_activation_balance [Pres OK
+ Registry updates - activation_queue_eligibility__less_than_min_activation_balance [Preset: OK
+ Registry updates - activation_queue_eligibility__min_activation_balance [Preset: minimal]  OK
+ Registry updates - activation_queue_eligibility__min_activation_balance_compounding_creds  OK
+ Registry updates - activation_queue_eligibility__min_activation_balance_eth1_creds [Preset OK
+ Registry updates - activation_queue_no_activation_no_finality [Preset: minimal]            OK
+ Registry updates - activation_queue_sorting [Preset: minimal]                              OK
+ Registry updates - activation_queue_to_activated_if_finalized [Preset: minimal]            OK
+ Registry updates - add_to_activation_queue [Preset: minimal]                               OK
+ Registry updates - ejection [Preset: minimal]                                              OK
+ Registry updates - ejection_past_churn_limit_min [Preset: minimal]                         OK
+ Registry updates - ejection_past_churn_limit_scaled [Preset: minimal]                      OK
+ Registry updates - invalid_large_withdrawable_epoch [Preset: minimal]                      OK
```
## EF - fulu - Epoch Processing - Rewards and penalties [Preset: minimal]
```diff
+ Rewards and penalties - almost_empty_attestations [Preset: minimal]                        OK
+ Rewards and penalties - almost_empty_attestations_with_leak [Preset: minimal]              OK
+ Rewards and penalties - almost_full_attestations [Preset: minimal]                         OK
+ Rewards and penalties - almost_full_attestations_with_leak [Preset: minimal]               OK
+ Rewards and penalties - attestations_some_slashed [Preset: minimal]                        OK
+ Rewards and penalties - duplicate_attestation [Preset: minimal]                            OK
+ Rewards and penalties - full_attestation_participation [Preset: minimal]                   OK
+ Rewards and penalties - full_attestation_participation_with_leak [Preset: minimal]         OK
+ Rewards and penalties - full_attestations_default_balances_except_a_validator_with_one_gwe OK
+ Rewards and penalties - full_attestations_misc_balances [Preset: minimal]                  OK
+ Rewards and penalties - genesis_epoch_full_attestations_no_rewards [Preset: minimal]       OK
+ Rewards and penalties - genesis_epoch_no_attestations_no_penalties [Preset: minimal]       OK
+ Rewards and penalties - no_attestations_all_penalties [Preset: minimal]                    OK
+ Rewards and penalties - random_fill_attestations [Preset: minimal]                         OK
+ Rewards and penalties - random_fill_attestations_with_leak [Preset: minimal]               OK
```
## EF - fulu - Epoch Processing - Slashings [Preset: minimal]
```diff
+ Slashings - low_penalty [Preset: minimal]                                                  OK
+ Slashings - max_penalties [Preset: minimal]                                                OK
+ Slashings - minimal_penalty [Preset: minimal]                                              OK
+ Slashings - scaled_penalties [Preset: minimal]                                             OK
+ Slashings - slashings_with_random_state [Preset: minimal]                                  OK
```
## EF - fulu - Epoch Processing - Slashings reset [Preset: minimal]
```diff
+ Slashings reset - flush_slashings [Preset: minimal]                                        OK
```
## EF - fulu - Epoch Processing - Sync committee updates [Preset: minimal]
```diff
+ Sync committee updates - sync_committees_no_progress_not_at_period_boundary [Preset: minim OK
+ Sync committee updates - sync_committees_progress_genesis [Preset: minimal]                OK
+ Sync committee updates - sync_committees_progress_misc_balances_genesis [Preset: minimal]  OK
+ Sync committee updates - sync_committees_progress_misc_balances_not_genesis [Preset: minim OK
+ Sync committee updates - sync_committees_progress_not_genesis [Preset: minimal]            OK
```
## EF - fulu - Finality  [Preset: minimal]
```diff
+ [Valid]   EF - fulu - Finality - finality_no_updates_at_genesis [Preset: minimal]          OK
+ [Valid]   EF - fulu - Finality - finality_rule_1 [Preset: minimal]                         OK
+ [Valid]   EF - fulu - Finality - finality_rule_2 [Preset: minimal]                         OK
+ [Valid]   EF - fulu - Finality - finality_rule_3 [Preset: minimal]                         OK
+ [Valid]   EF - fulu - Finality - finality_rule_4 [Preset: minimal]                         OK
```
## EF - fulu - Random  [Preset: minimal]
```diff
+ [Valid]   EF - fulu - Random - randomized_0 [Preset: minimal]                              OK
+ [Valid]   EF - fulu - Random - randomized_1 [Preset: minimal]                              OK
+ [Valid]   EF - fulu - Random - randomized_10 [Preset: minimal]                             OK
+ [Valid]   EF - fulu - Random - randomized_11 [Preset: minimal]                             OK
+ [Valid]   EF - fulu - Random - randomized_12 [Preset: minimal]                             OK
+ [Valid]   EF - fulu - Random - randomized_13 [Preset: minimal]                             OK
+ [Valid]   EF - fulu - Random - randomized_14 [Preset: minimal]                             OK
+ [Valid]   EF - fulu - Random - randomized_15 [Preset: minimal]                             OK
+ [Valid]   EF - fulu - Random - randomized_2 [Preset: minimal]                              OK
+ [Valid]   EF - fulu - Random - randomized_3 [Preset: minimal]                              OK
+ [Valid]   EF - fulu - Random - randomized_4 [Preset: minimal]                              OK
+ [Valid]   EF - fulu - Random - randomized_5 [Preset: minimal]                              OK
+ [Valid]   EF - fulu - Random - randomized_6 [Preset: minimal]                              OK
+ [Valid]   EF - fulu - Random - randomized_7 [Preset: minimal]                              OK
+ [Valid]   EF - fulu - Random - randomized_8 [Preset: minimal]                              OK
+ [Valid]   EF - fulu - Random - randomized_9 [Preset: minimal]                              OK
```
## EF - fulu - Rewards  [Preset: minimal]
```diff
+ EF - fulu - Rewards - all_balances_too_low_for_reward [Preset: minimal]                    OK
+ EF - fulu - Rewards - empty [Preset: minimal]                                              OK
+ EF - fulu - Rewards - empty_leak [Preset: minimal]                                         OK
+ EF - fulu - Rewards - full_all_correct [Preset: minimal]                                   OK
+ EF - fulu - Rewards - full_but_partial_participation [Preset: minimal]                     OK
+ EF - fulu - Rewards - full_but_partial_participation_leak [Preset: minimal]                OK
+ EF - fulu - Rewards - full_leak [Preset: minimal]                                          OK
+ EF - fulu - Rewards - full_random_0 [Preset: minimal]                                      OK
+ EF - fulu - Rewards - full_random_1 [Preset: minimal]                                      OK
+ EF - fulu - Rewards - full_random_2 [Preset: minimal]                                      OK
+ EF - fulu - Rewards - full_random_3 [Preset: minimal]                                      OK
+ EF - fulu - Rewards - full_random_4 [Preset: minimal]                                      OK
+ EF - fulu - Rewards - full_random_leak [Preset: minimal]                                   OK
+ EF - fulu - Rewards - full_random_low_balances_0 [Preset: minimal]                         OK
+ EF - fulu - Rewards - full_random_low_balances_1 [Preset: minimal]                         OK
+ EF - fulu - Rewards - full_random_misc_balances [Preset: minimal]                          OK
+ EF - fulu - Rewards - full_random_seven_epoch_leak [Preset: minimal]                       OK
+ EF - fulu - Rewards - full_random_ten_epoch_leak [Preset: minimal]                         OK
+ EF - fulu - Rewards - full_random_without_leak_0 [Preset: minimal]                         OK
+ EF - fulu - Rewards - full_random_without_leak_and_current_exit_0 [Preset: minimal]        OK
+ EF - fulu - Rewards - half_full [Preset: minimal]                                          OK
+ EF - fulu - Rewards - half_full_leak [Preset: minimal]                                     OK
+ EF - fulu - Rewards - quarter_full [Preset: minimal]                                       OK
+ EF - fulu - Rewards - quarter_full_leak [Preset: minimal]                                  OK
+ EF - fulu - Rewards - some_very_low_effective_balances_that_attested [Preset: minimal]     OK
+ EF - fulu - Rewards - some_very_low_effective_balances_that_attested_leak [Preset: minimal OK
+ EF - fulu - Rewards - some_very_low_effective_balances_that_did_not_attest [Preset: minima OK
+ EF - fulu - Rewards - some_very_low_effective_balances_that_did_not_attest_leak [Preset: m OK
+ EF - fulu - Rewards - with_exited_validators [Preset: minimal]                             OK
+ EF - fulu - Rewards - with_exited_validators_leak [Preset: minimal]                        OK
+ EF - fulu - Rewards - with_not_yet_activated_validators [Preset: minimal]                  OK
+ EF - fulu - Rewards - with_not_yet_activated_validators_leak [Preset: minimal]             OK
+ EF - fulu - Rewards - with_slashed_validators [Preset: minimal]                            OK
+ EF - fulu - Rewards - with_slashed_validators_leak [Preset: minimal]                       OK
```
## EF - fulu - Sanity - Blocks  [Preset: minimal]
```diff
+ [Invalid] EF - fulu - Sanity - Blocks - invalid_all_zeroed_sig [Preset: minimal]           OK
+ [Invalid] EF - fulu - Sanity - Blocks - invalid_duplicate_bls_changes_same_block [Preset:  OK
+ [Invalid] EF - fulu - Sanity - Blocks - invalid_duplicate_deposit_same_block [Preset: mini OK
+ [Invalid] EF - fulu - Sanity - Blocks - invalid_duplicate_proposer_slashings_same_block [P OK
+ [Invalid] EF - fulu - Sanity - Blocks - invalid_duplicate_validator_exit_same_block [Prese OK
+ [Invalid] EF - fulu - Sanity - Blocks - invalid_exceed_max_blobs_per_block [Preset: minima OK
+ [Invalid] EF - fulu - Sanity - Blocks - invalid_incorrect_block_sig [Preset: minimal]      OK
+ [Invalid] EF - fulu - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_expected OK
+ [Invalid] EF - fulu - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_proposer OK
+ [Invalid] EF - fulu - Sanity - Blocks - invalid_incorrect_state_root [Preset: minimal]     OK
+ [Invalid] EF - fulu - Sanity - Blocks - invalid_is_execution_enabled_false [Preset: minima OK
+ [Invalid] EF - fulu - Sanity - Blocks - invalid_max_blobs_per_block_two_txs [Preset: minim OK
+ [Invalid] EF - fulu - Sanity - Blocks - invalid_one_blob_max_plus_one_txs [Preset: minimal OK
+ [Invalid] EF - fulu - Sanity - Blocks - invalid_only_increase_deposit_count [Preset: minim OK
+ [Invalid] EF - fulu - Sanity - Blocks - invalid_parent_from_same_slot [Preset: minimal]    OK
+ [Invalid] EF - fulu - Sanity - Blocks - invalid_prev_slot_block_transition [Preset: minima OK
+ [Invalid] EF - fulu - Sanity - Blocks - invalid_same_slot_block_transition [Preset: minima OK
+ [Invalid] EF - fulu - Sanity - Blocks - invalid_similar_proposer_slashings_same_block [Pre OK
+ [Invalid] EF - fulu - Sanity - Blocks - invalid_two_bls_changes_of_different_addresses_sam OK
+ [Invalid] EF - fulu - Sanity - Blocks - invalid_withdrawal_fail_second_block_payload_isnt_ OK
+ [Invalid] EF - fulu - Sanity - Blocks - slash_and_exit_same_index [Preset: minimal]        OK
+ [Valid]   EF - fulu - Sanity - Blocks - activate_and_partial_withdrawal_max_effective_bala OK
+ [Valid]   EF - fulu - Sanity - Blocks - activate_and_partial_withdrawal_overdeposit [Prese OK
+ [Valid]   EF - fulu - Sanity - Blocks - attestation [Preset: minimal]                      OK
+ [Valid]   EF - fulu - Sanity - Blocks - attester_slashing [Preset: minimal]                OK
+ [Valid]   EF - fulu - Sanity - Blocks - balance_driven_status_transitions [Preset: minimal OK
+ [Valid]   EF - fulu - Sanity - Blocks - basic_btec_and_el_withdrawal_request_in_same_block OK
+ [Valid]   EF - fulu - Sanity - Blocks - basic_btec_before_el_withdrawal_request [Preset: m OK
+ [Valid]   EF - fulu - Sanity - Blocks - basic_el_withdrawal_request [Preset: minimal]      OK
+ [Valid]   EF - fulu - Sanity - Blocks - block_transition_randomized_payload [Preset: minim OK
+ [Valid]   EF - fulu - Sanity - Blocks - bls_change [Preset: minimal]                       OK
+ [Valid]   EF - fulu - Sanity - Blocks - cl_exit_and_el_withdrawal_request_in_same_block [P OK
+ [Valid]   EF - fulu - Sanity - Blocks - consolidation_requests_when_pending_consolidation_ OK
+ [Valid]   EF - fulu - Sanity - Blocks - deposit_and_bls_change [Preset: minimal]           OK
+ [Valid]   EF - fulu - Sanity - Blocks - deposit_in_block [Preset: minimal]                 OK
+ [Valid]   EF - fulu - Sanity - Blocks - deposit_request_max_per_payload [Preset: minimal]  OK
+ [Valid]   EF - fulu - Sanity - Blocks - deposit_request_with_same_pubkey_different_withdra OK
+ [Valid]   EF - fulu - Sanity - Blocks - deposit_top_up [Preset: minimal]                   OK
+ [Valid]   EF - fulu - Sanity - Blocks - duplicate_attestation_same_block [Preset: minimal] OK
+ [Valid]   EF - fulu - Sanity - Blocks - effective_balance_increase_changes_lookahead [Pres OK
+ [Valid]   EF - fulu - Sanity - Blocks - empty_block_transition [Preset: minimal]           OK
+ [Valid]   EF - fulu - Sanity - Blocks - empty_block_transition_large_validator_set [Preset OK
+ [Valid]   EF - fulu - Sanity - Blocks - empty_block_transition_no_tx [Preset: minimal]     OK
+ [Valid]   EF - fulu - Sanity - Blocks - empty_epoch_transition [Preset: minimal]           OK
+ [Valid]   EF - fulu - Sanity - Blocks - empty_epoch_transition_large_validator_set [Preset OK
+ [Valid]   EF - fulu - Sanity - Blocks - empty_epoch_transition_not_finalizing [Preset: min OK
+ [Valid]   EF - fulu - Sanity - Blocks - eth1_data_votes_consensus [Preset: minimal]        OK
+ [Valid]   EF - fulu - Sanity - Blocks - eth1_data_votes_no_consensus [Preset: minimal]     OK
+ [Valid]   EF - fulu - Sanity - Blocks - exit_and_bls_change [Preset: minimal]              OK
+ [Valid]   EF - fulu - Sanity - Blocks - full_random_operations_0 [Preset: minimal]         OK
+ [Valid]   EF - fulu - Sanity - Blocks - full_random_operations_1 [Preset: minimal]         OK
+ [Valid]   EF - fulu - Sanity - Blocks - full_random_operations_2 [Preset: minimal]         OK
+ [Valid]   EF - fulu - Sanity - Blocks - full_random_operations_3 [Preset: minimal]         OK
+ [Valid]   EF - fulu - Sanity - Blocks - full_withdrawal_in_epoch_transition [Preset: minim OK
+ [Valid]   EF - fulu - Sanity - Blocks - high_proposer_index [Preset: minimal]              OK
+ [Valid]   EF - fulu - Sanity - Blocks - historical_batch [Preset: minimal]                 OK
+ [Valid]   EF - fulu - Sanity - Blocks - inactivity_scores_full_participation_leaking [Pres OK
+ [Valid]   EF - fulu - Sanity - Blocks - inactivity_scores_leaking [Preset: minimal]        OK
+ [Valid]   EF - fulu - Sanity - Blocks - many_partial_withdrawals_in_epoch_transition [Pres OK
+ [Valid]   EF - fulu - Sanity - Blocks - max_blobs_per_block [Preset: minimal]              OK
+ [Valid]   EF - fulu - Sanity - Blocks - mix_blob_tx_and_non_blob_tx [Preset: minimal]      OK
+ [Valid]   EF - fulu - Sanity - Blocks - multi_epoch_consolidation_chain [Preset: minimal]  OK
+ [Valid]   EF - fulu - Sanity - Blocks - multiple_different_proposer_slashings_same_block [ OK
+ [Valid]   EF - fulu - Sanity - Blocks - multiple_different_validator_exits_same_block [Pre OK
+ [Valid]   EF - fulu - Sanity - Blocks - multiple_el_partial_withdrawal_requests_different_ OK
+ [Valid]   EF - fulu - Sanity - Blocks - multiple_el_partial_withdrawal_requests_same_valid OK
+ [Valid]   EF - fulu - Sanity - Blocks - one_blob [Preset: minimal]                         OK
+ [Valid]   EF - fulu - Sanity - Blocks - one_blob_max_txs [Preset: minimal]                 OK
+ [Valid]   EF - fulu - Sanity - Blocks - one_blob_two_txs [Preset: minimal]                 OK
+ [Valid]   EF - fulu - Sanity - Blocks - partial_withdrawal_in_epoch_transition [Preset: mi OK
+ [Valid]   EF - fulu - Sanity - Blocks - proposer_after_inactive_index [Preset: minimal]    OK
+ [Valid]   EF - fulu - Sanity - Blocks - proposer_self_slashing [Preset: minimal]           OK
+ [Valid]   EF - fulu - Sanity - Blocks - proposer_slashing [Preset: minimal]                OK
+ [Valid]   EF - fulu - Sanity - Blocks - skipped_slots [Preset: minimal]                    OK
+ [Valid]   EF - fulu - Sanity - Blocks - slash_and_exit_diff_index [Preset: minimal]        OK
+ [Valid]   EF - fulu - Sanity - Blocks - switch_to_compounding_requests_when_pending_consol OK
+ [Valid]   EF - fulu - Sanity - Blocks - switch_to_compounding_requests_when_too_little_con OK
+ [Valid]   EF - fulu - Sanity - Blocks - sync_committee_committee__empty [Preset: minimal]  OK
+ [Valid]   EF - fulu - Sanity - Blocks - sync_committee_committee__full [Preset: minimal]   OK
+ [Valid]   EF - fulu - Sanity - Blocks - sync_committee_committee__half [Preset: minimal]   OK
+ [Valid]   EF - fulu - Sanity - Blocks - sync_committee_committee_genesis__empty [Preset: m OK
+ [Valid]   EF - fulu - Sanity - Blocks - sync_committee_committee_genesis__full [Preset: mi OK
+ [Valid]   EF - fulu - Sanity - Blocks - sync_committee_committee_genesis__half [Preset: mi OK
+ [Valid]   EF - fulu - Sanity - Blocks - top_up_and_partial_withdrawable_validator [Preset: OK
+ [Valid]   EF - fulu - Sanity - Blocks - top_up_to_fully_withdrawn_validator [Preset: minim OK
+ [Valid]   EF - fulu - Sanity - Blocks - voluntary_exit [Preset: minimal]                   OK
+ [Valid]   EF - fulu - Sanity - Blocks - withdrawal_and_consolidation_effective_balance_upd OK
+ [Valid]   EF - fulu - Sanity - Blocks - withdrawal_and_switch_to_compounding_request_same_ OK
+ [Valid]   EF - fulu - Sanity - Blocks - withdrawal_and_withdrawal_request_same_validator [ OK
+ [Valid]   EF - fulu - Sanity - Blocks - withdrawal_requests_when_pending_withdrawal_queue_ OK
+ [Valid]   EF - fulu - Sanity - Blocks - withdrawal_success_two_blocks [Preset: minimal]    OK
+ [Valid]   EF - fulu - Sanity - Blocks - zero_blob [Preset: minimal]                        OK
```
## EF - gloas - Epoch Processing - Builder pending payments [Preset: minimal]
```diff
+ Builder pending payments - process_builder_pending_payments_above_quorum [Preset: minimal] OK
+ Builder pending payments - process_builder_pending_payments_below_quorum [Preset: minimal] OK
+ Builder pending payments - process_builder_pending_payments_empty_queue [Preset: minimal]  OK
+ Builder pending payments - process_builder_pending_payments_equal_quorum [Preset: minimal] OK
+ Builder pending payments - process_builder_pending_payments_large_amount_churn_impact [Pre OK
+ Builder pending payments - process_builder_pending_payments_mixed_weights [Preset: minimal OK
+ Builder pending payments - process_builder_pending_payments_multiple_above_quorum [Preset: OK
+ Builder pending payments - process_builder_pending_payments_queue_rotation [Preset: minima OK
```
## EF - gloas - Epoch Processing - Effective balance updates [Preset: minimal]
```diff
+ Effective balance updates - effective_balance_hysteresis [Preset: minimal]                 OK
+ Effective balance updates - effective_balance_hysteresis_with_compounding_credentials [Pre OK
```
## EF - gloas - Epoch Processing - Eth1 data reset [Preset: minimal]
```diff
+ Eth1 data reset - eth1_vote_no_reset [Preset: minimal]                                     OK
+ Eth1 data reset - eth1_vote_reset [Preset: minimal]                                        OK
```
## EF - gloas - Epoch Processing - Historical summaries update [Preset: minimal]
```diff
+ Historical summaries update - historical_summaries_accumulator [Preset: minimal]           OK
```
## EF - gloas - Epoch Processing - Inactivity [Preset: minimal]
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
## EF - gloas - Epoch Processing - Justification & Finalization [Preset: minimal]
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
## EF - gloas - Epoch Processing - PTC window [Preset: minimal]
```diff
+ PTC window - process_ptc_window__shifts_all_epochs [Preset: minimal]                       OK
```
## EF - gloas - Epoch Processing - Participation flag updates [Preset: minimal]
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
## EF - gloas - Epoch Processing - Pending consolidations [Preset: minimal]
```diff
+ Pending consolidations - all_consolidation_cases_together [Preset: minimal]                OK
+ Pending consolidations - basic_pending_consolidation [Preset: minimal]                     OK
+ Pending consolidations - consolidation_not_yet_withdrawable_validator [Preset: minimal]    OK
+ Pending consolidations - pending_consolidation_balance_computation_compounding [Preset: mi OK
+ Pending consolidations - pending_consolidation_balance_computation_eth1 [Preset: minimal]  OK
+ Pending consolidations - pending_consolidation_compounding_creds [Preset: minimal]         OK
+ Pending consolidations - pending_consolidation_future_epoch [Preset: minimal]              OK
+ Pending consolidations - pending_consolidation_source_balance_greater_than_max_effective [ OK
+ Pending consolidations - pending_consolidation_source_balance_greater_than_max_effective_c OK
+ Pending consolidations - pending_consolidation_source_balance_less_than_max_effective [Pre OK
+ Pending consolidations - pending_consolidation_source_balance_less_than_max_effective_comp OK
+ Pending consolidations - pending_consolidation_with_pending_deposit [Preset: minimal]      OK
+ Pending consolidations - skip_consolidation_when_source_slashed [Preset: minimal]          OK
```
## EF - gloas - Epoch Processing - Pending deposits [Preset: minimal]
```diff
+ Pending deposits - apply_pending_deposit_compounding_withdrawal_credentials_max [Preset: m OK
+ Pending deposits - apply_pending_deposit_compounding_withdrawal_credentials_over_max [Pres OK
+ Pending deposits - apply_pending_deposit_compounding_withdrawal_credentials_over_max_next_ OK
+ Pending deposits - apply_pending_deposit_compounding_withdrawal_credentials_under_max [Pre OK
+ Pending deposits - apply_pending_deposit_correct_sig_but_forked_state [Preset: minimal]    OK
+ Pending deposits - apply_pending_deposit_effective_deposit_with_genesis_fork_version [Pres OK
+ Pending deposits - apply_pending_deposit_eth1_withdrawal_credentials [Preset: minimal]     OK
+ Pending deposits - apply_pending_deposit_incorrect_sig_new_deposit [Preset: minimal]       OK
+ Pending deposits - apply_pending_deposit_incorrect_sig_top_up [Preset: minimal]            OK
+ Pending deposits - apply_pending_deposit_incorrect_withdrawal_credentials_top_up [Preset:  OK
+ Pending deposits - apply_pending_deposit_ineffective_deposit_with_bad_fork_version [Preset OK
+ Pending deposits - apply_pending_deposit_key_validate_invalid_decompression [Preset: minim OK
+ Pending deposits - apply_pending_deposit_key_validate_invalid_subgroup [Preset: minimal]   OK
+ Pending deposits - apply_pending_deposit_min_activation [Preset: minimal]                  OK
+ Pending deposits - apply_pending_deposit_non_versioned_withdrawal_credentials [Preset: min OK
+ Pending deposits - apply_pending_deposit_non_versioned_withdrawal_credentials_over_min_act OK
+ Pending deposits - apply_pending_deposit_over_min_activation [Preset: minimal]             OK
+ Pending deposits - apply_pending_deposit_over_min_activation_next_increment [Preset: minim OK
+ Pending deposits - apply_pending_deposit_success_top_up_to_withdrawn_validator [Preset: mi OK
+ Pending deposits - apply_pending_deposit_top_up__less_effective_balance [Preset: minimal]  OK
+ Pending deposits - apply_pending_deposit_top_up__max_effective_balance_compounding [Preset OK
+ Pending deposits - apply_pending_deposit_top_up__min_activation_balance [Preset: minimal]  OK
+ Pending deposits - apply_pending_deposit_top_up__min_activation_balance_compounding [Prese OK
+ Pending deposits - apply_pending_deposit_under_min_activation [Preset: minimal]            OK
+ Pending deposits - apply_pending_deposit_with_previous_fork_version [Preset: minimal]      OK
+ Pending deposits - ineffective_deposit_with_current_fork_version [Preset: minimal]         OK
+ Pending deposits - process_pending_deposits_balance_above_churn [Preset: minimal]          OK
+ Pending deposits - process_pending_deposits_balance_equal_churn [Preset: minimal]          OK
+ Pending deposits - process_pending_deposits_eth1_bridge_transition_complete [Preset: minim OK
+ Pending deposits - process_pending_deposits_eth1_bridge_transition_not_applied [Preset: mi OK
+ Pending deposits - process_pending_deposits_eth1_bridge_transition_pending [Preset: minima OK
+ Pending deposits - process_pending_deposits_limit_is_reached [Preset: minimal]             OK
+ Pending deposits - process_pending_deposits_mixture_of_skipped_and_above_churn [Preset: mi OK
+ Pending deposits - process_pending_deposits_multiple_for_new_validator [Preset: minimal]   OK
+ Pending deposits - process_pending_deposits_multiple_pending_deposits_above_churn [Preset: OK
+ Pending deposits - process_pending_deposits_multiple_pending_deposits_below_churn [Preset: OK
+ Pending deposits - process_pending_deposits_multiple_pending_one_skipped [Preset: minimal] OK
+ Pending deposits - process_pending_deposits_multiple_skipped_deposits_exiting_validators [ OK
+ Pending deposits - process_pending_deposits_not_finalized [Preset: minimal]                OK
+ Pending deposits - process_pending_deposits_preexisting_churn [Preset: minimal]            OK
+ Pending deposits - process_pending_deposits_scaled_churn [Preset: minimal]                 OK
+ Pending deposits - process_pending_deposits_skipped_deposit_exiting_validator [Preset: min OK
+ Pending deposits - process_pending_deposits_withdrawable_validator [Preset: minimal]       OK
+ Pending deposits - process_pending_deposits_withdrawable_validator_not_churned [Preset: mi OK
```
## EF - gloas - Epoch Processing - Proposer lookahead [Preset: minimal]
```diff
+ Proposer lookahead - proposer_lookahead_does_not_contain_exited_validators [Preset: minima OK
+ Proposer lookahead - proposer_lookahead_in_state_matches_computed_lookahead [Preset: minim OK
```
## EF - gloas - Epoch Processing - RANDAO mixes reset [Preset: minimal]
```diff
+ RANDAO mixes reset - updated_randao_mixes [Preset: minimal]                                OK
```
## EF - gloas - Epoch Processing - Registry updates [Preset: minimal]
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
+ Registry updates - activation_queue_eligibility__greater_than_min_activation_balance [Pres OK
+ Registry updates - activation_queue_eligibility__less_than_min_activation_balance [Preset: OK
+ Registry updates - activation_queue_eligibility__min_activation_balance [Preset: minimal]  OK
+ Registry updates - activation_queue_eligibility__min_activation_balance_compounding_creds  OK
+ Registry updates - activation_queue_eligibility__min_activation_balance_eth1_creds [Preset OK
+ Registry updates - activation_queue_no_activation_no_finality [Preset: minimal]            OK
+ Registry updates - activation_queue_sorting [Preset: minimal]                              OK
+ Registry updates - activation_queue_to_activated_if_finalized [Preset: minimal]            OK
+ Registry updates - add_to_activation_queue [Preset: minimal]                               OK
+ Registry updates - ejection [Preset: minimal]                                              OK
+ Registry updates - ejection_past_churn_limit_min [Preset: minimal]                         OK
+ Registry updates - ejection_past_churn_limit_scaled [Preset: minimal]                      OK
+ Registry updates - invalid_large_withdrawable_epoch [Preset: minimal]                      OK
```
## EF - gloas - Epoch Processing - Rewards and penalties [Preset: minimal]
```diff
+ Rewards and penalties - almost_empty_attestations [Preset: minimal]                        OK
+ Rewards and penalties - almost_empty_attestations_with_leak [Preset: minimal]              OK
+ Rewards and penalties - almost_full_attestations [Preset: minimal]                         OK
+ Rewards and penalties - almost_full_attestations_with_leak [Preset: minimal]               OK
+ Rewards and penalties - attestations_some_slashed [Preset: minimal]                        OK
+ Rewards and penalties - duplicate_attestation [Preset: minimal]                            OK
+ Rewards and penalties - full_attestation_participation [Preset: minimal]                   OK
+ Rewards and penalties - full_attestation_participation_with_leak [Preset: minimal]         OK
+ Rewards and penalties - full_attestations_default_balances_except_a_validator_with_one_gwe OK
+ Rewards and penalties - full_attestations_misc_balances [Preset: minimal]                  OK
+ Rewards and penalties - genesis_epoch_full_attestations_no_rewards [Preset: minimal]       OK
+ Rewards and penalties - genesis_epoch_no_attestations_no_penalties [Preset: minimal]       OK
+ Rewards and penalties - no_attestations_all_penalties [Preset: minimal]                    OK
+ Rewards and penalties - random_fill_attestations [Preset: minimal]                         OK
+ Rewards and penalties - random_fill_attestations_with_leak [Preset: minimal]               OK
```
## EF - gloas - Epoch Processing - Slashings [Preset: minimal]
```diff
+ Slashings - low_penalty [Preset: minimal]                                                  OK
+ Slashings - max_penalties [Preset: minimal]                                                OK
+ Slashings - minimal_penalty [Preset: minimal]                                              OK
+ Slashings - scaled_penalties [Preset: minimal]                                             OK
+ Slashings - slashings_with_random_state [Preset: minimal]                                  OK
```
## EF - gloas - Epoch Processing - Slashings reset [Preset: minimal]
```diff
+ Slashings reset - flush_slashings [Preset: minimal]                                        OK
```
## EF - gloas - Epoch Processing - Sync committee updates [Preset: minimal]
```diff
+ Sync committee updates - sync_committees_no_progress_not_at_period_boundary [Preset: minim OK
+ Sync committee updates - sync_committees_progress_genesis [Preset: minimal]                OK
+ Sync committee updates - sync_committees_progress_misc_balances_genesis [Preset: minimal]  OK
+ Sync committee updates - sync_committees_progress_misc_balances_not_genesis [Preset: minim OK
+ Sync committee updates - sync_committees_progress_not_genesis [Preset: minimal]            OK
```
## EF - gloas - Finality  [Preset: minimal]
```diff
+ [Valid]   EF - gloas - Finality - finality_no_updates_at_genesis [Preset: minimal]         OK
+ [Valid]   EF - gloas - Finality - finality_rule_1 [Preset: minimal]                        OK
+ [Valid]   EF - gloas - Finality - finality_rule_2 [Preset: minimal]                        OK
+ [Valid]   EF - gloas - Finality - finality_rule_3 [Preset: minimal]                        OK
+ [Valid]   EF - gloas - Finality - finality_rule_4 [Preset: minimal]                        OK
```
## EF - gloas - Random  [Preset: minimal]
```diff
+ [Valid]   EF - gloas - Random - randomized_0 [Preset: minimal]                             OK
+ [Valid]   EF - gloas - Random - randomized_1 [Preset: minimal]                             OK
+ [Valid]   EF - gloas - Random - randomized_10 [Preset: minimal]                            OK
+ [Valid]   EF - gloas - Random - randomized_11 [Preset: minimal]                            OK
+ [Valid]   EF - gloas - Random - randomized_12 [Preset: minimal]                            OK
+ [Valid]   EF - gloas - Random - randomized_13 [Preset: minimal]                            OK
+ [Valid]   EF - gloas - Random - randomized_14 [Preset: minimal]                            OK
+ [Valid]   EF - gloas - Random - randomized_15 [Preset: minimal]                            OK
+ [Valid]   EF - gloas - Random - randomized_2 [Preset: minimal]                             OK
+ [Valid]   EF - gloas - Random - randomized_3 [Preset: minimal]                             OK
+ [Valid]   EF - gloas - Random - randomized_4 [Preset: minimal]                             OK
+ [Valid]   EF - gloas - Random - randomized_5 [Preset: minimal]                             OK
+ [Valid]   EF - gloas - Random - randomized_6 [Preset: minimal]                             OK
+ [Valid]   EF - gloas - Random - randomized_7 [Preset: minimal]                             OK
+ [Valid]   EF - gloas - Random - randomized_8 [Preset: minimal]                             OK
+ [Valid]   EF - gloas - Random - randomized_9 [Preset: minimal]                             OK
```
## EF - gloas - Rewards  [Preset: minimal]
```diff
+ EF - gloas - Rewards - all_balances_too_low_for_reward [Preset: minimal]                   OK
+ EF - gloas - Rewards - empty [Preset: minimal]                                             OK
+ EF - gloas - Rewards - empty_leak [Preset: minimal]                                        OK
+ EF - gloas - Rewards - full_all_correct [Preset: minimal]                                  OK
+ EF - gloas - Rewards - full_but_partial_participation [Preset: minimal]                    OK
+ EF - gloas - Rewards - full_but_partial_participation_leak [Preset: minimal]               OK
+ EF - gloas - Rewards - full_leak [Preset: minimal]                                         OK
+ EF - gloas - Rewards - full_random_0 [Preset: minimal]                                     OK
+ EF - gloas - Rewards - full_random_1 [Preset: minimal]                                     OK
+ EF - gloas - Rewards - full_random_2 [Preset: minimal]                                     OK
+ EF - gloas - Rewards - full_random_3 [Preset: minimal]                                     OK
+ EF - gloas - Rewards - full_random_4 [Preset: minimal]                                     OK
+ EF - gloas - Rewards - full_random_leak [Preset: minimal]                                  OK
+ EF - gloas - Rewards - full_random_low_balances_0 [Preset: minimal]                        OK
+ EF - gloas - Rewards - full_random_low_balances_1 [Preset: minimal]                        OK
+ EF - gloas - Rewards - full_random_misc_balances [Preset: minimal]                         OK
+ EF - gloas - Rewards - full_random_seven_epoch_leak [Preset: minimal]                      OK
+ EF - gloas - Rewards - full_random_ten_epoch_leak [Preset: minimal]                        OK
+ EF - gloas - Rewards - full_random_without_leak_0 [Preset: minimal]                        OK
+ EF - gloas - Rewards - full_random_without_leak_and_current_exit_0 [Preset: minimal]       OK
+ EF - gloas - Rewards - half_full [Preset: minimal]                                         OK
+ EF - gloas - Rewards - half_full_leak [Preset: minimal]                                    OK
+ EF - gloas - Rewards - quarter_full [Preset: minimal]                                      OK
+ EF - gloas - Rewards - quarter_full_leak [Preset: minimal]                                 OK
+ EF - gloas - Rewards - some_very_low_effective_balances_that_attested [Preset: minimal]    OK
+ EF - gloas - Rewards - some_very_low_effective_balances_that_attested_leak [Preset: minima OK
+ EF - gloas - Rewards - some_very_low_effective_balances_that_did_not_attest [Preset: minim OK
+ EF - gloas - Rewards - some_very_low_effective_balances_that_did_not_attest_leak [Preset:  OK
+ EF - gloas - Rewards - with_exited_validators [Preset: minimal]                            OK
+ EF - gloas - Rewards - with_exited_validators_leak [Preset: minimal]                       OK
+ EF - gloas - Rewards - with_not_yet_activated_validators [Preset: minimal]                 OK
+ EF - gloas - Rewards - with_not_yet_activated_validators_leak [Preset: minimal]            OK
+ EF - gloas - Rewards - with_slashed_validators [Preset: minimal]                           OK
+ EF - gloas - Rewards - with_slashed_validators_leak [Preset: minimal]                      OK
```
## EF - gloas - Sanity - Blocks  [Preset: minimal]
```diff
+ [Invalid] EF - gloas - Sanity - Blocks - invalid_all_zeroed_sig [Preset: minimal]          OK
+ [Invalid] EF - gloas - Sanity - Blocks - invalid_duplicate_bls_changes_same_block [Preset: OK
+ [Invalid] EF - gloas - Sanity - Blocks - invalid_duplicate_deposit_same_block [Preset: min OK
+ [Invalid] EF - gloas - Sanity - Blocks - invalid_duplicate_proposer_slashings_same_block [ OK
+ [Invalid] EF - gloas - Sanity - Blocks - invalid_duplicate_validator_exit_same_block [Pres OK
+ [Invalid] EF - gloas - Sanity - Blocks - invalid_incorrect_block_sig [Preset: minimal]     OK
+ [Invalid] EF - gloas - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_expecte OK
+ [Invalid] EF - gloas - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_propose OK
+ [Invalid] EF - gloas - Sanity - Blocks - invalid_incorrect_state_root [Preset: minimal]    OK
+ [Invalid] EF - gloas - Sanity - Blocks - invalid_only_increase_deposit_count [Preset: mini OK
+ [Invalid] EF - gloas - Sanity - Blocks - invalid_parent_from_same_slot [Preset: minimal]   OK
+ [Invalid] EF - gloas - Sanity - Blocks - invalid_prev_slot_block_transition [Preset: minim OK
+ [Invalid] EF - gloas - Sanity - Blocks - invalid_same_slot_block_transition [Preset: minim OK
+ [Invalid] EF - gloas - Sanity - Blocks - invalid_similar_proposer_slashings_same_block [Pr OK
+ [Invalid] EF - gloas - Sanity - Blocks - invalid_two_bls_changes_of_different_addresses_sa OK
+ [Invalid] EF - gloas - Sanity - Blocks - invalid_withdrawal_fail_second_block_payload_isnt OK
+ [Invalid] EF - gloas - Sanity - Blocks - slash_and_exit_same_index [Preset: minimal]       OK
+ [Valid]   EF - gloas - Sanity - Blocks - activate_and_partial_withdrawal_max_effective_bal OK
+ [Valid]   EF - gloas - Sanity - Blocks - activate_and_partial_withdrawal_overdeposit [Pres OK
+ [Valid]   EF - gloas - Sanity - Blocks - attestation [Preset: minimal]                     OK
+ [Valid]   EF - gloas - Sanity - Blocks - attester_slashing [Preset: minimal]               OK
+ [Valid]   EF - gloas - Sanity - Blocks - balance_driven_status_transitions [Preset: minima OK
+ [Valid]   EF - gloas - Sanity - Blocks - bls_change [Preset: minimal]                      OK
+ [Valid]   EF - gloas - Sanity - Blocks - deposit_and_bls_change [Preset: minimal]          OK
+ [Valid]   EF - gloas - Sanity - Blocks - deposit_in_block [Preset: minimal]                OK
+ [Valid]   EF - gloas - Sanity - Blocks - deposit_top_up [Preset: minimal]                  OK
+ [Valid]   EF - gloas - Sanity - Blocks - duplicate_attestation_same_block [Preset: minimal OK
+ [Valid]   EF - gloas - Sanity - Blocks - empty_block_transition [Preset: minimal]          OK
+ [Valid]   EF - gloas - Sanity - Blocks - empty_block_transition_large_validator_set [Prese OK
+ [Valid]   EF - gloas - Sanity - Blocks - empty_epoch_transition [Preset: minimal]          OK
+ [Valid]   EF - gloas - Sanity - Blocks - empty_epoch_transition_large_validator_set [Prese OK
+ [Valid]   EF - gloas - Sanity - Blocks - empty_epoch_transition_not_finalizing [Preset: mi OK
+ [Valid]   EF - gloas - Sanity - Blocks - eth1_data_votes_consensus [Preset: minimal]       OK
+ [Valid]   EF - gloas - Sanity - Blocks - eth1_data_votes_no_consensus [Preset: minimal]    OK
+ [Valid]   EF - gloas - Sanity - Blocks - exit_and_bls_change [Preset: minimal]             OK
+ [Valid]   EF - gloas - Sanity - Blocks - full_random_operations_0 [Preset: minimal]        OK
+ [Valid]   EF - gloas - Sanity - Blocks - full_random_operations_1 [Preset: minimal]        OK
+ [Valid]   EF - gloas - Sanity - Blocks - full_random_operations_2 [Preset: minimal]        OK
+ [Valid]   EF - gloas - Sanity - Blocks - full_random_operations_3 [Preset: minimal]        OK
+ [Valid]   EF - gloas - Sanity - Blocks - high_proposer_index [Preset: minimal]             OK
+ [Valid]   EF - gloas - Sanity - Blocks - historical_batch [Preset: minimal]                OK
+ [Valid]   EF - gloas - Sanity - Blocks - inactivity_scores_full_participation_leaking [Pre OK
+ [Valid]   EF - gloas - Sanity - Blocks - inactivity_scores_leaking [Preset: minimal]       OK
+ [Valid]   EF - gloas - Sanity - Blocks - many_partial_withdrawals_in_epoch_transition [Pre OK
+ [Valid]   EF - gloas - Sanity - Blocks - missed_payload_next_block_with_withdrawals_satisf OK
+ [Valid]   EF - gloas - Sanity - Blocks - missed_payload_next_block_with_withdrawals_unsati OK
+ [Valid]   EF - gloas - Sanity - Blocks - missed_payload_next_block_without_withdrawals_sat OK
+ [Valid]   EF - gloas - Sanity - Blocks - missed_payload_next_block_without_withdrawals_uns OK
+ [Valid]   EF - gloas - Sanity - Blocks - multiple_different_proposer_slashings_same_block  OK
+ [Valid]   EF - gloas - Sanity - Blocks - multiple_different_validator_exits_same_block [Pr OK
+ [Valid]   EF - gloas - Sanity - Blocks - partial_withdrawal_in_epoch_transition [Preset: m OK
+ [Valid]   EF - gloas - Sanity - Blocks - proposer_after_inactive_index [Preset: minimal]   OK
+ [Valid]   EF - gloas - Sanity - Blocks - proposer_self_slashing [Preset: minimal]          OK
+ [Valid]   EF - gloas - Sanity - Blocks - proposer_slashing [Preset: minimal]               OK
+ [Valid]   EF - gloas - Sanity - Blocks - skipped_slots [Preset: minimal]                   OK
+ [Valid]   EF - gloas - Sanity - Blocks - slash_and_exit_diff_index [Preset: minimal]       OK
+ [Valid]   EF - gloas - Sanity - Blocks - sync_committee_committee__empty [Preset: minimal] OK
+ [Valid]   EF - gloas - Sanity - Blocks - sync_committee_committee__full [Preset: minimal]  OK
+ [Valid]   EF - gloas - Sanity - Blocks - sync_committee_committee__half [Preset: minimal]  OK
+ [Valid]   EF - gloas - Sanity - Blocks - sync_committee_committee_genesis__empty [Preset:  OK
+ [Valid]   EF - gloas - Sanity - Blocks - sync_committee_committee_genesis__full [Preset: m OK
+ [Valid]   EF - gloas - Sanity - Blocks - sync_committee_committee_genesis__half [Preset: m OK
+ [Valid]   EF - gloas - Sanity - Blocks - top_up_and_partial_withdrawable_validator [Preset OK
+ [Valid]   EF - gloas - Sanity - Blocks - top_up_to_fully_withdrawn_validator [Preset: mini OK
+ [Valid]   EF - gloas - Sanity - Blocks - voluntary_exit [Preset: minimal]                  OK
+ [Valid]   EF - gloas - Sanity - Blocks - withdrawal_success_two_blocks [Preset: minimal]   OK
```
## EF - heze - Epoch Processing - Builder pending payments [Preset: minimal]
```diff
+ Builder pending payments - process_builder_pending_payments_above_quorum [Preset: minimal] OK
+ Builder pending payments - process_builder_pending_payments_below_quorum [Preset: minimal] OK
+ Builder pending payments - process_builder_pending_payments_empty_queue [Preset: minimal]  OK
+ Builder pending payments - process_builder_pending_payments_equal_quorum [Preset: minimal] OK
+ Builder pending payments - process_builder_pending_payments_large_amount_churn_impact [Pre OK
+ Builder pending payments - process_builder_pending_payments_mixed_weights [Preset: minimal OK
+ Builder pending payments - process_builder_pending_payments_multiple_above_quorum [Preset: OK
+ Builder pending payments - process_builder_pending_payments_queue_rotation [Preset: minima OK
```
## EF - heze - Epoch Processing - Effective balance updates [Preset: minimal]
```diff
+ Effective balance updates - effective_balance_hysteresis [Preset: minimal]                 OK
+ Effective balance updates - effective_balance_hysteresis_with_compounding_credentials [Pre OK
```
## EF - heze - Epoch Processing - Eth1 data reset [Preset: minimal]
```diff
+ Eth1 data reset - eth1_vote_no_reset [Preset: minimal]                                     OK
+ Eth1 data reset - eth1_vote_reset [Preset: minimal]                                        OK
```
## EF - heze - Epoch Processing - Historical summaries update [Preset: minimal]
```diff
+ Historical summaries update - historical_summaries_accumulator [Preset: minimal]           OK
```
## EF - heze - Epoch Processing - Inactivity [Preset: minimal]
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
## EF - heze - Epoch Processing - Justification & Finalization [Preset: minimal]
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
## EF - heze - Epoch Processing - Participation flag updates [Preset: minimal]
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
## EF - heze - Epoch Processing - Pending consolidations [Preset: minimal]
```diff
+ Pending consolidations - all_consolidation_cases_together [Preset: minimal]                OK
+ Pending consolidations - basic_pending_consolidation [Preset: minimal]                     OK
+ Pending consolidations - consolidation_not_yet_withdrawable_validator [Preset: minimal]    OK
+ Pending consolidations - pending_consolidation_balance_computation_compounding [Preset: mi OK
+ Pending consolidations - pending_consolidation_balance_computation_eth1 [Preset: minimal]  OK
+ Pending consolidations - pending_consolidation_compounding_creds [Preset: minimal]         OK
+ Pending consolidations - pending_consolidation_future_epoch [Preset: minimal]              OK
+ Pending consolidations - pending_consolidation_source_balance_greater_than_max_effective [ OK
+ Pending consolidations - pending_consolidation_source_balance_greater_than_max_effective_c OK
+ Pending consolidations - pending_consolidation_source_balance_less_than_max_effective [Pre OK
+ Pending consolidations - pending_consolidation_source_balance_less_than_max_effective_comp OK
+ Pending consolidations - pending_consolidation_with_pending_deposit [Preset: minimal]      OK
+ Pending consolidations - skip_consolidation_when_source_slashed [Preset: minimal]          OK
```
## EF - heze - Epoch Processing - Pending deposits [Preset: minimal]
```diff
+ Pending deposits - apply_pending_deposit_compounding_withdrawal_credentials_max [Preset: m OK
+ Pending deposits - apply_pending_deposit_compounding_withdrawal_credentials_over_max [Pres OK
+ Pending deposits - apply_pending_deposit_compounding_withdrawal_credentials_over_max_next_ OK
+ Pending deposits - apply_pending_deposit_compounding_withdrawal_credentials_under_max [Pre OK
+ Pending deposits - apply_pending_deposit_correct_sig_but_forked_state [Preset: minimal]    OK
+ Pending deposits - apply_pending_deposit_effective_deposit_with_genesis_fork_version [Pres OK
+ Pending deposits - apply_pending_deposit_eth1_withdrawal_credentials [Preset: minimal]     OK
+ Pending deposits - apply_pending_deposit_incorrect_sig_new_deposit [Preset: minimal]       OK
+ Pending deposits - apply_pending_deposit_incorrect_sig_top_up [Preset: minimal]            OK
+ Pending deposits - apply_pending_deposit_incorrect_withdrawal_credentials_top_up [Preset:  OK
+ Pending deposits - apply_pending_deposit_ineffective_deposit_with_bad_fork_version [Preset OK
+ Pending deposits - apply_pending_deposit_key_validate_invalid_decompression [Preset: minim OK
+ Pending deposits - apply_pending_deposit_key_validate_invalid_subgroup [Preset: minimal]   OK
+ Pending deposits - apply_pending_deposit_min_activation [Preset: minimal]                  OK
+ Pending deposits - apply_pending_deposit_non_versioned_withdrawal_credentials [Preset: min OK
+ Pending deposits - apply_pending_deposit_non_versioned_withdrawal_credentials_over_min_act OK
+ Pending deposits - apply_pending_deposit_over_min_activation [Preset: minimal]             OK
+ Pending deposits - apply_pending_deposit_over_min_activation_next_increment [Preset: minim OK
+ Pending deposits - apply_pending_deposit_success_top_up_to_withdrawn_validator [Preset: mi OK
+ Pending deposits - apply_pending_deposit_top_up__less_effective_balance [Preset: minimal]  OK
+ Pending deposits - apply_pending_deposit_top_up__max_effective_balance_compounding [Preset OK
+ Pending deposits - apply_pending_deposit_top_up__min_activation_balance [Preset: minimal]  OK
+ Pending deposits - apply_pending_deposit_top_up__min_activation_balance_compounding [Prese OK
+ Pending deposits - apply_pending_deposit_under_min_activation [Preset: minimal]            OK
+ Pending deposits - apply_pending_deposit_with_previous_fork_version [Preset: minimal]      OK
+ Pending deposits - ineffective_deposit_with_current_fork_version [Preset: minimal]         OK
+ Pending deposits - process_pending_deposits_balance_above_churn [Preset: minimal]          OK
+ Pending deposits - process_pending_deposits_balance_equal_churn [Preset: minimal]          OK
+ Pending deposits - process_pending_deposits_eth1_bridge_transition_complete [Preset: minim OK
+ Pending deposits - process_pending_deposits_eth1_bridge_transition_not_applied [Preset: mi OK
+ Pending deposits - process_pending_deposits_eth1_bridge_transition_pending [Preset: minima OK
+ Pending deposits - process_pending_deposits_limit_is_reached [Preset: minimal]             OK
+ Pending deposits - process_pending_deposits_mixture_of_skipped_and_above_churn [Preset: mi OK
+ Pending deposits - process_pending_deposits_multiple_for_new_validator [Preset: minimal]   OK
+ Pending deposits - process_pending_deposits_multiple_pending_deposits_above_churn [Preset: OK
+ Pending deposits - process_pending_deposits_multiple_pending_deposits_below_churn [Preset: OK
+ Pending deposits - process_pending_deposits_multiple_pending_one_skipped [Preset: minimal] OK
+ Pending deposits - process_pending_deposits_multiple_skipped_deposits_exiting_validators [ OK
+ Pending deposits - process_pending_deposits_not_finalized [Preset: minimal]                OK
+ Pending deposits - process_pending_deposits_preexisting_churn [Preset: minimal]            OK
+ Pending deposits - process_pending_deposits_scaled_churn [Preset: minimal]                 OK
+ Pending deposits - process_pending_deposits_skipped_deposit_exiting_validator [Preset: min OK
+ Pending deposits - process_pending_deposits_withdrawable_validator [Preset: minimal]       OK
+ Pending deposits - process_pending_deposits_withdrawable_validator_not_churned [Preset: mi OK
```
## EF - heze - Epoch Processing - Proposer lookahead [Preset: minimal]
```diff
+ Proposer lookahead - proposer_lookahead_does_not_contain_exited_validators [Preset: minima OK
+ Proposer lookahead - proposer_lookahead_in_state_matches_computed_lookahead [Preset: minim OK
```
## EF - heze - Epoch Processing - RANDAO mixes reset [Preset: minimal]
```diff
+ RANDAO mixes reset - updated_randao_mixes [Preset: minimal]                                OK
```
## EF - heze - Epoch Processing - Registry updates [Preset: minimal]
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
+ Registry updates - activation_queue_eligibility__greater_than_min_activation_balance [Pres OK
+ Registry updates - activation_queue_eligibility__less_than_min_activation_balance [Preset: OK
+ Registry updates - activation_queue_eligibility__min_activation_balance [Preset: minimal]  OK
+ Registry updates - activation_queue_eligibility__min_activation_balance_compounding_creds  OK
+ Registry updates - activation_queue_eligibility__min_activation_balance_eth1_creds [Preset OK
+ Registry updates - activation_queue_no_activation_no_finality [Preset: minimal]            OK
+ Registry updates - activation_queue_sorting [Preset: minimal]                              OK
+ Registry updates - activation_queue_to_activated_if_finalized [Preset: minimal]            OK
+ Registry updates - add_to_activation_queue [Preset: minimal]                               OK
+ Registry updates - ejection [Preset: minimal]                                              OK
+ Registry updates - ejection_past_churn_limit_min [Preset: minimal]                         OK
+ Registry updates - ejection_past_churn_limit_scaled [Preset: minimal]                      OK
+ Registry updates - invalid_large_withdrawable_epoch [Preset: minimal]                      OK
```
## EF - heze - Epoch Processing - Rewards and penalties [Preset: minimal]
```diff
+ Rewards and penalties - almost_empty_attestations [Preset: minimal]                        OK
+ Rewards and penalties - almost_empty_attestations_with_leak [Preset: minimal]              OK
+ Rewards and penalties - almost_full_attestations [Preset: minimal]                         OK
+ Rewards and penalties - almost_full_attestations_with_leak [Preset: minimal]               OK
+ Rewards and penalties - attestations_some_slashed [Preset: minimal]                        OK
+ Rewards and penalties - duplicate_attestation [Preset: minimal]                            OK
+ Rewards and penalties - full_attestation_participation [Preset: minimal]                   OK
+ Rewards and penalties - full_attestation_participation_with_leak [Preset: minimal]         OK
+ Rewards and penalties - full_attestations_default_balances_except_a_validator_with_one_gwe OK
+ Rewards and penalties - full_attestations_misc_balances [Preset: minimal]                  OK
+ Rewards and penalties - genesis_epoch_full_attestations_no_rewards [Preset: minimal]       OK
+ Rewards and penalties - genesis_epoch_no_attestations_no_penalties [Preset: minimal]       OK
+ Rewards and penalties - no_attestations_all_penalties [Preset: minimal]                    OK
+ Rewards and penalties - random_fill_attestations [Preset: minimal]                         OK
+ Rewards and penalties - random_fill_attestations_with_leak [Preset: minimal]               OK
```
## EF - heze - Epoch Processing - Slashings [Preset: minimal]
```diff
+ Slashings - low_penalty [Preset: minimal]                                                  OK
+ Slashings - max_penalties [Preset: minimal]                                                OK
+ Slashings - minimal_penalty [Preset: minimal]                                              OK
+ Slashings - scaled_penalties [Preset: minimal]                                             OK
+ Slashings - slashings_with_random_state [Preset: minimal]                                  OK
```
## EF - heze - Epoch Processing - Slashings reset [Preset: minimal]
```diff
+ Slashings reset - flush_slashings [Preset: minimal]                                        OK
```
## EF - heze - Epoch Processing - Sync committee updates [Preset: minimal]
```diff
+ Sync committee updates - sync_committees_no_progress_not_at_period_boundary [Preset: minim OK
+ Sync committee updates - sync_committees_progress_genesis [Preset: minimal]                OK
+ Sync committee updates - sync_committees_progress_misc_balances_genesis [Preset: minimal]  OK
+ Sync committee updates - sync_committees_progress_misc_balances_not_genesis [Preset: minim OK
+ Sync committee updates - sync_committees_progress_not_genesis [Preset: minimal]            OK
```
## EF - heze - Finality  [Preset: minimal]
```diff
+ [Valid]   EF - heze - Finality - finality_no_updates_at_genesis [Preset: minimal]          OK
+ [Valid]   EF - heze - Finality - finality_rule_1 [Preset: minimal]                         OK
+ [Valid]   EF - heze - Finality - finality_rule_2 [Preset: minimal]                         OK
+ [Valid]   EF - heze - Finality - finality_rule_3 [Preset: minimal]                         OK
+ [Valid]   EF - heze - Finality - finality_rule_4 [Preset: minimal]                         OK
```
## EF - heze - Rewards  [Preset: minimal]
```diff
+ EF - heze - Rewards - all_balances_too_low_for_reward [Preset: minimal]                    OK
+ EF - heze - Rewards - empty [Preset: minimal]                                              OK
+ EF - heze - Rewards - empty_leak [Preset: minimal]                                         OK
+ EF - heze - Rewards - full_all_correct [Preset: minimal]                                   OK
+ EF - heze - Rewards - full_but_partial_participation [Preset: minimal]                     OK
+ EF - heze - Rewards - full_but_partial_participation_leak [Preset: minimal]                OK
+ EF - heze - Rewards - full_leak [Preset: minimal]                                          OK
+ EF - heze - Rewards - full_random_0 [Preset: minimal]                                      OK
+ EF - heze - Rewards - full_random_1 [Preset: minimal]                                      OK
+ EF - heze - Rewards - full_random_2 [Preset: minimal]                                      OK
+ EF - heze - Rewards - full_random_3 [Preset: minimal]                                      OK
+ EF - heze - Rewards - full_random_4 [Preset: minimal]                                      OK
+ EF - heze - Rewards - full_random_leak [Preset: minimal]                                   OK
+ EF - heze - Rewards - full_random_low_balances_0 [Preset: minimal]                         OK
+ EF - heze - Rewards - full_random_low_balances_1 [Preset: minimal]                         OK
+ EF - heze - Rewards - full_random_misc_balances [Preset: minimal]                          OK
+ EF - heze - Rewards - full_random_seven_epoch_leak [Preset: minimal]                       OK
+ EF - heze - Rewards - full_random_ten_epoch_leak [Preset: minimal]                         OK
+ EF - heze - Rewards - full_random_without_leak_0 [Preset: minimal]                         OK
+ EF - heze - Rewards - full_random_without_leak_and_current_exit_0 [Preset: minimal]        OK
+ EF - heze - Rewards - half_full [Preset: minimal]                                          OK
+ EF - heze - Rewards - half_full_leak [Preset: minimal]                                     OK
+ EF - heze - Rewards - quarter_full [Preset: minimal]                                       OK
+ EF - heze - Rewards - quarter_full_leak [Preset: minimal]                                  OK
+ EF - heze - Rewards - some_very_low_effective_balances_that_attested [Preset: minimal]     OK
+ EF - heze - Rewards - some_very_low_effective_balances_that_attested_leak [Preset: minimal OK
+ EF - heze - Rewards - some_very_low_effective_balances_that_did_not_attest [Preset: minima OK
+ EF - heze - Rewards - some_very_low_effective_balances_that_did_not_attest_leak [Preset: m OK
+ EF - heze - Rewards - with_exited_validators [Preset: minimal]                             OK
+ EF - heze - Rewards - with_exited_validators_leak [Preset: minimal]                        OK
+ EF - heze - Rewards - with_not_yet_activated_validators [Preset: minimal]                  OK
+ EF - heze - Rewards - with_not_yet_activated_validators_leak [Preset: minimal]             OK
+ EF - heze - Rewards - with_slashed_validators [Preset: minimal]                            OK
+ EF - heze - Rewards - with_slashed_validators_leak [Preset: minimal]                       OK
```
## EF - heze - Sanity - Blocks  [Preset: minimal]
```diff
+ [Invalid] EF - heze - Sanity - Blocks - invalid_all_zeroed_sig [Preset: minimal]           OK
+ [Invalid] EF - heze - Sanity - Blocks - invalid_duplicate_bls_changes_same_block [Preset:  OK
+ [Invalid] EF - heze - Sanity - Blocks - invalid_duplicate_deposit_same_block [Preset: mini OK
+ [Invalid] EF - heze - Sanity - Blocks - invalid_duplicate_proposer_slashings_same_block [P OK
+ [Invalid] EF - heze - Sanity - Blocks - invalid_duplicate_validator_exit_same_block [Prese OK
+ [Invalid] EF - heze - Sanity - Blocks - invalid_incorrect_block_sig [Preset: minimal]      OK
+ [Invalid] EF - heze - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_expected OK
+ [Invalid] EF - heze - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_proposer OK
+ [Invalid] EF - heze - Sanity - Blocks - invalid_incorrect_state_root [Preset: minimal]     OK
+ [Invalid] EF - heze - Sanity - Blocks - invalid_only_increase_deposit_count [Preset: minim OK
+ [Invalid] EF - heze - Sanity - Blocks - invalid_parent_from_same_slot [Preset: minimal]    OK
+ [Invalid] EF - heze - Sanity - Blocks - invalid_prev_slot_block_transition [Preset: minima OK
+ [Invalid] EF - heze - Sanity - Blocks - invalid_same_slot_block_transition [Preset: minima OK
+ [Invalid] EF - heze - Sanity - Blocks - invalid_similar_proposer_slashings_same_block [Pre OK
+ [Invalid] EF - heze - Sanity - Blocks - invalid_two_bls_changes_of_different_addresses_sam OK
+ [Invalid] EF - heze - Sanity - Blocks - invalid_withdrawal_fail_second_block_payload_isnt_ OK
+ [Invalid] EF - heze - Sanity - Blocks - slash_and_exit_same_index [Preset: minimal]        OK
+ [Valid]   EF - heze - Sanity - Blocks - activate_and_partial_withdrawal_max_effective_bala OK
+ [Valid]   EF - heze - Sanity - Blocks - activate_and_partial_withdrawal_overdeposit [Prese OK
+ [Valid]   EF - heze - Sanity - Blocks - attestation [Preset: minimal]                      OK
+ [Valid]   EF - heze - Sanity - Blocks - attester_slashing [Preset: minimal]                OK
+ [Valid]   EF - heze - Sanity - Blocks - balance_driven_status_transitions [Preset: minimal OK
+ [Valid]   EF - heze - Sanity - Blocks - bls_change [Preset: minimal]                       OK
+ [Valid]   EF - heze - Sanity - Blocks - deposit_and_bls_change [Preset: minimal]           OK
+ [Valid]   EF - heze - Sanity - Blocks - deposit_in_block [Preset: minimal]                 OK
+ [Valid]   EF - heze - Sanity - Blocks - deposit_top_up [Preset: minimal]                   OK
+ [Valid]   EF - heze - Sanity - Blocks - duplicate_attestation_same_block [Preset: minimal] OK
+ [Valid]   EF - heze - Sanity - Blocks - empty_block_transition [Preset: minimal]           OK
+ [Valid]   EF - heze - Sanity - Blocks - empty_block_transition_large_validator_set [Preset OK
+ [Valid]   EF - heze - Sanity - Blocks - empty_epoch_transition [Preset: minimal]           OK
+ [Valid]   EF - heze - Sanity - Blocks - empty_epoch_transition_large_validator_set [Preset OK
+ [Valid]   EF - heze - Sanity - Blocks - empty_epoch_transition_not_finalizing [Preset: min OK
+ [Valid]   EF - heze - Sanity - Blocks - eth1_data_votes_consensus [Preset: minimal]        OK
+ [Valid]   EF - heze - Sanity - Blocks - eth1_data_votes_no_consensus [Preset: minimal]     OK
+ [Valid]   EF - heze - Sanity - Blocks - exit_and_bls_change [Preset: minimal]              OK
+ [Valid]   EF - heze - Sanity - Blocks - full_random_operations_0 [Preset: minimal]         OK
+ [Valid]   EF - heze - Sanity - Blocks - full_random_operations_1 [Preset: minimal]         OK
+ [Valid]   EF - heze - Sanity - Blocks - full_random_operations_2 [Preset: minimal]         OK
+ [Valid]   EF - heze - Sanity - Blocks - full_random_operations_3 [Preset: minimal]         OK
+ [Valid]   EF - heze - Sanity - Blocks - high_proposer_index [Preset: minimal]              OK
+ [Valid]   EF - heze - Sanity - Blocks - historical_batch [Preset: minimal]                 OK
+ [Valid]   EF - heze - Sanity - Blocks - inactivity_scores_full_participation_leaking [Pres OK
+ [Valid]   EF - heze - Sanity - Blocks - inactivity_scores_leaking [Preset: minimal]        OK
+ [Valid]   EF - heze - Sanity - Blocks - many_partial_withdrawals_in_epoch_transition [Pres OK
+ [Valid]   EF - heze - Sanity - Blocks - missed_payload_next_block_with_withdrawals_satisfy OK
+ [Valid]   EF - heze - Sanity - Blocks - missed_payload_next_block_with_withdrawals_unsatis OK
+ [Valid]   EF - heze - Sanity - Blocks - missed_payload_next_block_without_withdrawals_sati OK
+ [Valid]   EF - heze - Sanity - Blocks - missed_payload_next_block_without_withdrawals_unsa OK
+ [Valid]   EF - heze - Sanity - Blocks - multiple_different_proposer_slashings_same_block [ OK
+ [Valid]   EF - heze - Sanity - Blocks - multiple_different_validator_exits_same_block [Pre OK
+ [Valid]   EF - heze - Sanity - Blocks - partial_withdrawal_in_epoch_transition [Preset: mi OK
+ [Valid]   EF - heze - Sanity - Blocks - proposer_after_inactive_index [Preset: minimal]    OK
+ [Valid]   EF - heze - Sanity - Blocks - proposer_self_slashing [Preset: minimal]           OK
+ [Valid]   EF - heze - Sanity - Blocks - proposer_slashing [Preset: minimal]                OK
+ [Valid]   EF - heze - Sanity - Blocks - skipped_slots [Preset: minimal]                    OK
+ [Valid]   EF - heze - Sanity - Blocks - slash_and_exit_diff_index [Preset: minimal]        OK
+ [Valid]   EF - heze - Sanity - Blocks - sync_committee_committee__empty [Preset: minimal]  OK
+ [Valid]   EF - heze - Sanity - Blocks - sync_committee_committee__full [Preset: minimal]   OK
+ [Valid]   EF - heze - Sanity - Blocks - sync_committee_committee__half [Preset: minimal]   OK
+ [Valid]   EF - heze - Sanity - Blocks - sync_committee_committee_genesis__empty [Preset: m OK
+ [Valid]   EF - heze - Sanity - Blocks - sync_committee_committee_genesis__full [Preset: mi OK
+ [Valid]   EF - heze - Sanity - Blocks - sync_committee_committee_genesis__half [Preset: mi OK
+ [Valid]   EF - heze - Sanity - Blocks - top_up_and_partial_withdrawable_validator [Preset: OK
+ [Valid]   EF - heze - Sanity - Blocks - top_up_to_fully_withdrawn_validator [Preset: minim OK
+ [Valid]   EF - heze - Sanity - Blocks - voluntary_exit [Preset: minimal]                   OK
+ [Valid]   EF - heze - Sanity - Blocks - withdrawal_success_two_blocks [Preset: minimal]    OK
```
## EF - phase0 - Epoch Processing - Effective balance updates [Preset: minimal]
```diff
+ Effective balance updates - effective_balance_hysteresis [Preset: minimal]                 OK
```
## EF - phase0 - Epoch Processing - Eth1 data reset [Preset: minimal]
```diff
+ Eth1 data reset - eth1_vote_no_reset [Preset: minimal]                                     OK
+ Eth1 data reset - eth1_vote_reset [Preset: minimal]                                        OK
```
## EF - phase0 - Epoch Processing - Historical roots update [Preset: minimal]
```diff
+ Historical roots update - historical_root_accumulator [Preset: minimal]                    OK
```
## EF - phase0 - Epoch Processing - Justification & Finalization [Preset: minimal]
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
## EF - phase0 - Epoch Processing - Participation record updates [Preset: minimal]
```diff
+ Participation record updates - updated_participation_record [Preset: minimal]              OK
```
## EF - phase0 - Epoch Processing - RANDAO mixes reset [Preset: minimal]
```diff
+ RANDAO mixes reset - updated_randao_mixes [Preset: minimal]                                OK
```
## EF - phase0 - Epoch Processing - Registry updates [Preset: minimal]
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
## EF - phase0 - Epoch Processing - Rewards and penalties [Preset: minimal]
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
+ Rewards and penalties - full_attestations_default_balances_except_a_validator_with_one_gwe OK
+ Rewards and penalties - full_attestations_misc_balances [Preset: minimal]                  OK
+ Rewards and penalties - full_attestations_random_incorrect_fields [Preset: minimal]        OK
+ Rewards and penalties - genesis_epoch_full_attestations_no_rewards [Preset: minimal]       OK
+ Rewards and penalties - genesis_epoch_no_attestations_no_penalties [Preset: minimal]       OK
+ Rewards and penalties - no_attestations_all_penalties [Preset: minimal]                    OK
+ Rewards and penalties - random_fill_attestations [Preset: minimal]                         OK
+ Rewards and penalties - random_fill_attestations_with_leak [Preset: minimal]               OK
```
## EF - phase0 - Epoch Processing - Slashings [Preset: minimal]
```diff
+ Slashings - low_penalty [Preset: minimal]                                                  OK
+ Slashings - max_penalties [Preset: minimal]                                                OK
+ Slashings - minimal_penalty [Preset: minimal]                                              OK
+ Slashings - scaled_penalties [Preset: minimal]                                             OK
+ Slashings - slashings_with_random_state [Preset: minimal]                                  OK
```
## EF - phase0 - Epoch Processing - Slashings reset [Preset: minimal]
```diff
+ Slashings reset - flush_slashings [Preset: minimal]                                        OK
```
## EF - phase0 - Finality  [Preset: minimal]
```diff
+ [Valid]   EF - phase0 - Finality - finality_no_updates_at_genesis [Preset: minimal]        OK
+ [Valid]   EF - phase0 - Finality - finality_rule_1 [Preset: minimal]                       OK
+ [Valid]   EF - phase0 - Finality - finality_rule_2 [Preset: minimal]                       OK
+ [Valid]   EF - phase0 - Finality - finality_rule_3 [Preset: minimal]                       OK
+ [Valid]   EF - phase0 - Finality - finality_rule_4 [Preset: minimal]                       OK
```
## EF - phase0 - Random  [Preset: minimal]
```diff
+ [Valid]   EF - phase0 - Random - randomized_0 [Preset: minimal]                            OK
+ [Valid]   EF - phase0 - Random - randomized_1 [Preset: minimal]                            OK
+ [Valid]   EF - phase0 - Random - randomized_10 [Preset: minimal]                           OK
+ [Valid]   EF - phase0 - Random - randomized_11 [Preset: minimal]                           OK
+ [Valid]   EF - phase0 - Random - randomized_12 [Preset: minimal]                           OK
+ [Valid]   EF - phase0 - Random - randomized_13 [Preset: minimal]                           OK
+ [Valid]   EF - phase0 - Random - randomized_14 [Preset: minimal]                           OK
+ [Valid]   EF - phase0 - Random - randomized_15 [Preset: minimal]                           OK
+ [Valid]   EF - phase0 - Random - randomized_2 [Preset: minimal]                            OK
+ [Valid]   EF - phase0 - Random - randomized_3 [Preset: minimal]                            OK
+ [Valid]   EF - phase0 - Random - randomized_4 [Preset: minimal]                            OK
+ [Valid]   EF - phase0 - Random - randomized_5 [Preset: minimal]                            OK
+ [Valid]   EF - phase0 - Random - randomized_6 [Preset: minimal]                            OK
+ [Valid]   EF - phase0 - Random - randomized_7 [Preset: minimal]                            OK
+ [Valid]   EF - phase0 - Random - randomized_8 [Preset: minimal]                            OK
+ [Valid]   EF - phase0 - Random - randomized_9 [Preset: minimal]                            OK
```
## EF - phase0 - Rewards  [Preset: minimal]
```diff
+ EF - phase0 - Rewards - all_balances_too_low_for_reward [Preset: minimal]                  OK
+ EF - phase0 - Rewards - duplicate_attestations_at_later_slots [Preset: minimal]            OK
+ EF - phase0 - Rewards - empty [Preset: minimal]                                            OK
+ EF - phase0 - Rewards - empty_leak [Preset: minimal]                                       OK
+ EF - phase0 - Rewards - full_all_correct [Preset: minimal]                                 OK
+ EF - phase0 - Rewards - full_but_partial_participation [Preset: minimal]                   OK
+ EF - phase0 - Rewards - full_but_partial_participation_leak [Preset: minimal]              OK
+ EF - phase0 - Rewards - full_correct_target_incorrect_head [Preset: minimal]               OK
+ EF - phase0 - Rewards - full_correct_target_incorrect_head_leak [Preset: minimal]          OK
+ EF - phase0 - Rewards - full_delay_max_slots [Preset: minimal]                             OK
+ EF - phase0 - Rewards - full_delay_one_slot [Preset: minimal]                              OK
+ EF - phase0 - Rewards - full_half_correct_target_incorrect_head [Preset: minimal]          OK
+ EF - phase0 - Rewards - full_half_correct_target_incorrect_head_leak [Preset: minimal]     OK
+ EF - phase0 - Rewards - full_half_incorrect_target_correct_head [Preset: minimal]          OK
+ EF - phase0 - Rewards - full_half_incorrect_target_correct_head_leak [Preset: minimal]     OK
+ EF - phase0 - Rewards - full_half_incorrect_target_incorrect_head [Preset: minimal]        OK
+ EF - phase0 - Rewards - full_half_incorrect_target_incorrect_head_leak [Preset: minimal]   OK
+ EF - phase0 - Rewards - full_leak [Preset: minimal]                                        OK
+ EF - phase0 - Rewards - full_mixed_delay [Preset: minimal]                                 OK
+ EF - phase0 - Rewards - full_random_0 [Preset: minimal]                                    OK
+ EF - phase0 - Rewards - full_random_1 [Preset: minimal]                                    OK
+ EF - phase0 - Rewards - full_random_2 [Preset: minimal]                                    OK
+ EF - phase0 - Rewards - full_random_3 [Preset: minimal]                                    OK
+ EF - phase0 - Rewards - full_random_4 [Preset: minimal]                                    OK
+ EF - phase0 - Rewards - full_random_leak [Preset: minimal]                                 OK
+ EF - phase0 - Rewards - full_random_low_balances_0 [Preset: minimal]                       OK
+ EF - phase0 - Rewards - full_random_low_balances_1 [Preset: minimal]                       OK
+ EF - phase0 - Rewards - full_random_misc_balances [Preset: minimal]                        OK
+ EF - phase0 - Rewards - full_random_seven_epoch_leak [Preset: minimal]                     OK
+ EF - phase0 - Rewards - full_random_ten_epoch_leak [Preset: minimal]                       OK
+ EF - phase0 - Rewards - full_random_without_leak_0 [Preset: minimal]                       OK
+ EF - phase0 - Rewards - full_random_without_leak_and_current_exit_0 [Preset: minimal]      OK
+ EF - phase0 - Rewards - half_full [Preset: minimal]                                        OK
+ EF - phase0 - Rewards - half_full_leak [Preset: minimal]                                   OK
+ EF - phase0 - Rewards - one_attestation_one_correct [Preset: minimal]                      OK
+ EF - phase0 - Rewards - one_attestation_one_correct_leak [Preset: minimal]                 OK
+ EF - phase0 - Rewards - proposer_not_in_attestations [Preset: minimal]                     OK
+ EF - phase0 - Rewards - quarter_full [Preset: minimal]                                     OK
+ EF - phase0 - Rewards - quarter_full_leak [Preset: minimal]                                OK
+ EF - phase0 - Rewards - some_very_low_effective_balances_that_attested [Preset: minimal]   OK
+ EF - phase0 - Rewards - some_very_low_effective_balances_that_attested_leak [Preset: minim OK
+ EF - phase0 - Rewards - some_very_low_effective_balances_that_did_not_attest [Preset: mini OK
+ EF - phase0 - Rewards - some_very_low_effective_balances_that_did_not_attest_leak [Preset: OK
+ EF - phase0 - Rewards - with_exited_validators [Preset: minimal]                           OK
+ EF - phase0 - Rewards - with_exited_validators_leak [Preset: minimal]                      OK
+ EF - phase0 - Rewards - with_not_yet_activated_validators [Preset: minimal]                OK
+ EF - phase0 - Rewards - with_not_yet_activated_validators_leak [Preset: minimal]           OK
+ EF - phase0 - Rewards - with_slashed_validators [Preset: minimal]                          OK
+ EF - phase0 - Rewards - with_slashed_validators_leak [Preset: minimal]                     OK
```
## EF - phase0 - Sanity - Blocks  [Preset: minimal]
```diff
+ [Invalid] EF - phase0 - Sanity - Blocks - invalid_all_zeroed_sig [Preset: minimal]         OK
+ [Invalid] EF - phase0 - Sanity - Blocks - invalid_duplicate_attester_slashing_same_block [ OK
+ [Invalid] EF - phase0 - Sanity - Blocks - invalid_duplicate_deposit_same_block [Preset: mi OK
+ [Invalid] EF - phase0 - Sanity - Blocks - invalid_duplicate_proposer_slashings_same_block  OK
+ [Invalid] EF - phase0 - Sanity - Blocks - invalid_duplicate_validator_exit_same_block [Pre OK
+ [Invalid] EF - phase0 - Sanity - Blocks - invalid_incorrect_block_sig [Preset: minimal]    OK
+ [Invalid] EF - phase0 - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_expect OK
+ [Invalid] EF - phase0 - Sanity - Blocks - invalid_incorrect_proposer_index_sig_from_propos OK
+ [Invalid] EF - phase0 - Sanity - Blocks - invalid_incorrect_state_root [Preset: minimal]   OK
+ [Invalid] EF - phase0 - Sanity - Blocks - invalid_only_increase_deposit_count [Preset: min OK
+ [Invalid] EF - phase0 - Sanity - Blocks - invalid_parent_from_same_slot [Preset: minimal]  OK
+ [Invalid] EF - phase0 - Sanity - Blocks - invalid_prev_slot_block_transition [Preset: mini OK
+ [Invalid] EF - phase0 - Sanity - Blocks - invalid_proposal_for_genesis_slot [Preset: minim OK
+ [Invalid] EF - phase0 - Sanity - Blocks - invalid_same_slot_block_transition [Preset: mini OK
+ [Invalid] EF - phase0 - Sanity - Blocks - invalid_similar_proposer_slashings_same_block [P OK
+ [Invalid] EF - phase0 - Sanity - Blocks - slash_and_exit_same_index [Preset: minimal]      OK
+ [Valid]   EF - phase0 - Sanity - Blocks - attestation [Preset: minimal]                    OK
+ [Valid]   EF - phase0 - Sanity - Blocks - attester_slashing [Preset: minimal]              OK
+ [Valid]   EF - phase0 - Sanity - Blocks - balance_driven_status_transitions [Preset: minim OK
+ [Valid]   EF - phase0 - Sanity - Blocks - deposit_in_block [Preset: minimal]               OK
+ [Valid]   EF - phase0 - Sanity - Blocks - deposit_top_up [Preset: minimal]                 OK
+ [Valid]   EF - phase0 - Sanity - Blocks - duplicate_attestation_same_block [Preset: minima OK
+ [Valid]   EF - phase0 - Sanity - Blocks - empty_block_transition [Preset: minimal]         OK
+ [Valid]   EF - phase0 - Sanity - Blocks - empty_block_transition_large_validator_set [Pres OK
+ [Valid]   EF - phase0 - Sanity - Blocks - empty_epoch_transition [Preset: minimal]         OK
+ [Valid]   EF - phase0 - Sanity - Blocks - empty_epoch_transition_large_validator_set [Pres OK
+ [Valid]   EF - phase0 - Sanity - Blocks - empty_epoch_transition_not_finalizing [Preset: m OK
+ [Valid]   EF - phase0 - Sanity - Blocks - eth1_data_votes_consensus [Preset: minimal]      OK
+ [Valid]   EF - phase0 - Sanity - Blocks - eth1_data_votes_no_consensus [Preset: minimal]   OK
+ [Valid]   EF - phase0 - Sanity - Blocks - full_random_operations_0 [Preset: minimal]       OK
+ [Valid]   EF - phase0 - Sanity - Blocks - full_random_operations_1 [Preset: minimal]       OK
+ [Valid]   EF - phase0 - Sanity - Blocks - full_random_operations_2 [Preset: minimal]       OK
+ [Valid]   EF - phase0 - Sanity - Blocks - full_random_operations_3 [Preset: minimal]       OK
+ [Valid]   EF - phase0 - Sanity - Blocks - high_proposer_index [Preset: minimal]            OK
+ [Valid]   EF - phase0 - Sanity - Blocks - historical_batch [Preset: minimal]               OK
+ [Valid]   EF - phase0 - Sanity - Blocks - multiple_attester_slashings_no_overlap [Preset:  OK
+ [Valid]   EF - phase0 - Sanity - Blocks - multiple_attester_slashings_partial_overlap [Pre OK
+ [Valid]   EF - phase0 - Sanity - Blocks - multiple_different_proposer_slashings_same_block OK
+ [Valid]   EF - phase0 - Sanity - Blocks - multiple_different_validator_exits_same_block [P OK
+ [Valid]   EF - phase0 - Sanity - Blocks - proposer_after_inactive_index [Preset: minimal]  OK
+ [Valid]   EF - phase0 - Sanity - Blocks - proposer_self_slashing [Preset: minimal]         OK
+ [Valid]   EF - phase0 - Sanity - Blocks - proposer_slashing [Preset: minimal]              OK
+ [Valid]   EF - phase0 - Sanity - Blocks - skipped_slots [Preset: minimal]                  OK
+ [Valid]   EF - phase0 - Sanity - Blocks - slash_and_exit_diff_index [Preset: minimal]      OK
+ [Valid]   EF - phase0 - Sanity - Blocks - voluntary_exit [Preset: minimal]                 OK
```
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
+ ForkChoice - minimal/altair/fork_choice/on_block/pyspec_tests/justified_update_monotonic   OK
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
+ ForkChoice - minimal/bellatrix/fork_choice/on_block/pyspec_tests/justified_update_monotoni OK
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
+ ForkChoice - minimal/capella/fork_choice/on_block/pyspec_tests/justified_update_monotonic  OK
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
+ ForkChoice - minimal/deneb/fork_choice/on_block/pyspec_tests/justified_update_monotonic    OK
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
+ ForkChoice - minimal/electra/fork_choice/deposit_with_reorg/pyspec_tests/new_validator_dep OK
+ ForkChoice - minimal/electra/fork_choice/ex_ante/pyspec_tests/ex_ante_sandwich_with_honest OK
+ ForkChoice - minimal/electra/fork_choice/ex_ante/pyspec_tests/ex_ante_sandwich_without_att OK
+ ForkChoice - minimal/electra/fork_choice/ex_ante/pyspec_tests/ex_ante_vanilla              OK
+ ForkChoice - minimal/electra/fork_choice/get_head/pyspec_tests/chain_no_attestations       OK
+ ForkChoice - minimal/electra/fork_choice/get_head/pyspec_tests/discard_equivocations_on_at OK
+ ForkChoice - minimal/electra/fork_choice/get_head/pyspec_tests/discard_equivocations_slash OK
+ ForkChoice - minimal/electra/fork_choice/get_head/pyspec_tests/filtered_block_tree         OK
+ ForkChoice - minimal/electra/fork_choice/get_head/pyspec_tests/genesis                     OK
+ ForkChoice - minimal/electra/fork_choice/get_head/pyspec_tests/proposer_boost_correct_head OK
+ ForkChoice - minimal/electra/fork_choice/get_head/pyspec_tests/shorter_chain_but_heavier_w OK
+ ForkChoice - minimal/electra/fork_choice/get_head/pyspec_tests/split_tie_breaker_no_attest OK
+ ForkChoice - minimal/electra/fork_choice/get_head/pyspec_tests/voting_source_within_two_ep OK
  ForkChoice - minimal/electra/fork_choice/get_proposer_head/pyspec_tests/basic_is_head_root Skip
  ForkChoice - minimal/electra/fork_choice/get_proposer_head/pyspec_tests/basic_is_parent_ro Skip
+ ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/basic                       OK
+ ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/incompatible_justification_ OK
+ ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/incompatible_justification_ OK
+ ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/invalid_data_unavailable    OK
+ ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/invalid_incorrect_proof     OK
+ ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/invalid_wrong_blobs_length  OK
+ ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/invalid_wrong_proofs_length OK
+ ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/justification_update_beginn OK
+ ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/justification_update_end_of OK
+ ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/justification_withholding   OK
+ ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/justification_withholding_r OK
+ ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/justified_update_monotonic  OK
+ ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/new_finalized_slot_is_justi OK
+ ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/not_pull_up_current_epoch_b OK
+ ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/on_block_bad_parent_root    OK
+ ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/on_block_before_finalized   OK
+ ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/on_block_checkpoints        OK
+ ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/on_block_finalized_skip_slo OK
+ ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/on_block_finalized_skip_slo OK
  ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/on_block_future_block       Skip
+ ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/proposer_boost              OK
+ ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/proposer_boost_is_first_blo OK
+ ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/proposer_boost_root_same_sl OK
+ ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/pull_up_on_tick             OK
+ ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/pull_up_past_epoch_block    OK
+ ForkChoice - minimal/electra/fork_choice/on_block/pyspec_tests/simple_blob_data            OK
+ ForkChoice - minimal/electra/fork_choice/reorg/pyspec_tests/delayed_justification_current_ OK
+ ForkChoice - minimal/electra/fork_choice/reorg/pyspec_tests/delayed_justification_previous OK
+ ForkChoice - minimal/electra/fork_choice/reorg/pyspec_tests/include_votes_another_empty_ch OK
+ ForkChoice - minimal/electra/fork_choice/reorg/pyspec_tests/include_votes_another_empty_ch OK
+ ForkChoice - minimal/electra/fork_choice/reorg/pyspec_tests/include_votes_another_empty_ch OK
+ ForkChoice - minimal/electra/fork_choice/reorg/pyspec_tests/simple_attempted_reorg_delayed OK
+ ForkChoice - minimal/electra/fork_choice/reorg/pyspec_tests/simple_attempted_reorg_delayed OK
+ ForkChoice - minimal/electra/fork_choice/reorg/pyspec_tests/simple_attempted_reorg_without OK
  ForkChoice - minimal/electra/fork_choice/should_override_forkchoice_update/pyspec_tests/sh Skip
  ForkChoice - minimal/electra/fork_choice/should_override_forkchoice_update/pyspec_tests/sh Skip
+ ForkChoice - minimal/electra/fork_choice/withholding/pyspec_tests/withholding_attack       OK
+ ForkChoice - minimal/electra/fork_choice/withholding/pyspec_tests/withholding_attack_unvia OK
+ ForkChoice - minimal/fulu/fork_choice/deposit_with_reorg/pyspec_tests/new_validator_deposi OK
+ ForkChoice - minimal/fulu/fork_choice/ex_ante/pyspec_tests/ex_ante_sandwich_with_honest_at OK
+ ForkChoice - minimal/fulu/fork_choice/ex_ante/pyspec_tests/ex_ante_sandwich_without_attest OK
+ ForkChoice - minimal/fulu/fork_choice/ex_ante/pyspec_tests/ex_ante_vanilla                 OK
+ ForkChoice - minimal/fulu/fork_choice/get_head/pyspec_tests/chain_no_attestations          OK
+ ForkChoice - minimal/fulu/fork_choice/get_head/pyspec_tests/discard_equivocations_on_attes OK
+ ForkChoice - minimal/fulu/fork_choice/get_head/pyspec_tests/discard_equivocations_slashed_ OK
+ ForkChoice - minimal/fulu/fork_choice/get_head/pyspec_tests/filtered_block_tree            OK
+ ForkChoice - minimal/fulu/fork_choice/get_head/pyspec_tests/genesis                        OK
+ ForkChoice - minimal/fulu/fork_choice/get_head/pyspec_tests/proposer_boost_correct_head    OK
+ ForkChoice - minimal/fulu/fork_choice/get_head/pyspec_tests/shorter_chain_but_heavier_weig OK
+ ForkChoice - minimal/fulu/fork_choice/get_head/pyspec_tests/split_tie_breaker_no_attestati OK
+ ForkChoice - minimal/fulu/fork_choice/get_head/pyspec_tests/voting_source_within_two_epoch OK
  ForkChoice - minimal/fulu/fork_choice/get_proposer_head/pyspec_tests/basic_is_head_root    Skip
  ForkChoice - minimal/fulu/fork_choice/get_proposer_head/pyspec_tests/basic_is_parent_root  Skip
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/basic                          OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/incompatible_justification_upd OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/incompatible_justification_upd OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/justification_update_beginning OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/justification_update_end_of_ep OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/justification_withholding      OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/justification_withholding_reve OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/justified_update_monotonic     OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/new_finalized_slot_is_justifie OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/not_pull_up_current_epoch_bloc OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/on_block_bad_parent_root       OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/on_block_before_finalized      OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/on_block_checkpoints           OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/on_block_finalized_skip_slots  OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/on_block_finalized_skip_slots_ OK
  ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/on_block_future_block          Skip
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/on_block_peerdas__invalid_inde OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/on_block_peerdas__invalid_inde OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/on_block_peerdas__invalid_mism OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/on_block_peerdas__invalid_mism OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/on_block_peerdas__invalid_mism OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/on_block_peerdas__invalid_mism OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/on_block_peerdas__invalid_mism OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/on_block_peerdas__invalid_mism OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/on_block_peerdas__invalid_wron OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/on_block_peerdas__invalid_wron OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/on_block_peerdas__invalid_wron OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/on_block_peerdas__invalid_wron OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/on_block_peerdas__invalid_wron OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/on_block_peerdas__invalid_wron OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/on_block_peerdas__invalid_zero OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/on_block_peerdas__not_availabl OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/on_block_peerdas__ok           OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/proposer_boost                 OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/proposer_boost_is_first_block  OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/proposer_boost_root_same_slot_ OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/pull_up_on_tick                OK
+ ForkChoice - minimal/fulu/fork_choice/on_block/pyspec_tests/pull_up_past_epoch_block       OK
+ ForkChoice - minimal/fulu/fork_choice/reorg/pyspec_tests/delayed_justification_current_epo OK
+ ForkChoice - minimal/fulu/fork_choice/reorg/pyspec_tests/delayed_justification_previous_ep OK
+ ForkChoice - minimal/fulu/fork_choice/reorg/pyspec_tests/include_votes_another_empty_chain OK
+ ForkChoice - minimal/fulu/fork_choice/reorg/pyspec_tests/include_votes_another_empty_chain OK
+ ForkChoice - minimal/fulu/fork_choice/reorg/pyspec_tests/include_votes_another_empty_chain OK
+ ForkChoice - minimal/fulu/fork_choice/reorg/pyspec_tests/simple_attempted_reorg_delayed_ju OK
+ ForkChoice - minimal/fulu/fork_choice/reorg/pyspec_tests/simple_attempted_reorg_delayed_ju OK
+ ForkChoice - minimal/fulu/fork_choice/reorg/pyspec_tests/simple_attempted_reorg_without_en OK
  ForkChoice - minimal/fulu/fork_choice/should_override_forkchoice_update/pyspec_tests/shoul Skip
  ForkChoice - minimal/fulu/fork_choice/should_override_forkchoice_update/pyspec_tests/shoul Skip
+ ForkChoice - minimal/fulu/fork_choice/withholding/pyspec_tests/withholding_attack          OK
+ ForkChoice - minimal/fulu/fork_choice/withholding/pyspec_tests/withholding_attack_unviable OK
```
## Sync
```diff
+ Sync - minimal/bellatrix/sync/optimistic/pyspec_tests/from_syncing_to_invalid              OK
+ Sync - minimal/capella/sync/optimistic/pyspec_tests/from_syncing_to_invalid                OK
+ Sync - minimal/deneb/sync/optimistic/pyspec_tests/from_syncing_to_invalid                  OK
+ Sync - minimal/electra/sync/optimistic/pyspec_tests/from_syncing_to_invalid                OK
+ Sync - minimal/fulu/sync/optimistic/pyspec_tests/from_syncing_to_invalid                   OK
```
