import
  ./beacon_chain/spec/datatypes/electra,
  ./beacon_chain/spec/forks

echo $const_preset
# echo $LightClientPeriodData.minSize
# echo $LightClientPeriodData.maxSize

echo $(LightClientBeaconStateSummary.minSize.float / 1024.0 / 1024.0)
echo $(LightClientBeaconStateSummary.maxSize.float / 1024.0 / 1024.0)

echo ""
echo "historical roots"
echo $(LightClientBeaconStatePartialHistoricalRoots.maxSize.float / 1024.0 / 1024.0)
echo $(0x040000 * Eth2Digest.maxSize.float / 1024.0 / 1024.0)
echo $(HISTORICAL_ROOTS_LIMIT.float / 0x040000.float)  # 2^6 chunks of 2^18 roots

echo ""
echo "validators"
echo $(LightClientBeaconStatePartialValidators.maxSize.float / 1024.0 / 1024.0)
echo $(0x010000 * Validator.maxSize.float / 1024.0 / 1024.0)
echo $(VALIDATOR_REGISTRY_LIMIT.float / 0x010000.float)  # 2^24 chunks of 2^16 vals

echo ""
echo "balances"
echo $(LightClientBeaconStatePartialBalances.maxSize.float / 1024.0 / 1024.0)
echo $(0x100000 * Gwei.maxSize.float / 1024.0 / 1024.0)
echo $(VALIDATOR_REGISTRY_LIMIT.float / 0x100000.float)  # 2^20 chunks of 2^20 balances


echo ""
echo "epoch participation flags"
echo $(LightClientBeaconStatePartialEpochParticipation.maxSize.float / 1024.0 / 1024.0)
echo $(0x800000 * ParticipationFlags.maxSize.float / 1024.0 / 1024.0)
echo $(VALIDATOR_REGISTRY_LIMIT.float / 0x800000.float)  # 2^17 chunks of 2^23 flags

echo ""
echo "inactivity scores"
echo $(LightClientBeaconStatePartialInactivityScores.maxSize.float / 1024.0 / 1024.0)
echo $(0x100000 * InactivityScores.T.maxSize.float / 1024.0 / 1024.0)
echo $(VALIDATOR_REGISTRY_LIMIT.float / 0x100000.float)  # 2^20 chunks of 2^20 scores

echo ""
echo "historical summaries"
echo $(LightClientBeaconStatePartialHistoricalSummaries.maxSize.float / 1024.0 / 1024.0)
echo $(0x020000 * HistoricalSummary.maxSize.float / 1024.0 / 1024.0)
echo $(HISTORICAL_ROOTS_LIMIT.float / 0x020000.float)  # 2^7 chunks of 2^17 summaries

echo ""
echo "pending deposits"
echo $(LightClientBeaconStatePartialPendingDeposits.maxSize.float / 1024.0 / 1024.0)
echo $(0x008000 * PendingDeposit.maxSize.float / 1024.0 / 1024.0)
echo $(PENDING_DEPOSITS_LIMIT.float / 0x008000.float)  # 2^12 chunks of 2^15 deposits

echo ""
echo "pending withdrawals"
echo $(LightClientBeaconStatePartialPendingPartialWithdrawals.maxSize.float / 1024.0 / 1024.0)
echo $(0x040000 * PendingPartialWithdrawal.maxSize.float / 1024.0 / 1024.0)
echo $(PENDING_PARTIAL_WITHDRAWALS_LIMIT.float / 0x040000.float)  # 2^9 chunks of 2^18 withdrawals

echo ""
echo "pending consolidations"
echo $(LightClientBeaconStatePartialPendingConsolidations.maxSize.float / 1024.0 / 1024.0)
echo $(0x040000 * PendingConsolidation.maxSize.float / 1024.0 / 1024.0)
echo $(PENDING_CONSOLIDATIONS_LIMIT.float / 0x040000.float)  # 2^0 chunks of 2^18 consolidations


# /eth/v1/beacon/light_client/states/


# /eth2/beacon_chain/req/light_client_beacon_state_by_period/1/
