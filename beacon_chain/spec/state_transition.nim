import
  results,
  "."/forks

proc makeBeaconBlock*(
    cfg: RuntimeConfig,
    state: var ForkedHashedBeaconState,
    proposer_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    eth1_data: Eth1Data,
    graffiti: GraffitiBytes,
    attestations: seq[Attestation],
    deposits: seq[Deposit],
    validator_changes: BeaconBlockValidatorChanges,
    sync_aggregate: SyncAggregate,
    executionPayload: ForkyExecutionPayloadForSigning,
    cache: var StateCache,
    transactions_root: Opt[Eth2Digest],
    execution_payload_root: Opt[Eth2Digest],
    kzg_commitments: Opt[KzgCommitments]):
    Result[ForkedBeaconBlock, cstring] =
  ok(default(ForkedBeaconBlock))
