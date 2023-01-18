# beacon_chain
# Copyright (c) 2020-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  ../beacon_chain/spec/[
    datatypes/base, forks, presets, signatures, state_transition],
  ../beacon_chain/consensus_object_pools/[
    block_quarantine, blockchain_dag, exit_pool],
  "."/[testutil, testblockutil, testdbutil]

func makeSignedBeaconBlockHeader(
    fork: Fork, genesis_validators_root: Eth2Digest, slot: Slot,
    proposer_index: uint64, parent_root: Eth2Digest): SignedBeaconBlockHeader =
  let tmp = BeaconBlockHeader(
    slot: slot, proposer_index: proposer_index, parent_root: parent_root)

  SignedBeaconBlockHeader(
    message: tmp,
    signature: get_block_signature(
      fork, genesis_validators_root, slot, hash_tree_root(tmp),
      MockPrivKeys[proposer_index]).toValidatorSig())

func makeIndexedAttestation(
    fork: Fork, genesis_validators_root: Eth2Digest, slot: Slot,
    validator_index: uint64, beacon_block_root: Eth2Digest): IndexedAttestation =
  let tmp = AttestationData(slot: slot, beacon_block_root: beacon_block_root)

  IndexedAttestation(
    data: tmp,
    attesting_indices: List[uint64, Limit MAX_VALIDATORS_PER_COMMITTEE](@[validator_index]),
    signature: get_attestation_signature(
      fork, genesis_validators_root, tmp,
      MockPrivKeys[validator_index]).toValidatorSig)

func makeSignedVoluntaryExit(
    fork: Fork, genesis_validators_root: Eth2Digest, epoch: Epoch,
    validator_index: uint64): SignedVoluntaryExit =
  let tmp = VoluntaryExit(epoch: epoch, validator_index: validator_index)

  SignedVoluntaryExit(
    message: tmp,
    signature: get_voluntary_exit_signature(
      fork, genesis_validators_root, tmp,
      MockPrivKeys[validator_index]).toValidatorSig)

suite "Validator change pool testing suite":
  setup:
    let
      cfg = block:
        var tmp = defaultRuntimeConfig
        tmp.ALTAIR_FORK_EPOCH = Epoch(tmp.SHARD_COMMITTEE_PERIOD)
        tmp.BELLATRIX_FORK_EPOCH = Epoch(tmp.SHARD_COMMITTEE_PERIOD) + 1
        tmp.CAPELLA_FORK_EPOCH = Epoch(tmp.SHARD_COMMITTEE_PERIOD) + 2
        tmp

      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(
        ChainDAGRef, cfg, makeTestDB(SLOTS_PER_EPOCH * 3),
        validatorMonitor, {})
      fork = dag.forkAtEpoch(Epoch(0))
      genesis_validators_root = dag.genesis_validators_root
      pool = newClone(ValidatorChangePool.init(dag))

  test "addValidatorChangeMessage/getProposerSlashingMessage":
    for i in 0'u64 .. MAX_PROPOSER_SLASHINGS + 5:
      for j in 0'u64 .. i:
        let
          msg = ProposerSlashing(
            signed_header_1:
              makeSignedBeaconBlockHeader(
                fork, genesis_validators_root, Slot(1), j, makeFakeHash(0)),
            signed_header_2:
              makeSignedBeaconBlockHeader(
                fork, genesis_validators_root, Slot(1), j, makeFakeHash(1)))

        if i == 0:
          check not pool[].isSeen(msg)

        pool[].addMessage(msg)
        check: pool[].isSeen(msg)
      withState(dag.headState):
        check:
          pool[].getBeaconBlockValidatorChanges(
              cfg, forkyState.data).proposer_slashings.lenu64 ==
            min(i + 1, MAX_PROPOSER_SLASHINGS)
          pool[].getBeaconBlockValidatorChanges(
            cfg, forkyState.data).proposer_slashings.len == 0

  test "addValidatorChangeMessage/getAttesterSlashingMessage":
    for i in 0'u64 .. MAX_ATTESTER_SLASHINGS + 5:
      for j in 0'u64 .. i:
        let
          msg = AttesterSlashing(
            attestation_1: makeIndexedAttestation(
              fork, genesis_validators_root, Slot(1), j, makeFakeHash(0)),
            attestation_2: makeIndexedAttestation(
              fork, genesis_validators_root, Slot(1), j, makeFakeHash(1)))

        if i == 0:
          check not pool[].isSeen(msg)

        pool[].addMessage(msg)
        check: pool[].isSeen(msg)
      withState(dag.headState):
        check:
          pool[].getBeaconBlockValidatorChanges(
              cfg, forkyState.data).attester_slashings.lenu64 ==
            min(i + 1, MAX_ATTESTER_SLASHINGS)
          pool[].getBeaconBlockValidatorChanges(
            cfg, forkyState.data).attester_slashings.len == 0

  test "addValidatorChangeMessage/getVoluntaryExitMessage":
    # Need to advance state or it will not accept voluntary exits
    var
      cache: StateCache
      info: ForkedEpochInfo
    process_slots(
      dag.cfg, dag.headState,
      Epoch(dag.cfg.SHARD_COMMITTEE_PERIOD).start_slot + 1, cache, info,
      {}).expect("ok")
    let
      fork = dag.forkAtEpoch(dag.headState.get_current_epoch())

    for i in 0'u64 .. MAX_VOLUNTARY_EXITS + 5:
      for j in 0'u64 .. i:
        # Cannot exit until
        let msg = makeSignedVoluntaryExit(
          fork, genesis_validators_root, dag.headState.get_current_epoch(), j)
        if i == 0:
          check not pool[].isSeen(msg)

        pool[].addMessage(msg)
        check: pool[].isSeen(msg)

      withState(dag.headState):
        check:
          pool[].getBeaconBlockValidatorChanges(
              cfg, forkyState.data).voluntary_exits.lenu64 ==
            min(i + 1, MAX_VOLUNTARY_EXITS)
          pool[].getBeaconBlockValidatorChanges(
            cfg, forkyState.data).voluntary_exits.len == 0

  test "addValidatorChangeMessage/getBlsToExecutionChange (pre-capella)":
    # Need to advance state or it will not accept voluntary exits
    var
      cache: StateCache
      info: ForkedEpochInfo
    process_slots(
      dag.cfg, dag.headState,
      Epoch(dag.cfg.SHARD_COMMITTEE_PERIOD).start_slot + 1 + SLOTS_PER_EPOCH * 1,
      cache, info, {}).expect("ok")
    let fork = dag.forkAtEpoch(dag.headState.get_current_epoch())

    for i in 0'u64 .. MAX_BLS_TO_EXECUTION_CHANGES + 5:
      for j in 0'u64 .. i:
        let msg = SignedBLSToExecutionChange(
          message: BLSToExecutionChange(validator_index: j))
        if i == 0:
          check not pool[].isSeen(msg)

        pool[].addMessage(msg)
        check: pool[].isSeen(msg)

      withState(dag.headState):
        # Too early to get BLS to execution changes for blocks
        check pool[].getBeaconBlockValidatorChanges(
          cfg, forkyState.data).bls_to_execution_changes.len == 0

  test "addValidatorChangeMessage/getBlsToExecutionChange (post-capella)":
    # Need to advance state or it will not accept voluntary exits
    var
      cache: StateCache
      info: ForkedEpochInfo
    process_slots(
      dag.cfg, dag.headState,
      Epoch(dag.cfg.SHARD_COMMITTEE_PERIOD).start_slot + 1 + SLOTS_PER_EPOCH * 2,
      cache, info, {}).expect("ok")
    let fork = dag.forkAtEpoch(dag.headState.get_current_epoch())

    for i in 0'u64 .. MAX_BLS_TO_EXECUTION_CHANGES + 5:
      for j in 0'u64 .. i:
        let msg = SignedBLSToExecutionChange(
          message: BLSToExecutionChange(validator_index: j))
        if i == 0:
          check not pool[].isSeen(msg)

        pool[].addMessage(msg)
        check: pool[].isSeen(msg)

      withState(dag.headState):
        check:
          pool[].getBeaconBlockValidatorChanges(
              cfg, forkyState.data).bls_to_execution_changes.lenu64 ==
            min(i + 1, MAX_BLS_TO_EXECUTION_CHANGES)
          pool[].getBeaconBlockValidatorChanges(
            cfg, forkyState.data).bls_to_execution_changes.len == 0

  test "pre-pre-fork voluntary exit":
    var
      cache: StateCache
      info: ForkedEpochInfo
    process_slots(
      dag.cfg, dag.headState,
      Epoch(dag.cfg.SHARD_COMMITTEE_PERIOD).start_slot + 1, cache, info,
      {}).expect("ok")

    let msg = makeSignedVoluntaryExit(
      fork, genesis_validators_root, dag.headState.get_current_epoch(), 0)

    pool[].addMessage(msg)
    check: pool[].isSeen(msg)

    process_slots(
      dag.cfg, dag.headState,
      (Epoch(dag.cfg.SHARD_COMMITTEE_PERIOD) + 1).start_slot + 1, cache, info,
      {}).expect("ok")

    withState(dag.headState):
      check:
        # Message signed with a (fork-2) domain can no longer be added as that
        # fork is not present in the BeaconState and thus fails transition
        pool[].getBeaconBlockValidatorChanges(
          cfg, forkyState.data).voluntary_exits.lenu64 == 0
