# beacon_chain
# Copyright (c) 2021-2026 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  chronicles,
  ../beacon_chain/el/merkle_minimal,
  ../beacon_chain/spec/[beaconstate, forks, state_transition],
  ./testblockutil

const mockEth1BlockHash* =
  Eth2Digest.fromHex("0x4242424242424242424242424242424242424242")

from ".."/beacon_chain/validator_bucket_sort import sortValidatorBuckets

func round_multiple_down(x: Gwei, n: Gwei): Gwei =
  ## Round the input to the previous multiple of "n"
  x - x mod n

proc initGenesisState*(
    cfg: RuntimeConfig,
    eth1_block_hash: Eth2Digest,
    eth1_timestamp: uint64,
    deposits: openArray[DepositData],
    flags: UpdateFlags = {},
): ref ForkedHashedBeaconState =
  result = (ref ForkedHashedBeaconState)(
    kind: ConsensusFork.Phase0,
    phase0Data: initialize_hashed_beacon_state_from_eth1(
      cfg, eth1_block_hash, eth1_timestamp, deposits, flags
    ),
  )

  var cache: StateCache
  maybeUpgradeState(cfg, result[], cache)

  # Adjust latest_block_header with the right fork
  # https://github.com/ethereum/consensus-specs/pull/2323
  # https://github.com/ethereum/consensus-specs/pull/5172
  withState(result[]):
    forkyState.data.latest_block_header.body_root =
      when consensusFork >= ConsensusFork.Gloas:
        hash_tree_root(consensusFork.BeaconBlockBody(
          signed_execution_payload_bid: SignedExecutionPayloadBid(
            message: forkyState.data.latest_execution_payload_bid)))
      else:
        hash_tree_root(default(consensusFork.BeaconBlockBody))
    forkyState.root = hash_tree_root(forkyState.data)

proc initGenesisState*(
    cfg: RuntimeConfig, num_validators = 8'u64 * SLOTS_PER_EPOCH
): ref ForkedHashedBeaconState =
  initGenesisState(
    cfg,
    mockEth1BlockHash,
    0,
    makeInitialDeposits(cfg, num_validators, {skipBlsValidation}),
    {skipBlsValidation},
  )

proc mockUpdateStateForNewDeposit(
       state: var ForkyBeaconState,
       validator_index: int,
       amount: Gwei,
       # withdrawal_credentials: Eth2Digest
       flags: UpdateFlags
    ): Deposit =
  # TODO withdrawal credentials

  result.data = makeDepositData(validator_index, amount, flags)

  var result_seq = @[result]
  let deposit_root = attachMerkleProofs(result_seq)
  result.proof = result_seq[0].proof

  # TODO: this logic from the consensus-specs test suite seems strange
  #       but confirmed by running it
  state.eth1_deposit_index = 0
  state.eth1_data.deposit_root = deposit_root
  state.eth1_data.deposit_count = 1

proc valid_deposit(state: var ForkyHashedBeaconState) =
  const deposit_amount = MAX_EFFECTIVE_BALANCE.Gwei
  let validator_index = state.data.validators.len
  let deposit = mockUpdateStateForNewDeposit(
                  state.data,
                  validator_index,
                  deposit_amount,
                  flags = {}
                )

  let pre_val_count = state.data.validators.len
  let pre_balance = if validator_index < pre_val_count:
                      state.data.balances.item(validator_index)
                    else:
                      0.Gwei
  doAssert process_deposit(
    defaultRuntimeConfig, state.data,
    sortValidatorBuckets(state.data.validators.asSeq)[], deposit, {}).isOk
  doAssert state.data.validators.len == pre_val_count + 1
  when typeof(state).kind >= ConsensusFork.Electra:
    doAssert state.data.balances.item(validator_index) == pre_balance
  else:
    doAssert state.data.balances.item(validator_index) ==
      pre_balance + deposit.data.amount

  doAssert state.data.validators.item(validator_index).effective_balance ==
    round_multiple_down(
      min(
        MAX_EFFECTIVE_BALANCE.Gwei,
        state.data.balances.item(validator_index)),
      EFFECTIVE_BALANCE_INCREMENT.Gwei
    )
  state.root = hash_tree_root(state.data)

proc getTestStates*(
    initialState: ForkedHashedBeaconState, consensusFork: ConsensusFork):
    seq[ref ForkedHashedBeaconState] =
  # Randomly generated slot numbers, with a jump to around
  # SLOTS_PER_HISTORICAL_ROOT to force wraparound of those
  # slot-based mod/increment fields.
  const stateEpochs = [
    0, 1,

    # Around minimal wraparound SLOTS_PER_HISTORICAL_ROOT wraparound
    7, 8, 9,

    # Unexceptional cases, with 2 and 3-long runs
    39, 40, 114, 115, 116, 130, 131,

    # Approaching and passing mainnet SLOTS_PER_HISTORICAL_ROOT wraparound
    255, 256, 257]

  var
    tmpState = assignClone(initialState)
    cache = StateCache()
    info = ForkedEpochInfo()
    cfg = defaultRuntimeConfig

  static: doAssert high(ConsensusFork) == ConsensusFork.Heze
  if consensusFork >= ConsensusFork.Altair:
    cfg.ALTAIR_FORK_EPOCH = 1.Epoch
  if consensusFork >= ConsensusFork.Bellatrix:
    cfg.BELLATRIX_FORK_EPOCH = 2.Epoch
  if consensusFork >= ConsensusFork.Capella:
    cfg.CAPELLA_FORK_EPOCH = 3.Epoch
  if consensusFork >= ConsensusFork.Deneb:
    cfg.DENEB_FORK_EPOCH = 4.Epoch
  if consensusFork >= ConsensusFork.Electra:
    cfg.ELECTRA_FORK_EPOCH = 5.Epoch
  if consensusFork >= ConsensusFork.Fulu:
    cfg.FULU_FORK_EPOCH = 6.Epoch
  if consensusFork >= ConsensusFork.Gloas:
    cfg.GLOAS_FORK_EPOCH = 7.Epoch
  if consensusFork >= ConsensusFork.Heze:
    cfg.HEZE_FORK_EPOCH = 8.Epoch

  for i, epoch in stateEpochs:
    let slot = epoch.Epoch.start_slot
    if tmpState[].slot < slot:
      process_slots(
        cfg, tmpState[], slot, cache, info, {}).expect("no failure")

    if i mod 3 == 0:
      withState(tmpState[]):
        valid_deposit(forkyState)
    doAssert tmpState[].slot == slot

    if tmpState[].kind == consensusFork:
      result.add assignClone(tmpState[])

when isMainModule:
  # Smoke test
  let state = initGenesisState(defaultRuntimeConfig, num_validators = SLOTS_PER_EPOCH)
  doAssert state[].validators.lenu64 == SLOTS_PER_EPOCH
