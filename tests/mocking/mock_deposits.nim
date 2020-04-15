# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Mocking deposits and genesis deposits
# ---------------------------------------------------------------

import
  # Standard library
  math, random,
  # Specs
  ../../beacon_chain/spec/[datatypes, crypto, helpers, digest],
  # Internals
  ../../beacon_chain/[ssz, extras],
  # Mocking procs
  ./mock_validator_keys,
  # Other test utilities, for attachMerkleProofs()
  ../testblockutil

func signMockDepositData(
        deposit_data: var DepositData,
        privkey: ValidatorPrivKey
      ) =
  # No state --> Genesis
  let domain = compute_domain(
      DOMAIN_DEPOSIT,
      default(array[4, byte]) # Genesis is fork_version 0
    )
  let signing_root = compute_signing_root(
    deposit_data.getDepositMessage(),
    domain
  )
  deposit_data.signature = blsSign(
    privkey,
    signing_root.data
  )

func signMockDepositData(
        deposit_data: var DepositData,
        privkey: ValidatorPrivKey,
        state: BeaconState
      ) =
  let domain = compute_domain(
      DOMAIN_DEPOSIT,
      default(array[4, byte]) # Genesis is fork_version 0
    )
  let signing_root = compute_signing_root(
    deposit_data.getDepositMessage(),
    domain
  )
  deposit_data.signature = blsSign(
    privkey,
    signing_root.data
  )

func mockDepositData(
        deposit_data: var DepositData,
        pubkey: ValidatorPubKey,
        amount: uint64,
        # withdrawal_credentials: Eth2Digest
      ) =
  deposit_data.pubkey = pubkey
  deposit_data.amount = amount

  # Insecurely use pubkey as withdrawal key
  deposit_data.withdrawal_credentials.data[0] = byte BLS_WITHDRAWAL_PREFIX
  deposit_data.withdrawal_credentials.data[1..^1] = pubkey.toRaw()
                                                          .eth2hash()
                                                          .data
                                                          .toOpenArray(1, 31)

func mockDepositData(
        deposit_data: var DepositData,
        pubkey: ValidatorPubKey,
        privkey: ValidatorPrivKey,
        amount: uint64,
        # withdrawal_credentials: Eth2Digest,
        flags: UpdateFlags = {}
      ) =
  mockDepositData(deposit_data, pubkey, amount)
  if skipBlsValidation notin flags:
    signMockDepositData(deposit_data, privkey)

func mockDepositData(
        deposit_data: var DepositData,
        pubkey: ValidatorPubKey,
        privkey: ValidatorPrivKey,
        amount: uint64,
        # withdrawal_credentials: Eth2Digest,
        state: BeaconState,
        flags: UpdateFlags = {}
      ) =
  mockDepositData(deposit_data, pubkey, amount)
  if skipBlsValidation notin flags:
    signMockDepositData(deposit_data, privkey, state)

template mockGenesisDepositsImpl(
        result: seq[Deposit],
        validatorCount: uint64,
        amount: untyped,
        flags: UpdateFlags = {},
        updateAmount: untyped,
      ) =
  # Genesis deposits with varying amounts

  # NOTE: this could also apply for skipMerkleValidation, but prefer to er on the
  # side of caution and generate a valid Deposit (it can still be skipped later).
  if skipBlsValidation in flags:
    # 1st loop - build deposit data
    for valIdx in 0 ..< validatorCount.int:
      # Directly build the Deposit in-place for speed
      result.setLen(valIdx + 1)

      updateAmount

      # DepositData
      mockDepositData(
        result[valIdx].data,
        MockPubKeys[valIdx],
        amount
      )
  else: # With signing
    var depositsDataHash: seq[Eth2Digest]
    var depositsData: seq[DepositData]

    # 1st loop - build deposit data
    for valIdx in 0 ..< validatorCount.int:
      # Directly build the Deposit in-place for speed
      result.setLen(valIdx + 1)

      updateAmount

      # DepositData
      mockDepositData(
        result[valIdx].data,
        MockPubKeys[valIdx],
        MockPrivKeys[valIdx],
        amount,
        flags
      )

      depositsData.add result[valIdx].data
      depositsDataHash.add hash_tree_root(result[valIdx].data)

proc mockGenesisBalancedDeposits*(
        validatorCount: uint64,
        amountInEth: Positive,
        flags: UpdateFlags = {}
      ): seq[Deposit] =
  ## The amount should be strictly positive
  ## - 1 is the minimum deposit amount (MIN_DEPOSIT_AMOUNT)
  ## - 16 is the ejection balance (EJECTION_BALANCE)
  ## - 32 is the max effective balance (MAX_EFFECTIVE_BALANCE)
  ##   ETH beyond do not contribute more for staking.
  ##
  ## Only validators with 32 ETH will be active at genesis

  let amount = amountInEth.uint64 * 10'u64^9
  mockGenesisDepositsImpl(result, validatorCount,amount,flags):
    discard
  attachMerkleProofs(result)

proc mockGenesisUnBalancedDeposits*(
        validatorCount: uint64,
        amountRangeInEth: Slice[int], # TODO: use "Positive", Nim range bug
        flags: UpdateFlags = {}
      ): seq[Deposit] =

  ## The range of deposit amount should be strictly positive
  ## - 1 is the minimum deposit amount (MIN_DEPOSIT_AMOUNT)
  ## - 16 is the ejection balance (EJECTION_BALANCE)
  ## - 32 is the max effective balance (MAX_EFFECTIVE_BALANCE)
  ##   ETH beyond do not contribute more for staking.
  ##
  ## Only validators with 32 ETH will be active at genesis

  var rng {.global.} = initRand(0x42) # Fixed seed for reproducibility
  var amount: uint64

  mockGenesisDepositsImpl(result, validatorCount, amount, flags):
    amount = rng.rand(amountRangeInEth).uint64 * 10'u64^9
  attachMerkleProofs(result)

proc mockUpdateStateForNewDeposit*(
       state: var BeaconState,
       validator_index: uint64,
       amount: uint64,
       # withdrawal_credentials: Eth2Digest
       flags: UpdateFlags
    ): Deposit =


  # TODO withdrawal credentials

  mockDepositData(
    result.data,
    MockPubKeys[validator_index],
    MockPrivKeys[validator_index],
    amount,
    # withdrawal_credentials: Eth2Digest
    flags
  )

  var result_seq = @[result]
  attachMerkleProofs(result_seq)
  result.proof = result_seq[0].proof

  # TODO: this logic from the eth2.0-specs test suite seems strange
  #       but confirmed by running it
  state.eth1_deposit_index = 0
  state.eth1_data.deposit_root =
     hash_tree_root(sszList(@[result.data], 2'i64^DEPOSIT_CONTRACT_TREE_DEPTH))
  state.eth1_data.deposit_count = 1
