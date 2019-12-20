# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
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
  ../../beacon_chain/spec/[datatypes, crypto, helpers, digest, beaconstate],
  # Internals
  ../../beacon_chain/[ssz, extras],
  # Mocking procs
  ./merkle_minimal, ./mock_validator_keys

func signMockDepositData(
        deposit_data: var DepositData,
        privkey: ValidatorPrivKey
      ) =
  # No state --> Genesis
  deposit_data.signature = bls_sign(
    key = privkey,
    msg = deposit_data.getDepositMessage().hash_tree_root().data,
    domain = compute_domain(
      DOMAIN_DEPOSIT,
      default(array[4, byte]) # Genesis is fork_version 0
    )
  )

func signMockDepositData(
        deposit_data: var DepositData,
        privkey: ValidatorPrivKey,
        state: BeaconState
      ) =
  deposit_data.signature = bls_sign(
    key = privkey,
    msg = deposit_data.getDepositMessage().hash_tree_root().data,
    domain = get_domain(
      state,
      DOMAIN_DEPOSIT
    )
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
  deposit_data.withdrawal_credentials.data[1..^1] = pubkey.getBytes()
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
  if skipValidation notin flags:
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
  if skipValidation notin flags:
    signMockDepositData(deposit_data, privkey, state)

template mockGenesisDepositsImpl(
        result: seq[Deposit],
        validatorCount: uint64,
        amount: untyped,
        flags: UpdateFlags = {},
        updateAmount: untyped,
      ) =
  # Genesis deposits with varying amounts

  if skipValidation in flags:
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

    # 2nd & 3rd loops - build hashes and proofs
    let root = hash_tree_root(depositsData)
    let tree = merkleTreeFromLeaves(depositsDataHash)

    # 4th loop - append proof
    for valIdx in 0 ..< validatorCount.int:
      # TODO ensure genesis & deposit process tests suffice to catch whether
      # changes here break things; ensure that this matches the merkle proof
      # sequence is_valid_merkle_branch(...) now looks for
      result[valIdx].proof[0..31] = tree.getMerkleProof(valIdx)
      result[valIdx].proof[32] =
        Eth2Digest(data: int_to_bytes32((valIdx + 1).uint64))
      doAssert is_valid_merkle_branch(
          depositsDataHash[valIdx],
          result[valIdx].proof,
          DEPOSIT_CONTRACT_TREE_DEPTH,
          valIdx.uint64,
          root
        )

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

  when false: # TODO
    let tree = merkleTreeFromLeaves([hash_tree_root(result.data)])
    result[valIdx].proof[0..31] = tree.getMerkleProof(0)
    result[valIdx].proof[32] = int_to_bytes32(0 + 1)
    # doAssert is_valid_merkle_branch(...)

  # TODO: this logic from the eth2.0-specs test suite seems strange
  #       but confirmed by running it
  state.eth1_deposit_index = 0
  state.eth1_data.deposit_root = hash_tree_root(result.data)
  state.eth1_data.deposit_count = 1
