# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Mocking deposits and genesis deposits
# ---------------------------------------------------------------

import
  # 0.19.6 shims
  stew/objects, # import default
  # Specs
  ../../beacon_chain/spec/[datatypes, crypto, helpers, digest, beaconstate],
  # Internals
  ../../beacon_chain/[ssz, extras],
  # Mocking procs
  ./merkle_minimal,./mock_validator_keys


func signMockDepositData(
        deposit_data: var DepositData,
        privkey: ValidatorPrivKey
      ) =
  # No state --> Genesis
  deposit_data.signature = bls_sign(
    key = privkey,
    msg = deposit_data.signing_root().data,
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
    msg = deposit_data.signing_root().data,
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

proc mockGenesisDeposits*(
        validatorCount: int,
        amount: uint64,
        flags: UpdateFlags = {}
      ): seq[Deposit] =


  if skipValidation in flags:
    # 1st loop - build deposit data
    for valIdx in 0 ..< validatorCount:
      # Directly build the Deposit in-place for speed
      result.setLen(valIdx + 1)

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
    for valIdx in 0 ..< validatorCount:
      # Directly build the Deposit in-place for speed
      result.setLen(valIdx + 1)

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
    for valIdx in 0 ..< validatorCount:
      result[valIdx].proof = tree.getMerkleProof(valIdx)
      when false: # requires compliant SSZ hash_tree_root
        doAssert:
          verify_merkle_branch(
            depositsDataHash[valIdx],
            result[valIdx].proof,
            DEPOSIT_CONTRACT_TREE_DEPTH,
            valIdx,
            root
          )
