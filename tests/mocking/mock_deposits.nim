# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Mocking deposits and genesis deposits
# ---------------------------------------------------------------

import
  # Specs
  ../../beacon_chain/spec/[datatypes, crypto, helpers, digest, beaconstate],
  # Internals
  ../../beacon_chain/[ssz, extras],
  # 0.19.6 shims
  stew/objects # import default

func signMockDepositData(
        deposit_data: var DepositData,
        privkey: ValidatorPrivKey
      ) =
  # No state --> Genesis
  deposit_data.signature = bls_sign(
    key = privkey,
    msg = deposit_data.signing_root(),

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
    msg = deposit_data.signing_root(),
    domain = get_domain(
      state,
      DOMAIN_DEPOSIT
    )
  )

func mockDepositData(
        pubkey: ValidatorPubKey,
        privkey: ValidatorPrivKey,
        amount: uint64,
        withdrawal_credentials: Eth2Digest
      ): DepositData =
  result.pubkey = pubkey
  result.withdrawal_credentials = withdrawal_credentials
  result.amount = amount

func mockDepositData(
        pubkey: ValidatorPubKey,
        privkey: ValidatorPrivKey,
        amount: uint64,
        withdrawal_credentials: Eth2Digest,
        state: BeaconState,
        flags: UpdateFlags = {}
      ): DepositData =
  result = mockDepositData(pubkey, privkey, amount, withdrawal_credentials)
  if skipValidation notin flags:
    signMockDepositData(result, privkey, state)

proc mockDepositImpl(
        deposit: var Deposit,
        deposit_hash: var Eth2Digest,
        deposit_data_seq: var seq[DepositData],
        deposit_data: DepositData,
        deposit_index: int,
        pubkey: ValidatorPubKey,
        privkey: ValidatorPrivKey,
        amount: uint64,
        withdrawal_credentials: Eth2Digest,
      )=
  ## Mock a deposit:
  ## - Store it in "deposit"
  ## - Compute its hash into "depositHash"
  ## - Append its data in deposit_data_seq

  deposit_data_seq.add deposit_data
  deposit_hash = hash_tree_root(deposit_data_seq)

  # TODO: we really need get_proof_indices
  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.1/specs/light_client/merkle_proofs.md
