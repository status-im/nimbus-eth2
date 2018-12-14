# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  milagro_crypto,
  ../beacon_chain/[extras, ssz],
  ../beacon_chain/spec/[crypto, datatypes, digest, helpers]

const
  randaoRounds = 100

func makeValidatorPrivKey(i: int): ValidatorPrivKey =
  var i = i + 1 # 0 does not work, as private key...
  copyMem(result.x[0].addr, i.addr, min(sizeof(result.x), sizeof(i)))

func makeFakeHash(i: int): Eth2Digest =
  copyMem(result.data[0].addr, i.unsafeAddr, min(sizeof(result.data), sizeof(i)))

func hackPrivKey(v: ValidatorRecord): ValidatorPrivKey =
  ## Extract private key, per above hack
  var i: int
  copyMem(
    i.addr, v.withdrawal_credentials.data[0].unsafeAddr,
    min(sizeof(v.withdrawal_credentials.data), sizeof(i)))
  makeValidatorPrivKey(i)

func hackReveal(v: ValidatorRecord): Eth2Digest =
  result = v.withdrawal_credentials
  for i in 0..randaoRounds:
    let tmp = repeat_hash(result, 1)
    if tmp == v.randao_commitment:
      return
    result = tmp
  raise newException(Exception, "can't find randao hack value")

func makeDeposit(i: int): Deposit =
  ## Ugly hack for now: we stick the private key in withdrawal_credentials
  ## which means we can repro private key and randao reveal from this data,
  ## for testing :)
  let
    privkey = makeValidatorPrivKey(i)
    pubkey = privkey.fromSigKey()
    withdrawal_credentials = makeFakeHash(i)
    randao_commitment = repeat_hash(withdrawal_credentials, randaoRounds)
    pop = signMessage(privkey, hash_tree_root(
      (pubkey, withdrawal_credentials, randao_commitment)))

  Deposit(
    deposit_data: DepositData(
      deposit_parameters: DepositParameters(
        pubkey: pubkey,
        proof_of_possession: pop,
        withdrawal_credentials: withdrawal_credentials,
        randao_commitment: randao_commitment
      ),
      value: MAX_DEPOSIT * GWEI_PER_ETH,
    )
  )

func makeInitialDeposits*(n = EPOCH_LENGTH): seq[Deposit] =
  for i in 0..<n.int:
    result.add makeDeposit(i + 1)

func makeGenesisBlock*(state: BeaconState): BeaconBlock =
  BeaconBlock(
    slot: INITIAL_SLOT_NUMBER,
    state_root: Eth2Digest(data: hash_tree_root(state))
  )

func makeBlock*(
    state: BeaconState, latest_block: BeaconBlock): BeaconBlock =
  var next_state = state
  next_state.slot += 1
  let
    proposer = state.validator_registry[
      get_beacon_proposer_index(next_state, next_state.slot)]

  var new_block = BeaconBlock(
      slot: next_state.slot,
      state_root: Eth2Digest(data: hash_tree_root(state)),
      randao_reveal: hackReveal(proposer)
    )

  let
    signed_data = ProposalSignedData(
      slot: new_block.slot,
      shard: BEACON_CHAIN_SHARD_NUMBER,
      block_root: Eth2Digest(data: hash_tree_root(new_block))
    )
    proposal_hash = hash_tree_root(signed_data)

    proposerPrivkey = hackPrivKey(proposer)

  assert proposerPrivkey.fromSigKey() == proposer.pubkey

  new_block.signature =
    signMessage(proposerPrivkey, proposal_hash)

  assert verifyMessage(
    new_block.signature, proposal_hash, proposerPrivkey.fromSigKey())

  new_block
