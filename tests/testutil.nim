# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  options, milagro_crypto, sequtils,
  ../beacon_chain/[extras, ssz, state_transition],
  ../beacon_chain/spec/[beaconstate, crypto, datatypes, digest, helpers]

const
  randaoRounds = 100

func makeValidatorPrivKey(i: int): ValidatorPrivKey =
  var i = i + 1 # 0 does not work, as private key...
  copyMem(result.x[0].addr, i.addr, min(sizeof(result.x), sizeof(i)))

func makeFakeHash*(i: int): Eth2Digest =
  copyMem(result.data[0].addr, i.unsafeAddr, min(sizeof(result.data), sizeof(i)))

func hackPrivKey(v: Validator): ValidatorPrivKey =
  ## Extract private key, per above hack
  var i: int
  copyMem(
    i.addr, v.withdrawal_credentials.data[0].unsafeAddr,
    min(sizeof(v.withdrawal_credentials.data), sizeof(i)))
  makeValidatorPrivKey(i)

func hackReveal(v: Validator): Eth2Digest =
  result = v.withdrawal_credentials
  for i in 0..randaoRounds:
    let tmp = repeat_hash(result, 1)
    if tmp == v.randao_commitment:
      return
    result = tmp
  raise newException(Exception, "can't find randao hack value")

func makeDeposit(i: int, flags: UpdateFlags): Deposit =
  ## Ugly hack for now: we stick the private key in withdrawal_credentials
  ## which means we can repro private key and randao reveal from this data,
  ## for testing :)
  let
    privkey = makeValidatorPrivKey(i)
    pubkey = privkey.fromSigKey()
    withdrawal_credentials = makeFakeHash(i)
    randao_commitment = repeat_hash(withdrawal_credentials, randaoRounds)

  let pop =
    if skipValidation in flags:
      ValidatorSig()
    else:
      let proof_of_possession_data = DepositInput(
        pubkey: pubkey,
        withdrawal_credentials: withdrawal_credentials,
        randao_commitment: randao_commitment
      )
      signMessage(
        privkey, hash_tree_root_final(proof_of_possession_data).data)

  Deposit(
    deposit_data: DepositData(
      deposit_input: DepositInput(
        pubkey: pubkey,
        proof_of_possession: pop,
        withdrawal_credentials: withdrawal_credentials,
        randao_commitment: randao_commitment
      ),
      amount: MAX_DEPOSIT_AMOUNT,
    )
  )

func makeInitialDeposits*(
    n = EPOCH_LENGTH, flags: UpdateFlags = {}): seq[Deposit] =
  for i in 0..<n.int:
    result.add makeDeposit(i + 1, flags)

func makeGenesisBlock*(state: BeaconState): BeaconBlock =
  BeaconBlock(
    slot: GENESIS_SLOT,
    state_root: Eth2Digest(data: hash_tree_root(state))
  )

func getNextBeaconProposerIndex*(state: BeaconState): Uint24 =
  # TODO: This is a special version of get_beacon_proposer_index that takes into
  #       account the partial update done at the start of slot processing -
  #       see get_shard_committees_index
  var next_state = state
  next_state.slot += 1
  get_beacon_proposer_index(next_state, next_state.slot)

proc addBlock*(
    state: var BeaconState, previous_block_root: Eth2Digest,
    body: BeaconBlockBody, flags: UpdateFlags = {}): BeaconBlock =
  # Create and add a block to state - state will advance by one slot!
  # This is the equivalent of running
  # updateState(state, prev_block, makeBlock(...), {skipValidation})
  # but avoids some slow block copies

  state.slot += 1
  let proposer_index = get_beacon_proposer_index(state, state.slot)
  state.slot -= 1

  let
    # Index from the new state, but registry from the old state.. hmm...
    proposer = state.validator_registry[proposer_index]

  var
    # In order to reuse the state transition function, we first create a dummy
    # block that has some fields set, and use that to generate the state as it
    # would look with the new block applied.
    new_block = BeaconBlock(
      slot: state.slot + 1,
      parent_root: previous_block_root,
      state_root: Eth2Digest(), # we need the new state first
      randao_reveal: hackReveal(proposer),
      eth1_data: Eth1Data(), # TODO
      signature: ValidatorSig(), # we need the rest of the block first!
      body: body
    )

  let block_ok = updateState(
    state, previous_block_root, some(new_block), {skipValidation})
  assert block_ok

  # Ok, we have the new state as it would look with the block applied - now we
  # can set the state root in order to be able to create a valid signature
  new_block.state_root = Eth2Digest(data: hash_tree_root(state))

  let
    proposerPrivkey = hackPrivKey(proposer)

    # Once we've collected all the state data, we sign the block data along with
    # some book-keeping values
    signed_data = ProposalSignedData(
      slot: new_block.slot,
      shard: BEACON_CHAIN_SHARD_NUMBER,
      block_root: Eth2Digest(data: hash_tree_root(new_block))
    )
    proposal_hash = hash_tree_root(signed_data)

  assert proposerPrivkey.fromSigKey() == proposer.pubkey,
    "signature key should be derived from private key! - wrong privkey?"

  if skipValidation notin flags:
    # We have a signature - put it in the block and we should be done!
    new_block.signature =
      # TODO domain missing!
      signMessage(proposerPrivkey, proposal_hash)

    assert bls_verify(
      proposer.pubkey,
      proposal_hash, new_block.signature,
      get_domain(state.fork_data, state.slot, DOMAIN_PROPOSAL)),
      "we just signed this message - it should pass verification!"

  new_block

proc makeBlock*(
    state: BeaconState, previous_block_root: Eth2Digest,
    body: BeaconBlockBody): BeaconBlock =
  # Create a block for `state.slot + 1` - like a block proposer would do!
  # It's a bit awkward - in order to produce a block for N+1, we need to
  # calculate what the state will look like after that block has been applied,
  # because the block includes the state root.
  var next_state = state
  addBlock(next_state, previous_block_root, body)

proc find_shard_committee(
    sacs: openArray[ShardCommittee], validator_index: Uint24): ShardCommittee =
  for sac in sacs:
    if validator_index in sac.committee: return sac
  doAssert false

proc makeAttestation*(
    state: BeaconState, beacon_block_root: Eth2Digest,
    validator_index: Uint24, flags: UpdateFlags = {}): Attestation =
  let
    sac = find_shard_committee(
      get_shard_committees_at_slot(state, state.slot), validator_index)
    validator = state.validator_registry[validator_index]
    sac_index = sac.committee.find(validator_index)

    data = AttestationData(
      slot: state.slot,
      shard: sac.shard,
      beacon_block_root: beacon_block_root,
      epoch_boundary_root: Eth2Digest(), # TODO
      shard_block_root: Eth2Digest(), # TODO
      latest_crosslink_root: Eth2Digest(), # TODO
      justified_slot: state.justified_slot,
      justified_block_root: get_block_root(state, state.justified_slot),
    )

  assert sac_index != -1, "find_shard_committe should guarantee this"

  var
    participation_bitfield = repeat(0'u8, ceil_div8(sac.committee.len))
  bitSet(participation_bitfield, sac_index)

  let
    msg = hash_tree_root_final(data)
    sig =
      if skipValidation notin flags:
        signMessage(hackPrivKey(validator), @(msg.data) & @[0'u8])
      else:
        ValidatorSig()

  Attestation(
    data: data,
    participation_bitfield: participation_bitfield,
    aggregate_signature: sig
  )
