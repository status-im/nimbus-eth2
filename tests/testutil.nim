# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  options, sequtils,
  eth/trie/[db],
  ../beacon_chain/[beacon_chain_db, extras, ssz, state_transition, validator_pool],
  ../beacon_chain/spec/[beaconstate, bitfield, crypto, datatypes, digest, helpers, validator]

func makeFakeValidatorPrivKey*(i: int): ValidatorPrivKey =
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
  makeFakeValidatorPrivKey(i)

func makeDeposit(i: int, flags: UpdateFlags): Deposit =
  ## Ugly hack for now: we stick the private key in withdrawal_credentials
  ## which means we can repro private key and randao reveal from this data,
  ## for testing :)
  let
    privkey = makeFakeValidatorPrivKey(i)
    pubkey = privkey.pubKey()
    withdrawal_credentials = makeFakeHash(i)

  let pop =
    if skipValidation in flags:
      ValidatorSig()
    else:
      let proof_of_possession_data = DepositInput(
        pubkey: pubkey,
        withdrawal_credentials: withdrawal_credentials,
      )
      let domain = 0'u64
      bls_sign(privkey, hash_tree_root(proof_of_possession_data).data, domain)

  Deposit(
    index: i.uint64,
    deposit_data: DepositData(
      deposit_input: DepositInput(
        pubkey: pubkey,
        proof_of_possession: pop,
        withdrawal_credentials: withdrawal_credentials,
      ),
      amount: MAX_DEPOSIT_AMOUNT,
    )
  )

func makeInitialDeposits*(
    n = SLOTS_PER_EPOCH, flags: UpdateFlags = {}): seq[Deposit] =
  for i in 0..<n.int:
    result.add makeDeposit(i + 1, flags)

func getNextBeaconProposerIndex*(state: BeaconState): ValidatorIndex =
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

  # Ferret out remaining GENESIS_EPOCH == 0 assumptions in test code
  doAssert allIt(
    body.attestations,
    it.data.previous_crosslink.epoch >= GENESIS_EPOCH)

  let
    # Index from the new state, but registry from the old state.. hmm...
    proposer = state.validator_registry[proposer_index]
    privKey = hackPrivKey(proposer)

  # TODO ugly hack; API needs rethinking
  var new_body = body
  new_body.randao_reveal = privKey.genRandaoReveal(state, state.slot + 1)
  new_body.eth1_data = Eth1Data()

  var
    # In order to reuse the state transition function, we first create a dummy
    # block that has some fields set, and use that to generate the state as it
    # would look with the new block applied.
    new_block = BeaconBlock(
      slot: state.slot + 1,
      previous_block_root: previous_block_root,
      state_root: Eth2Digest(), # we need the new state first
      signature: ValidatorSig(), # we need the rest of the block first!
      body: new_body
    )

  let block_ok = updateState(
    state, previous_block_root, new_block, {skipValidation})
  doAssert block_ok

  # Ok, we have the new state as it would look with the block applied - now we
  # can set the state root in order to be able to create a valid signature
  new_block.state_root = hash_tree_root(state)

  let proposerPrivkey = hackPrivKey(proposer)
  doAssert proposerPrivkey.pubKey() == proposer.pubkey,
    "signature key should be derived from private key! - wrong privkey?"

  if skipValidation notin flags:
    let block_root = signed_root(new_block)
    # We have a signature - put it in the block and we should be done!
    new_block.signature =
      bls_sign(proposerPrivkey, block_root,
               get_domain(state.fork, slot_to_epoch(new_block.slot), DOMAIN_BEACON_BLOCK))

    doAssert bls_verify(
      proposer.pubkey,
      block_root, new_block.signature,
      get_domain(state.fork, slot_to_epoch(new_block.slot), DOMAIN_BEACON_BLOCK)),
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
    sacs: openArray[CrosslinkCommittee], validator_index: ValidatorIndex): CrosslinkCommittee =
  for sac in sacs:
    if validator_index in sac.committee: return sac
  doAssert false

proc makeAttestation*(
    state: BeaconState, beacon_block_root: Eth2Digest,
    validator_index: ValidatorIndex, flags: UpdateFlags = {}): Attestation =
  let
    sac = find_shard_committee(
      get_crosslink_committees_at_slot(state, state.slot), validator_index)
    validator = state.validator_registry[validator_index]
    sac_index = sac.committee.find(validator_index)
    data = makeAttestationData(state, sac.shard, beacon_block_root)

  doAssert sac_index != -1, "find_shard_committe should guarantee this"

  var
    aggregation_bitfield = BitField.init(sac.committee.len)
  set_bitfield_bit(aggregation_bitfield, sac_index)

  let
    msg = hash_tree_root(
      AttestationDataAndCustodyBit(data: data, custody_bit: false))
    sig =
      if skipValidation notin flags:
        bls_sign(
          hackPrivKey(validator), @(msg.data),
          get_domain(
            state.fork,
            slot_to_epoch(state.slot),
            DOMAIN_ATTESTATION))
      else:
        ValidatorSig()

  Attestation(
    data: data,
    aggregation_bitfield: aggregation_bitfield,
    aggregate_signature: sig,
    custody_bitfield: BitField.init(sac.committee.len)
  )

proc makeTestDB*(tailState: BeaconState, tailBlock: BeaconBlock): BeaconChainDB =
  let
    tailRoot = hash_tree_root(tailBlock)

  result = init(BeaconChainDB, newMemoryDB())
  result.putState(tailState)
  result.putBlock(tailBlock)
  result.putTailBlock(tailRoot)
  result.putHeadBlock(tailRoot)
