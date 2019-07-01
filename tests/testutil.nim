# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  options, sequtils,
  chronicles, eth/trie/[db],
  ../beacon_chain/[beacon_chain_db, block_pool, extras, ssz, state_transition,
    validator_pool, beacon_node_types],
  ../beacon_chain/spec/[beaconstate, bitfield, crypto, datatypes, digest,
    helpers, validator]

func preset*(): string =
  " [Preset: " & const_preset & ']'

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
    domain = 3'u64

  result = Deposit(
    data: DepositData(
      pubkey: pubkey,
      withdrawal_credentials: withdrawal_credentials,
      amount: MAX_EFFECTIVE_BALANCE,
    )
  )

  if skipValidation notin flags:
    result.data.signature =
      bls_sign(privkey, signing_root(result.data).data,
               domain)

func makeInitialDeposits*(
    n = SLOTS_PER_EPOCH, flags: UpdateFlags = {}): seq[Deposit] =
  for i in 0..<n.int:
    result.add makeDeposit(i, flags)

func getNextBeaconProposerIndex*(state: BeaconState): ValidatorIndex =
  # TODO: This is a special version of get_beacon_proposer_index that takes into
  #       account the partial update done at the start of slot processing -
  #       see get_shard_committees_index
  var
    next_state = state
    cache = get_empty_per_epoch_cache()

  next_state.slot += 1
  get_beacon_proposer_index(next_state, cache)

proc addBlock*(
    state: var BeaconState, previous_block_root: Eth2Digest,
    body: BeaconBlockBody, flags: UpdateFlags = {}): BeaconBlock =
  # Create and add a block to state - state will advance by one slot!
  # This is the equivalent of running
  # updateState(state, prev_block, makeBlock(...), {skipValidation})
  # but avoids some slow block copies

  state.slot += 1
  var cache = get_empty_per_epoch_cache()
  let proposer_index = get_beacon_proposer_index(state, cache)
  state.slot -= 1

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
      parent_root: previous_block_root,
      state_root: Eth2Digest(), # we need the new state first
      body: new_body,
      signature: ValidatorSig(), # we need the rest of the block first!
    )

  let block_ok = updateState(state, new_block, {skipValidation})
  doAssert block_ok

  # Ok, we have the new state as it would look with the block applied - now we
  # can set the state root in order to be able to create a valid signature
  new_block.state_root = hash_tree_root(state)

  let proposerPrivkey = hackPrivKey(proposer)
  doAssert proposerPrivkey.pubKey() == proposer.pubkey,
    "signature key should be derived from private key! - wrong privkey?"

  if skipValidation notin flags:
    let block_root = signing_root(new_block)
    # We have a signature - put it in the block and we should be done!
    new_block.signature =
      bls_sign(proposerPrivkey, block_root.data,
               get_domain(state, DOMAIN_BEACON_PROPOSER, compute_epoch_of_slot(new_block.slot)))

    doAssert bls_verify(
      proposer.pubkey,
      block_root.data, new_block.signature,
      get_domain(state, DOMAIN_BEACON_PROPOSER, compute_epoch_of_slot(new_block.slot))),
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
    state: BeaconState, validator_index: ValidatorIndex): auto =
  let epoch = compute_epoch_of_slot(state.slot)
  var cache = get_empty_per_epoch_cache()
  for shard in 0'u64 ..< get_epoch_committee_count(state, epoch):
    let committee = get_crosslink_committee(state, epoch,
      (shard + get_epoch_start_shard(state, epoch)) mod SHARD_COUNT, cache)
    if validator_index in committee:
      return (committee, shard)
  doAssert false

proc makeAttestation*(
    state: BeaconState, beacon_block_root: Eth2Digest,
    validator_index: ValidatorIndex, flags: UpdateFlags = {}): Attestation =
  let
    (committee, shard) = find_shard_committee(state, validator_index)
    validator = state.validator_registry[validator_index]
    sac_index = committee.find(validator_index)
    data = makeAttestationData(state, shard, beacon_block_root)

  doAssert sac_index != -1, "find_shard_committee should guarantee this"

  var
    aggregation_bitfield = BitField.init(committee.len)
  set_bitfield_bit(aggregation_bitfield, sac_index)

  let
    msg = hash_tree_root(
      AttestationDataAndCustodyBit(data: data, custody_bit: false))
    sig =
      if skipValidation notin flags:
        bls_sign(
          hackPrivKey(validator), @(msg.data),
          get_domain(
            state,
            DOMAIN_ATTESTATION,
            compute_epoch_of_slot(state.slot)))
      else:
        ValidatorSig()

  Attestation(
    data: data,
    aggregation_bitfield: aggregation_bitfield,
    signature: sig,
    custody_bitfield: BitField.init(committee.len)
  )

proc makeTestDB*(tailState: BeaconState, tailBlock: BeaconBlock): BeaconChainDB =
  let
    tailRoot = signing_root(tailBlock)

  result = init(BeaconChainDB, newMemoryDB())
  BlockPool.preInit(result, tailState, tailBlock)
