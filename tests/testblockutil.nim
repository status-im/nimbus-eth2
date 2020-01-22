# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  options, stew/endians2,
  chronicles, eth/trie/[db],
  ../beacon_chain/[beacon_chain_db, block_pool, extras, ssz, state_transition,
    validator_pool],
  ../beacon_chain/spec/[beaconstate, crypto, datatypes, digest,
    helpers, validator]

when ValidatorPrivKey is BlsValue:
  func makeFakeValidatorPrivKey(i: int): ValidatorPrivKey =
    # 0 is not a valid BLS private key - 1000 helps interop with rust BLS library,
    # lighthouse.
    # TODO: switch to https://github.com/ethereum/eth2.0-pm/issues/60
    result.kind = BlsValueType.Real
    var bytes = uint64(i + 1000).toBytesLE()
    copyMem(addr result.blsValue.x[0], addr bytes[0], sizeof(bytes))
else:
  func makeFakeValidatorPrivKey(i: int): ValidatorPrivKey =
    # 0 is not a valid BLS private key - 1000 helps interop with rust BLS library,
    # lighthouse.
    # TODO: switch to https://github.com/ethereum/eth2.0-pm/issues/60
    var bytes = uint64(i + 1000).toBytesLE()
    copyMem(addr result.x[0], addr bytes[0], sizeof(bytes))

func makeFakeHash(i: int): Eth2Digest =
  var bytes = uint64(i).toBytesLE()
  static: doAssert sizeof(bytes) <= sizeof(result.data)
  copyMem(addr result.data[0], addr bytes[0], sizeof(bytes))

func hackPrivKey(v: Validator): ValidatorPrivKey =
  ## Extract private key, per above hack
  var bytes: array[8, byte]
  static: doAssert sizeof(bytes) <= sizeof(v.withdrawal_credentials.data)

  copyMem(
    addr bytes, unsafeAddr v.withdrawal_credentials.data[0], sizeof(bytes))
  let i = int(uint64.fromBytesLE(bytes))
  makeFakeValidatorPrivKey(i)

func makeDeposit(i: int, flags: UpdateFlags): Deposit =
  ## Ugly hack for now: we stick the private key in withdrawal_credentials
  ## which means we can repro private key and randao reveal from this data,
  ## for testing :)
  let
    privkey = makeFakeValidatorPrivKey(i)
    pubkey = privkey.pubKey()
    withdrawal_credentials = makeFakeHash(i)
    domain = compute_domain(DOMAIN_DEPOSIT)

  result = Deposit(
    data: DepositData(
      pubkey: pubkey,
      withdrawal_credentials: withdrawal_credentials,
      amount: MAX_EFFECTIVE_BALANCE,
    )
  )

  if skipValidation notin flags:
    result.data.signature =
      bls_sign(privkey, hash_tree_root(result.getDepositMessage).data,
               domain)

func makeInitialDeposits*(
    n = SLOTS_PER_EPOCH, flags: UpdateFlags = {}): seq[Deposit] =
  for i in 0..<n.int:
    result.add makeDeposit(i, flags)

proc addBlock*(
    state: var BeaconState, previous_block_root: Eth2Digest,
    body: BeaconBlockBody, flags: UpdateFlags = {}): SignedBeaconBlock =
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
    # In tests, let this throw
    proposer = state.validators[proposer_index.get]
    privKey = hackPrivKey(proposer)

  # TODO ugly hack; API needs rethinking
  var new_body = body
  if skipValidation notin flags:
    new_body.randao_reveal = privKey.genRandaoReveal(state.fork, state.slot + 1)

  new_body.eth1_data = Eth1Data()

  var
    # In order to reuse the state transition function, we first create a dummy
    # block that has some fields set, and use that to generate the state as it
    # would look with the new block applied.
    new_block = SignedBeaconBlock(
      message: BeaconBlock(
        slot: state.slot + 1,
        parent_root: previous_block_root,
        state_root: Eth2Digest(), # we need the new state first
        body: new_body
      )
    )

  let block_ok = state_transition(state, new_block.message, {skipValidation})
  doAssert block_ok

  # Ok, we have the new state as it would look with the block applied - now we
  # can set the state root in order to be able to create a valid signature
  new_block.message.state_root = hash_tree_root(state)

  doAssert privKey.pubKey() == proposer.pubkey,
    "signature key should be derived from private key! - wrong privkey?"

  if skipValidation notin flags:
    let block_root = hash_tree_root(new_block.message)
    # We have a signature - put it in the block and we should be done!
    new_block.signature =
      bls_sign(privKey, block_root.data,
               get_domain(state, DOMAIN_BEACON_PROPOSER,
               compute_epoch_at_slot(new_block.message.slot)))

    doAssert bls_verify(
      proposer.pubkey,
      block_root.data, new_block.signature,
      get_domain(
        state, DOMAIN_BEACON_PROPOSER,
        compute_epoch_at_slot(new_block.message.slot))),
      "we just signed this message - it should pass verification!"

  new_block

proc makeBlock*(
    state: BeaconState, previous_block_root: Eth2Digest,
    body: BeaconBlockBody): SignedBeaconBlock =
  # Create a block for `state.slot + 1` - like a block proposer would do!
  # It's a bit awkward - in order to produce a block for N+1, we need to
  # calculate what the state will look like after that block has been applied,
  # because the block includes the state root.
  var next_state = state
  addBlock(next_state, previous_block_root, body)

proc makeAttestation*(
    state: BeaconState, beacon_block_root: Eth2Digest,
    committee: seq[ValidatorIndex], slot: Slot, index: uint64,
    validator_index: auto, cache: var StateCache,
    flags: UpdateFlags = {}): Attestation =
  # Avoids state_sim silliness; as it's responsible for all validators,
  # transforming, from monotonic enumerable index -> committee index ->
  # montonoic enumerable index, is wasteful and slow. Most test callers
  # want ValidatorIndex, so that's supported too.
  let
    validator = state.validators[validator_index]
    sac_index = committee.find(validator_index)
    data = makeAttestationData(state, slot, index, beacon_block_root)

  doAssert sac_index != -1, "find_beacon_committee should guarantee this"

  var aggregation_bits = CommitteeValidatorsBits.init(committee.len)
  aggregation_bits.setBit sac_index

  let
    msg = hash_tree_root(data)
    sig =
      if skipValidation notin flags:
        bls_sign(
          hackPrivKey(validator), msg.data,
          get_domain(state, DOMAIN_BEACON_ATTESTER, data.target.epoch))
      else:
        ValidatorSig()

  Attestation(
    data: data,
    aggregation_bits: aggregation_bits,
    signature: sig
  )

proc find_beacon_committee(
    state: BeaconState, validator_index: ValidatorIndex,
    cache: var StateCache): auto =
  let epoch = compute_epoch_at_slot(state.slot)
  for epoch_committee_index in 0'u64 ..< get_committee_count_at_slot(
      state, epoch.compute_start_slot_at_epoch) * SLOTS_PER_EPOCH:
    let
      slot = ((epoch_committee_index mod SLOTS_PER_EPOCH) +
        epoch.compute_start_slot_at_epoch.uint64).Slot
      index = epoch_committee_index div SLOTS_PER_EPOCH
      committee = get_beacon_committee(state, slot, index, cache)
    if validator_index in committee:
      return (committee, slot, index)
  doAssert false

proc makeAttestation*(
    state: BeaconState, beacon_block_root: Eth2Digest,
    validator_index: ValidatorIndex, cache: var StateCache,
    flags: UpdateFlags = {}): Attestation =
  let (committee, slot, index) =
    find_beacon_committee(state, validator_index, cache)
  makeAttestation(state, beacon_block_root, committee, slot, index,
    validator_index, cache, flags)

proc makeFullAttestations*(
    state: BeaconState, beacon_block_root: Eth2Digest, slot: Slot,
    cache: var StateCache,
    flags: UpdateFlags = {}): seq[Attestation] =
  # Create attestations in which the full committee participates for each shard
  # that should be attested to during a particular slot
  let
    count = get_committee_count_at_slot(state, slot)

  for index in 0..<count:
    let
      committee = get_beacon_committee(state, slot, index, cache)
      data = makeAttestationData(state, slot, index, beacon_block_root)
      msg = hash_tree_root(data)

    var
      attestation = Attestation(
        aggregation_bits: CommitteeValidatorsBits.init(committee.len),
        data: data,
        signature: ValidatorSig(kind: Real, blsValue: Signature.init())
      )
    for j in 0..<committee.len():
      attestation.aggregation_bits.setBit j
      if skipValidation notin flags:
        attestation.signature.combine(bls_sign(
          hackPrivKey(state.validators[committee[j]]), msg.data,
          get_domain(state, DOMAIN_BEACON_ATTESTER, data.target.epoch)))

    result.add attestation
