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
    helpers, validator, state_transition_block]

func makeFakeValidatorPrivKey(i: int): ValidatorPrivKey =
  # 0 is not a valid BLS private key - 1000 helps interop with rust BLS library,
  # lighthouse.
  # TODO: switch to https://github.com/ethereum/eth2.0-pm/issues/60
  var bytes = uint64(i + 1000).toBytesLE()
  copyMem(addr result, addr bytes[0], sizeof(bytes))

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

  if skipBLSValidation notin flags:
    let signing_root = compute_signing_root(result.getDepositMessage, domain)
    result.data.signature = bls_sign(privkey, signing_root.data)

func makeInitialDeposits*(
    n = SLOTS_PER_EPOCH, flags: UpdateFlags = {}): seq[Deposit] =
  for i in 0..<n.int:
    result.add makeDeposit(i, flags)

proc addTestBlock*(
    state: var BeaconState,
    parent_root: Eth2Digest,
    eth1_data = Eth1Data(),
    attestations = newSeq[Attestation](),
    deposits = newSeq[Deposit](),
    graffiti = Eth2Digest(),
    flags: set[UpdateFlag] = {}): SignedBeaconBlock =
  # Create and add a block to state - state will advance by one slot!

  process_slots(state, state.slot + 1)

  var cache = get_empty_per_epoch_cache()
  let proposer_index = get_beacon_proposer_index(state, cache)

  let
    # Index from the new state, but registry from the old state.. hmm...
    # In tests, let this throw
    proposer = state.validators[proposer_index.get]
    privKey = hackPrivKey(proposer)
    randao_reveal =
      if skipBlsValidation notin flags:
        privKey.genRandaoReveal(
          state.fork, state.slot, state.genesis_validators_root)
      else:
        ValidatorSig()

  let
    message = makeBeaconBlock(
      state,
      parent_root,
      randao_reveal,
      eth1_data,
      graffiti,
      attestations,
      deposits)

  doAssert message.isSome(), "Should have created a valid block!"

  var
    new_block = SignedBeaconBlock(
      message: message.get()
    )


  let ok = process_block(state, new_block.message, flags, cache)

  doAssert ok, "adding block after producing it should work"
  new_block

proc makeTestBlock*(
    state: BeaconState,
    parent_root: Eth2Digest,
    eth1_data = Eth1Data(),
    attestations = newSeq[Attestation](),
    deposits = newSeq[Deposit](),
    graffiti = Eth2Digest(),
    flags: set[UpdateFlag] = {}): SignedBeaconBlock =
  # Create a block for `state.slot + 1` - like a block proposer would do!
  # It's a bit awkward - in order to produce a block for N+1, we need to
  # calculate what the state will look like after that block has been applied,
  # because the block includes the state root.
  var tmpState = state
  addTestBlock(
    tmpState, parent_root, eth1_data, attestations, deposits, graffiti, flags)

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
    sig =
      if skipBLSValidation notin flags:
        get_attestation_signature(state.fork, data, hackPrivKey(validator),
          state.genesis_validators_root)
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

    doAssert committee.len() >= 1
    # Initial attestation
    var attestation = Attestation(
      aggregation_bits: CommitteeValidatorsBits.init(committee.len),
      data: data,
      signature: get_attestation_signature(
        state.fork, data,
        hackPrivKey(state.validators[committee[0]]),
        state.genesis_validators_root)
    )
    # Aggregate the remainder
    attestation.aggregation_bits.setBit 0
    for j in 1 ..< committee.len():
      attestation.aggregation_bits.setBit j
      if skipBLSValidation notin flags:
        attestation.signature.aggregate(get_attestation_signature(
          state.fork, data,
          hackPrivKey(state.validators[committee[j]]),
          state.genesis_validators_root
        ))

    result.add attestation
