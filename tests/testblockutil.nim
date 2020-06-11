# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  options, stew/endians2,
  chronicles, eth/trie/[db],
  ../beacon_chain/[beacon_chain_db, block_pool, extras, merkle_minimal,
  ../beacon_chain/ssz/merkleization,
    state_transition, validator_pool],
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

func hackPrivKey*(v: Validator): ValidatorPrivKey =
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
    pubkey = privkey.toPubKey()
    withdrawal_credentials = makeFakeHash(i)
    domain = compute_domain(DOMAIN_DEPOSIT, Version(GENESIS_FORK_VERSION))

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

proc makeInitialDeposits*(
    n = SLOTS_PER_EPOCH, flags: UpdateFlags = {}): seq[Deposit] =
  for i in 0..<n.int:
    result.add makeDeposit(i, flags)

  # This needs to be done as a batch, since the Merkle proof of the i'th
  # deposit depends on the deposit (data) of the 0th through (i-1)st, of
  # deposits. Computing partial hash_tree_root sequences of DepositData,
  # and ideally (but not yet) efficiently only once calculating a Merkle
  # tree utilizing as much of the shared substructure as feasible, means
  # attaching proofs all together, as a separate step.
  if skipMerkleValidation notin flags:
    attachMerkleProofs(result)

func signBlock*(
    fork: Fork, genesis_validators_root: Eth2Digest, blck: BeaconBlock,
    privKey: ValidatorPrivKey, flags: UpdateFlags = {}): SignedBeaconBlock =
  SignedBeaconBlock(
    message: blck,
    signature:
      if skipBlsValidation notin flags:
        get_block_signature(
          fork, genesis_validators_root, blck.slot,
          hash_tree_root(blck), privKey)
      else:
        ValidatorSig()
  )

proc addTestBlock*(
    state: var HashedBeaconState,
    parent_root: Eth2Digest,
    cache: var StateCache,
    eth1_data = Eth1Data(),
    attestations = newSeq[Attestation](),
    deposits = newSeq[Deposit](),
    graffiti = Eth2Digest(),
    flags: set[UpdateFlag] = {}): SignedBeaconBlock =
  # Create and add a block to state - state will advance by one slot!
  advance_slot(state, err(Opt[Eth2Digest]), flags, cache)

  let
    proposer_index = get_beacon_proposer_index(state.data, cache)
    privKey = hackPrivKey(state.data.validators[proposer_index.get])
    randao_reveal =
      if skipBlsValidation notin flags:
        privKey.genRandaoReveal(
          state.data.fork, state.data.genesis_validators_root, state.data.slot)
      else:
        ValidatorSig()

  let
    message = makeBeaconBlock(
      state,
      proposer_index.get(),
      parent_root,
      randao_reveal,
      # Keep deposit counts internally consistent.
      Eth1Data(
        deposit_root: eth1_data.deposit_root,
        deposit_count: state.data.eth1_deposit_index + deposits.len.uint64,
        block_hash: eth1_data.block_hash),
      graffiti,
      attestations,
      deposits,
      noRollback,
      cache)

  doAssert message.isSome(), "Should have created a valid block!"

  let
    new_block = signBlock(
      state.data.fork,
      state.data.genesis_validators_root, message.get(), privKey, flags)

  new_block

proc makeTestBlock*(
    state: HashedBeaconState,
    parent_root: Eth2Digest,
    cache: var StateCache,
    eth1_data = Eth1Data(),
    attestations = newSeq[Attestation](),
    deposits = newSeq[Deposit](),
    graffiti = Eth2Digest(),
    flags: set[UpdateFlag] = {}): SignedBeaconBlock =
  # Create a block for `state.slot + 1` - like a block proposer would do!
  # It's a bit awkward - in order to produce a block for N+1, we need to
  # calculate what the state will look like after that block has been applied,
  # because the block includes the state root.
  var tmpState = newClone(state)
  addTestBlock(
    tmpState[], parent_root, cache, eth1_data, attestations, deposits,
    graffiti, flags)

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
        get_attestation_signature(state.fork, state.genesis_validators_root,
          data, hackPrivKey(validator))
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
      committee = get_beacon_committee(state, slot, index.CommitteeIndex, cache)
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
      committee = get_beacon_committee(
        state, slot, index.CommitteeIndex, cache)
      data = makeAttestationData(state, slot, index, beacon_block_root)

    doAssert committee.len() >= 1
    # Initial attestation
    var attestation = Attestation(
      aggregation_bits: CommitteeValidatorsBits.init(committee.len),
      data: data,
      signature: get_attestation_signature(
        state.fork, state.genesis_validators_root, data,
        hackPrivKey(state.validators[committee[0]]))
    )
    # Aggregate the remainder
    attestation.aggregation_bits.setBit 0
    for j in 1 ..< committee.len():
      attestation.aggregation_bits.setBit j
      if skipBLSValidation notin flags:
        attestation.signature.aggregate(get_attestation_signature(
          state.fork, state.genesis_validators_root, data,
          hackPrivKey(state.validators[committee[j]])
        ))

    result.add attestation
