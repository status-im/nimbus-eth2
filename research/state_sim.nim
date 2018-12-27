import
  cligen,
  json, strformat,
  options, sequtils, random,
  milagro_crypto,
  ../tests/[testutil],
  ../beacon_chain/spec/[beaconstate, crypto, datatypes, digest, helpers],
  ../beacon_chain/[extras, ssz, state_transition]

proc `%`(v: uint64): JsonNode = newJInt(v.BiggestInt)
proc `%`(v: Eth2Digest): JsonNode = newJString($v)
proc `%`(v: ValidatorSig|ValidatorPubKey): JsonNode = newJString($v)

proc writeJson*(prefix, slot, v: auto) =
  var f: File
  defer: close(f)
  discard open(f, fmt"{prefix:04}-{slot:08}.json", fmWrite)
  write(f, pretty(%*(v)))

proc combine(tgt: var Attestation, src: Attestation, flags: UpdateFlags) =
  # Combine the signature and participation bitfield, with the assumption that
  # the same data is being signed!
  # TODO similar code in work_pool, clean up

  assert tgt.data == src.data

  for i in 0..<len(tgt.participation_bitfield):
    tgt.participation_bitfield[i] =
      tgt.participation_bitfield[i] or
      src.participation_bitfield[i]

  if skipValidation notin flags:
    tgt.aggregate_signature.combine(src.aggregate_signature)

proc transition(
    slots = 1945,
    validators = EPOCH_LENGTH, # One per shard is minimum
    json_interval = EPOCH_LENGTH,
    prefix = 0,
    attesterRatio = 0.0,
    validate = false) =
  let
    flags = if validate: {} else: {skipValidation}
    genesisState = get_initial_beacon_state(
      makeInitialDeposits(validators, flags), 0, Eth2Digest(), flags)
    genesisBlock = makeGenesisBlock(genesisState)

  var
    attestations: array[MIN_ATTESTATION_INCLUSION_DELAY, seq[Attestation]]
    state = genesisState
    latest_block_root = hash_tree_root_final(genesisBlock)

  var r: Rand
  for i in 0..<slots:
    if state.slot mod json_interval.uint64 == 0:
      writeJson(prefix, state.slot, state)
      write(stdout, ":")
    else:
      write(stdout, ".")

    let
      attestations_idx = state.slot mod MIN_ATTESTATION_INCLUSION_DELAY
      body =  BeaconBlockBody(attestations: attestations[attestations_idx])

    attestations[attestations_idx] = @[]

    latest_block_root = hash_tree_root_final(
      addBlock(state, latest_block_root, body, flags))

    if attesterRatio > 0.0:
      # attesterRatio is the fraction of attesters that actually do their
      # work for every slot - we'll randimize it deterministically to give
      # some variation
      let scass = get_shard_committees_at_slot(state, state.slot)

      for scas in scass:
        var
          attestation: Attestation
          first = true

        for v in scas.committee:
          if (rand(r, high(int)).float * attesterRatio).int <= high(int):
            if first:
              attestation = makeAttestation(state, latest_block_root, v)
              first = false
            else:
              attestation.combine(
                makeAttestation(state, latest_block_root, v), flags)

        if not first:
          # add the attestation if any of the validators attested, as given
          # by the randomness. We have to delay when the attestation is
          # actually added to the block per the attestation delay rule!
          attestations[
            (state.slot + MIN_ATTESTATION_INCLUSION_DELAY - 1) mod
              MIN_ATTESTATION_INCLUSION_DELAY].add attestation

    flushFile(stdout)

  echo "done!"

dispatch(
  transition,
  help = { "attesterRatio": "ratio of validators that attest in each round" }
)
