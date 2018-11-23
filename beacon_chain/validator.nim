import
  options,
  eth_common,
  ./datatypes, ./private/helpers

func min_empty_validator(validators: seq[ValidatorRecord], current_slot: uint64): Option[int] =
  for i, v in validators:
      if v.status == WITHDRAWN and v.exit_slot + DELETION_PERIOD.uint64 <= current_slot:
          return some(i)

func add_validator*(validators: var seq[ValidatorRecord],
                    pubkey: BLSPublicKey,
                    proof_of_possession: seq[byte],
                    withdrawal_shard: uint16,
                    withdrawal_address: EthAddress,
                    randao_commitment: Blake2_256_Digest,
                    status: ValidatorStatusCodes,
                    current_slot: uint64
                    ): int =
  # Check that validator really did register
  # let signed_message = as_bytes32(pubkey) + as_bytes2(withdrawal_shard) + withdrawal_address + randao_commitment
  # assert BLSVerify(pub=pubkey,
  #                  msg=hash(signed_message),
  #                  sig=proof_of_possession)

  # Pubkey uniqueness
  # assert pubkey not in [v.pubkey for v in validators]
  let
    rec = ValidatorRecord(
      pubkey: pubkey,
      withdrawal_shard: withdrawal_shard,
      withdrawal_address: withdrawal_address,
      randao_commitment: randao_commitment,
      randao_last_change: current_slot,
      balance: DEPOSIT_SIZE * GWEI_PER_ETH,
      status: status,
      exit_slot: 0,
      exit_seq: 0
    )

  let index = min_empty_validator(validators, current_slot)
  if index.isNone:
      validators.add(rec)
      return len(validators) - 1
  else:
      validators[index.get()] = rec
      return index.get()
