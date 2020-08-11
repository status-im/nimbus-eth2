import
  # Standard library
  options,
  # Local modules
  ../[datatypes, digest, crypto],
  json_rpc/jsonmarshal,
  callsigs_types

proc areAllKeysLoaded(): bool

proc getAllValidatorPubkeys(): seq[ValidatorPubKey]

proc signBlockProposal(pubkey: ValidatorPubKey,
                       fork: Fork,
                       genesis_validators_root: Eth2Digest,
                       slot: Slot,
                       blockRoot: Eth2Digest): ValidatorSig

proc signAttestation(pubkey: ValidatorPubKey,
                     fork: Fork,
                     genesis_validators_root: Eth2Digest,
                     attestation_data: AttestationData): ValidatorSig

proc signAggregateAndProof(pubkey: ValidatorPubKey,
                           fork: Fork,
                           genesis_validators_root: Eth2Digest,
                           aggregate_and_proof: AggregateAndProof): ValidatorSig

proc genRandaoReveal(pubkey: ValidatorPubKey,
                     fork: Fork,
                     genesis_validators_root: Eth2Digest,
                     slot: Slot): ValidatorSig

proc getSlotSig(pubkey: ValidatorPubKey,
                fork: Fork,
                genesis_validators_root: Eth2Digest,
                slot: Slot): ValidatorSig
