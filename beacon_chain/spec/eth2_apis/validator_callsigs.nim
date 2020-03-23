import
  options,
  ../datatypes

# https://github.com/ethereum/eth2.0-APIs/tree/master/apis/validator

type
  SyncStatus* = object
    starting_slot*: Slot
    current_slot*: Slot
    highest_slot*: Slot

  SyncingStatusResponse* = object
    is_syncing*: bool
    sync_status*: SyncStatus

  ValidatorDuty* = object
    validator_pubkey: ValidatorPubKey
    attestation_slot: Slot
    attestation_shard: uint
    block_proposal_slot: Slot

proc getNodeVersion(): string
proc getGenesisTime(): uint64
proc getSyncingStatus(): SyncingStatusResponse
proc getValidator(key: ValidatorPubKey): Validator
proc getValidatorDuties(validators: openarray[ValidatorPubKey], epoch: Epoch): seq[ValidatorDuty]
proc getBlockForSigning(slot: Slot, randaoReveal: string): BeaconBlock
proc postBlock(blk: BeaconBlock)
proc getAttestationForSigning(validatorKey: ValidatorPubKey, pocBit: int, slot: Slot, shard: uint): Attestation
proc postAttestation(attestation: Attestation)

# Optional RPCs

proc getForkId()

