import
  # Standard library
  options,
  # Local modules
  # TODO for some reason "../[datatypes, digest, crypto]" results in "Error: cannot open file"
  ../datatypes,
  ../digest,
  ../crypto

type
  AttesterDuties* = tuple
    public_key: ValidatorPubKey
    committee_index: CommitteeIndex
    committee_length: uint64
    validator_committee_index: uint64
    slot: Slot

  ValidatorPubkeySlotPair* = tuple[public_key: ValidatorPubKey, slot: Slot]

  BeaconGenesisTuple* = tuple
    genesis_time: uint64
    genesis_validators_root: Eth2Digest
    genesis_fork_version: Version

  BeaconStatesFinalityCheckpointsTuple* = tuple
    previous_justified: Checkpoint
    current_justified: Checkpoint
    finalized: Checkpoint

  BeaconStatesValidatorsTuple* = tuple
    validator: Validator
    status: string
    balance: uint64

  BeaconStatesCommitteesTuple* = tuple
    index: uint64
    slot: uint64
    validators: seq[uint64] # each object in the sequence should have an index field...

  BeaconHeadersTuple* = tuple
    root: Eth2Digest
    canonical: bool
    header: SignedBeaconBlockHeader
