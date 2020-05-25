import
  # Standard library
  options,
  # Local modules
  # TODO for some reason "../[datatypes, digest, crypto]" results in "Error: cannot open file"
  ../datatypes,
  ../digest,
  ../crypto

type
  AttesterDuties* = object
    public_key*: ValidatorPubKey
    committee_index*: CommitteeIndex
    committee_length*: uint64
    validator_committee_index*: uint64
    slot*: Slot

  # TODO do we even need this? how about a simple tuple?
  ValidatorPubkeySlotPair* = object
    public_key*: ValidatorPubKey
    slot*: Slot
