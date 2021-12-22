import ../spec/helpers

const
  MaxEpoch* = compute_epoch_at_slot(not(0'u64))

  BlockValidationError* =
    "The block failed validation, but was successfully broadcast anyway. It " &
    "was not integrated into the beacon node's database."
  BlockValidationSuccess* =
    "The block was validated successfully and has been broadcast"
  BeaconNodeInSyncError* =
    "Beacon node is currently syncing and not serving request on that endpoint"
  BlockNotFoundError* =
    "Block header/data has not been found"
  BlockProduceError* =
    "Could not produce the block"
  EmptyRequestBodyError* =
    "Empty request's body"
  InvalidBlockObjectError* =
    "Unable to decode block object(s)"
  InvalidAttestationObjectError* =
    "Unable to decode attestation object(s)"
  AttestationValidationError* =
    "Some errors happened while validating attestation(s)"
  AttestationValidationSuccess* =
    "Attestation object(s) was broadcasted"
  InvalidAttesterSlashingObjectError* =
    "Unable to decode attester slashing object(s)"
  AttesterSlashingValidationError* =
    "Invalid attester slashing, it will never pass validation so it's rejected"
  AttesterSlashingValidationSuccess* =
    "Attester slashing object was broadcasted"
  InvalidProposerSlashingObjectError* =
    "Unable to decode proposer slashing object(s)"
  ProposerSlashingValidationError* =
    "Invalid proposer slashing, it will never pass validation so it's rejected"
  ProposerSlashingValidationSuccess* =
    "Proposer slashing object was broadcasted"
  InvalidVoluntaryExitObjectError* =
    "Unable to decode voluntary exit object(s)"
  VoluntaryExitValidationError* =
    "Invalid voluntary exit, it will never pass validation so it's rejected"
  VoluntaryExitValidationSuccess* =
    "Voluntary exit object(s) was broadcasted"
  InvalidAggregateAndProofObjectError* =
    "Unable to decode aggregate and proof object(s)"
  AggregateAndProofValidationError* =
    "Invalid aggregate and proof, it will never pass validation so it's " &
    "rejected"
  AggregateAndProofValidationSuccess* =
    "Aggregate and proof object(s) was broadcasted"
  BeaconCommitteeSubscriptionSuccess* =
    "Beacon node processed committee subscription request(s)"
  SyncCommitteeSubscriptionSuccess* =
    "Beacon node processed sync committee subscription request(s)"
  InvalidParentRootValueError* =
    "Invalid parent root value"
  MissingSlotValueError* =
    "Missing `slot` value"
  InvalidSlotValueError* =
    "Invalid slot value"
  MissingCommitteeIndexValueError* =
    "Missing `committee_index` value"
  InvalidCommitteeIndexValueError* =
    "Invalid committee index value"
  MissingAttestationDataRootValueError* =
    "Missing `attestation_data_root` value"
  InvalidAttestationDataRootValueError* =
    "Invalid attestation data root value"
  UnableToGetAggregatedAttestationError* =
    "Unable to retrieve an aggregated attestation"
  MissingRandaoRevealValue* =
    "Missing `randao_reveal` value"
  InvalidRandaoRevealValue* =
    "Invalid randao reveal value"
  InvalidGraffitiBytesValye* =
    "Invalid graffiti bytes value"
  InvalidEpochValueError* =
    "Invalid epoch value"
  EpochFromFutureError* =
    "Epoch value is far from the future"
  InvalidStateIdValueError* =
    "Invalid state identifier value"
  InvalidBlockIdValueError* =
    "Invalid block identifier value"
  InvalidValidatorIdValueError* =
    "Invalid validator's identifier value(s)"
  MaximumNumberOfValidatorIdsError* =
    "Maximum number of validator identifier values exceeded"
  InvalidValidatorStatusValueError* =
    "Invalid validator's status value error"
  InvalidValidatorIndexValueError* =
    "Invalid validator's index value(s)"
  EmptyValidatorIndexArrayError* =
    "Empty validator's index array"
  InvalidSubscriptionRequestValueError* =
    "Invalid subscription request object(s)"
  ValidatorNotFoundError* =
    "Could not find validator"
  ValidatorStatusNotFoundError* =
    "Could not obtain validator's status"
  TooHighValidatorIndexValueError* =
    "Validator index exceeds maximum number of validators allowed"
  UnsupportedValidatorIndexValueError* =
    "Validator index exceeds maximum supported number of validators"
  StateNotFoundError* =
    "Could not get requested state"
  SlotNotFoundError* =
    "Slot number is too far away"
  SlotNotInNextWallSlotEpochError* =
    "Requested slot not in next wall-slot epoch"
  SlotFromThePastError* =
    "Requested slot from the past"
  SlotFromTheIncorrectForkError* =
    "Requested slot is from incorrect fork"
  EpochFromTheIncorrectForkError* =
    "Requested epoch is from incorrect fork"
  ProposerNotFoundError* =
    "Could not find proposer for the head and slot"
  NoHeadForSlotError* =
    "Cound not find head for slot"
  EpochOverflowValueError* =
    "Requesting epoch for which slot would overflow"
  InvalidPeerStateValueError* =
    "Invalid peer's state value(s) error"
  InvalidPeerDirectionValueError* =
    "Invalid peer's direction value(s) error"
  InvalidPeerIdValueError* =
    "Invalid peer's id value(s) error"
  PeerNotFoundError* =
    "Peer not found"
  InvalidLogLevelValueError* =
    "Invalid log level value error"
  ContentNotAcceptableError* =
    "Could not find out accepted content type"
  InvalidAcceptError* =
    "Incorrect accept response type"
  MissingSubCommitteeIndexValueError* =
    "Missing `subcommittee_index` value"
  InvalidSubCommitteeIndexValueError* =
    "Invalid `subcommittee_index` value"
  MissingBeaconBlockRootValueError* =
    "Missing `beacon_block_root` value"
  InvalidBeaconBlockRootValueError* =
    "Invalid `beacon_block_root` value"
  EpochOutsideSyncCommitteePeriodError* =
    "Epoch is outside the sync committee period of the state"
  InvalidSyncCommitteeSignatureMessageError* =
    "Unable to decode sync committee message(s)"
  InvalidSyncCommitteeSubscriptionRequestError* =
    "Unable to decode sync committee subscription request(s)"
  InvalidContributionAndProofMessageError* =
    "Unable to decode contribute and proof message(s)"
  SyncCommitteeMessageValidationError* =
    "Some errors happened while validating sync committee message(s)"
  SyncCommitteeMessageValidationSuccess* =
    "Sync committee message(s) was broadcasted"
  ContributionAndProofValidationError* =
    "Some errors happened while validating contribution and proof(s)"
  ContributionAndProofValidationSuccess* =
    "Contribution and proof(s) was broadcasted"
  ProduceContributionError* =
    "Unable to produce contribution using the passed parameters"
  InternalServerError* =
    "Internal server error"
  NoImplementationError* =
    "Not implemented yet"
  KeystoreAdditionFailure* =
    "Could not add some keystores"
  InvalidKeystoreObjects* =
    "Invalid keystore objects found"
  KeystoreAdditionSuccess* =
    "All keystores has been added"
  KeystoreModificationFailure* =
    "Could not change keystore(s) state"
  KeystoreModificationSuccess* =
    "Keystore(s) state was successfully modified"
  KeystoreRemovalSuccess* =
    "Keystore(s) was successfully removed"
  KeystoreRemovalFailure* =
    "Could not remove keystore(s)"
  InvalidValidatorPublicKey* =
    "Invalid validator's public key(s) found"
  BadRequestFormatError* =
    "Bad request format"
  InvalidAuthorization* =
    "Invalid Authorization Header"
