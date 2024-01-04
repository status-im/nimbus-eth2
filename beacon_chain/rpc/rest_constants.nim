# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  ../spec/beacon_time

export beacon_time

const
  MaxEpoch* = epoch(FAR_FUTURE_SLOT)

  BlockValidationError* =
    "The block failed validation, but was successfully broadcast anyway. It " &
    "was not integrated into the beacon node's database."
  BlockValidationSuccess* =
    "The block was validated successfully and has been broadcast"
  BeaconNodeInSyncError* =
    "Beacon node is currently syncing and not serving request on that endpoint"
  BlockNotFoundError* =
    "Block header/data has not been found"
  EmptyRequestBodyError* =
    "Empty request body"
  InvalidRequestBodyError* =
    "Invalid request body"
  InvalidBlockObjectError* =
    "Unable to decode block object(s)"
  InvalidAttestationObjectError* =
    "Unable to decode attestation object(s)"
  AttestationValidationError* =
    "Some errors happened while validating attestation(s)"
  AttestationValidationSuccess* =
    "Attestation object(s) was broadcast"
  InvalidAttesterSlashingObjectError* =
    "Unable to decode attester slashing object(s)"
  AttesterSlashingValidationError* =
    "Invalid attester slashing, it will never pass validation so it's rejected"
  AttesterSlashingValidationSuccess* =
    "Attester slashing object was broadcast"
  InvalidProposerSlashingObjectError* =
    "Unable to decode proposer slashing object(s)"
  ProposerSlashingValidationError* =
    "Invalid proposer slashing, it will never pass validation so it's rejected"
  ProposerSlashingValidationSuccess* =
    "Proposer slashing object was broadcast"
  InvalidVoluntaryExitObjectError* =
    "Unable to decode voluntary exit object(s)"
  InvalidFeeRecipientRequestError* =
    "Bad request. Request was malformed and could not be processed"
  InvalidGasLimitRequestError* =
    "Bad request. Request was malformed and could not be processed"
  VoluntaryExitValidationError* =
    "Invalid voluntary exit, it will never pass validation so it's rejected"
  VoluntaryExitValidationSuccess* =
    "Voluntary exit object(s) was broadcast"
  InvalidAggregateAndProofObjectError* =
    "Unable to decode aggregate and proof object(s)"
  AggregateAndProofValidationError* =
    "Invalid aggregate and proof, it will never pass validation so it's " &
    "rejected"
  AggregateAndProofValidationSuccess* =
    "Aggregate and proof object(s) was broadcast"
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
  InvalidSkipRandaoVerificationValue* =
    "Invalid skip_randao_verification value"
  InvalidGraffitiBytesValue* =
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
    "Invalid validator identifier value(s)"
  NonUniqueValidatorIdError* =
    "Non-unique validator identifier value(s)"
  MaximumNumberOfValidatorIdsError* =
    "Maximum number of validator identifier values exceeded"
  InvalidValidatorStatusValueError* =
    "Invalid validator's status value error"
  InvalidValidatorIndexValueError* =
    "Invalid validator's index value(s)"
  EmptyValidatorIndexArrayError* =
    "Empty validator's index array"
  DuplicateValidatorIndexArrayError* =
    "Duplicate validator index found in array"
  InvalidSubscriptionRequestValueError* =
    "Invalid subscription request object(s)"
  ValidatorNotFoundError* =
    "Could not find validator"
  ValidatorIndexMissingError* =
    "Validator missing index value"
  ValidatorStatusNotFoundError* =
    "Could not obtain validator's status"
  TooHighValidatorIndexValueError* =
    "Validator index exceeds maximum number of validators allowed"
  UnsupportedValidatorIndexValueError* =
    "Validator index exceeds maximum supported number of validators"
  StateNotFoundError* =
    "Could not get requested state"
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
    "Accepted media type not supported"
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
  InvalidSyncCommitteeSignatureMessageError* =
    "Unable to decode sync committee message(s)"
  InvalidSyncCommitteeSubscriptionRequestError* =
    "Unable to decode sync committee subscription request(s)"
  InvalidContributionAndProofMessageError* =
    "Unable to decode contribute and proof message(s)"
  InvalidPrepareBeaconProposerError* =
    "Unable to decode prepare beacon proposer request"
  SyncCommitteeMessageValidationError* =
    "Some errors happened while validating sync committee message(s)"
  SyncCommitteeMessageValidationSuccess* =
    "Sync committee message(s) was broadcast"
  ContributionAndProofValidationError* =
    "Some errors happened while validating contribution and proof(s)"
  ContributionAndProofValidationSuccess* =
    "Contribution and proof(s) was broadcast"
  ProduceContributionError* =
    "Unable to produce contribution using the passed parameters"
  InternalServerError* =
    "Internal server error"
  NoFinalizedSnapshotAvailableError* =
    "No Finalized Snapshot Available"
  NoImplementationError* =
    "Not implemented yet"
  InvalidKeystoreObjects* =
    "Invalid keystore objects found"
  InvalidValidatorPublicKey* =
    "Invalid validator's public key(s) found"
  InvalidAuthorizationError* =
    "Invalid Authorization Header"
  PrunedStateError* =
    "Trying to access a pruned historical state"
  InvalidBlockRootValueError* =
    "Invalid block root value"
  InvalidSyncPeriodError* =
    "Invalid sync committee period requested"
  InvalidCountError* =
    "Invalid count requested"
  MissingStartPeriodValueError* =
    "Missing `start_period` value"
  MissingCountValueError* =
    "Missing `count` value"
  LCBootstrapUnavailable* =
    "LC bootstrap unavailable"
  LCFinUpdateUnavailable* =
    "LC finality update unavailable"
  LCOptUpdateUnavailable* =
    "LC optimistic update unavailable"
  DeprecatedRemovalBeaconBlocksDebugStateV1* =
    "v1/beacon/blocks/{block_id} and v1/debug/beacon/states/{state_id} " &
      "endpoints were deprecated and replaced by v2: " &
      "https://github.com/ethereum/beacon-APIs/pull/218"
  DeprecatedRemovalValidatorBlocksV1* =
    "v1/validator/blocks/{slot} endpoint was deprecated and replaced by v2: " &
      "https://github.com/ethereum/beacon-APIs/pull/220"
  DeprecatedRemovalGetDebugChainHeadsV1* =
    "v1/debug/beacon/heads endpoint was deprecated and replaced by v2: " &
      "https://github.com/ethereum/beacon-APIs/pull/319"
  BlockIncorrectFork* =
    "Block has incorrect fork"
  ValidatorNotActive* =
    "Validator inactive"
  BlobsOutOfRange* =
    "Requested slot is outside of blobs window"
  InvalidBlsToExecutionChangeObjectError* =
    "Unable to decode BLS to execution change object(s)"
  BlsToExecutionChangeValidationError* =
    "Invalid BLS to execution change; it won't validate, so it's rejected"
  BlsToExecutionChangeValidationSuccess* =
    "BLS to execution change was broadcast"
  AggregationSelectionNotImplemented* =
    "Attestation and sync committee aggreggation selection are not implemented"
  MissingMerkleProofError* =
    "Required Merkle proof is missing"
  InvalidMerkleProofError* =
    "The given Merkle proof is invalid"
  InvalidMerkleProofIndexError* =
    "The given Merkle proof index is invalid"
  FailedToObtainForkError* =
    "Failed to obtain fork information"
  InvalidTimestampValue* =
    "Invalid or missing timestamp value"
  InvalidSidecarIndexValueError* =
    "Invalid blob index"
  InvalidBroadcastValidationType* =
    "Invalid broadcast_validation type value"
