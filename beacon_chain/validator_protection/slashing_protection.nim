# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Status
  eth/db/[kvstore, kvstore_sqlite3],
  stew/results, chronicles,
  # Internal
  ../spec/[datatypes, digest, crypto],
  ./slashing_protection_types,
  ./slashing_protection_v1,
  ./slashing_protection_v2

export slashing_protection_types

# The high-level slashing protection DB
# -------------------------------------
# This file abstracts differences and
# migration between slashing protection implementations
# and DB schemas
#
# This is done by instantiating
# multiple slashing DB versions using the same handle.
#
# We assume that in case of backward compatible changes
# The new version will use different tables.
#
# During transition period, we allow using multiple
# slashing protection implementations to validate
# the behavior of the new implementation.
#
# Note: this will increase disk IO.

type
  SlashProtDBMode* = enum
    kCompleteArchiveV1 # Complete Format V1 backend (saves all attestations)
    kCompleteArchiveV2 # Complete Format V2 backend (saves all attestations)
    kLowWatermarkV2    # Low-Watermark Format V2 backend (prunes attestations)

  SlashingProtectionDB* = ref object
    ## Database storing the blocks attested
    ## by validators attached to a beacon node
    ## or validator client.
    db_v1: SlashingProtectionDB_v1
    db_v2: SlashingProtectionDB_v2
    modes: set[SlashProtDBMode]
    disagreementBehavior: DisagreementBehavior

  DisagreementBehavior* = enum
    ## How to handle disagreement between DB versions
    kCrash
    kChooseV1
    kChooseV2

# DB Multiversioning
# -------------------------------------------------------------

func version*(_: type SlashingProtectionDB): static int =
  # The highest DB version supported
  2

# DB Migration
# -------------------------------------------------------------

# Resource Management
# -------------------------------------------------------------

proc init*(
       T: type SlashingProtectionDB,
       genesis_validator_root: Eth2Digest,
       basePath, dbname: string,
       mode: SlashProtDBMode,
       disagreementBehavior: DisagreementBehavior
     ): T =
  ## Initialize or load a slashing protection DB
  ## This is for Beacon Node usage

  doAssert mode.card >= 1, "No slashing protection mode chosen. Choose a v1, a v2 or v1 and v2 slashing DB mode."
  doAssert not(
    kCompleteArchiveV2 in mode and
    kLowWatermarkV2 in mode), "Mode(s): " & $mode & ". Choose only one of V2 DB modes."

  result.mode = mode
  result.disagreementBehavior = disagreementBehavior

  result.db_v2 = SlashingProtectionDB_v2.initCompatV1(
    genesis_validator_root,
    basePath, dbname
  )

  result.db_v1.fromRawDB(kvstore result.db_v2.getRawDBHandle())

proc loadUnchecked*(
       T: type SlashingProtectionDB,
       basePath, dbname: string, readOnly: bool
     ): SlashingProtectionDB {.raises:[Defect, IOError].}=
  ## Load a slashing protection DB
  ## Note: This is for CLI tool usage
  ##       this doesn't check the genesis validator root

  result.modes = {kCompleteArchiveV1, kCompleteArchiveV2}
  result.disagreementBehavior = kCrash

  result.db_v2 = SlashingProtectionDB_v2.loadUnchecked(
    basePath, dbname, readOnly
  )

  result.db_v1.fromRawDB(kvstore result.db_v2.getRawDBHandle())

proc close*(db: SlashingProtectionDB) =
  ## Close a slashing protection database
  db.db_v2.close()
  # v1 and v2 are ref objects and use the same DB handle
  # so closing one closes both

# DB Queries
# --------------------------------------------

proc useV1(db: SlashingProtectionDB): bool =
  kCompleteArchiveV1 in db.modes

proc useV2(db: SlashingProtectionDB): bool =
  kCompleteArchiveV2 in db.modes or
    kLowWatermarkV2 in db.modes

template queryVersions(
          db: SlashingProtectionDB,
          query: untyped
         ): auto =
  ## Query multiple DB versions
  ## Query should be in the form
  ## myQuery(db_version, args...)
  ##
  ## Resolve conflicts according to
  ## `db.disagreementBehavior`
  ##
  ## For example
  ## checkSlashableBlockProposal(db_version, validator, slot)
  ##
  ## db_version will be replaced by db_v1 and db_v2 accordingly
  type T = typeof(block:
    template db_version: untyped = db.db_v1
    query
  )

  var res1, res2: T
  let useV1 = db.useV1()
  let useV2 = db.useV2()

  if useV1:
    template db_version: untyped = db.db_v1
    res1 = query
  if useV2:
    template db_version: untyped = db.db_v2
    res2 = query

  if useV1 and useV2:
    if res1 == res2:
      res1
    else:
      const queryStr = astToStr(query)
      case db.disagreementBehavior
      of kCrash:
        # fatal "Slashing protection DB has an internal error",
        #   query = queryStr,
        #   dbV1_result = res1,
        #   dbV2_result = res2
        doAssert false, "Slashing DB internal error"
        res1 # For proper type deduction
      of kChooseV1:
        # error "Slashing protection DB has an internal error, using v1 result",
        #   query = queryStr,
        #   dbV1_result = res1,
        #   dbV2_result = res2
        res1
      of kChooseV2:
        # error "Slashing protection DB has an internal error, using v2 result",
        #   query = queryStr,
        #   dbV1_result = res1,
        #   dbV2_result = res2
        res2
  elif useV1:
    res1
  else:
    res2

proc checkSlashableBlockProposal*(
       db: SlashingProtectionDB,
       validator: ValidatorPubKey,
       slot: Slot
     ): Result[void, Eth2Digest] =
  ## Returns an error if the specified validator
  ## already proposed a block for the specified slot.
  ## This would lead to slashing.
  ## The error contains the blockroot that was already proposed
  ##
  ## Returns success otherwise
  db.queryVersions(
    checkSlashableBlockProposal(db_version, validator, slot)
  )

proc checkSlashableAttestation*(
       db: SlashingProtectionDB,
       validator: ValidatorPubKey,
       source: Epoch,
       target: Epoch
     ): Result[void, BadVote] =
  ## Returns an error if the specified validator
  ## already proposed a block for the specified slot.
  ## This would lead to slashing.
  ## The error contains the blockroot that was already proposed
  ##
  ## Returns success otherwise
  db.queryVersions(
    checkSlashableAttestation(db_version, validator, source, target)
  )

# DB Updates
# --------------------------------------------

template updateVersions(
          db: SlashingProtectionDB,
          query: untyped
         ) =
  ## Update multiple DB versions
  ## Query should be in the form
  ## myQuery(db_version, args...)
  ##
  ## Resolve conflicts according to
  ## `db.disagreementBehavior`
  ##
  ## For example
  ## registerBlock(db_version, validator, slot, block_root)
  ##
  ## db_version will be replaced by db_v1 and db_v2 accordingly
  if db.useV1():
    template db_version: untyped = db.db_v1
    query
  if db.useV2():
    template db_version: untyped = db.db_v2
    query

proc registerBlock*(
       db: SlashingProtectionDB_v2,
       validator: ValidatorPubKey,
       slot: Slot, block_signing_root: Eth2Digest) =
  ## Add a block to the slashing protection DB
  ## `checkSlashableBlockProposal` MUST be run
  ## before to ensure no overwrite.
  ##
  ## block_signing_root is the output of
  ## compute_signing_root(block, domain)
  updateVersions(
    registerBlock(db_version, validator, slot, block_signing_root)
  )

proc registerAttestation*(
       db: SlashingProtectionDB_v2,
       validator: ValidatorPubKey,
       source, target: Epoch,
       attestation_signing_root: Eth2Digest) =
  ## Add an attestation to the slashing protection DB
  ## `checkSlashableAttestation` MUST be run
  ## before to ensure no overwrite.
  ##
  ## attestation_signing_root is the output of
  ## compute_signing_root(attestation, domain)
  updateVersions(
    registerAttestation(db_version, validator,
      source, target, attestation_signing_root)
  )

# DB maintenance
# --------------------------------------------
# TODO: pruning

# Interchange
# --------------------------------------------
