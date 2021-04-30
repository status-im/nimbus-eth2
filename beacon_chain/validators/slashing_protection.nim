# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # stdlib
  std/os,
  # Status
  eth/db/[kvstore, kvstore_sqlite3],
  stew/results, chronicles,
  # Internal
  ../spec/[datatypes, digest, crypto],
  ./slashing_protection_common,
  ./slashing_protection_v1,
  ./slashing_protection_v2

export slashing_protection_common

# Generic sandwich
export chronicles

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
    db_v2*: SlashingProtectionDB_v2
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

# Resource Management
# -------------------------------------------------------------

proc init*(
       T: type SlashingProtectionDB,
       genesis_validators_root: Eth2Digest,
       basePath, dbname: string,
       modes: set[SlashProtDBMode],
       disagreementBehavior: DisagreementBehavior
     ): T =
  ## Initialize or load a slashing protection DB
  ## This is for Beacon Node usage
  ## Handles DB version migration

  doAssert modes.card >= 1, "No slashing protection mode chosen. Choose a v1, a v2 or v1 and v2 slashing DB mode."
  doAssert not(
    kCompleteArchiveV2 in modes and
    kLowWatermarkV2 in modes), "Mode(s): " & $modes & ". Choose only one of V2 DB modes."

  new result
  result.modes = modes
  result.disagreementBehavior = disagreementBehavior

  let (db, requiresMigration) = SlashingProtectionDB_v2.initCompatV1(
    genesis_validators_root,
    basePath, dbname
  )
  result.db_v2 = db

  var db_v1: SlashingProtectionDB_v1

  let rawdb = kvstore result.db_v2.getRawDBHandle()
  if not rawdb.checkOrPutGenesis_DbV1(genesis_validators_root):
    fatal "The slashing database refers to another chain/mainnet/testnet",
      path = basePath/dbname,
      genesis_validators_root = genesis_validators_root
  db_v1.fromRawDB(rawdb)

  if requiresMigration:
    info "Migrating local validators slashing DB from v1 to v2"
    let spdir = try: db_v1.toSPDIR_lowWatermark()
    except IOError as exc:
      fatal "Cannot migrate v1 database", err = exc.msg
      quit 1

    let status = try: result.db_v2.inclSPDIR(spdir)
    except CatchableError as exc:
      fatal "Writing DB v2 failed", err = exc.msg
      quit 1

    case status
    of siSuccess:
      info "Slashing DB migration successful."
    of siPartial:
      warn "Slashing DB migration is a partial success."
    of siFailure:
      fatal "Slashing DB migration failure. Aborting to protect validators."
      quit 1

proc init*(
       T: type SlashingProtectionDB,
       genesis_validators_root: Eth2Digest,
       basePath, dbname: string
     ): T =
  ## Initialize or load a slashing protection DB
  ## With defaults
  ## - v2 DB only, low watermark (regular pruning)
  ##
  ## Does not handle migration
  init(
    T, genesis_validators_root, basePath, dbname,
    modes = {kLowWatermarkV2},
    disagreementBehavior = kChooseV2
  )

proc loadUnchecked*(
       T: type SlashingProtectionDB,
       basePath, dbname: string, readOnly: bool
     ): SlashingProtectionDB {.raises:[Defect, IOError].}=
  ## Load a slashing protection DB
  ## Note: This is for CLI tool usage
  ##       this doesn't check the genesis validator root
  ##
  ## Does not handle migration

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

proc checkSlashableBlockProposal*(
       db: SlashingProtectionDB,
       index: ValidatorIndex,
       validator: ValidatorPubKey,
       slot: Slot
     ): Result[void, BadProposal] =
  ## Returns an error if the specified validator
  ## already proposed a block for the specified slot.
  ## This would lead to slashing.
  ## The error contains the blockroot that was already proposed
  ##
  ## Returns success otherwise
  checkSlashableBlockProposal(db.db_v2, some(index), validator, slot)

proc checkSlashableAttestation*(
       db: SlashingProtectionDB,
       index: ValidatorIndex,
       validator: ValidatorPubKey,
       source: Epoch,
       target: Epoch
     ): Result[void, BadVote] =
  ## Returns an error if the specified validator
  ## already voted for the specified slot
  ## or would vote in a contradiction to previous votes
  ## (surrounding vote or surrounded vote).
  ##
  ## Returns success otherwise
  checkSlashableAttestation(db.db_v2, some(index), validator, source, target)

# DB Updates - only v2 supported here
# --------------------------------------------

proc registerBlock*(
       db: SlashingProtectionDB,
       index: ValidatorIndex,
       validator: ValidatorPubKey,
       slot: Slot, block_signing_root: Eth2Digest): Result[void, BadProposal] =
  ## Add a block to the slashing protection DB - the registration will
  ## fail if it would violate a slashing protection rule.
  ##
  ## block_signing_root is the output of
  ## compute_signing_root(block, domain)
  registerBlock(db.db_v2, some(index), validator, slot, block_signing_root)

proc registerAttestation*(
       db: SlashingProtectionDB,
       index: ValidatorIndex,
       validator: ValidatorPubKey,
       source, target: Epoch,
       attestation_signing_root: Eth2Digest): Result[void, BadVote] =
  ## Add an attestation to the slashing protection DB - the registration will
  ## fail if it would violate a slashing protection rule.
  ##
  ## attestation_signing_root is the output of
  ## compute_signing_root(attestation, domain)
  registerAttestation(db.db_v2, some(index), validator,
      source, target, attestation_signing_root)

# DB maintenance
# --------------------------------------------
# private for now

proc pruneBlocks*(
       db: SlashingProtectionDB,
       validator: ValidatorPubkey,
       newMinSlot: Slot) =
  ## Prune all blocks from a validator before the specified newMinSlot
  ## This is intended for interchange import to ensure
  ## that in case of a gap, we don't allow signing in that gap.
  ##
  ## Note: DB v1 does not support pruning

  # {.error: "This is a backend specific proc".}
  fatal "This is a backend specific proc"
  quit 1

proc pruneAttestations*(
       db: SlashingProtectionDB,
       validator: ValidatorPubkey,
       newMinSourceEpoch: int64,
       newMinTargetEpoch: int64) =
  ## Prune all blocks from a validator before the specified newMinSlot
  ## This is intended for interchange import to ensure
  ## that in case of a gap, we don't allow signing in that gap.
  ##
  ## Note: DB v1 does not support pruning

  # {.error: "This is a backend specific proc".}
  fatal "This is a backend specific proc"
  quit 1

proc pruneAfterFinalization*(
       db: SlashingProtectionDB,
       finalizedEpoch: Epoch
     ) =
  # TODO
  # call sqlPruneAfterFinalizationBlocks
  # and sqlPruneAfterFinalizationAttestations
  # and test that wherever pruning happens, tests still pass
  # and/or devise new tests

  # {.error: "NotImplementedError".}
  fatal "Pruning is not implemented"
  quit 1

# The high-level import/export functions are
# - importSlashingInterchange
# - exportSlashingInterchange
# in slashing_protection_types.nim
#
# That builds on a DB backend inclSPDIR and toSPDIR
# SPDIR being a common Intermediate Representation

proc inclSPDIR*(db: SlashingProtectionDB, spdir: SPDIR): SlashingImportStatus
             {.raises: [SerializationError, IOError, Defect].} =
  db.db_v2.inclSPDIR(spdir)

proc toSPDIR*(db: SlashingProtectionDB): SPDIR
             {.raises: [IOError, Defect].} =
  db.db_v2.toSPDIR()
