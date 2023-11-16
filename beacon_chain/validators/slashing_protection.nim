# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  # stdlib
  std/[os, algorithm, sequtils],
  # Status
  eth/db/[kvstore, kvstore_sqlite3],
  stew/[results, byteutils],
  chronicles, chronicles/timings,
  # Internal
  ../spec/datatypes/base,
  ./slashing_protection_common,
  ./slashing_protection_v2

export slashing_protection_common, kvstore, kvstore_sqlite3

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
    kCompleteArchive # Complete Format V2 backend (saves all attestations)
    kLowWatermark    # Low-Watermark Format V2 backend (prunes attestations)

  SlashingProtectionDB* = ref object
    ## Database storing the blocks attested
    ## by validators attached to a beacon node
    ## or validator client.
    db_v2*: SlashingProtectionDB_v2
    modes: set[SlashProtDBMode]

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
       modes: set[SlashProtDBMode]
    ): T =
  ## Initialize or load a slashing protection DB
  ## This is for Beacon Node usage
  ## Handles DB version migration

  doAssert modes.card >= 1, "No slashing protection mode chosen. Choose a v1, a v2 or v1 and v2 slashing DB mode."
  doAssert not(
    kCompleteArchive in modes and
    kLowWatermark in modes), "Mode(s): " & $modes & ". Choose only one of V2 DB modes."

  new result
  result.modes = modes

  let (db, requiresMigration) = SlashingProtectionDB_v2.initCompatV1(
    genesis_validators_root,
    basePath, dbname
  )
  result.db_v2 = db

  if requiresMigration:
    fatal "The slashing database predates Altair hardfork from October 2021." &
      " You can migrate to the new DB format using Nimbus 1.6.0" &
      " for a few minutes at https://github.com/status-im/nimbus-eth2/releases/tag/v1.6.0" &
      " until the messages \"Migrating local validators slashing DB from v1 to v2\"" &
      " and \"Slashing DB migration successful.\""

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
    modes = {kLowWatermark}
  )

proc loadUnchecked*(
       T: type SlashingProtectionDB,
       basePath, dbname: string, readOnly: bool
     ): SlashingProtectionDB {.raises:[IOError].}=
  ## Load a slashing protection DB
  ## Note: This is for CLI tool usage
  ##       this doesn't check the genesis validator root
  ##
  ## Does not handle migration
  new result

  result.modes = {}
  try:
    result.db_v2 = SlashingProtectionDB_v2.loadUnchecked(
      basePath, dbname, readOnly
    )
    result.modes.incl(kCompleteArchive)
  except CatchableError as err:
    error "Failed to load the Slashing protection database", err = err.msg
    quit 1

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
  checkSlashableBlockProposal(db.db_v2, Opt.some(index), validator, slot)

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
  checkSlashableAttestation(db.db_v2, Opt.some(index), validator, source, target)

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
  registerBlock(db.db_v2, Opt.some(index), validator, slot, block_signing_root)

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
  registerAttestation(db.db_v2, Opt.some(index), validator,
      source, target, attestation_signing_root)

template withContext*(db: SlashingProtectionDB, body: untyped): untyped =
  ## Perform multiple slashing database operations within a single database
  ## context
  db.db_v2.withContext:
    template registerAttestationInContext(
      index: ValidatorIndex,
        validator: ValidatorPubKey,
        source, target: Epoch,
        attestation_signing_root: Eth2Digest): Result[void, BadVote] =
      registerAttestationInContextV2(Opt.some(index), validator, source, target, attestation_signing_root)
    block:
      body

# DB maintenance
# --------------------------------------------
# private for now

proc pruneBlocks*(
       db: SlashingProtectionDB,
       validator: ValidatorPubKey,
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
       validator: ValidatorPubKey,
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
  ## Prune blocks and attestations after a specified `finalizedEpoch`
  ## The block with the highest slot
  ## and the attestation(s) with the highest source and target epochs
  ## are never pruned.
  ##
  ## This ensures that even if pruning is called with an incorrect epoch
  ## slashing protection can fallback to the minimal / high-watermark protection mode.
  ##
  ## Pruning is only done if pruning is enabled (DB in kLowWatermark mode)
  ## Pruning is only triggered on v2 database.

  if kLowWatermark in db.modes:
    debug.logTime "Pruning slashing DB":
      db.db_v2.pruneAfterFinalization(finalizedEpoch)

# Interchange
# --------------------------------------------

# The high-level import/export functions are
# - importSlashingInterchange
# - exportSlashingInterchange
# in slashing_protection_types.nim
#
# That builds on a DB backend inclSPDIR and toSPDIR
# SPDIR being a common Intermediate Representation

proc registerSyntheticAttestation*(db: SlashingProtectionDB,
       validator: ValidatorPubKey,
       source, target: Epoch) =
  db.db_v2.registerSyntheticAttestation(validator, source, target)

proc inclSPDIR*(db: SlashingProtectionDB, spdir: SPDIR): SlashingImportStatus
             {.raises: [SerializationError, IOError].} =
  db.db_v2.inclSPDIR(spdir)

proc toSPDIR*(db: SlashingProtectionDB): SPDIR
             {.raises: [IOError].} =
  db.db_v2.toSPDIR()

proc exportSlashingInterchange*(
       db: SlashingProtectionDB,
       path: string,
       validatorsWhiteList: seq[PubKey0x] = @[],
       prettify = true) {.raises: [IOError].} =
  ## Export a database to the Slashing Protection Database Interchange Format
  # We could modify toSPDIR to do the filtering directly
  # but this is not a performance sensitive operation.
  # so it's better to keep it simple.
  var spdir = db.toSPDIR()

  if validatorsWhiteList.len > 0:
    # O(a log b) with b the number of validators to keep
    #        and a the total number of validators in DB
    let validators = validatorsWhiteList.sorted()
    spdir.data.keepItIf(validators.binarySearch(it.pubkey) != -1)

    if spdir.data.len != validatorsWhiteList.len:
      let exportedKeys = spdir.data.mapIt(it.pubkey).sorted()
      for v in validators:
        if exportedKeys.binarySearch(v) == -1:
          warn "Specified validator key not found in the slashing database",
                key = v.PubKeyBytes.toHex

  Json.saveFile(path, spdir, prettify)
  echo "Exported slashing protection DB to '", path, "'"
