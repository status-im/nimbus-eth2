# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  std/[tables, os, options, strutils, typetraits],
  # Status
  stew/byteutils,
  eth/db/[kvstore, kvstore_sqlite3],
  chronicles,
  nimcrypto/hash,
  serialization,
  json_serialization,
  sqlite3_abi,
  # Internal
  ./spec/[datatypes, digest, crypto],
  ./ssz

# Requirements
# --------------------------------------------
#
# Overview of slashing and how it ties in with the rest of Eth2.0
#
# EIP 3076:
# https://eips.ethereum.org/EIPS/eip-3076
# https://ethereum-magicians.org/t/eip-3076-validator-client-interchange-format-slashing-protection/
#
# Phase 0 for humans - Validator responsibilities:
# - https://notes.ethereum.org/@djrtwo/Bkn3zpwxB#Validator-responsibilities
#
# Phase 0 spec - Honest Validator - how to avoid slashing
# - https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/validator.md#how-to-avoid-slashing
#
# In-depth reading on slashing conditions
#
# - Detecting slashing conditions https://hackmd.io/@n0ble/By897a5sH
# - Open issue on writing a slashing detector https://github.com/ethereum/eth2.0-pm/issues/63
# - Casper the Friendly Finality Gadget, Vitalik Buterin and Virgil Griffith
#   https://arxiv.org/pdf/1710.09437.pdf
#   Figure 2
#   An individual validator ν MUST NOT publish two distinct votes,
#   〈ν,s1,t1,h(s1),h(t1) AND〈ν,s2,t2,h(s2),h(t2)〉,
#   such that either:
#   I. h(t1) = h(t2).
#      Equivalently, a validator MUST NOT publish two distinct votes for the same target height.
#   OR
#   II. h(s1) < h(s2) < h(t2) < h(t1).
#      Equivalently, a validator MUST NOT vote within the span of its other votes.
# - Vitalik's annotated spec: https://github.com/ethereum/annotated-spec/blob/d8c51af84f9f309d91c37379c1fcb0810bc5f10a/phase0/beacon-chain.md#proposerslashing
#   1. A proposer can get slashed for signing two distinct headers at the same slot.
#   2. An attester can get slashed for signing
#      two attestations that together violate
#      the Casper FFG slashing conditions.
# - https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/validator.md#ffg-vote
#   The "source" is the current_justified_epoch
#   The "target" is the current_epoch
#
# Reading on weak subjectivity
# - https://notes.ethereum.org/@adiasg/weak-subjectvity-eth2
# - https://www.symphonious.net/2019/11/27/exploring-ethereum-2-weak-subjectivity-period/
# - https://ethresear.ch/t/weak-subjectivity-under-the-exit-queue-model/5187
#
# Reading of interop serialization format
# - Import/export format: https://hackmd.io/@sproul/Bk0Y0qdGD
# - Tests: https://github.com/eth2-clients/slashing-protection-interchange-tests
#
# Relaxation for Nimbus
#
# We are not building a slashing detector but only protecting
# attached validator from slashing, hence we make the following assumptions
#
# 1. We only need to store specific validators signed blocks and attestations
# 2. We assume that our node is synced past
#    the last finalized epoch
#    hence we only need to keep track of blocks and attestations
#    since the last finalized epoch and we don't need to care
#    about the weak subjectivity period.
#    i.e. if `Node.isSynced()` returns false
#    a node skips its validator duties and doesn't invoke slashing protection.
#    and `isSynced` syncs at least up to the blockchain last finalized epoch.
#
# Hence the database or key-value store should support
#
# Queries
# 1. db.signedBlockExistsFor(validator, slot) -> bool
# 2. db.attestationExistsFor(validator, target_epoch) -> bool
# 3. db.attestationSurrounding(validator, source_epoch, target_epoch)
# 4. db.attestationSurrounded(validator, source_epoch, target_epoch)
#
# Update
# 1. db.registerBlock(validator, slot, block_root)
# 2. db.registerAttestation(validator, source_epoch, target_epoch, attestation_root)
#
# Maintenance
# 1. db.prune(finalized_epoch)
#
# Interop
# 1. db.import(json)
# 2. db.export(json)
# 3. db.export(json, validator)
# 4. db.export(json, seq[validator])
#
# Additionally after EIP3067 slashing protection requires
# a "low watermark" protection that can be used
# instead of keeping track of the whole history (and allows pruning)
# In that case we need the following queries
#
# 1. db.signedBlockMinimalSlot (EIP3067 condition 1)
# 2. db.signedAttMinimalSourceEpoch (EIP3067 condition 4)
# 3. db.signedAttMinimalTargetEpoch (EIP3067 condition 5)

# Technical Discussion
# --------------------------------------------
#
# TODO: Merge with BeaconChainDB?
# - https://stackoverflow.com/questions/21844479/multiple-databases-vs-single-database-with-logically-partitioned-data
#
# Reasons for merging
# - Single database
#
# Reasons for not merging
# - BeaconChainDB is about the beacon node itself
#   while slashing protection is about validators
# - BeaconChainDB is append-only
#   while slashing protection will be pruned
#   at each finalization.
#   Hence we might want different backend in the future
# - In a VC/BN split configuration the slashing protection
#   may be better attached to the VC. (VC: Validator Client, BN: Beacon Node)
# - The slashing protection DB only held cryptographic hashes
#   and epoch/slot integers which are uncompressible
#   while BeaconChainDB is snappy-compressed.
#
# TODO: if we enshrine the split we likely want to use
#       a relational DB instead of KV-Store,
#       for efficient pruning, range queries support
#       and filtering on validators

# SQLite primitives
# --------------------------------------------
# For now we choose to enforce the SQLite backend as a DB (and not a KV-Store)
#
# Cons
# 1. Harder to switch away from a DB than from a KV-Store
#
# Pros
# 1. No need for adhoc per-validator range queries implementation using LinkedList
#    with high potential of bug (as found in audit)
# 2. uses robust and fuzzed SQLite codepath
# 3. Straightforward pruning
# 4. Can be maintained and inspected with standard tooling
#
# In particular the following query leads to complex code with a KV store
#
# Select 1 from attestations
# where validator = '0x1234ABCDEF'
# AND (
#   -- Don't publish distinct vote for the same target
#   (target_epoch = candidate_target_epoch)
#   -- surrounded vote
#   OR
#   (source_epoch < candidate_source_epoch and candidate_target_epoch < target_epoch)
#   -- surrounding vote
#   OR
#   (candidate_source_epoch < source_epoch and target_epoch < candidate_target_epoch)
# )
#
# Note, with SQLite splitting into multiple small queries is also efficient
# as it is embedded in the application: https://www.sqlite.org/np1queryprob.html

# Future optimizations
# --------------------------------------------
# To limit disk IO we might want to keep a data-structure in memory.
# Surround voting detection is very similar to:
# - Collision detection in games
# - point of interest localisation in geographical DBs or maps
#
# A reasonable acceleration structure would be:
# - O(log n) for adding new attestations
# - O(log n) to check for surround voting.
# - O(n) space usage
#
# Suitable inspirations may be:
# - Bounding Volume Hierarchy and Axis-ligned Bounding Boxes from collision detection
# - R-Trees from geospatial data processing and maps
# - Kd-Trees from both
# - less common structures like quadtrees and octrees
#
# See also optimizing a slashing detector for the whole chain
# - https://github.com/protolambda/eth2-surround
# - Detecting slashing conditions https://hackmd.io/@n0ble/By897a5sH
# - Open issue on writing a slashing detector https://github.com/ethereum/eth2.0-pm/issues/63

type
  SlashingProtectionDB* = ref object
    ## Database storing the blocks attested
    ## by validators attached to a beacon node
    ## or validator client.
    # For now we commit to using SqLite
    # Splitting attestations queries
    # into small queries is fine with SqLite
    # https://www.sqlite.org/np1queryprob.html
    backend: SqStoreRef
    # Cached queries - write
    sqlInsertValidator: SqliteStmt[PubKeyBytes, void]
    sqlInsertAtt: SqliteStmt[(ValidatorInternalID, int64, int64, Hash32), void]
    sqlInsertBlock: SqliteStmt[(ValidatorInternalID, int64, Hash32), void]
    # Cached queries - read
    sqlGetValidatorInternalID: SqliteStmt[PubKeyBytes, ValidatorInternalID]
    sqlAttForSameTargetEpoch: SqliteStmt[(ValidatorInternalID, int64), Hash32]
    sqlAttSurrounded: SqliteStmt[(ValidatorInternalID, int64, int64), (int64, int64, Hash32)]
    sqlAttSurrounding: SqliteStmt[(ValidatorInternalID, int64, int64), (int64, int64, Hash32)]
    sqlAttMinSourceEpoch: SqliteStmt[ValidatorInternalID, int64]
    sqlAttMinTargetEpoch: SqliteStmt[ValidatorInternalID, int64]
    sqlBlockForSameSlot: SqliteStmt[(ValidatorInternalID, int64), Hash32]
    sqlBlockMinSlot: SqliteStmt[ValidatorInternalID, int64]

  ValidatorInternalID = int32
    ## Validator internal ID in the DB
    ## This is cached to cost querying cost

  PubKeyBytes = array[RawPubKeySize, byte]
    ## This is the serialized byte representation
    ## of a Validator Public Key.
    ## Portable between Miracl/BLST
    ## and limits serialization/deserialization call

  Hash32 = array[32, byte]

  BadVoteKind* = enum
    ## Attestation bad vote kind
    # h: height (i.e. epoch for attestation, slot for blocks)
    # t: target
    # s: source
    # 1: existing attestations
    # 2: candidate attestation

    # Spec slashing condition
    DoubleVote           # h(t1) = h(t2)
    SurroundedVote       # h(s1) < h(s2) < h(t2) < h(t1)
    SurroundingVote      # h(s2) < h(s1) < h(t1) < h(t2)
    # Non-spec, should never happen in a well functioning client
    TargetPrecedesSource # h(t1) < h(s1) - current epoch precedes last justified epoch

  BadVote* = object
    case kind*: BadVoteKind
    of DoubleVote:
      existingAttestation*: Eth2Digest
    of SurroundedVote, SurroundingVote:
      existingAttestationRoot*: Eth2Digest # Many roots might be in conflict
      sourceExisting*, targetExisting*: Epoch
      sourceSlashable*, targetSlashable*: Epoch
    of TargetPrecedesSource:
      discard

{.push raises: [Defect].}
logScope:
  topics = "antislash"

# version history:
# 0 -> https://github.com/status-im/nimbus-eth2/pull/1643, based on KV-store
const SlashingDB_version = 1

template dispose(sqlStmt: SqliteStmt) =
  discard sqlite3_finalize((ptr sqlite3_stmt) sqlStmt)

proc setupDB(db: SlashingProtectionDB, genesis_validator_root: Eth2Digest) =
  ## Initial setup of the DB
  block: # Metadata
    db.backend.exec("""
      CREATE TABLE metadata(
          slashing_db_version INTEGER,
          genesis_validator_root BLOB NOT NULL
      );
    """).expect("DB should be working and \"metadata\" should not exist")

    # TODO: db.backend.exec does not take parameters
    var rootTuple: tuple[bytes: Hash32]
    rootTuple[0] = genesis_validator_root.data
    db.backend.exec("""
      INSERT INTO
        metadata(slashing_db_version, genesis_validator_root)
      VALUES
        (""" & $SlashingDB_version & """, ?);
    """, rootTuple
    ).expect("Metadata initialized in the DB")

  block: # Tables
    db.backend.exec("""
      CREATE TABLE validators(
          id INTEGER PRIMARY KEY,
          pubkey BLOB NOT NULL UNIQUE
      );
    """).expect("DB should be working and \"validators\" should not exist")

    db.backend.exec("""
      CREATE TABLE attestations(
          validator_id INTEGER NOT NULL,
          source_epoch INTEGER NOT NULL,
          target_epoch INTEGER NOT NULL,
          attestation_root BLOB NOT NULL UNIQUE,
          FOREIGN KEY(validator_id) REFERENCES validators(id)
          UNIQUE (validator_id, target_epoch)
      );
    """).expect("DB should be working and \"attestations\" should not exist")

    db.backend.exec("""
      CREATE TABLE blocks(
          validator_id INTEGER NOT NULL,
          slot INTEGER NOT NULL,
          block_root BLOB NOT NULL UNIQUE,
          FOREIGN KEY(validator_id) REFERENCES validators(id)
          UNIQUE (validator_id, slot)
      );
    """).expect("DB should be working and \"blocks\" should not exist")

proc checkDB(db: SlashingProtectionDB, genesis_validator_root: Eth2Digest) =
  ## Check the metadata of the DB
  let selectStmt = db.backend.prepareStmt(
    "SELECT * FROM metadata;",
    NoParams, (int32, Hash32),
    managed = false # manual memory management
  ).get()

  var version: int32
  var root: Eth2Digest
  let status = selectStmt.exec do (res: (int32, Hash32)):
    version = res[0]
    root.data = res[1]

  selectStmt.dispose()

  doAssert status.isOk()
  doAssert version == SlashingDB_version,
    "Incorrect database version: " & $version & "\n" &
    "but expected: " & $SlashingDB_version
  doAssert root == genesis_validator_root,
    "Invalid database genesis validator root: " & root.data.toHex() & "\n" &
    "but expected: " & genesis_validator_root.data.toHex()

proc setupCachedQueries(db: SlashingProtectionDB) =
  ## Create prepared queries for reuse
  # Insertions
  # --------------------------------------------------------
  db.sqlInsertValidator = db.backend.prepareStmt("""
    INSERT INTO
      validators(pubkey)
    VALUES
      (?);
  """, PubKeyBytes, void).get()

  db.sqlInsertAtt = db.backend.prepareStmt("""
    INSERT INTO attestations(
      validator_id,
      source_epoch,
      target_epoch,
      attestation_root)
    VALUES
      (?,?,?,?);
  """, (ValidatorInternalID, int64, int64, Hash32), void).get()

  db.sqlInsertBlock = db.backend.prepareStmt("""
    INSERT INTO blocks(
      validator_id,
      slot,
      block_root)
    VALUES
      (?,?,?);
    """, (ValidatorInternalID, int64, Hash32), void
  ).get()

  # Read internal validator ID
  # --------------------------------------------------------
  db.sqlGetValidatorInternalID = db.backend.prepareStmt(
    "SELECT id from validators WHERE pubkey = ?;",
    PubKeyBytes, ValidatorInternalID
  ).get()

  # Inspect attestations
  # --------------------------------------------------------
  db.sqlAttForSameTargetEpoch = db.backend.prepareStmt("""
    SELECT
      attestation_root
    FROM
      attestations
    WHERE
      validator_id = ?
      AND
      target_epoch = ?
    """, (ValidatorInternalID, int64), Hash32
  ).get()

  db.sqlAttSurrounded = db.backend.prepareStmt("""
    SELECT
      source_epoch, target_epoch, attestation_root
    FROM
      attestations
    WHERE
      validator_id = ?
      AND
      source_epoch < ? AND ? < target_epoch
    LIMIT 1
    """, (ValidatorInternalID, int64, int64), (int64, int64, Hash32)
  ).get()

  db.sqlAttSurrounding = db.backend.prepareStmt("""
    SELECT
      source_epoch, target_epoch, attestation_root
    FROM
      attestations
    WHERE
      validator_id = ?
      AND
      ? < source_epoch AND target_epoch < ?
    LIMIT 1
    """, (ValidatorInternalID, int64, int64), (int64, int64, Hash32)
  ).get()

  db.sqlAttMinSourceEpoch = db.backend.prepareStmt("""
    SELECT
      MIN(source_epoch)
    FROM
      attestations
    WHERE
      validator_id = ?
    """, ValidatorInternalID, int64
  ).get()

  db.sqlAttMinTargetEpoch = db.backend.prepareStmt("""
    SELECT
      MIN(source_epoch)
    FROM
      attestations
    WHERE
      validator_id = ?
    """, ValidatorInternalID, int64
  ).get()

  # Inspect blocks
  # --------------------------------------------------------
  db.sqlBlockForSameSlot = db.backend.prepareStmt("""
    SELECT
      block_root
    FROM
      blocks
    WHERE
      validator_id = ?
      AND
      slot = ?;
    """, (ValidatorInternalID, int64), Hash32
  ).get()

  db.sqlBlockMinSlot = db.backend.prepareStmt("""
    SELECT
      MIN(slot)
    FROM
      blocks
    WHERE
      validator_id = ?;
    """, ValidatorInternalID, int64
  ).get()

proc init*(T: type SlashingProtectionDB,
           genesis_validator_root: Eth2Digest,
           basePath: string,
           dbname: string): T =
  ## Initialize a new slashing protection database
  ## or load an existing one with matching genesis root
  ## `dbname` MUST not be ending with .sqlite3

  let alreadyExists = fileExists(basepath/ dbname&".sqlite3")

  result = T(backend: SqStoreRef.init(basePath, dbname, keyspaces = []).get())
  if alreadyExists:
    result.checkDB(genesis_validator_root)
  else:
    result.setupDB(genesis_validator_root)

  # Cached queries
  result.setupCachedQueries()

proc load*(
       T: type SlashingProtectionDB,
       backend: KVStoreRef): SlashingProtectionDB =
  ## Load a slashing protection DB
  ## Note: This is for conversion usage
  ##       this doesn't check the genesis validator root
  result = T(backend: backend)

proc close*(db: SlashingProtectionDB) =
  ## Close a slashing protection database
  db.backend.close()

# DB Queries
# --------------------------------------------
proc foundAnyResult(status: KVResult[bool]): bool {.inline.}=
  ## Checks a DB query status for errors
  ## Then returns true if any result was found
  ## and false otherwise.
  ## There are 2 layers to a DB result
  ## 1. Did the query result in error.
  ##    This is a logic bug and crashes NBC in this proc.
  ## 2. Did the query return any line.
  status.expect("DB is not corrupted and query is working")

proc getValidatorInternalID(
       db: SlashingProtectionDB,
       validator: ValidatorPubKey): Option[ValidatorInternalID] =
  ## Retrieve a validator internal ID
  let serializedPubkey = validator.toRaw() # Miracl/BLST to bytes
  var valID: ValidatorInternalID
  let status = db.sqlGetValidatorInternalID.exec(serializedPubkey) do (res: ValidatorInternalID):
    valID = res

  # Note: we enforce at the DB level that if the pubkey exists it is unique.
  if status.foundAnyResult():
    some(valID)
  else:
    none(ValidatorInternalID)

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
  # TODO distinct type for the result block root

  let valID = block:
    let id = db.getValidatorInternalID(validator)
    if id.isNone():
      notice "No slashing protection data - first block proposal?",
        validator = validator,
        slot = slot
      return ok()
    else:
      id.unsafeGet()

  var root: ETH2Digest
  let status = db.sqlBlockForSameSlot.exec(
        (valID, int64 slot)
      ) do (res: Hash32):
    root.data = res

  # Note: we enforce at the DB level that if (pubkey, slot) exists it maps to a unique block root.
  if status.foundAnyResult():
    # Conflicting block exist
    err(root)
  else:
    ok()

  # TODO: low-watermark check for EIP3067

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
  # TODO distinct type for the result attestation root

  # Sanity
  # ---------------------------------
  if source > target:
    return err(BadVote(kind: TargetPrecedesSource))

  # Internal metadata
  # ---------------------------------
  let valID = block:
    let id = db.getValidatorInternalID(validator)
    if id.isNone():
      notice "No slashing protection data - first attestation?",
        validator = validator,
        attSource = source,
        attTarget = target
      return ok()
    else:
      id.unsafeGet()

  # Casper FFG 1st slashing condition
  # Detect h(t1) = h(t2)
  # ---------------------------------
  block:
    var root: ETH2Digest
    let status = db.sqlAttForSameTargetEpoch.exec(
          (valID, int64 target)
        ) do (res: Hash32):
      root.data = res

    # Note: we enforce at the DB level that if (pubkey, target) exists it maps to a unique block root.
    if status.foundAnyResult():
      # Conflicting attestation exist, log by caller
      return err(BadVote(
        kind: DoubleVote,
        existingAttestation: root
      ))

  # Casper FFG 2nd slashing condition
  # -> Surrounded vote
  # Detect h(s1) < h(s2) < h(t2) < h(t1)
  # ---------------------------------
  block:
    var root: ETH2Digest
    var db_source, db_target: Epoch
    let status = db.sqlAttSurrounded.exec(
          (valID, int64 source, int64 target)
        ) do (res: tuple[source, target: int64, root: Hash32]):
      db_source = Epoch res.source
      db_target = Epoch res.target
      root.data = res.root

    # Note: we enforce at the DB level that if (pubkey, target) exists it maps to a unique block root.
    if status.foundAnyResult():
      # Conflicting attestation exist, log by caller
      # s1 < s2 < t2 < t1
      return err(BadVote(
        kind: SurroundedVote,
        existingAttestationRoot: root,
        sourceExisting: db_source,
        targetExisting: db_target,
        sourceSlashable: source,
        targetSlashable: target
      ))

  # Casper FFG 2nd slashing condition
  # -> Surrounding vote
  # Detect h(s2) < h(s1) < h(t1) < h(t2)
  # ---------------------------------
  block:
    var root: ETH2Digest
    var db_source, db_target: Epoch
    let status = db.sqlAttSurrounding.exec(
          (valID, int64 source, int64 target)
        ) do (res: tuple[source, target: int64, root: Hash32]):
      db_source = Epoch res.source
      db_target = Epoch res.target
      root.data = res.root

    # Note: we enforce at the DB level that if (pubkey, target) exists it maps to a unique block root.
    if status.foundAnyResult():
      # Conflicting attestation exist, log by caller
      # s1 < s2 < t2 < t1
      return err(BadVote(
        kind: SurroundingVote,
        existingAttestationRoot: root,
        sourceExisting: db_source,
        targetExisting: db_target,
        sourceSlashable: source,
        targetSlashable: target
      ))

  # TODO: low-watermark check for EIP3067
  return ok()

# DB update
# --------------------------------------------

proc registerValidator(db: SlashingProtectionDB, validator: ValidatorPubKey) =
  ## Get validator from the database
  ## or register it
  ## Assumes the validator does not exist
  let serializedPubkey = validator.toRaw() # Miracl/BLST to bytes
  let status = db.sqlInsertValidator.exec(serializedPubkey)
  doAssert status.isOk()

proc getOrRegisterValidator(
       db: SlashingProtectionDB,
       validator: ValidatorPubKey): ValidatorInternalID =
  ## Get validator from the database
  ## or register it and then return it
  let id = db.getValidatorInternalID(validator)
  if id.isNone():
    info "No slashing protection data for validator - initiating",
      validator = validator

    db.registerValidator(validator)
    let id = db.getValidatorInternalID(validator)
    doAssert id.isSome()
    id.unsafeGet()
  else:
    id.unsafeGet()

proc registerBlock*(
       db: SlashingProtectionDB,
       validator: ValidatorPubKey,
       slot: Slot, block_root: Eth2Digest) =
  ## Add a block to the slashing protection DB
  ## `checkSlashableBlockProposal` MUST be run
  ## before to ensure no overwrite.
  let valID = db.getOrRegisterValidator(validator)
  let status = db.sqlInsertBlock.exec(
    (valID, int64 slot,
    block_root.data))
  doAssert status.isOk(),
    "SQLite error when registering block: " & $status.error & "\n" &
    "for validator: 0x" & validator.toHex() & ", slot: " & $slot

proc registerAttestation*(
       db: SlashingProtectionDB,
       validator: ValidatorPubKey,
       source, target: Epoch,
       attestation_root: Eth2Digest) =
  ## Add an attestation to the slashing protection DB
  ## `checkSlashableAttestation` MUST be run
  ## before to ensure no overwrite.
  let valID = db.getOrRegisterValidator(validator)
  let status = db.sqlInsertAtt.exec(
    (valID, int64 source, int64 target,
    attestation_root.data))
  doAssert status.isOk(),
    "SQLite error when registering attestation: " & $status.error & "\n" &
    "for validator: 0x" & validator.toHex() & ", target_epoch: " & $target

# DB maintenance
# --------------------------------------------
# TODO: pruning

# Interchange
# --------------------------------------------

type
  SPDIF = object
    ## Slashing Protection Database Interchange Format
    metadata: SPDIF_Meta
    data: seq[SPDIF_Validator]

  Eth2Digest0x = distinct Eth2Digest
    ## The spec mandates "0x" prefix on serialization
    ## So we need to set custom read/write
  PubKey0x = distinct PubKeyBytes
    ## The spec mandates "0x" prefix on serialization
    ## So we need to set custom read/write
    ## We also assume that pubkeys in the database
    ## are valid points on the BLS12-381 G1 curve
    ## (so we skip fromRaw/serialization checks)

  SlotString = distinct Slot
    ## The spec mandates string serialization for wide compatibility (javascript)
  EpochString = distinct Epoch
    ## The spec mandates string serialization for wide compatibility (javascript)

  SPDIF_Meta = object
    interchange_format_version: string
    genesis_validator_root: Eth2Digest0x

  SPDIF_Validator = object
    pubkey: PubKey0x
    signed_blocks: seq[SPDIF_SignedBlock]
    signed_attestations: seq[SPDIF_SignedAttestation]

  SPDIF_SignedBlock = object
    slot: SlotString
    signing_root: Eth2Digest0x # compute_signing_root(block, domain)

  SPDIF_SignedAttestation = object
    source_epoch: EpochString
    target_epoch: EpochString
    signing_root: Eth2Digest0x # compute_signing_root(attestation, domain)

proc writeValue*(writer: var JsonWriter, value: PubKey0x)
                {.inline, raises: [IOError, Defect].} =
  writer.writeValue("0x" & value.PubKeyBytes.toHex())

proc readValue*(reader: var JsonReader, value: var PubKey0x)
               {.raises: [SerializationError, IOError, ValueError, Defect].} =
  value = PubKey0x reader.readValue(string).hexToByteArray[:RawPubKeySize]()

proc writeValue*(w: var JsonWriter, a: Eth2Digest0x)
                {.inline, raises: [IOError, Defect].} =
  w.writeValue "0x" & a.Eth2Digest.data.toHex()

proc readValue*(r: var JsonReader, a: var Eth2Digest0x)
               {.raises: [SerializationError, IOError, Defect].} =
  try:
    a = Eth2Digest0x fromHex(Eth2Digest, r.readValue(string))
  except ValueError:
    raiseUnexpectedValue(r, "Hex string expected")

proc writeValue*(w: var JsonWriter, a: SlotString or EpochString)
                {.inline, raises: [IOError, Defect].} =
  w.writeValue $distinctBase(a)

proc readValue*(r: var JsonReader, a: var (SlotString or EpochString))
               {.raises: [SerializationError, IOError, ValueError, Defect].} =
  a = (typeof a)(r.readValue(string).parseBiggestUint())

proc toSPDIF*(db: SlashingProtectionDB, path: string)
             {.raises: [IOError, Defect].} =
  ## Export the full slashing protection database
  ## to a json the Slashing Protection Database Interchange (Complete) Format
  var extract: SPDIF
  extract.metadata.interchange_format_version = "5"

  # genesis_validator_root
  # -----------------------------------------------------
  block:
    let selectRootStmt = db.backend.prepareStmt(
      "SELECT genesis_validator_root FROM metadata;",
      NoParams, Hash32,
      managed = false # manual memory management
    ).get()

    let status = selectRootStmt.exec do (res: Hash32):
      extract.metadata.genesis_validator_root = Eth2Digest0x(ETH2Digest(data: res))
    doAssert status.isOk()

    selectRootStmt.dispose()

  # Validators
  # -----------------------------------------------------
  block:
    let selectValStmt = db.backend.prepareStmt(
      "SELECT pubkey FROM validators;",
      NoParams, PubKeyBytes,
      managed = false # manual memory management
    ).get()

    let status = selectValStmt.exec do (res: PubKeyBytes):
      extract.data.add SPDIF_Validator(pubkey: PubKey0x res)
    doAssert status.isOk()

    selectValStmt.dispose()

  # For each validator found, collect their signatures
  # -----------------------------------------------------
  block:
    let selectBlkStmt = db.backend.prepareStmt("""
      SELECT
        slot, block_root
      FROM
        blocks b
      INNER JOIN
        validators v on b.validator_id = v.id
      WHERE
        v.pubkey = ?
      ORDER BY
        slot ASC
      """, PubKeyBytes, (int64, Hash32),
      managed = false # manual memory management
    ).get()

    let selectAttStmt = db.backend.prepareStmt("""
      SELECT
        source_epoch, target_epoch, attestation_root
      FROM
        attestations a
      INNER JOIN
        validators v on a.validator_id = v.id
      WHERE
        v.pubkey = ?
      ORDER BY
        target_epoch ASC
      """, PubKeyBytes, (int64, int64, Hash32),
      managed = false # manual memory management
    ).get()

    defer:
      selectBlkStmt.dispose()
      selectAttStmt.dispose()

    for i in 0 ..< extract.data.len:
      template validator: untyped = extract.data[i] # alias
      block: # Blocks
        let status = selectBlkStmt.exec(validator.pubkey.PubKeyBytes) do (res: tuple[slot: int64, root: Hash32]):
          validator.signed_blocks.add SPDIF_SignedBlock(
            slot: SlotString res.slot,
            signing_root: Eth2Digest0x(Eth2Digest(data: res.root))
          )
        doAssert status.isOk()
      block: # Attestations
        let status = selectAttStmt.exec(validator.pubkey.PubKeyBytes) do (res: tuple[source, target: int64, root: Hash32]):
          validator.signed_attestations.add SPDIF_SignedAttestation(
            source_epoch: EpochString res.source,
            target_epoch: EpochString res.target,
            signing_root: Eth2Digest0x(Eth2Digest(data: res.root))
          )
        doAssert status.isOk()

  Json.saveFile(path, extract, pretty = true)
  echo "Exported slashing protection DB to '", path, "'"

proc fromSPDIF*(db: SlashingProtectionDB, path: string): bool
             {.raises: [SerializationError, IOError, Defect].} =
  ## Import a (Complete) Slashing Protection Database Interchange Format
  ## file into the specified slahsing protection DB
  ##
  ## The database must be initialized.
  ## The genesis_validator_root must match or
  ## the DB must have a zero root

  let extract = Json.loadFile(path, SPDIF)

  doAssert not db.isNil, "The Slashing Protection DB must be initialized."
  doAssert not db.backend.isNil, "The Slashing Protection DB must be initialized."

  # genesis_validator_root
  # -----------------------------------------------------
  block:
    var dbGenValRoot: ETH2Digest

    let selectRootStmt = db.backend.prepareStmt(
      "SELECT genesis_validator_root FROM metadata;",
      NoParams, Hash32,
      managed = false # manual memory management
    ).get()

    let status = selectRootStmt.exec do (res: Hash32):
      dbGenValRoot.data = res
    doAssert status.isOk()

    selectRootStmt.dispose()

    if dbGenValRoot != default(Eth2Digest) and
      dbGenValRoot != extract.metadata.genesis_validator_root.Eth2Digest:
      echo "The slashing protection database and imported file refer to different blockchains."
      return false

    if not status.get():
      # Query worked but returned no result
      # We assume that the DB wasn't setup or
      # is in an earlier version that used the kvstore table
      db.setupDB(extract.metadata.genesis_validator_root.Eth2Digest)

    # TODO: dbGenValRoot == default(Eth2Digest)

  db.setupCachedQueries()

  for v in 0 ..< extract.data.len:
    let parsedKey = block:
      let key = ValidatorPubKey.fromRaw(extract.data[v].pubkey.PubKeyBytes).get()
      if key.kind == OpaqueBlob:
        # The bytes does not describe a point on the BLS12-381 G1 curve
        echo "Warning! Invalid public key: 0x" & extract.data[v].pubkey.PubKeyBytes.toHex()
        continue
      key
    # TODO: this is a bit wasteful to convert parsedKey back to PubKeyBytes
    #       in the register* proc but this is something done very rarely and offline.
    for b in 0 ..< extract.data[v].signed_blocks.len:
      db.registerBlock(
        parsedKey,
        extract.data[v].signed_blocks[b].slot.Slot,
        extract.data[v].signed_blocks[b].signing_root.Eth2Digest
      )
    for a in 0 ..< extract.data[v].signed_attestations.len:
      db.registerAttestation(
        parsedKey,
        extract.data[v].signed_attestations[a].source_epoch.Epoch,
        extract.data[v].signed_attestations[a].target_epoch.Epoch,
        extract.data[v].signed_attestations[a].signing_root.Eth2Digest
      )

  return true
