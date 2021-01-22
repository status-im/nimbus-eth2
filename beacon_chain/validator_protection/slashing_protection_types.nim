# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Status
  eth/db/[kvstore, kvstore_sqlite3],
  stew/results,
  # Internal
  ../spec/[datatypes, digest, crypto]

# Slashing Protection types
# --------------------------------------------

type
  SlashingProtectionDB* = concept db, type DB
    ## Database storing the blocks attested
    ## by validators attached to a beacon node
    ## or validator client.

    # Metadata
    # --------------------------------------------
    DB.version is int

    # Resource Management
    # --------------------------------------------
    DB is ref

    DB.init(Eth2Digest, string, string) is DB
      # DB.init(genesis_root, dir, filename)
    DB.load(string, string, bool) is DB
      # DB.load(dir, filename, readOnly)
    db.close()

    # Queries
    # --------------------------------------------
    db.checkSlashableBlockProposal(ValidatorPubKey, Slot) is Result[void, Eth2Digest]
      # db.checkSlashableBlockProposal(validator, slot)
    db.checkSlashableAttestation(ValidatorPubKey, Epoch, Epoch) is Result[void, BadVote]
      # db.checkSlashableAttestation(validator, source, target)

    # Updates
    # --------------------------------------------
    db.registerBlock(ValidatorPubKey, Slot, Eth2Digest)
      # db.checkSlashableAttestation(validator, slot, block_root)
    db.registerAttestation(ValidatorPubKey, Epoch, Epoch, Eth2Digest)
      # db.checkSlashableAttestation(validator, source, target, block_root)

    # Pruning
    # --------------------------------------------

    # Interchange
    # --------------------------------------------
    db.toSPDIF(string)
      # to Slashing Protection Data Interchange Format
      # db.toSPDIF(path)
    db.fromSPDIF(string) is bool
      # from Slashing Protection Data Interchange Format
      # db.fromSPDIF(path)

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

  SlashProtDBMode* = enum
    kCompleteArchiveV1 # Complete Format V1 backend (saves all attestations)
    kCompleteArchiveV2 # Complete Format V2 backend (saves all attestations)
    kLowWaterMarkV2    # Low-Watermark Format V2 backend (prunes attestations)
