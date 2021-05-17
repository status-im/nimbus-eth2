# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Stdlib
  std/[typetraits, strutils, algorithm],
  # Status
  eth/db/[kvstore, kvstore_sqlite3],
  stew/results,
  stew/byteutils,
  serialization,
  json_serialization,
  chronicles,
  # Internal
  ../spec/[datatypes, digest, crypto]

export serialization, json_serialization # Generic sandwich https://github.com/nim-lang/Nim/issues/11225

# Slashing Protection Interop
# --------------------------------------------
# We use the SPDIR type as an intermediate representation
# between database versions and to generate
# the serialized interchanged format.
#
# References: https://eips.ethereum.org/EIPS/eip-3076
#
# SPDIR: Nimbus-specific, Slashing Protection Database Intermediate Representation
# SPDIF: Cross-client, json, Slashing Protection Database Interchange Format

type
  SPDIR* = object
    ## Slashing Protection Database Interchange Format
    metadata*: SPDIR_Meta
    data*: seq[SPDIR_Validator]

  Eth2Digest0x* = distinct Eth2Digest
    ## The spec mandates "0x" prefix on serialization
    ## So we need to set custom read/write

  PubKeyBytes* = array[RawPubKeySize, byte]
    ## This is the serialized byte representation
    ## of a Validator Public Key.
    ## Portable between Miracl/BLST
    ## and limits serialization/deserialization call

  PubKey0x* = distinct PubKeyBytes
    ## The spec mandates "0x" prefix on serialization
    ## So we need to set custom read/write
    ## We also assume that pubkeys in the database
    ## are valid points on the BLS12-381 G1 curve
    ## (so we skip fromRaw/serialization checks)

  SlotString* = distinct Slot
    ## The spec mandates string serialization for wide compatibility (javascript)
  EpochString* = distinct Epoch
    ## The spec mandates string serialization for wide compatibility (javascript)

  SPDIR_Meta* = object
    interchange_format_version*: string
    genesis_validators_root*: Eth2Digest0x

  SPDIR_Validator* = object
    pubkey*: PubKey0x
    signed_blocks*: seq[SPDIR_SignedBlock]
    signed_attestations*: seq[SPDIR_SignedAttestation]

  SPDIR_SignedBlock* = object
    slot*: SlotString
    signing_root*: Eth2Digest0x # compute_signing_root(block, domain)

  SPDIR_SignedAttestation* = object
    source_epoch*: EpochString
    target_epoch*: EpochString
    signing_root*: Eth2Digest0x # compute_signing_root(attestation, domain)

# Slashing Protection types
# --------------------------------------------

  SlashingImportStatus* = enum
    siSuccess
    siFailure
    siPartial

  BadVoteKind* = enum
    ## Attestation bad vote kind
    # h: height (i.e. epoch for attestation, slot for blocks)
    # t: target
    # s: source
    # 1: existing attestations
    # 2: candidate attestation

    # Spec slashing condition
    DoubleVote   # h(t1) == h(t2)
    SurroundVote # h(s1) < h(s2) < h(t2) < h(t1) or h(s2) < h(s1) < h(t1) < h(t2)

    # Non-spec, should never happen in a well functioning client
    TargetPrecedesSource # h(t1) < h(s1) - current epoch precedes last justified epoch

    # EIP-3067 (https://eips.ethereum.org/EIPS/eip-3076)
    MinSourceViolation   # h(s2) < h(s1) - EIP3067 condition 4 (strict inequality)
    MinTargetViolation   # h(t2) <= h(t1) - EIP3067 condition 5
    DatabaseError          # Cannot read/write the slashing protection db

  BadVote* {.pure.} = object
    case kind*: BadVoteKind
    of DoubleVote:
      existingAttestation*: Eth2Digest
    of SurroundVote:
      existingAttestationRoot*: Eth2Digest # Many roots might be in conflict
      sourceExisting*, targetExisting*: Epoch
      sourceSlashable*, targetSlashable*: Epoch
    of TargetPrecedesSource:
      discard
    of MinSourceViolation:
      minSource*: Epoch
      candidateSource*: Epoch
    of MinTargetViolation:
      minTarget*: Epoch
      candidateTarget*: Epoch
    of BadVoteKind.DatabaseError:
      message*: string

  BadProposalKind* {.pure.} = enum
    # Spec slashing condition
    DoubleProposal         # h(t1) == h(t2)
    # EIP-3067 (https://eips.ethereum.org/EIPS/eip-3076)
    MinSlotViolation       # h(t2) <= h(t1)
    DatabaseError          # Cannot read/write the slashing protection db

  BadProposal* = object
    case kind*: BadProposalKind
    of DoubleProposal:
      existingBlock*: Eth2Digest
    of MinSlotViolation:
      minSlot*: Slot
      candidateSlot*: Slot
    of BadProposalKind.DatabaseError:
      message*: string

func `==`*(a, b: BadVote): bool =
  ## Comparison operator.
  ## Used implictily by Result when comparing the
  ## result of multiple DB versions
  if a.kind != b.kind:
    false
  else:
    case a.kind
    of DoubleVote:
      a.existingAttestation == b.existingAttestation
    of SurroundVote:
      (a.existingAttestationRoot == b.existingAttestationRoot) and
        (a.sourceExisting == b.sourceExisting) and
        (a.targetExisting == b.targetExisting) and
        (a.sourceSlashable == b.sourceSlashable) and
        (a.targetSlashable == b.targetSlashable)
    of TargetPrecedesSource:
      true
    of MinSourceViolation:
      (a.minSource == b.minSource) and
        (a.candidateSource == b.candidateSource)
    of MinTargetViolation:
      (a.minTarget == b.minTarget) and
        (a.candidateTarget == b.candidateTarget)
    of BadVoteKind.DatabaseError:
      true

template `==`*(a, b: PubKey0x): bool =
  PubKeyBytes(a) == PubKeyBytes(b)

template `<`*(a, b: PubKey0x): bool =
  PubKeyBytes(a) < PubKeyBytes(b)

template cmp*(a, b: PubKey0x): bool =
  cmp(PubKeyBytes(a), PubKeyBytes(b))

func `==`*(a, b: BadProposal): bool =
  ## Comparison operator.
  ## Used implictily by Result when comparing the
  ## result of multiple DB versions
  ##
  ## Except that V1 doesn't support low-watermark...
  if a.kind != b.kind:
    false
  elif a.kind == DoubleProposal:
    a.existingBlock == b.existingBlock
  elif a.kind == MinSlotViolation:
    a.minSlot == b.minSlot and
      a.candidateSlot == b.candidateSlot
  else: # Unreachable
    false

# Serialization
# --------------------------------------------

proc writeValue*(writer: var JsonWriter, value: PubKey0x)
                {.inline, raises: [IOError, Defect].} =
  writer.writeValue("0x" & value.PubKeyBytes.toHex())

proc readValue*(reader: var JsonReader, value: var PubKey0x)
               {.raises: [SerializationError, IOError, Defect].} =
  try:
    value = PubKey0x hexToByteArray(reader.readValue(string), RawPubKeySize)
  except ValueError:
    raiseUnexpectedValue(reader, "Hex string expected")

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
               {.raises: [SerializationError, IOError, Defect].} =
  try:
    a = (typeof a)(r.readValue(string).parseBiggestUint())
  except ValueError:
    raiseUnexpectedValue(r, "Integer in a string expected")

proc importSlashingInterchange*(
       db: auto,
       path: string): SlashingImportStatus {.raises: [Defect, IOError, SerializationError].} =
  ## Import a Slashing Protection Database Interchange Format
  ## into a Nimbus DB.
  ## This adds data to already existing data.
  let spdir = Json.loadFile(path, SPDIR)
  return db.inclSPDIR(spdir)

# Logging
# --------------------------------------------

func shortLog*(v: SPDIR_SignedBlock): auto =
  (
    slot: shortLog(v.slot.Slot),
    signing_root: shortLog(v.signing_root.Eth2Digest)
  )
func shortLog*(v: SPDIR_SignedAttestation): auto =
  (
    source_epoch: shortLog(v.source_epoch.Epoch),
    target_epoch: shortLog(v.target_epoch.Epoch),
    signing_root: shortLog(v.signing_root.Eth2Digest)
  )

chronicles.formatIt SlotString: it.Slot.shortLog
chronicles.formatIt EpochString: it.Slot.shortLog
chronicles.formatIt Eth2Digest0x: it.Eth2Digest.shortLog
chronicles.formatIt SPDIR_SignedBlock: it.shortLog
chronicles.formatIt SPDIR_SignedAttestation: it.shortLog

# Interchange import
# --------------------------------------------

proc importInterchangeV5Impl*(
       db: auto,
       spdir: var SPDIR
     ): SlashingImportStatus
      {.raises: [SerializationError, IOError, Defect].} =
  ## Common implementation of interchange import
  ## according to https://eips.ethereum.org/EIPS/eip-3076
  ## spdir needs to be `var` as it will be sorted in-place

  result = siSuccess

  for v in 0 ..< spdir.data.len:
    let parsedKey = block:
      let key = ValidatorPubKey.fromRaw(spdir.data[v].pubkey.PubKeyBytes)
      if key.isErr:
        # The bytes does not describe a valid encoding (length error)
        error "Invalid public key.",
          pubkey = "0x" & spdir.data[v].pubkey.PubKeyBytes.toHex()

        result = siPartial
        continue
      if key.get().loadWithCache().isNone():
        # The bytes don't deserialize to a valid BLS G1 elliptic curve point.
        # Deserialization is costly but done only once per validator.
        # and SlashingDB import is a very rare event.
        error "Invalid public key.",
          pubkey = "0x" & spdir.data[v].pubkey.PubKeyBytes.toHex()

        result = siPartial
        continue
      key.get()

    # Sort by ascending minimum slot so that we don't trigger MinSlotViolation
    spdir.data[v].signed_blocks.sort do (a, b: SPDIR_SignedBlock) -> int:
      result = cmp(a.slot.int, b.slot.int)

    spdir.data[v].signed_attestations.sort do (a, b: SPDIR_SignedAttestation) -> int:
      result = cmp(a.source_epoch.int, b.source_epoch.int)
      if result == 0: # Same epoch
        result = cmp(a.target_epoch.int, b.target_epoch.int)

    const ZeroDigest = Eth2Digest()

    # Blocks
    # ---------------------------------------------------
    # After import we need to prune the DB from everything
    # besides the last imported block slot.
    # This ensures that even if 2 slashing DB are imported in the wrong order
    # (the last before the earliest) the minSlotViolation check stays consistent.
    var maxValidSlotSeen = -1

    for b in 0 ..< spdir.data[v].signed_blocks.len:
      template B: untyped = spdir.data[v].signed_blocks[b]
      let status = db.registerBlock(
        parsedKey, B.slot.Slot, B.signing_root.Eth2Digest
      )
      if status.isErr():
        # We might be importing a duplicate which EIP-3076 allows
        # there is no reason during normal operation to integrate
        # a duplicate so checkSlashableBlockProposal would have rejected it.
        # We special-case that for imports.
        # Note: rule 2 mentions repeat signing in the MinSlotViolation case
        #       having 2 blocks with the same signing root and different slots
        #       would break the blockchain so we only check for exact slot.
        if status.error.kind == DoubleProposal and
            B.signing_root.Eth2Digest != ZeroDigest and
            status.error.existingBlock == B.signing_root.Eth2Digest:
          warn "Block already exists in the DB",
            pubkey = spdir.data[v].pubkey.PubKeyBytes.toHex(),
            candidateBlock = B
          continue
        else:
          error "Slashable block. Skipping its import.",
            pubkey = spdir.data[v].pubkey.PubKeyBytes.toHex(),
            candidateBlock = B,
            conflict = status.error()
          result = siPartial
          continue

      if B.slot.int > maxValidSlotSeen:
        maxValidSlotSeen = B.slot.int

    # Now prune everything that predates
    # this interchange file max slot
    db.pruneBlocks(parsedKey, Slot maxValidSlotSeen)

    # Attestations
    # ---------------------------------------------------
    # After import we need to prune the DB from everything
    # besides the last imported attestation source and target epochs.
    # This ensures that even if 2 slashing DB are imported in the wrong order
    # (the last before the earliest) the minEpochViolation check stays consistent.
    var maxValidSourceEpochSeen = -1
    var maxValidTargetEpochSeen = -1

    for a in 0 ..< spdir.data[v].signed_attestations.len:
      template A: untyped = spdir.data[v].signed_attestations[a]
      let status = db.registerAttestation(
        parsedKey,
        A.source_epoch.Epoch,
        A.target_epoch.Epoch,
        A.signing_root.Eth2Digest
      )
      if status.isErr():
        # We might be importing a duplicate which EIP-3076 allows
        # there is no reason during normal operation to integrate
        # a duplicate so checkSlashableAttestation would have rejected it.
        # We special-case that for imports.
        if status.error.kind == DoubleVote and
            A.signing_root.Eth2Digest != ZeroDigest and
            status.error.existingAttestation == A.signing_root.Eth2Digest:
          warn "Attestation already exists in the DB",
            pubkey = spdir.data[v].pubkey.PubKeyBytes.toHex(),
            candidateAttestation = A
          continue
        else:
          error "Slashable vote. Skipping its import.",
            pubkey = spdir.data[v].pubkey.PubKeyBytes.toHex(),
            candidateAttestation = A,
            conflict = status.error()
          result = siPartial
          continue

      if A.source_epoch.int > maxValidSourceEpochSeen:
        maxValidSourceEpochSeen = A.source_epoch.int
      if A.target_epoch.int > maxValidTargetEpochSeen:
        maxValidTargetEpochSeen = A.target_epoch.int

    # Now prune everything that predates
    # this interchange file max slot
    if maxValidSourceEpochSeen < 0 or maxValidTargetEpochSeen < 0:
      doAssert maxValidSourceEpochSeen == -1 and maxValidTargetEpochSeen == -1
      notice "No attestation found in slashing interchange file"
      return
    db.pruneAttestations(parsedKey, maxValidSourceEpochSeen, maxValidTargetEpochSeen)
