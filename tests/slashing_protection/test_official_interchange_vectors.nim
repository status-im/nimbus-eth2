# Nimbus
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  std/[os],
  # Status lib
  stew/[results, byteutils],
  nimcrypto/utils,
  chronicles,
  # Internal
  ../../beacon_chain/validators/[slashing_protection, slashing_protection_v2],
  ../../beacon_chain/spec/[datatypes, digest, crypto, presets],
  # Test utilies
  ../testutil, ../testdbutil,
  ../official/fixtures_utils

type
  TestInterchange = object
    name: string
      ## Name of the test case
    genesis_validators_root: Eth2Digest0x
      ## Genesis validator root to use when creating the empty DB
      ## or to compare the import against
    steps: seq[TestStep]

  TestStep = object
    should_succeed: bool
      ## Is "interchange" given a valid import
    allow_partial_import: bool
      ## Does "interchange" contain slashable data either as standalone
      ## or with regards to previous steps
    interchange: SPDIR
    blocks: seq[CandidateBlock]
      ## Blocks to try as proposer after DB is imported
    attestations: seq[CandidateVote]
      ## Attestations to try as validator after DB is imported

  CandidateBlock = object
    pubkey: PubKey0x
    slot: SlotString
    signing_root: Eth2Digest0x
    should_succeed: bool

  CandidateVote = object
    pubkey: PubKey0x
    source_epoch: EpochString
    target_epoch: EpochString
    signing_root: Eth2Digest0x
    should_succeed: bool

func toHexLogs(v: CandidateBlock): auto =
  (
    pubkey: v.pubkey.PubKeyBytes.toHex(),
    slot: $v.slot.Slot.shortLog(),
    signing_root: v.signing_root.Eth2Digest.data.toHex(),
    should_succeed: v.should_succeed
  )
func toHexLogs(v: CandidateVote): auto =
  (
    pubkey: v.pubkey.PubKeyBytes.toHex(),
    source_epoch: v.source_epoch.Epoch.shortLog(),
    target_epoch: v.target_epoch.Epoch.shortLog(),
    signing_root: v.signing_root.Eth2Digest.data.toHex(),
    should_succeed: v.should_succeed
  )

chronicles.formatIt CandidateBlock: it.toHexLogs
chronicles.formatIt CandidateVote: it.toHexLogs

proc sqlite3db_delete(basepath, dbname: string) =
  removeFile(basepath / dbname&".sqlite3-shm")
  removeFile(basepath / dbname&".sqlite3-wal")
  removeFile(basepath / dbname&".sqlite3")

const InterchangeTestsDir = FixturesDir / "tests-slashing-v5.0.0" / "generated"
const TestDir = ""
const TestDbPrefix = "test_slashprot_"

proc statusOkOrDuplicateOrMinSlotViolation(
       status: Result[void, BadProposal], candidate: CandidateBlock): bool =
  # 1. We might be importing a duplicate which EIP-3076 allows
  #    there is no reason during normal operation to integrate
  #    a duplicate so checkSlashableBlockProposal would have rejected it.
  # 2. The last test "multiple_interchanges_single_validator_single_message_gap"
  #    requires implementing pruning in-between import to keep the
  #    MinSlotViolation check relevant.
  #    That check prevents duplicate because it doesn't keep history.
  #
  # We need to special-case those exceptions to pass all tests
  if status.isOk:
    return true
  if status.error.kind == DoubleProposal and
      candidate.signing_root.Eth2Digest != Eth2Digest() and
      status.error.existingBlock == candidate.signing_root.Eth2Digest:
    warn "Block already exists in the DB",
      candidateBlock = candidate
    return true
  elif status.error.kind == MinSlotViolation:
    # Note: we tested the codepath without pruning.
    # Furthermore it's better to be to eager on MinSlotViolation
    # than allow slashing (unless the MinSlot is too far in the future)
    warn "Block violates low watermark requirement. It's likely a duplicate though.",
      candidateBlock = candidate,
      error = status.error
    return true
  return false

proc statusOkOrDuplicateOrMinEpochViolation(
       status: Result[void, BadVote], candidate: CandidateVote): bool =
  # We might be importing a duplicate which EIP-3076 allows
  # there is no reason during normal operation to integrate
  # a duplicate so checkSlashableAttestation would have rejected it.
  # We special-case that for imports.
  if status.isOk:
    return true
  if status.error.kind == DoubleVote and
      candidate.signing_root.Eth2Digest != Eth2Digest() and
      status.error.existingAttestation == candidate.signing_root.Eth2Digest:
    warn "Attestation already exists in the DB",
      candidateAttestation = candidate
    return true
  elif status.error.kind in {MinSourceViolation, MinTargetViolation}:
    # Note: we tested the codepath without pruning.
    # Furthermore it's better to be to eager on MinSlotViolation
    # than allow slashing (unless the MinSlot is too far in the future)
    warn "Attestation violates low watermark requirement. It's likely a duplicate though.",
      candidateAttestation = candidate,
      error = status.error
    return true
  return false

proc runTest(identifier: string) =

  # The tests produce a lot of log noise
  echo "\n\n===========================================\n\n"


  let testCase = InterchangeTestsDir / identifier
  test "Slashing test: " & identifier:
    let t = parseTest(InterchangeTestsDir/identifier, Json, TestInterchange)

    # Create a test specific DB
    let dbname = TestDbPrefix & identifier.changeFileExt("")

    # Delete existing db in case of previous test failure
    sqlite3db_delete(TestDir, dbname)

    let db = SlashingProtectionDB.init(
      Eth2Digest t.genesis_validators_root,
      TestDir,
      dbname
    )
    # We don't use defer to auto-close+delete the DB
    # as in case of issue we want to keep the DB around for investigation.

    for step in t.steps:
      let status = db.inclSPDIR(step.interchange)
      if not step.should_succeed:
        doAssert siFailure == status,
          "Unexpected error:\n" &
          "    " & $status & "\n"
      elif step.allow_partial_import:
        doAssert siPartial == status,
          "Unexpected error:\n" &
          "    " & $status & "\n"
      else:
        doAssert siSuccess == status,
          "Unexpected error:\n" &
          "    " & $status & "\n"

      for blck in step.blocks:
        let status = db.db_v2.checkSlashableBlockProposal(none(ValidatorIndex),
          ValidatorPubKey.fromRaw(blck.pubkey.PubKeyBytes).get(),
          Slot blck.slot
        )
        if blck.should_succeed:
          doAssert status.statusOkOrDuplicateOrMinSlotViolation(blck),
            "Unexpected error:\n" &
            "    " & $status & "\n" &
            "    for " & $toHexLogs(blck)
        else:
          doAssert status.isErr(),
            "Unexpected success:\n" &
            "    " & $status & "\n" &
            "    for " & $toHexLogs(blck)

      for att in step.attestations:
        let status = db.db_v2.checkSlashableAttestation(none(ValidatorIndex),
          ValidatorPubKey.fromRaw(att.pubkey.PubKeyBytes).get(),
          Epoch att.source_epoch,
          Epoch att.target_epoch
        )
        if att.should_succeed:
          doAssert status.statusOkOrDuplicateOrMinEpochViolation(att),
            "Unexpected error:\n" &
            "    " & $status & "\n" &
            "    for " & $toHexLogs(att)
        else:
          doAssert status.isErr(),
            "Unexpected success:\n" &
            "    " & $status & "\n" &
            "    for " & $toHexLogs(att)

    # Now close and delete resources.
    db.close()
    sqlite3db_delete(TestDir, dbname)


suite "Slashing Interchange tests " & preset():
  for kind, path in walkDir(InterchangeTestsDir, true):
    runTest(path)
