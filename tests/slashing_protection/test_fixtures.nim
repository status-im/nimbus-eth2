# Nimbus
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Status lib
  stew/results,
  chronicles,
  # Internal
  ../../beacon_chain/validators/[slashing_protection, slashing_protection_v2],
  ../../beacon_chain/spec/datatypes/base,
  # Test utilies
  ../testutil, ../testdbutil,
  ../consensus_spec/fixtures_utils

from std/os import changeFileExt, removeFile, walkDir, `/`
from stew/byteutils import toHex

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
    contains_slashable_data: bool
      ## Does "interchange" contain slashable data either as standalone
      ## or with regards to previous steps
      ## If contains_slashable_data is false, then the given interchange must be imported
      ## successfully, and the given block/attestation checks must pass.
      ## If contains_slashable_data is true, then implementations have the option to do one of two
      ## things:
      ##     - Import the interchange successfully, working around the slashable data by minification
      ##       or some other mechanism. If the import succeeds, all checks must pass and the test
      ##       should continue to the next step.
      ##     - Reject the interchange (or partially import it), in which case the block/attestation
      ##       checks and all future steps should be ignored.
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
    should_succeed_complete: bool

  CandidateVote = object
    pubkey: PubKey0x
    source_epoch: EpochString
    target_epoch: EpochString
    signing_root: Eth2Digest0x
    should_succeed: bool
    should_succeed_complete: bool

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

const InterchangeTestsDir = FixturesDir / "tests-slashing-v5.3.0" / "tests" / "generated"
const TestDir = ""
const TestDbPrefix = "test_slashprot_"

proc statusOkOrDuplicateOrMinSlotViolation(
       status: Result[void, BadProposal], candidate: CandidateBlock): bool =
  # 1. We might be importing a duplicate which EIP-3076 allows
  #    there is no reason during normal operation to integrate
  #    a duplicate so checkSlashableBlockProposal would have rejected it.
  # 2. The test "multiple_interchanges_single_validator_single_message_gap"
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
    warn "Block violates low watermark requirement. It might be an already pruned block.",
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
    warn "Attestation violates low watermark requirement. It might be an already pruned attestation.",
      candidateAttestation = candidate,
      error = status.error
    return true
  return false

proc runTest(identifier: string) =

  # The tests produce a lot of log noise
  # echo "\n\n===========================================\n\n"

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
    elif step.contains_slashable_data:
      doAssert status in {siPartial, siSuccess},
        "Unexpected error:\n" &
        "    " & $status & "\n"
    else:
      doAssert siSuccess == status,
        "Unexpected error:\n" &
        "    " & $status & "\n"

    for blck in step.blocks:
      let pubkey = ValidatorPubKey.fromRaw(blck.pubkey.PubKeyBytes).get()
      let status = db.db_v2.checkSlashableBlockProposal(
        Opt.none(ValidatorIndex),
        pubkey,
        Slot blck.slot
      )
      if blck.should_succeed:
        doAssert status.statusOkOrDuplicateOrMinSlotViolation(blck),
          "Unexpected error:\n" &
          "    " & $status & "\n" &
          "    for " & $toHexLogs(blck)

        # https://github.com/eth-clients/slashing-protection-interchange-tests/pull/14
        # Successful blocks are to be incoporated in the DB
        if status.isOk(): # Skip duplicates
          let status = db.db_v2.registerBlock(
            Opt.none(ValidatorIndex),
            pubkey, Slot blck.slot,
            Eth2Digest blck.signing_root
          )
          doAssert status.isOk(),
            "Failure to register block: " & $status

      else:
        doAssert status.isErr(),
          "Unexpected success:\n" &
          "    status: " & $status & "\n" &
          "    for " & $toHexLogs(blck)

    for att in step.attestations:
      let pubkey = ValidatorPubKey.fromRaw(att.pubkey.PubKeyBytes).get()

      let status = db.db_v2.checkSlashableAttestation(Opt.none(ValidatorIndex),
        pubkey,
        Epoch att.source_epoch,
        Epoch att.target_epoch
      )
      if att.should_succeed:
        doAssert status.statusOkOrDuplicateOrMinEpochViolation(att),
          "Unexpected error:\n" &
          "    " & $status & "\n" &
          "    for " & $toHexLogs(att)

        # https://github.com/eth-clients/slashing-protection-interchange-tests/pull/14
        # Successful attestations are to be incoporated in the DB
        if status.isOk(): # Skip duplicates
          let status = db.db_v2.registerAttestation(
            Opt.none(ValidatorIndex),
            pubkey,
            Epoch att.source_epoch,
            Epoch att.target_epoch,
            Eth2Digest att.signing_root
          )
          doAssert status.isOk(),
            "Failure to register attestation: " & $status
      else:
        doAssert status.isErr(),
          "Unexpected success:\n" &
          "    " & $status & "\n" &
          "    for " & $toHexLogs(att)

  # Now close and delete resources.
  db.close()
  sqlite3db_delete(TestDir, dbname)

suite "Slashing Interchange tests " & preset():
  for kind, path in walkDir(
      InterchangeTestsDir, relative = true, checkDir = true):
    test "Slashing test: " & path:

      if path == "single_validator_source_greater_than_target_surrounded.json":
        # TODO: test relying on invalid behavior source > target
        skip()
      elif path == "single_validator_source_greater_than_target_surrounding.json":
        # TODO: test relying on unclear minification behavior:
        #       creating an invalid minified attestation with source > target
        #       or setting target = max(source, target)
        skip()
      elif path == "single_validator_resign_attestation.json":
        # It's simpler to just disallow register an attestation twice for the same (source, target)
        # rather than also checking the actual signing_root
        skip()
      else:
        runTest(path)
