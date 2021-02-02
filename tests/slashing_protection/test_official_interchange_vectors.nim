# Nimbus
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  std/[unittest, os],
  # Status lib
  stew/results,
  nimcrypto/utils,
  # Internal
  ../../beacon_chain/validator_protection/[slashing_protection_types, slashing_protection],
  ../../beacon_chain/spec/[datatypes, digest, crypto, presets],
  # Test utilies
  ../testutil,
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

proc sqlite3db_delete(basepath, dbname: string) =
  removeFile(basepath/ dbname&".sqlite3-shm")
  removeFile(basepath/ dbname&".sqlite3-wal")
  removeFile(basepath/ dbname&".sqlite3")

const InterchangeTestsDir = FixturesDir / "tests-slashing-v5.0.0" / "generated"
const TestDir = ""
const TestDbPrefix = "test_slashprot_"

proc runTest(identifier: string) =
  let testCase = InterchangeTestsDir / identifier
  timedTest "Slashing test: " & identifier:
    let t = parseTest(InterchangeTestsDir/identifier, Json, TestInterchange)

    # Create a test specific DB
    let dbname = TestDbPrefix & identifier.changeFileExt("")
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
        doAssert siFailure == status
      elif step.allow_partial_import:
        doAssert siPartial == status
      else:
        doAssert siSuccess == status

      for blck in step.blocks:
        let status = db.checkSlashableBlockProposal(
          ValidatorPubKey.fromRaw(blck.pubkey.PubKeyBytes).get(),
          Slot blck.slot
        )
        if step.should_succeed:
          doAssert status.isOk()
        else:
          doAssert status.isErr()

      for att in step.attestations:
        let status = db.checkSlashableAttestation(
          ValidatorPubKey.fromRaw(att.pubkey.PubKeyBytes).get(),
          Epoch att.source_epoch,
          Epoch att.target_epoch
        )
        if step.should_succeed:
          doAssert status.isOk()
        else:
          doAssert status.isErr()

    # Now close and delete resources.
    db.close()
    sqlite3db_delete(TestDir, dbname)


suiteReport "Slashing Interchange tests " & preset():
  for kind, path in walkDir(InterchangeTestsDir, true):
    runTest(path)
