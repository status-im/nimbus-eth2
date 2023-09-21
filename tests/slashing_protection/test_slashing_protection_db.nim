# Nimbus
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  std/[os],
  # Status lib
  eth/db/[kvstore, kvstore_sqlite3],
  stew/[results, endians2],
  # Internal
  ../../beacon_chain/validators/slashing_protection,
  ../../beacon_chain/spec/[helpers],
  ../../beacon_chain/spec/datatypes/base,
  # Test utilies
  ../testutil

func fakeRoot(index: SomeInteger): Eth2Digest =
  ## Create fake roots
  ## Those are just the value serialized in big-endian
  ## We prevent zero hash special case via a power of 2 prefix
  result.data[0 ..< 8] = (1'u64 shl 32 + index.uint64).toBytesBE()

func fakeValidator(index: SomeInteger): ValidatorPubKey =
  ## Create fake validator public key
  result = ValidatorPubKey()
  result.blob[0 ..< 8] = (1'u64 shl 48 + index.uint64).toBytesBE()

proc sqlite3db_delete(basepath, dbname: string) =
  removeFile(basepath / dbname&".sqlite3-shm")
  removeFile(basepath / dbname&".sqlite3-wal")
  removeFile(basepath / dbname&".sqlite3")

const TestDir = ""
const TestDbName = "test_slashprot"

# Reminder of SQLite constraints for fake data:
# attestations:
# - all fields are NOT NULL
# - attestation_root is unique
# - (validator_id, target_epoch)
# blocks:
# - all fields are NOT NULL
# - block_root is unique
# - (validator_id, slot)

suite "Slashing Protection DB" & preset():
  test "Empty database" & preset():
    sqlite3db_delete(TestDir, TestDbName)
    let db = SlashingProtectionDB.init(ZERO_HASH, TestDir, TestDbName)
    defer:
      db.close()
      sqlite3db_delete(TestDir, TestDbName)

    check:
      db.checkSlashableBlockProposal(
        ValidatorIndex(1234),
        fakeValidator(1234),
        slot = Slot 1
      ).isOk()
      db.checkSlashableAttestation(
        ValidatorIndex(1234),
        fakeValidator(1234),
        source = Epoch 1,
        target = Epoch 2
      ).isOk()
      db.checkSlashableAttestation(
        ValidatorIndex(1234),
        fakeValidator(1234),
        source = Epoch 2,
        target = Epoch 1
      ).error.kind == TargetPrecedesSource

  test "SP for block proposal - linear append":
    sqlite3db_delete(TestDir, TestDbName)
    let db = SlashingProtectionDB.init(ZERO_HASH, TestDir, TestDbName)
    defer:
      db.close()
      sqlite3db_delete(TestDir, TestDbName)

    check:
      db.registerBlock(
        ValidatorIndex(100),
        fakeValidator(100),
        Slot 10,
        fakeRoot(100)
      ).isOk()
      db.registerBlock(
        ValidatorIndex(111),
        fakeValidator(111),
        Slot 15,
        fakeRoot(111)
      ).isOk()

      # Slot occupied by same validator
      db.checkSlashableBlockProposal(
        ValidatorIndex(100),
        fakeValidator(100),
        slot = Slot 10
      ).isErr()
      db.registerBlock(
        ValidatorIndex(100),
        fakeValidator(100),
        slot = Slot 10,
        fakeRoot(101)
      ).isErr()
      # Slot occupied by another validator
      db.checkSlashableBlockProposal(
        ValidatorIndex(100),
        fakeValidator(100),
        slot = Slot 15
      ).isOk()
      db.registerBlock(
        ValidatorIndex(100),
        fakeValidator(100),
        slot = Slot 15,
        fakeRoot(150)
      ).isOk()
      # Slot occupied by same validator
      db.checkSlashableBlockProposal(
        ValidatorIndex(111),
        fakeValidator(111),
        slot = Slot 15
      ).isErr()
      db.registerBlock(
        ValidatorIndex(111),
        fakeValidator(111),
        slot = Slot 15,
        fakeRoot(151)
      ).isErr()

      # Slot inoccupied
      db.checkSlashableBlockProposal(
        ValidatorIndex(255),
        fakeValidator(255),
        slot = Slot 20
      ).isOk()

      db.registerBlock(
        ValidatorIndex(255),
        fakeValidator(255),
        slot = Slot 20,
        fakeRoot(4321)
      ).isOk()

    check:
      # Slot now occupied
      db.checkSlashableBlockProposal(
        ValidatorIndex(255),
        fakeValidator(255),
        slot = Slot 20
      ).isErr()
      db.registerBlock(
        ValidatorIndex(255),
        fakeValidator(255),
        slot = Slot 20,
        fakeRoot(4322)
      ).isErr()

  test "SP for block proposal - backtracking append":
    sqlite3db_delete(TestDir, TestDbName)
    let db = SlashingProtectionDB.init(ZERO_HASH, TestDir, TestDbName)
    defer:
      db.close()
      sqlite3db_delete(TestDir, TestDbName)

    # last finalized block
    check:
      db.registerBlock(
        ValidatorIndex(0),
        fakeValidator(0),
        Slot 0,
        fakeRoot(0)
      ).isOk()

      db.registerBlock(
        ValidatorIndex(100),
        fakeValidator(100),
        Slot 10,
        fakeRoot(10)
      ).isOk()
      db.registerBlock(
        ValidatorIndex(100),
        fakeValidator(100),
        Slot 20,
        fakeRoot(20)
      ).isOk()
    for i in 0 ..< 30:
      let status = db.checkSlashableBlockProposal(
        ValidatorIndex(100),
        fakeValidator(100),
        Slot i
      )
      if i > 10 and i != 20: # MinSlotViolation and DupSlot
        doAssert status.isOk, "error: " & $status
      else:
        doAssert status.isErr, "error: " & $status
    check:
      db.registerBlock(
        ValidatorIndex(100),
        fakeValidator(100),
        Slot 15,
        fakeRoot(15)
      ).isOk()
    for i in 0 ..< 30:
      if i > 10 and i notin {15, 20}: # MinSlotViolation and DupSlot
        let status = db.checkSlashableBlockProposal(
          ValidatorIndex(100),
          fakeValidator(100),
          Slot i
        )
        doAssert status.isOk, "error: " & $status
      else:
        let status = db.checkSlashableBlockProposal(
          ValidatorIndex(100),
          fakeValidator(100),
          Slot i
        )
        doAssert status.isErr, "error: " & $status
        check:
          db.checkSlashableBlockProposal(
            ValidatorIndex(0xDEADBEEF),
            fakeValidator(0xDEADBEEF),
            Slot i
          ).isOk()
    check:
      db.registerBlock(
        ValidatorIndex(100),
        fakeValidator(100),
        Slot 12,
        fakeRoot(12)
      ).isOk()
      db.registerBlock(
        ValidatorIndex(100),
        fakeValidator(100),
        Slot 17,
        fakeRoot(17)
      ).isOk()
    for i in 0 ..< 30:
      if i > 10 and i notin {12, 15, 17, 20}:
        let status = db.checkSlashableBlockProposal(
          ValidatorIndex(100),
          fakeValidator(100),
          Slot i
        )
        doAssert status.isOk, "error: " & $status
      else:
        let status = db.checkSlashableBlockProposal(
          ValidatorIndex(100),
          fakeValidator(100),
          Slot i
        )
        doAssert status.isErr, "error: " & $status
        check:
          db.checkSlashableBlockProposal(
            ValidatorIndex(0xDEADBEEF),
            fakeValidator(0xDEADBEEF),
            Slot i
          ).isOk()
    check:
      db.registerBlock(
        ValidatorIndex(100),
        fakeValidator(100),
        Slot 29,
        fakeRoot(29)
      ).isOk()

    for i in 0 ..< 30:
      if i > 10 and i notin {12, 15, 17, 20, 29}:
        let status = db.checkSlashableBlockProposal(
          ValidatorIndex(100),
          fakeValidator(100),
          Slot i
        )
        doAssert status.isOk, "error: " & $status
      else:
        let status = db.checkSlashableBlockProposal(
          ValidatorIndex(100),
          fakeValidator(100),
          Slot i
        )
        doAssert status.isErr, "error: " & $status
        check:
          db.checkSlashableBlockProposal(
            ValidatorIndex(0xDEADBEEF),
            fakeValidator(0xDEADBEEF),
            Slot i
          ).isOk()

  test "SP for same epoch attestation target - linear append":
    sqlite3db_delete(TestDir, TestDbName)
    let db = SlashingProtectionDB.init(ZERO_HASH, TestDir, TestDbName)
    defer:
      db.close()
      sqlite3db_delete(TestDir, TestDbName)

    check:
      db.registerAttestation(
        ValidatorIndex(100),
        fakeValidator(100),
        Epoch 0, Epoch 10,
        fakeRoot(100)
      ).isOk()
      db.registerAttestation(
        ValidatorIndex(111),
        fakeValidator(111),
        Epoch 0, Epoch 15,
        fakeRoot(111)
      ).isOk()

      # Epoch occupied by same validator
      db.checkSlashableAttestation(
        ValidatorIndex(100),
        fakeValidator(100),
        Epoch 0, Epoch 10,
      ).error.kind == DoubleVote
      db.registerAttestation(
        ValidatorIndex(100),
        fakeValidator(100),
        Epoch 0, Epoch 10, fakeRoot(101)
      ).error.kind == DoubleVote

      # Epoch occupied by another validator
      db.checkSlashableAttestation(
        ValidatorIndex(100),
        fakeValidator(100),
        Epoch 0, Epoch 15
      ).isOk()
      db.registerAttestation(
        ValidatorIndex(100),
        fakeValidator(100),
        Epoch 0, Epoch 15, fakeRoot(151)
      ).isOk()

      # Epoch occupied by same validator
      db.checkSlashableAttestation(
        ValidatorIndex(111),
        fakeValidator(111),
        Epoch 0, Epoch 15
      ).error.kind == DoubleVote
      db.registerAttestation(
        ValidatorIndex(111),
        fakeValidator(111),
        Epoch 0, Epoch 15, fakeRoot(161)
      ).error.kind == DoubleVote

      # Epoch inoccupied
      db.checkSlashableAttestation(
        ValidatorIndex(255),
        fakeValidator(255),
        Epoch 0, Epoch 20
      ).isOk()
      db.registerAttestation(
        ValidatorIndex(255),
        fakeValidator(255),
        Epoch 0, Epoch 20, fakeRoot(4321)
      ).isOk()

      # Epoch now occupied
      db.checkSlashableAttestation(
        ValidatorIndex(255),
        fakeValidator(255),
        Epoch 0, Epoch 20
      ).error.kind == DoubleVote
      db.registerAttestation(
        ValidatorIndex(255),
        fakeValidator(255),
        Epoch 0, Epoch 20, fakeRoot(4322)
      ).error.kind == DoubleVote

  test "SP for surrounded attestations":
    block:
      sqlite3db_delete(TestDir, TestDbName)
      let db = SlashingProtectionDB.init(ZERO_HASH, TestDir, TestDbName)
      defer:
        db.close()
        sqlite3db_delete(TestDir, TestDbName)

      check:
        db.registerAttestation(
          ValidatorIndex(100),
          fakeValidator(100),
          Epoch 10, Epoch 20,
          fakeRoot(20)
        ).isOk()

        db.checkSlashableAttestation(
          ValidatorIndex(100),
          fakeValidator(100),
          Epoch 11, Epoch 19
        ).error.kind == SurroundVote
        db.checkSlashableAttestation(
          ValidatorIndex(200),
          fakeValidator(200),
          Epoch 11, Epoch 19
        ).isOk
        db.checkSlashableAttestation(
          ValidatorIndex(100),
          fakeValidator(100),
          Epoch 11, Epoch 21
        ).isOk

    block:
      sqlite3db_delete(TestDir, TestDbName)
      let db = SlashingProtectionDB.init(ZERO_HASH, TestDir, TestDbName)
      defer:
        db.close()
        sqlite3db_delete(TestDir, TestDbName)

      check:
        db.registerAttestation(
          ValidatorIndex(100),
          fakeValidator(100),
          Epoch 0, Epoch 1,
          fakeRoot(1)
        ).isOk()

        db.registerAttestation(
          ValidatorIndex(100),
          fakeValidator(100),
          Epoch 10, Epoch 20,
          fakeRoot(20)
        ).isOk()

        db.checkSlashableAttestation(
          ValidatorIndex(100),
          fakeValidator(100),
          Epoch 11, Epoch 19
        ).error.kind == SurroundVote
        db.checkSlashableAttestation(
          ValidatorIndex(200),
          fakeValidator(200),
          Epoch 11, Epoch 19
        ).isOk
        db.checkSlashableAttestation(
          ValidatorIndex(100),
          fakeValidator(100),
          Epoch 11, Epoch 21
        ).isOk
        # TODO: is that possible?
        db.checkSlashableAttestation(
          ValidatorIndex(100),
          fakeValidator(100),
          Epoch 9, Epoch 19
        ).isOk

  test "SP for surrounding attestations":
    block:
      sqlite3db_delete(TestDir, TestDbName)
      let db = SlashingProtectionDB.init(ZERO_HASH, TestDir, TestDbName)
      defer:
        db.close()
        sqlite3db_delete(TestDir, TestDbName)
      check:
        db.registerAttestation(
          ValidatorIndex(100),
          fakeValidator(100),
          Epoch 10, Epoch 20,
          fakeRoot(20)
        ).isOk()

        db.checkSlashableAttestation(
          ValidatorIndex(100),
          fakeValidator(100),
          Epoch 9, Epoch 21
        ).error.kind == SurroundVote
        db.checkSlashableAttestation(
          ValidatorIndex(100),
          fakeValidator(100),
          Epoch 0, Epoch 21
        ).error.kind == SurroundVote

    block:
      sqlite3db_delete(TestDir, TestDbName)
      let db = SlashingProtectionDB.init(ZERO_HASH, TestDir, TestDbName)
      defer:
        db.close()
        sqlite3db_delete(TestDir, TestDbName)

      check:
        db.registerAttestation(
         ValidatorIndex(100),
         fakeValidator(100),
          Epoch 0, Epoch 1,
          fakeRoot(1)
        ).isOk()

        db.registerAttestation(
          ValidatorIndex(100),
          fakeValidator(100),
          Epoch 10, Epoch 20,
          fakeRoot(20)
        ).isOk()

      check:
        db.checkSlashableAttestation(
          ValidatorIndex(100),
          fakeValidator(100),
          Epoch 9, Epoch 21
        ).error.kind == SurroundVote
        db.checkSlashableAttestation(
          ValidatorIndex(100),
          fakeValidator(100),
          Epoch 0, Epoch 21
        ).error.kind == SurroundVote

  test "Attestation ordering #1698":
    block:
      sqlite3db_delete(TestDir, TestDbName)
      let db = SlashingProtectionDB.init(ZERO_HASH, TestDir, TestDbName)
      defer:
        db.close()
        sqlite3db_delete(TestDir, TestDbName)

      check:
        db.registerAttestation(
          ValidatorIndex(100),
          fakeValidator(100),
          Epoch 1, Epoch 2,
          fakeRoot(2)
        ).isOk()

        db.registerAttestation(
          ValidatorIndex(100),
          fakeValidator(100),
          Epoch 8, Epoch 10,
          fakeRoot(10)
        ).isOk()

        db.registerAttestation(
          ValidatorIndex(100),
          fakeValidator(100),
          Epoch 14, Epoch 15,
          fakeRoot(15)
        ).isOk()

        # The current list is, 2 -> 10 -> 15

        db.registerAttestation(
          ValidatorIndex(100),
          fakeValidator(100),
          Epoch 3, Epoch 6,
          fakeRoot(6)
        ).isOk()

        # The current list is 2 -> 6 -> 10 -> 15

      check:
        db.checkSlashableAttestation(
          ValidatorIndex(100),
          fakeValidator(100),
          Epoch 7, Epoch 11
        ).error.kind == SurroundVote

  test "Test valid attestation #1699":
    block:
      sqlite3db_delete(TestDir, TestDbName)
      let db = SlashingProtectionDB.init(ZERO_HASH, TestDir, TestDbName)
      defer:
        db.close()
        sqlite3db_delete(TestDir, TestDbName)

      check:
        db.registerAttestation(
          ValidatorIndex(100),
          fakeValidator(100),
          Epoch 10, Epoch 20,
          fakeRoot(20)
        ).isOk()

        db.registerAttestation(
          ValidatorIndex(100),
          fakeValidator(100),
          Epoch 40, Epoch 50,
          fakeRoot(50)
        ).isOk()

      check:
        db.checkSlashableAttestation(
          ValidatorIndex(100),
          fakeValidator(100),
          Epoch 20, Epoch 30
        ).isOk

  test "Pruning blocks works":
    block:
      sqlite3db_delete(TestDir, TestDbName)
      let db = SlashingProtectionDB.init(ZERO_HASH, TestDir, TestDbName)
      defer:
        db.close()
        sqlite3db_delete(TestDir, TestDbName)

      db.registerBlock(
        ValidatorIndex(100),
        fakeValidator(100),
        Slot 10,
        fakeRoot(10)
      ).expect("registered block")
      db.registerBlock(
        ValidatorIndex(100),
        fakeValidator(100),
        Slot 1000,
        fakeRoot(20)
      ).expect("registered block")

      # After pruning, duplicate becomes a min slot violation
      doAssert db.checkSlashableBlockProposal(
        ValidatorIndex(100),
        fakeValidator(100),
        Slot 10,
      ).error.kind == DoubleProposal

      db.pruneAfterFinalization(
        epoch(Slot 1000)
      )

      doAssert db.checkSlashableBlockProposal(
        ValidatorIndex(100),
        fakeValidator(100),
        Slot 10,
      ).error.kind == MinSlotViolation

  test "Don't prune the very last block even by mistake":
    block:
      sqlite3db_delete(TestDir, TestDbName)
      let db = SlashingProtectionDB.init(ZERO_HASH, TestDir, TestDbName)
      defer:
        db.close()
        sqlite3db_delete(TestDir, TestDbName)

      db.registerBlock(
        ValidatorIndex(100),
        fakeValidator(100),
        Slot 10,
        fakeRoot(10)
      ).expect("registered block")
      db.registerBlock(
        ValidatorIndex(100),
        fakeValidator(100),
        Slot 1000,
        fakeRoot(20)
      ).expect("registered block")

      doAssert db.checkSlashableBlockProposal(
        ValidatorIndex(100),
        fakeValidator(100),
        Slot 1000,
      ).error.kind == DoubleProposal

      # Pruning far in the future
      db.pruneAfterFinalization(
        epoch(Slot 10000)
      )

      # Last block is still there
      doAssert db.checkSlashableBlockProposal(
        ValidatorIndex(100),
        fakeValidator(100),
        Slot 1000,
      ).error.kind == DoubleProposal

  test "Pruning attestations works":
    block:
      sqlite3db_delete(TestDir, TestDbName)
      let db = SlashingProtectionDB.init(ZERO_HASH, TestDir, TestDbName)
      defer:
        db.close()
        sqlite3db_delete(TestDir, TestDbName)


      db.registerAttestation(
        ValidatorIndex(100),
        fakeValidator(100),
        Epoch 10, Epoch 20,
        fakeRoot(20)
      ).expect("registered block")

      db.registerAttestation(
        ValidatorIndex(100),
        fakeValidator(100),
        Epoch 40, Epoch 50,
        fakeRoot(50)
      ).expect("registered block")

      # After pruning, duplicate becomes a min source epoch violation
      doAssert db.checkSlashableAttestation(
        ValidatorIndex(100),
        fakeValidator(100),
        Epoch 10, Epoch 20
      ).error.kind == DoubleVote

      # After pruning, surrounding vote becomes a min source epoch violation
      doAssert db.checkSlashableAttestation(
        ValidatorIndex(100),
        fakeValidator(100),
        Epoch 9, Epoch 21
      ).error.kind == SurroundVote

      # After pruning, surrounded vote becomes a min source epoch violation
      doAssert db.checkSlashableAttestation(
        ValidatorIndex(100),
        fakeValidator(100),
        Epoch 11, Epoch 19
      ).error.kind == SurroundVote

      # --------------------------------
      db.pruneAfterFinalization(
        Epoch 40
      )
      # --------------------------------

      doAssert db.checkSlashableAttestation(
        ValidatorIndex(100),
        fakeValidator(100),
        Epoch 10, Epoch 20
      ).error.kind == MinSourceViolation

      doAssert db.checkSlashableAttestation(
        ValidatorIndex(100),
        fakeValidator(100),
        Epoch 9, Epoch 21
      ).error.kind == MinSourceViolation

      doAssert db.checkSlashableAttestation(
        ValidatorIndex(100),
        fakeValidator(100),
        Epoch 11, Epoch 19
      ).error.kind == MinSourceViolation

      # TODO is it possible to actually trigger MinTargetViolation
      # given all the other constraints?

  test "Don't prune the very last attestation(s) even by mistake":
    block:
      sqlite3db_delete(TestDir, TestDbName)
      let db = SlashingProtectionDB.init(ZERO_HASH, TestDir, TestDbName)
      defer:
        db.close()
        sqlite3db_delete(TestDir, TestDbName)

      db.registerAttestation(
        ValidatorIndex(100),
        fakeValidator(100),
        Epoch 10, Epoch 20,
        fakeRoot(20)
      ).expect("registered block")

      db.registerAttestation(
        ValidatorIndex(100),
        fakeValidator(100),
        Epoch 40, Epoch 50,
        fakeRoot(50)
      ).expect("registered block")

      # --------------------------------
      db.pruneAfterFinalization(
        epoch(Slot 10000)
      )
      # --------------------------------

      doAssert db.checkSlashableAttestation(
        ValidatorIndex(100),
        fakeValidator(100),
        Epoch 40, Epoch 50
      ).error.kind == DoubleVote

      # TODO is it possible to actually to have
      # the MAX(SourceEpoch) and MAX(TargetEpoch)
      # on 2 different attestations
      # given all the other constraints?
