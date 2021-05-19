# Nimbus
# Copyright (c) 2018 Status Research & Development GmbH
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
  stew/results,
  nimcrypto/utils,
  # Internal
  ../../beacon_chain/validators/[slashing_protection, slashing_protection_v2],
  ../../beacon_chain/spec/[datatypes, digest, crypto, presets],
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

func hexToDigest(hex: string): Eth2Digest =
  result = Eth2Digest.fromHex(hex)

proc sqlite3db_delete(basepath, dbname: string) =
  removeFile(basepath / dbname&".sqlite3-shm")
  removeFile(basepath / dbname&".sqlite3-wal")
  removeFile(basepath / dbname&".sqlite3")

const TestDir = ""
const TestDbName = "test_slashprot"

suite "Slashing Protection DB - Interchange" & preset():
  # https://hackmd.io/@sproul/Bk0Y0qdGD#Format-1-Complete
  # https://eips.ethereum.org/EIPS/eip-3076
  sqlite3db_delete(TestDir, TestDbName)

  test "Smoke test - Complete format" & preset():
    let genesis_validators_root = hexToDigest"0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
    block: # export
      let db = SlashingProtectionDB.init(
                genesis_validators_root,
                TestDir,
                TestDbName
              )
      defer:
        db.close()
        sqlite3db_delete(TestDir, TestDbName)

      let pubkey = ValidatorPubKey
                    .fromHex"0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed"
                    .get()
      check:
        db.db_v2.registerBlock(
          pubkey,
          Slot 81952,
          hexToDigest"0x4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b"
        ).isOk()
        # db.registerBlock(
        #   pubkey,
        #   Slot 81951,
        #   fakeRoot(65535)
        # )

        db.db_v2.registerAttestation(
          pubkey,
          source = Epoch 2290,
          target = Epoch 3007,
          hexToDigest"0x587d6a4f59a58fe24f406e0502413e77fe1babddee641fda30034ed37ecc884d"
        ).isOk()
        db.db_v2.registerAttestation(
          pubkey,
          source = Epoch 2290,
          target = Epoch 3008,
          fakeRoot(65535)
        ).isOk()

      db.exportSlashingInterchange(currentSourcePath.parentDir/"test_complete_export_slashing_protection.json")

    block: # import - zero root db
      let db2 = SlashingProtectionDB.init(
                Eth2Digest(),
                TestDir,
                TestDbName
              )
      defer:
        db2.close()
        sqlite3db_delete(TestDir, TestDbName)

      doAssert siSuccess == db2.importSlashingInterchange(currentSourcePath.parentDir/"test_complete_export_slashing_protection.json")
      db2.exportSlashingInterchange(currentSourcePath.parentDir/"test_complete_export_slashing_protection_roundtrip1.json")

    block: # import - same root db
      let db3 = SlashingProtectionDB.init(
                genesis_validators_root,
                TestDir,
                TestDbName
              )
      defer:
        db3.close()
        sqlite3db_delete(TestDir, TestDbName)

      doAssert siSuccess == db3.importSlashingInterchange(currentSourcePath.parentDir/"test_complete_export_slashing_protection.json")
      db3.exportSlashingInterchange(currentSourcePath.parentDir/"test_complete_export_slashing_protection_roundtrip2.json")

  test "Smoke test - Complete format - Invalid database is refused" & preset():
    block: # import - invalid root db
      let invalid_genvalroot = hexToDigest"0x1234"
      let db4 = SlashingProtectionDB.init(
                invalid_genvalroot,
                TestDir,
                TestDbName
              )
      defer:
        db4.close()
        sqlite3db_delete(TestDir, TestDbName)

      doAssert siFailure == db4.importSlashingInterchange(currentSourcePath.parentDir/"test_complete_export_slashing_protection.json")
