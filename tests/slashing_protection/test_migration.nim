# Nimbus
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  std/[os],
  # Status lib
  eth/db/kvstore,
  stew/results,
  nimcrypto/utils,
  serialization,
  json_serialization,
  # Internal
  ../../beacon_chain/validators/[
    slashing_protection,
    slashing_protection_v1
  ],
  ../../beacon_chain/spec/[datatypes, digest, crypto, presets],
  # Test utilies
  ../testutil

template wrappedTimedTest(name: string, body: untyped) =
  # `check` macro takes a copy of whatever it's checking, on the stack!
  block: # Symbol namespacing
    proc wrappedTest() =
      test name:
        body
    wrappedTest()

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
const TestDbName = "t_slashprot_migration"

suite "Slashing Protection DB - v1 and v2 migration" & preset():
  # https://eips.ethereum.org/EIPS/eip-3076
  sqlite3db_delete(TestDir, TestDbName)

  wrappedTimedTest "Minimal format migration" & preset():
    let genesis_validators_root = hexToDigest"0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
    block: # export from a v1 DB
      let db = SlashingProtectionDB_v1.init(
                genesis_validators_root,
                TestDir,
                TestDbName
              )

      let pubkey = ValidatorPubKey
                    .fromHex"0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed"
                    .get()
      db.registerBlock(
        pubkey,
        Slot 81952,
        Eth2Digest()
      )

      db.registerAttestation(
        pubkey,
        source = Epoch 2290,
        target = Epoch 3007,
        Eth2Digest()
      )

      let spdir = db.toSPDIR_lowWatermark()
      Json.saveFile(
        currentSourcePath.parentDir/"t_migration_slashing_protection_v1.json",
        spdir,
        pretty = true
      )

      db.close()

    block: # Reopen as the new version
      let db = SlashingProtectionDB.init(
                genesis_validators_root,
                TestDir,
                TestDbName
              )

      # Check that v2 as been initialized (private field :/)
      # doAssert: db.db_v2.getMetadataTable_DbV2().get() == genesis_validators_root

      db.exportSlashingInterchange(
        currentSourcePath.parentDir/"t_migration_slashing_protection_migrated.json"
      )

      doAssert sameFileContent(
        currentSourcePath.parentDir/"t_migration_slashing_protection_v1.json",
        currentSourcePath.parentDir/"t_migration_slashing_protection_migrated.json"
      )
