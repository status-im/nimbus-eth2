# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Import/export the validator slashing protection database

import
  std/[os, strutils],
  confutils,
  eth/db/[kvstore, kvstore_sqlite3],
  ../beacon_chain/validator_slashing_protection,
  ../beacon_chain/spec/digest

type
  SlashProtCmd = enum
    dump = "Dump the validator slashing protection DB to json"
    restore = "Restore the validator slashing protection DB from json"

  SlashProtConf = object

    case cmd {.
      command,
      desc: "Dump database or restore" .}: SlashProtCmd
    of dump, restore:
      infile {.argument.}: string
      outfile {.argument.}: string

proc doDump(conf: SlashProtConf) =
  let (dir, file) = splitPath(conf.infile)
  # TODO: Make it read-only https://github.com/status-im/nim-eth/issues/312
  # TODO: why is sqlite3 always appending .sqlite3 ?
  let filetrunc = file.changeFileExt("")
  let rawDB = SqStoreRef.init(dir, filetrunc, readOnly = false).tryGet()
  let db = SlashingProtectionDB.load(kvStore rawDB)
  db.toSPDIF(conf.outfile)

when isMainModule:
  let conf = SlashProtConf.load()

  case conf.cmd:
  of dump: conf.doDump()
  of restore: doAssert false, "unimplemented"
