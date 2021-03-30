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
  serialization, json_serialization,
  eth/db/[kvstore, kvstore_sqlite3],
  ../beacon_chain/validators/slashing_protection,
  ../beacon_chain/spec/digest

type
  SlashProtCmd = enum
    dump = "Dump the validator slashing protection DB to json"
    restore = "Restore the validator slashing protection DB from json"

  SlashProtConf = object

    db{.desc: "The path to the database .sqlite3 file" .}: string

    case cmd {.
      command,
      desc: "Dump database to or restore from a slashing interchange file" .}: SlashProtCmd
    of dump:
      outfile {.argument.}: string
    of restore:
      infile {.argument.}: string

proc doDump(conf: SlashProtConf) =
  let (dir, file) = splitPath(conf.db)
  # TODO: Make it read-only https://github.com/status-im/nim-eth/issues/312
  # TODO: why is sqlite3 always appending .sqlite3 ?
  let filetrunc = file.changeFileExt("")
  let db = SlashingProtectionDB.loadUnchecked(dir, filetrunc, readOnly = false)
  db.exportSlashingInterchange(conf.outfile)
  echo "Export finished: '", conf.db, "' into '", conf.outfile, "'"

proc doRestore(conf: SlashProtConf) =
  let (dir, file) = splitPath(conf.db)
  # TODO: Make it read-only https://github.com/status-im/nim-eth/issues/312
  # TODO: why is sqlite3 always appending .sqlite3 ?
  let filetrunc = file.changeFileExt("")

  var spdir: SPDIR
  try:
    spdir = JSON.loadFile(conf.infile, SPDIR)
  except SerializationError as err:
    writeStackTrace()
    stderr.write $JSON & " load issue for file \"", conf.infile, "\"\n"
    stderr.write err.formatMsg(conf.infile), "\n"
    quit 1

  # Open DB and handle migration from v1 to v2 if needed
  let db = SlashingProtectionDB.init(
    genesis_validators_root = Eth2Digest spdir.metadata.genesis_validators_root,
    basePath = dir,
    dbname = filetrunc,
    modes = {kCompleteArchiveV2},
    disagreementBehavior = kChooseV2
  )

  # Now import the slashing interchange file
  # Failures mode:
  # - siError can only happen with invalid genesis_validators_root which would be caught above
  # - siPartial can happen for invalid public keys, slashable blocks, slashable votes
  let status = db.inclSPDIR(spdir)
  doAssert status in {siSuccess, siPartial}

  echo "Import finished: '", conf.infile, "' into '", conf.db, "'"
  # TODO: do we mention that v2 MUST be used?
  #       normally this has always been a hidden option.

when isMainModule:
  let conf = SlashProtConf.load()

  case conf.cmd:
  of dump: conf.doDump()
  of restore: conf.doRestore()
