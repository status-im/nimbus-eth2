# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Common routines for a BeaconNode and a BeaconValidator node

import
  # Standard library
  os, tables, random, strutils,

  # Nimble packages
  chronos,
  chronicles, chronicles/helpers as chroniclesHelpers,

  # Local modules
  spec/[datatypes, crypto],
  conf,
  block_pool, eth2_network

const
  genesisFile* = "genesis.ssz"

proc getStateFromSnapshot*(conf: BeaconNodeConf|ValidatorClientConf): NilableBeaconStateRef =
  var
    genesisPath = conf.dataDir/genesisFile
    snapshotContents: TaintedString
    writeGenesisFile = false

  if conf.stateSnapshot.isSome:
    let
      snapshotPath = conf.stateSnapshot.get.string
      snapshotExt = splitFile(snapshotPath).ext

    if cmpIgnoreCase(snapshotExt, ".ssz") != 0:
      error "The supplied state snapshot must be a SSZ file",
            suppliedPath = snapshotPath
      quit 1

    snapshotContents = readFile(snapshotPath)
    if fileExists(genesisPath):
      let genesisContents = readFile(genesisPath)
      if snapshotContents != genesisContents:
        error "Data directory not empty. Existing genesis state differs from supplied snapshot",
              dataDir = conf.dataDir.string, snapshot = snapshotPath
        quit 1
    else:
      debug "No previous genesis state. Importing snapshot",
            genesisPath, dataDir = conf.dataDir.string
      writeGenesisFile = true
      genesisPath = snapshotPath
  else:
    try:
      snapshotContents = readFile(genesisPath)
    except CatchableError as err:
      error "Failed to read genesis file", err = err.msg
      quit 1

  result = try:
    newClone(SSZ.decode(
      toOpenArrayByte(snapshotContents, 0, snapshotContents.high), BeaconState))
  except SerializationError:
    error "Failed to import genesis file", path = genesisPath
    quit 1

  info "Loaded genesis state", path = genesisPath

  if writeGenesisFile:
    try:
      notice "Writing genesis to data directory", path = conf.dataDir/genesisFile
      writeFile(conf.dataDir/genesisFile, snapshotContents.string)
    except CatchableError as err:
      error "Failed to persist genesis file to data dir",
        err = err.msg, genesisFile = conf.dataDir/genesisFile
      quit 1

proc setupMainProc*(logLevel: string) =
  when compiles(defaultChroniclesStream.output.writer):
    defaultChroniclesStream.output.writer =
      proc (logLevel: LogLevel, msg: LogOutputStr) {.gcsafe, raises: [Defect].} =
        try:
          stdout.write(msg)
        except IOError as err:
          logLoggingFailure(cstring(msg), err)

  randomize()

  try:
    let directives = logLevel.split(";")
    try:
      setLogLevel(parseEnum[LogLevel](directives[0]))
    except ValueError:
      raise (ref ValueError)(msg: "Please specify one of TRACE, DEBUG, INFO, NOTICE, WARN, ERROR or FATAL")

    if directives.len > 1:
      for topicName, settings in parseTopicDirectives(directives[1..^1]):
        if not setTopicState(topicName, settings.state, settings.logLevel):
          warn "Unrecognized logging topic", topic = topicName
  except ValueError as err:
    stderr.write "Invalid value for --log-level. " & err.msg
    quit 1

template ctrlCHandling*(extraCode: untyped) =
  ## Ctrl+C handling
  proc controlCHandler() {.noconv.} =
    when defined(windows):
      # workaround for https://github.com/nim-lang/Nim/issues/4057
      setupForeignThreadGc()
    info "Shutting down after having received SIGINT"
    extraCode
  setControlCHook(controlCHandler)
