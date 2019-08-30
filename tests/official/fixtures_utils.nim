# beacon_chain
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  os, strutils,
  # Status libs
  stew/byteutils,
  serialization, json_serialization

export  # Workaround:
  #   - https://github.com/status-im/nim-serialization/issues/4
  #   - https://github.com/status-im/nim-serialization/issues/5
  #   - https://github.com/nim-lang/Nim/issues/11225
  serialization.readValue

# Process current EF test format (up to 0.8.2+)
# ---------------------------------------------

# #######################
# JSON deserialization

proc readValue*(r: var JsonReader, a: var seq[byte]) {.inline.} =
  ## Custom deserializer for seq[byte]
  a = hexToSeqByte(r.readValue(string))

# #######################
# Test helpers

const
  FixturesDir* = currentSourcePath.rsplit(DirSep, 1)[0] / "fixtures"
  JsonTestsDir* = FixturesDir / "json_tests_v0.8.3"

proc parseTest*(jsonPath: string, T: typedesc): T =
  try:
    # debugEcho "          [Debug] Loading file: \"", jsonPath, '\"'
    result = Json.loadFile(jsonPath, T)
  except SerializationError as err:
    writeStackTrace()
    stderr.write "Json load issue for file \"", jsonPath, "\"\n"
    stderr.write err.formatMsg(jsonPath), "\n"
    quit 1
