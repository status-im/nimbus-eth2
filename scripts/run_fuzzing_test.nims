# beacon_chain
# Copyright (c) 2020-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import std/os except dirExists
import
  std/[sequtils, strformat],
  confutils, testutils/fuzzing_engines

const
  gitRoot = thisDir() / ".."
  fuzzingTestsDir = gitRoot / "tests" / "fuzzing"

cli do (testname {.argument.}: string,
        fuzzer = defaultFuzzingEngine):

  let fuzzingTestDir = fuzzingTestsDir / testname

  if not dirExists(fuzzingTestDir):
    echo "Cannot find a fuzz test directory named '", testname, "' in ", fuzzingTestsDir
    quit 1

  let nimFiles = listFiles(fuzzingTestDir).filterIt(splitFile(it).ext == ".nim")
  if nimFiles.len != 1:
    echo "The fuzzing test dir '" & fuzzingTestDir & "' should contain exactly one Nim file"
    quit 1

  let
    corpusDir = fuzzingTestDir / "corpus"
    testProgram = nimFiles[0]

  exec &"""ntu fuzz --fuzzer={fuzzer} --corpus="{corpusDir}" "{testProgram}" """
