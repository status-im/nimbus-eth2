import os except dirExists
import
  sequtils, strformat,
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

