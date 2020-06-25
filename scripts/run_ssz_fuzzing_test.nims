import os except dirExists
import strformat, confutils
import testutils/fuzzing_engines

const
  gitRoot = thisDir() / ".."
  fixturesDir = gitRoot / "vendor" / "nim-eth2-scenarios" / "tests-v0.11.3" / "mainnet" / "phase0" / "ssz_static"

  fuzzingTestsDir = gitRoot / "tests" / "fuzzing"
  fuzzingCorpusesDir = fuzzingTestsDir / "corpus"

  fuzzNims = gitRoot / "vendor" / "nim-testutils" / "testutils" / "fuzzing" / "fuzz.nims"

cli do (testname {.argument.}: string,
        fuzzer = defaultFuzzingEngine):

  if not dirExists(fixturesDir):
    echo "Please run `make test` first in order to download the official ETH2 test vectors"
    quit 1

  if not dirExists(fixturesDir / testname):
    echo testname, " is not a recognized SSZ type name (type names are case-sensitive)"
    quit 1

  let corpusDir = fuzzingCorpusesDir / testname

  rmDir corpusDir
  mkDir corpusDir

  var inputIdx = 0
  template nextInputName: string =
    inc inputIdx
    "input" & $inputIdx

  for file in walkDirRec(fixturesDir / testname):
    if splitFile(file).ext == ".ssz":
      # TODO Can we create hard links here?
      cpFile file, corpusDir / nextInputName()

  let testProgram = fuzzingTestsDir / &"ssz_decode_{testname}.nim"

  exec &"""ntu fuzz --fuzzer={fuzzer} --corpus="{corpusDir}" "{testProgram}" """

