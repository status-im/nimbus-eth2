import
  confutils, strutils, strformat, os

const
  rootDir = thisDir() / ".."
  bootstrapFile = "bootstrap_nodes.txt"
  depositContractFile = "deposit_contract.txt"
  genesisFile = "genesis.ssz"
  configFile = "config.yaml"
  testnetsRepo = "eth2-testnets"

let
  testnetsOrg = getEnv("ETH2_TESTNETS_ORG", "eth2-clients")
  testnetsGitUrl = getEnv("ETH2_TESTNETS_GIT_URL", "https://github.com/" & testnetsOrg & "/" & testnetsRepo)

mode = Verbose

proc validateTestnetName(parts: openarray[string]): auto =
  if parts.len != 2:
    echo "The testnet name should have the format `client/network-name`"
    quit 1
  (parts[0], parts[1])

cli do (testnetName {.argument.}: string):
  let
    nameParts = testnetName.split "/"
    (team, testnet) = if nameParts.len > 1: validateTestnetName nameParts
                      else: ("nimbus", testnetName)

  let
    buildDir = rootDir / "build"
    allTestnetsDir = buildDir / testnetsRepo

  rmDir(allTestnetsDir)
  cd buildDir
  exec &"git clone --quiet --depth=1 {testnetsGitUrl}"

  let testnetDir = allTestnetsDir / team / testnet
  if not system.dirExists(testnetDir):
    echo &"No metadata files exists for the '{testnetName}' testnet"
    quit 1

  proc checkRequiredFile(fileName: string) =
    let filePath = testnetDir / fileName
    if not system.fileExists(filePath):
      echo &"The required file {fileName} is not present in '{testnetDir}'."
      quit 1

  checkRequiredFile bootstrapFile
  checkRequiredFile genesisFile

  var preset = testnetDir / configFile
  if not system.fileExists(preset): preset = "minimal"

  let
    dataDirName = testnetName.replace("/", "_")
    dataDir = buildDir / "data" / dataDirName
    beaconNodeBinary = buildDir / "beacon_node_" & dataDirName
    nimFlags = "-d:chronicles_log_level=DEBUG " & getEnv("NIM_PARAMS")

  var depositContractOpt = ""
  let depositContractFile = testnetDir / depositContractFile
  if system.fileExists(depositContractFile):
    depositContractOpt = "--deposit-contract=" & readFile(depositContractFile).strip

  if system.dirExists(dataDir):
    if system.fileExists(dataDir/genesisFile):
      let localGenesisContent = readFile(dataDir/genesisFile)
      let testnetGenesisContent = readFile(testnetDir/genesisFile)
      if localGenesisContent != testnetGenesisContent:
        echo "Detected testnet restart. Deleting previous database..."
        rmDir dataDir

  cd rootDir
  exec &"""nim c {nimFlags} -d:"const_preset={preset}" -o:"{beaconNodeBinary}" beacon_chain/beacon_node.nim"""
  exec replace(&"""{beaconNodeBinary}
    --data-dir="{dataDir}"
    --bootstrap-file="{testnetDir/bootstrapFile}"
    --state-snapshot="{testnetDir/genesisFile}" """ & depositContractOpt, "\n", " ")

