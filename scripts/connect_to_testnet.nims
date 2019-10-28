import
  confutils, strutils, strformat, ospaths

const
  rootDir = thisDir() / ".."
  bootstrapFile = "bootstrap_nodes.txt"
  depositContractFile = "deposit_contract.txt"
  genesisFile = "genesis.ssz"
  configFile = "config.yaml"
  clientsOrg = "zah" # "eth2-clients"
  testnetsRepo = "eth2-testnets"
  testnetsRepoGitUrl = "git://github.com/" & clientsOrg & "/" & testnetsRepo

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

  if not dirExists(allTestnetsDir):
    cd buildDir
    exec &"git clone {testnetsRepoGitUrl}"

  cd allTestnetsDir
  exec &"git remote set-url origin {testnetsRepoGitUrl}"
  exec "git reset --hard master"
  exec "git pull"

  let testnetDir = allTestnetsDir / team / testnet
  if not dirExists(testnetDir):
    echo &"No metadata files exists for the '{testnetName}' testnet"
    quit 1

  proc checkRequiredFile(fileName: string) =
    let filePath = testnetDir / fileName
    if not fileExists(filePath):
      echo &"The required file {fileName} is not present in '{testnetDir}'."
      quit 1

  checkRequiredFile bootstrapFile
  checkRequiredFile depositContractFile
  checkRequiredFile genesisFile

  var preset = testnetDir / configFile
  if not fileExists(preset): preset = "minimal"

  let
    depositContract = readFile(testnetDir / depositContractFile).strip
    dataDirName = testnetName.replace("/", "_")
    dataDir = buildDir / "data" / dataDirName
    beaconNodeBinary = buildDir / "beacon_node_" & dataDirName
    nimFlags = "-d:release --lineTrace:on -d:chronicles_log_level=DEBUG"

  cd rootDir
  exec &"""nim c {nimFlags} -d:"const_preset={preset}" -o:"{beaconNodeBinary}" beacon_chain/beacon_node.nim"""
  exec replace(&"""{beaconNodeBinary}
    --data-dir="{dataDir}"
    --bootstrap-file="{testnetDir/bootstrapFile}"
    --state-snapshot="{testnetDir/genesisFile}"
    --deposit-contract={depositContract}""", "\n", " ")

