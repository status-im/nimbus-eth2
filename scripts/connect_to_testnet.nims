import
  confutils, strutils, strformat, os

const
  rootDir = thisDir() / ".."
  bootstrapTxtFileName = "bootstrap_nodes.txt"
  bootstrapYamlFileName = "boot_enr.yaml"
  depositContractFileName = "deposit_contract.txt"
  genesisFile = "genesis.ssz"
  configFile = "config.yaml"
  testnetsRepo = "eth2-testnets"
  web3Url = "wss://goerli.infura.io/ws/v3/809a18497dd74102b5f37d25aae3c85a"

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

  var
    depositContractOpt = ""
    bootstrapFileOpt = ""

  let testnetDir = allTestnetsDir / team / testnet
  if not system.dirExists(testnetDir):
    echo &"No metadata files exists for the '{testnetName}' testnet"
    quit 1

  proc checkRequiredFile(fileName: string) =
    let filePath = testnetDir / fileName
    if not system.fileExists(filePath):
      echo &"The required file {fileName} is not present in '{testnetDir}'."
      quit 1

  checkRequiredFile genesisFile

  let bootstrapTxtFile = testnetDir / bootstrapTxtFileName
  if system.fileExists(bootstrapTxtFile):
    bootstrapFileOpt = &"--bootstrap-file=\"{bootstrapTxtFile}\""
  else:
    let bootstrapYamlFile = testnetDir / bootstrapYamlFileName
    if system.fileExists(bootstrapYamlFile):
      bootstrapFileOpt = &"--enr-bootstrap-file=\"{bootstrapYamlFile}\""
    else:
      echo "Warning: the network metadata doesn't include a bootstrap file"

  var preset = testnetDir / configFile
  if not system.fileExists(preset): preset = "minimal"

  let
    dataDirName = testnetName.replace("/", "_")
                             .replace("(", "_")
                             .replace(")", "_")
    dataDir = buildDir / "data" / dataDirName
    validatorsDir = dataDir / "validators"
    dumpDir = dataDir / "dump"
    beaconNodeBinary = buildDir / "beacon_node_" & dataDirName
  var
    nimFlags = "-d:chronicles_log_level=TRACE " & getEnv("NIM_PARAMS")

  let depositContractFile = testnetDir / depositContractFileName
  if system.fileExists(depositContractFile):
    depositContractOpt = "--deposit-contract=" & readFile(depositContractFile).strip

  if system.dirExists(dataDir):
    block resetDataDir:
      # We reset the testnet data dir if the existing data dir is
      # incomplete (it misses a genesis file) or if it has a genesis
      # file from an older testnet:
      if system.fileExists(dataDir/genesisFile):
        let localGenesisContent = readFile(dataDir/genesisFile)
        let testnetGenesisContent = readFile(testnetDir/genesisFile)
        if localGenesisContent == testnetGenesisContent:
          break
      echo "Detected testnet restart. Deleting previous database..."
      rmDir dataDir

  cd rootDir
  if testnet == "testnet1":
    nimFlags &= " -d:NETWORK_TYPE=libp2p"
  exec &"""nim c {nimFlags} -d:"const_preset={preset}" -o:"{beaconNodeBinary}" beacon_chain/beacon_node.nim"""

  mkDir dumpDir

  proc execIgnoringExitCode(s: string) =
    # reduces the error output when interrupting an external command with Ctrl+C
    try:
      exec s
    except OsError:
      discard

  if depositContractOpt.len > 0 and not system.dirExists(validatorsDir):
    mode = Silent
    echo "\nPlease enter your Goerli Eth1 private key in hex form (e.g. 0x1a2...f3c) in order to become a validator (you'll need access to 32 GoETH)."
    echo "Hit Enter to skip this."
    # is there no other way to print without a trailing newline?
    exec "printf '> '"
    let privKey = readLineFromStdin()
    if privKey.len > 0:
      mkDir validatorsDir
      mode = Verbose
      execIgnoringExitCode replace(&"""{beaconNodeBinary} makeDeposits
        --random-deposits=1
        --deposits-dir="{validatorsDir}"
        --deposit-private-key={privKey}
        --web3-url={web3Url}
        {depositContractOpt}
        """, "\n", " ")
      mode = Silent
      echo "\nDeposit sent, wait for confirmation then press enter to continue"
      discard readLineFromStdin()

  let logLevel = getEnv("LOG_LEVEL")
  var logLevelOpt = ""
  if logLevel.len > 0:
    logLevelOpt = "--log-level=" & logLevel

  mode = Verbose
  execIgnoringExitCode replace(&"""{beaconNodeBinary}
    --data-dir="{dataDir}"
    --dump=true
    --web3-url={web3Url}
    {bootstrapFileOpt}
    {logLevelOpt}
    --state-snapshot="{testnetDir/genesisFile}" """ & depositContractOpt, "\n", " ")

