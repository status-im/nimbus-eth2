import
  confutils, strutils, strformat, os

const
  rootDir = thisDir() / ".."
  bootstrapTxtFileName = "bootstrap_nodes.txt"
  bootstrapYamlFileName = "boot_enr.yaml"
  depositContractFileName = "deposit_contract.txt"
  depositContractBlockFileName = "deposit_contract_block.txt"
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

cli do (skipGoerliKey {.
          desc: "Don't prompt for an Eth1 Goerli key to become a validator" .}: bool,

        specVersion {.
          desc: "Spec version"
          name: "spec" .}: string = "v0.11.3",

        constPreset {.
          desc: "The Ethereum 2.0 const preset of the network (optional)"
          name: "const-preset" .} = "",

        nodeID {.
          desc: "Node ID" .} = 0.int,

        basePort {.
          desc: "Base TCP/UDP port (nodeID will be added to it)" .} = 9000.int,

        baseMetricsPort {.
          desc: "Base metrics port (nodeID will be added to it)" .} = 8008.int,

        baseRpcPort {.
          desc: "Base rpc port (nodeID will be added to it)" .} = 9190.int,

        testnetName {.argument .}: string):
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
    genesisFileOpt = ""

  let
    testnetDir = allTestnetsDir / team / testnet
    genesisFilePath = testnetDir / genesisFile

  if not system.dirExists(testnetDir):
    echo &"No metadata files exists for the '{testnetName}' testnet"
    quit 1

  if system.fileExists(genesisFilePath):
    genesisFileOpt = &"--state-snapshot=\"{genesisFilePath}\""

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
  if not system.fileExists(preset):
    preset = constPreset
    if preset.len == 0: preset = "minimal"

  let
    dataDirName = testnetName.replace("/", "_")
                             .replace("(", "_")
                             .replace(")", "_") & "_" & $nodeID
    dataDir = buildDir / "data" / dataDirName
    validatorsDir = dataDir / "validators"
    secretsDir = dataDir / "secrets"
    beaconNodeBinary = buildDir / "beacon_node_" & dataDirName
  var
    nimFlags = &"-d:chronicles_log_level=TRACE -d:ETH2_SPEC={specVersion} " & getEnv("NIM_PARAMS")

  # write the logs to a file
  nimFlags.add """ -d:"chronicles_sinks=textlines,json[file(nbc""" & staticExec("date +\"%Y%m%d%H%M%S\"") & """.log)]" """

  let depositContractFile = testnetDir / depositContractFileName
  if system.fileExists(depositContractFile):
    depositContractOpt = "--deposit-contract=" & readFile(depositContractFile).strip

  let depositContractBlockFile = testnetDir / depositContractBlockFileName
  if system.fileExists(depositContractBlockFile):
    depositContractOpt.add " --deposit-contract-block=" & readFile(depositContractBlockFile).strip

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

  proc execIgnoringExitCode(s: string) =
    # reduces the error output when interrupting an external command with Ctrl+C
    try:
      exec s
    except OsError:
      discard

  cd rootDir
  mkDir dataDir

  # macOS may not have gnu-getopts installed and in the PATH
  execIgnoringExitCode &"""./scripts/make_prometheus_config.sh --nodes """ & $(1 + nodeID) & &""" --base-metrics-port {baseMetricsPort} --config-file "{dataDir}/prometheus.yml""""

  exec &"""nim c {nimFlags} -d:"const_preset={preset}" -o:"{beaconNodeBinary}" beacon_chain/beacon_node.nim"""

  if not skipGoerliKey and depositContractOpt.len > 0 and not system.dirExists(validatorsDir):
    mode = Silent
    echo "\nPlease enter your Goerli Eth1 private key in hex form (e.g. 0x1a2...f3c) in order to become a validator (you'll need access to 32 GoETH)."
    echo "Hit Enter to skip this."
    # is there no other way to print without a trailing newline?
    exec "printf '> '"
    let privKey = readLineFromStdin()
    if privKey.len > 0:
      mkDir validatorsDir
      mode = Verbose
      exec replace(&"""{beaconNodeBinary} deposits create
        --count=1
        --out-deposits-dir="{validatorsDir}"
        --out-secrets-dir="{secretsDir}"
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
    logLevelOpt = &"""--log-level="{logLevel}" """

  mode = Verbose
  cd dataDir
  execIgnoringExitCode replace(&"""{beaconNodeBinary}
    --data-dir="{dataDir}"
    --dump
    --web3-url={web3Url}
    --tcp-port=""" & $(basePort + nodeID) & &"""
    --udp-port=""" & $(basePort + nodeID) & &"""
    --metrics
    --metrics-port=""" & $(baseMetricsPort + nodeID) & &"""
    --rpc
    --rpc-port=""" & $(baseRpcPort + nodeID) & &"""
    {bootstrapFileOpt}
    {logLevelOpt}
    {depositContractOpt}
    {genesisFileOpt} """, "\n", " ")

