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
  web3Url = "wss://goerli.infura.io/ws/v3/6224f3c792cc443fafb64e70a98f871e"

let
  testnetsOrg = getEnv("ETH2_TESTNETS_ORG", "eth2-clients")
  testnetsGitUrl = getEnv("ETH2_TESTNETS_GIT_URL", "https://github.com/" & testnetsOrg & "/" & testnetsRepo)

mode = Verbose

proc validateTestnetName(parts: openarray[string]): auto =
  if parts.len != 2:
    echo "The testnet name should have the format `client/network-name`"
    quit 1
  (parts[0], parts[1])

# reduces the error output when interrupting an external command with Ctrl+C
proc execIgnoringExitCode(s: string) =
  try:
    exec s
  except OsError:
    discard

proc updateTestnetsRepo(allTestnetsDir, buildDir: string) =
  rmDir(allTestnetsDir)
  let cwd = system.getCurrentDir()
  cd buildDir
  exec &"git clone --quiet --depth=1 {testnetsGitUrl}"
  cd cwd

proc makePrometheusConfig(nodeID, baseMetricsPort: int, dataDir: string) =
  # macOS may not have gnu-getopts installed and in the PATH
  execIgnoringExitCode &"""./scripts/make_prometheus_config.sh --nodes """ & $(1 + nodeID) & &""" --base-metrics-port {baseMetricsPort} --config-file "{dataDir}/prometheus.yml""""

proc buildNode(nimFlags, preset, beaconNodeBinary: string) =
  exec &"""nim c {nimFlags} -d:"const_preset={preset}" -o:"{beaconNodeBinary}" beacon_chain/beacon_node.nim"""

proc becomeValidator(validatorsDir, beaconNodeBinary, secretsDir, depositContractOpt, privateGoerliKey: string,
                    becomeValidatorOnly: bool) =
  mode = Silent
  var privKey = privateGoerliKey

  if privKey.len == 0:
    echo "\nPlease enter your Goerli Eth1 private key in hex form (e.g. 0x1a2...f3c) in order to become a validator (you'll need access to 32 GoETH)."
    echo "Hit Enter to skip this."
    # is there no other way to print without a trailing newline?
    exec "printf '> '"
    privKey = readLineFromStdin()

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
    if becomeValidatorOnly:
      echo "\nDeposit sent."
    else:
      echo "\nDeposit sent, wait for confirmation then press enter to continue"
      discard readLineFromStdin()

proc runNode(dataDir, beaconNodeBinary, bootstrapFileOpt, depositContractOpt,
             genesisFileOpt, extraBeaconNodeOptions: string,
             basePort, nodeID, baseMetricsPort, baseRpcPort: int,
             printCmdOnly: bool) =
  let logLevel = getEnv("LOG_LEVEL")
  var logLevelOpt = ""
  if logLevel.len > 0:
    logLevelOpt = &"""--log-level="{logLevel}" """

  mode = Verbose

  var cmd: string
  if printCmdOnly:
    # When you reinvent getopt() and you forget to support repeating the same
    # option to overwrite the old value...
    cmd = replace(&"""{beaconNodeBinary}
      --data-dir="{dataDir}"
      --web3-url={web3Url}
      {bootstrapFileOpt}
      {depositContractOpt}
      {genesisFileOpt} """, "\n", " ")
    echo &"cd {dataDir}; exec {cmd}"
  else:
    cd dataDir
    cmd = replace(&"""{beaconNodeBinary}
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
      {genesisFileOpt}
      {extraBeaconNodeOptions}""", "\n", " ")
    execIgnoringExitCode cmd

cli do (skipGoerliKey {.
          desc: "Don't prompt for an Eth1 Goerli key to become a validator" .}: bool,

        privateGoerliKey {.
          desc: "Use this private Eth1 Goerli key to become a validator (careful with this option, the private key will end up in your shell's command history)" .} = "",

        specVersion {.
          desc: "Spec version"
          name: "spec" .} = "v0.11.3",

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

        extraBeaconNodeOptions {.
          desc: "Extra options to pass to our beacon_node instance" .} = "",

        writeLogFile {.
          desc: "Write a log file in dataDir" .} = true,

        buildOnly {.
          desc: "Just the build, please." .} = false,

        becomeValidatorOnly {.
          desc: "Just become a validator." .} = false,

        runOnly {.
          desc: "Just run it." .} = false,

        printCmdOnly {.
          desc: "Just print the commands (suitable for passing to 'eval'; might replace current shell)." .} = false,

        testnetName {.argument .}: string):
  let
    nameParts = testnetName.split "/"
    (team, testnet) = if nameParts.len > 1: validateTestnetName nameParts
                      else: ("nimbus", testnetName)

  let
    buildDir = rootDir / "build"
    allTestnetsDir = buildDir / testnetsRepo

  if not (runOnly or becomeValidatorOnly):
    updateTestnetsRepo(allTestnetsDir, buildDir)

  var
    depositContractOpt = ""
    bootstrapFileOpt = ""
    genesisFileOpt = ""
    doBuild, doBecomeValidator, doRun = true

  # step-skipping logic
  if skipGoerliKey:
    doBecomeValidator = false
  if buildOnly:
    doBecomeValidator = false
    doRun = false
  if becomeValidatorOnly:
    doBuild = false
    doRun = false
  if runOnly:
    doBuild = false
    doBecomeValidator = false

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
      bootstrapFileOpt = &"--bootstrap-file=\"{bootstrapYamlFile}\""
    else:
      echo "Warning: the network metadata doesn't include a bootstrap file"

  var preset = testnetDir / configFile
  if not system.fileExists(preset):
    preset = constPreset
    if preset.len == 0: preset = "minimal"

  doAssert specVersion in ["v0.11.3", "v0.12.1"]

  let
    dataDirName = testnetName.replace("/", "_")
                             .replace("(", "_")
                             .replace(")", "_") & "_" & $nodeID
    dataDir = buildDir / "data" / dataDirName
    validatorsDir = dataDir / "validators"
    secretsDir = dataDir / "secrets"
    beaconNodeBinary = buildDir / "beacon_node_" & dataDirName
  var
    nimFlags = &"-d:chronicles_log_level=TRACE " & getEnv("NIM_PARAMS")

  if writeLogFile:
    # write the logs to a file
    nimFlags.add """ -d:"chronicles_sinks=textlines,json[file(nbc""" & staticExec("date +\"%Y%m%d%H%M%S\"") & """.log)]" """

  let depositContractFile = testnetDir / depositContractFileName
  if system.fileExists(depositContractFile):
    depositContractOpt = "--deposit-contract=" & readFile(depositContractFile).strip

  let depositContractBlockFile = testnetDir / depositContractBlockFileName
  if system.fileExists(depositContractBlockFile):
    depositContractOpt.add " --deposit-contract-block=" & readFile(depositContractBlockFile).strip

  cd rootDir
  mkDir dataDir

  if doBuild:
    makePrometheusConfig(nodeID, baseMetricsPort, dataDir)
    buildNode(nimFlags, preset, beaconNodeBinary)

  if doBecomeValidator and depositContractOpt.len > 0 and not system.dirExists(validatorsDir):
    becomeValidator(validatorsDir, beaconNodeBinary, secretsDir, depositContractOpt, privateGoerliKey, becomeValidatorOnly)

  echo &"extraBeaconNodeOptions = '{extraBeaconNodeOptions}'"

  if doRun:
    runNode(dataDir, beaconNodeBinary, bootstrapFileOpt, depositContractOpt,
            genesisFileOpt, extraBeaconNodeOptions,
            basePort, nodeID, baseMetricsPort, baseRpcPort,
            printCmdOnly)
