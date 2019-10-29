import
  strformat, ospaths, confutils

type
  Command = enum
    restart_nodes
    redist_validators

  CliConfig = object
    network: string

    case cmd {.command.}: Command
    of restart_nodes:
      discard

    of redist_validators:
      depositsDir {.
        longform: "deposits-dir" }: string
      networkDataDir {.
        longform: "network-data-dir"}: string
      totalValidators {.
        longform: "total-validators" }: int
      totalUserValidators {.
        longform: "user-validators" }: int

var conf = load CliConfig

var
  serverCount = 10
  instancesCount = 2

  systemValidators = conf.totalValidators - conf.totalUserValidators
  validatorsPerServer = systemValidators div serverCount
  validatorsPerNode = validatorsPerServer div instancesCount

iterator nodes: tuple[server, container: string, firstValidator, lastValidator: int] =
  for i in 0 ..< serverCount:
    let
      baseIdx = conf.totalUserValidators + i * validatorsPerServer
      nodeName = if i == 0: "master-01" else: &"node-0{i}"
      server = &"{nodeName}.do-ams3.nimbus.test.statusim.net"

    for j in 0 ..< instancesCount:
      let firstIdx = baseIdx + j * validatorsPerNode
      let lastIdx = firstIdx + validatorsPerNode - 1
      yield (server, &"beacon-node-{conf.network}-{j+1}", firstIdx, lastIdx)

case conf.cmd
of restart_nodes:
  for n in nodes():
    echo &"ssh {n.server} docker restart {n.container}"

of redist_validators:
  for n in nodes():
    var
      keysList = ""
      networkDataFiles = conf.networkDataDir & "/{genesis.ssz,bootstrap_nodes.txt}"

    for i in n.firstValidator..n.lastValidator:
      let validatorKey = fmt"v{i:07}.privkey"
      keysList.add " "
      keysList.add conf.depositsDir / validatorKey

    let dockerPath = &"/docker/{n.container}/data/BeaconNode"
    echo &"echo Distributing keys {n.firstValidator}..{n.lastValidator} to container {n.container}@{n.server} ... && \\"
    echo &"  ssh {n.server} 'sudo rm -rf /tmp/nimbus && mkdir -p /tmp/nimbus' && \\"
    echo &"  rsync {networkDataFiles} {n.server}:/tmp/nimbus/net-data/ && \\"
    echo &"  rsync {keysList} {n.server}:/tmp/nimbus/keys/ && \\"
    echo &"  ssh {n.server} 'sudo mkdir -p {dockerPath}/validators && sudo rm -f {dockerPath}/validators/* && " &
                         &"sudo mv /tmp/nimbus/keys/* {dockerPath}/validators/ && " &
                         &"sudo mv /tmp/nimbus/net-data/* {dockerPath}/ && " &
                         &"sudo chown dockremap:docker -R {dockerPath}'"

