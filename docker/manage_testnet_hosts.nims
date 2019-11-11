import
  strformat, ospaths, confutils

type
  Command = enum
    restart_nodes
    reset_network

  CliConfig = object
    network: string

    case cmd {.command.}: Command
    of restart_nodes:
      discard

    of reset_network:
      depositsDir {.
        defaultValue: "deposits"
        name: "deposits-dir" }: string

      networkDataDir {.
        defaultValue: "data"
        name: "network-data-dir" }: string

      totalValidators {.
        name: "total-validators" }: int

      totalUserValidators {.
        defaultValue: 0
        name: "user-validators" }: int

var conf = load CliConfig

var
  serverCount = 10
  instancesCount = 2
  systemValidators = conf.totalValidators - conf.totalUserValidators

let customValidatorAssignments = {
  "testnet0": proc (nodeIdx: int): int =
    if nodeidx < 4:
      systemValidators div 4
    else:
      0
}

proc findOrDefault[K, V](tupleList: openarray[(K, V)], key: K, default: V): V =
  for t in tupleList:
    if t[0] == key:
      return t[1]

  return default

let defaultValidatorAssignment = proc (nodeIdx: int): int =
  (systemValidators div serverCount) div instancesCount

iterator nodes: tuple[server, container: string, firstValidator, lastValidator: int] =
  var nextValidatorIdx = conf.totalUserValidators
  for i in 0 ..< serverCount:
    let
      nodeName = if i == 0: "master-01" else: &"node-0{i}"
      server = &"{nodeName}.do-ams3.nimbus.test.statusim.net"

    for j in 0 ..< instancesCount:
      let
        globalNodeIdx = i*instancesCount + j
        validatorAssignmentFn = customValidatorAssignments.findOrDefault(
          conf.network, defaultValidatorAssignment)
        nodeValidatorCount = validatorAssignmentFn(globalNodeIdx)

      yield (server,
             &"beacon-node-{conf.network}-{j+1}",
             nextValidatorIdx,
             nextValidatorIdx + nodeValidatorCount)

      inc nextValidatorIdx, nodeValidatorCount

case conf.cmd
of restart_nodes:
  for n in nodes():
    echo &"ssh {n.server} docker restart {n.container}"

of reset_network:
  for n in nodes():
    var
      keysList = ""
      networkDataFiles = conf.networkDataDir & "/{genesis.ssz,bootstrap_nodes.txt}"

    for i in n.firstValidator ..< n.lastValidator:
      let validatorKey = fmt"v{i:07}.privkey"
      keysList.add " "
      keysList.add conf.depositsDir / validatorKey

    let dockerPath = &"/docker/{n.container}/data/BeaconNode"
    echo &"echo Syncing {n.lastValidator - n.firstValidator} keys starting from {n.firstValidator} to container {n.container}@{n.server} ... && \\"
    echo &"  ssh {n.server} 'sudo rm -rf /tmp/nimbus && mkdir -p /tmp/nimbus/' && \\"
    echo &"  rsync {networkDataFiles} {n.server}:/tmp/nimbus/net-data/ && \\"
    if keysList.len > 0: echo &"  rsync {keysList} {n.server}:/tmp/nimbus/keys/ && \\"

    echo &"  ssh {n.server} 'sudo docker container stop {n.container} && " &
                         &"sudo mkdir -p {dockerPath}/validators && " &
                         &"sudo rm -rf {dockerPath}/validators/* && " &
                         &"sudo rm -rf {dockerPath}/db && " &
                         (if keysList.len > 0: &"sudo mv /tmp/nimbus/keys/* {dockerPath}/validators/ && " else: "") &
                         &"sudo mv /tmp/nimbus/net-data/* {dockerPath}/ && " &
                         &"sudo chown dockremap:docker -R {dockerPath}'"

