import
  strformat, os, confutils, algorithm, sequtils

type
  Command = enum
    restart_nodes
    reset_network

  CliConfig = object
    network: string

    validatorsDir {.
      defaultValue: "validators"
      name: "validators-dir" }: string

    case cmd {.command.}: Command
    of restart_nodes:
      discard

    of reset_network:
      secretsDir {.
        defaultValue: "secrets"
        name: "secrets-dir" }: string

      networkDataDir {.
        defaultValue: "data"
        name: "network-data-dir" }: string

      totalUserValidators {.
        defaultValue: 0
        name: "user-validators" }: int

  Node = object
    id: int
    server: string
    container: string

var conf = load CliConfig

var
  serverCount = 6
  instancesCount = 1
  validators = listDirs(conf.validatorsDir).mapIt(splitPath(it)[1])

sort(validators)

proc findOrDefault[K, V](tupleList: openarray[(K, V)], key: K, default: V): V =
  for t in tupleList:
    if t[0] == key:
      return t[1]

  return default

iterator nodes: Node =
  for i in 0 ..< serverCount:
    let
      serverShortName = if i == 0: "master-01" else: &"node-0{i}"
      server = &"{serverShortName}.aws-eu-central-1a.nimbus.test.statusim.net"

    for j in 0 ..< instancesCount:
      yield Node(id: i*instancesCount + j,
                 server: server,
                 container: &"beacon-node-{conf.network}-{j+1}")

iterator validatorAssignments: tuple[node: Node; firstValidator, lastValidator: int] =
  let
    systemValidators = validators.len - conf.totalUserValidators

    defaultValidatorAssignment = proc (nodeIdx: int): int =
      (systemValidators div serverCount) div instancesCount

    customValidatorAssignments = {
      # This is used just to force the correct type of the table
      "default": defaultValidatorAssignment
      ,
      "testnet0": proc (nodeIdx: int): int =
        if nodeidx < 4:
          systemValidators div 4
        else:
          0
      ,
      "testnet1": proc (nodeIdx: int): int =
        if nodeidx < 4:
          systemValidators div 4
        else:
          0
    }

  var nextValidatorIdx = conf.totalUserValidators
  for node in nodes():
    let
      validatorAssignmentFn = customValidatorAssignments.findOrDefault(
        conf.network, defaultValidatorAssignment)
      nodeValidatorCount = validatorAssignmentFn(node.id)

    yield (node,
           nextValidatorIdx,
           nextValidatorIdx + nodeValidatorCount)

    inc nextValidatorIdx, nodeValidatorCount

case conf.cmd
of restart_nodes:
  for n in nodes():
    if n.id mod 2 == 0:
      echo &"echo Pulling container image on {n.server} ..."
      # This will only print one line: "docker.io/statusteam/nimbus_beacon_node:testnet1".
      echo &"ssh {n.server} docker pull -q statusteam/nimbus_beacon_node:{conf.network}"
    echo &"echo Starting container {n.container}@{n.server} ..."
    # docker-compose will rebuild the container if it detects a newer image.
    # Prints: "Recreating beacon-node-testnet1-1 ... done".
    echo &"ssh {n.server} 'cd /docker/{n.container} && docker-compose --compatibility up -d'"

of reset_network:
  for n, firstValidator, lastValidator in validatorAssignments():
    var
      validatorDirs = ""
      secretFiles = ""
      networkDataFiles = conf.networkDataDir & "/{genesis.ssz,bootstrap_nodes.txt}"

    for i in firstValidator ..< lastValidator:
      validatorDirs.add " "
      validatorDirs.add conf.validatorsDir / validators[i]
      secretFiles.add " "
      secretFiles.add conf.secretsDir / validators[i]

    let dockerPath = &"/docker/{n.container}/data/BeaconNode"
    echo &"echo Syncing {lastValidator - firstValidator} keys starting from {firstValidator} to container {n.container}@{n.server} ... && \\"
    echo &"  ssh {n.server} 'sudo rm -rf /tmp/nimbus && mkdir -p /tmp/nimbus/{{net-data,validators,secrets}}' && \\"
    echo &"  rsync -a -zz {networkDataFiles} {n.server}:/tmp/nimbus/net-data/ && \\"
    if validators.len > 0:
      echo &"  rsync -a -zz {validatorDirs} {n.server}:/tmp/nimbus/validators/ && \\"
      echo &"  rsync -a -zz {secretFiles} {n.server}:/tmp/nimbus/secrets/ && \\"

    echo &"  ssh {n.server} 'sudo docker container stop {n.container}; " &
                         &"sudo rm -rf {dockerPath}/{{db,validators,secrets,net-data}}* && " &
                         &"sudo mv /tmp/nimbus/* {dockerPath}/ && " &
                         &"sudo chown dockremap:docker -R {dockerPath}'"

