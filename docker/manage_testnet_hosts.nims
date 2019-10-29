import
  strformat, ospaths

var
  serverCount = 10
  instancesCount = 2

  totalValidators = 1000
  userValidators = 200

  systemValidators = totalValidators - userValidators
  validatorsPerServer = systemValidators div serverCount
  validatorsPerNode = validatorsPerServer div instancesCount

if paramCount() < 4:
  echo "Usage: nim --verbosity:0 manage_testnet_hosts.nim NETWORK COMMAND"
  quit 1

let
  network = paramStr(3)
  cmd = paramStr(4)

iterator nodes: tuple[server, container: string, firstValidator, lastValidator: int] =
  for i in 0 ..< serverCount:
    let
      baseIdx = userValidators + i * validatorsPerServer
      nodeName = if i == 0: "master-01" else: &"node-0{i}"
      server = &"{nodeName}.do-ams3.nimbus.test.statusim.net"

    for j in 1 .. instancesCount:
      let firstIdx = baseIdx + j * validatorsPerNode
      let lastIdx = firstIdx + validatorsPerNode - 1
      yield (server, &"beacon-node-{network}-{j}", firstIdx, lastIdx)

case cmd
of "restart-nodes":
  for n in nodes():
    echo &"ssh {n.server} docker restart {n.container}"

of "redist-validators":
  let depositsDir = paramStr(5)
  for n in nodes():
    var keysList = ""
    for i in n.firstValidator..n.lastValidator:
      let validatorKey = fmt"v{i:07}.privkey"
      keysList.add " "
      keysList.add depositsDir / validatorKey

    let dockerPath = &"/docker/{n.container}/data/BeaconNode/{network}"
    echo &"rsync {keysList} {n.server}:/tmp/nimbus-keys"
    echo &"ssh {n.server} 'sudo mkdir -p {dockerPath}/validators && sudo rm -f {dockerPath}/validators/* && " &
                         &"sudo mv /tmp/nimbus-keys/* {dockerPath}/validators/ && " &
                         &"sudo chown dockremap:docker -R {dockerPath}'"
else:
  echo "Unrecognized command: ", cmd
