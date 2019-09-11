import
  strformat

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
  for n in nodes():
    let dockerPath = &"/docker/{n.container}/data/BeaconNode/{network}"
    echo &"ssh {n.server} 'sudo mkdir -p {dockerPath}/validators && sudo rm -f {dockerPath}/validators/* && " &
                         &"sudo ~/nimbus/vendor/nim-beacon-chain/scripts/download_validator_keys.sh {network} {n.firstValidator} {n.lastValidator} {dockerPath} && " &
                         &"sudo chown dockremap:docker -R {dockerPath}'"
else:
  echo "Unrecognized command: ", cmd
