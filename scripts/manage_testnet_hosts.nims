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

  network = "testnet0"

type
  ContainerCmd = enum
    restart
    stop

iterator containers: tuple[cmd: ContainerCmd, node, container: string, firstValidator, lastValidator: int] =
  for i in 0 ..< serverCount:
    let baseIdx = userValidators + i * validatorsPerServer
    for j in 1 .. instancesCount:
      let firstIdx = baseIdx + j * validatorsPerNode
      let lastIdx = firstIdx + validatorsPerNode - 1
      yield (restart, &"nimbus-node-0{i}", &"beacon-node-{network}-{j}", firstIdx, lastIdx)

when false:
  for i in 0 ..< serverCount:
    let baseIdx = userValidators + i * validatorsPerServer
    for j in 1 .. instancesCount:
      let firstIdx = baseIdx + (j - 1) * validatorsPerNode
      let lastIdx = firstIdx + validatorsPerNode - 1
      let dockerPath = &"/docker/beacon-node-{network}-{j}/data/BeaconNode/{network}"

      echo &"ssh nimbus-node-0{i} 'sudo mkdir -p {dockerPath}/validators && sudo rm -f {dockerPath}/validators/* && " &
                                 &"sudo ~/nimbus/vendor/nim-beacon-chain/scripts/download_validator_keys.sh {network} {firstIdx} {lastIdx} {dockerPath} && " &
                                 &"sudo chown dockremap:docker -R {dockerPath}'"

for c in containers():
  echo &"ssh {c.node} docker {c.cmd} {c.container}"

