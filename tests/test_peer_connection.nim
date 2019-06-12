import
  unittest, os,
  chronos, confutils,
  ../beacon_chain/[conf, eth2_network]

template asyncTest*(name, body: untyped) =
  test name:
    proc scenario {.async.} = body
    waitFor scenario()

asyncTest "connect two nodes":
  let tempDir = getTempDir() / "peers_test"

  var c1 = BeaconNodeConf.defaults
  c1.dataDir = OutDir(tempDir / "node-1")

  var n1PersistentAddress = c1.getPersistenBootstrapAddr(
    parseIpAddress("127.0.0.1"), Port 50000)

  var n1 = await createEth2Node(c1)
  var n1ActualAddress = await n1.daemon.identity()

  echo "persistent: ", n1PersistentAddress
  echo "actual:", n1ActualAddress
  doAssert n1PersistentAddress == n1ActualAddress

  echo "Node 1 address: ", n1PersistentAddress
  echo "Press any key to continue"
  discard stdin.readLine()

  var c2 = BeaconNodeConf.defaults
  c2.dataDir = OutDir(tempDir / "node-2")
  var n2 = await createEth2Node(c2)

  await n2.connectToNetwork(bootstrapNodes = @[n1ActualAddress])

