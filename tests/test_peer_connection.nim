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
  var n1 = await createEth2Node(c1)
  var n1Address = getPersistenBootstrapAddr(c1, parseIpAddress("127.0.0.1"), Port 50000)

  var c2 = BeaconNodeConf.defaults
  c2.dataDir = OutDir(tempDir / "node-2")
  var n2 = await createEth2Node(c2)

  await n2.connectToNetwork(bootstrapNodes = @[n1Address])

