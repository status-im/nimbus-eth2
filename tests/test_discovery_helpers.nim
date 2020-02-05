import
  net, unittest, testutil,
  eth/p2p/enode, libp2p/multiaddress,
  ../beacon_chain/eth2_discovery

suite "Discovery v5 utilities":
  timedTest "Multiaddress to ENode":
    let addrStr = "/ip4/178.128.140.61/tcp/9000/p2p/16Uiu2HAmL5A5DAiiupFi6sUTF6Zq1TCKf6Pd5T8oFt9opQJqLqTQ"
    let ma = MultiAddress.init addrStr
    let enode = ma.toENode

    check:
      enode.isOk
      enode.value.address.tcpPort == Port(9000)
      $enode.value.address.ip == "178.128.140.61"
      enode.value.toMultiAddressStr == addrStr

