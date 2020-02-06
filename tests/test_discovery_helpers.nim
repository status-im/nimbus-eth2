import
  net, unittest, testutil,
  eth/keys, eth/p2p/enode, libp2p/multiaddress,
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

  timedTest "ENR to ENode":
    let enr = "enr:-Iu4QPONEndy6aWOJLWBaCLS1KRg7YPeK0qptnxJzuBW8OcFP9tLgA_ewmAvHBzn9zPG6XIgdH83Mq_5cyLF5yWRYmYBgmlkgnY0gmlwhDaZ6cGJc2VjcDI1NmsxoQK-9tWOso2Kco7L5L-zKoj-MwPfeBbEP12bxr9bqzwZV4N0Y3CCIyiDdWRwgiMo"
    let enrParsed = parseBootstrapAddress(enr)

    check:
      enrParsed.isOk
      $enrParsed.value.address.ip == "193.233.153.54"
      enrParsed.value.address.tcpPort == Port(9000)
      $enrParsed.value.pubkey == "bef6d58eb28d8a728ecbe4bfb32a88fe3303df7816c43f5d9bc6bf5bab3c19571012d3dd5ab492b1b0d2b42e32ce32f6bafc1075dbaaabe1fa6be711be7a992a"

