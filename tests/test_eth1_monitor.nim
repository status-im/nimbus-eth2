{.used.}

import
  unittest,
  chronos, web3/ethtypes,
  ../beacon_chain/eth1_monitor

suite "Eth1 Chain":
  discard

suite "Eth1 monitor":
  test "Rewrite HTTPS Infura URLs":
    var
      mainnetWssUrl = "wss://mainnet.infura.io/ws/v3/6224f3c792cc443fafb64e70a98f871e"
      mainnetHttpUrl = "http://mainnet.infura.io/v3/6224f3c792cc443fafb64e70a98f871e"
      mainnetHttpsUrl = "https://mainnet.infura.io/v3/6224f3c792cc443fafb64e70a98f871e"
      goerliWssUrl = "wss://goerli.infura.io/ws/v3/6224f3c792cc443fafb64e70a98f871e"
      goerliHttpUrl = "http://goerli.infura.io/v3/6224f3c792cc443fafb64e70a98f871e"
      goerliHttpsUrl = "https://goerli.infura.io/v3/6224f3c792cc443fafb64e70a98f871e"
      gethUrl = "ws://localhost:8545"

    fixupInfuraUrls mainnetWssUrl
    fixupInfuraUrls mainnetHttpUrl
    fixupInfuraUrls mainnetHttpsUrl
    fixupInfuraUrls goerliWssUrl
    fixupInfuraUrls goerliHttpUrl
    fixupInfuraUrls goerliHttpsUrl
    fixupInfuraUrls gethUrl

    check:
      mainnetWssUrl == "wss://mainnet.infura.io/ws/v3/6224f3c792cc443fafb64e70a98f871e"
      mainnetHttpUrl == mainnetWssUrl
      mainnetHttpsUrl == mainnetWssUrl

      goerliWssUrl == "wss://goerli.infura.io/ws/v3/6224f3c792cc443fafb64e70a98f871e"
      goerliHttpUrl == goerliWssUrl
      goerliHttpsUrl == goerliWssUrl

      gethUrl == "ws://localhost:8545"

