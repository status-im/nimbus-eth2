{.used.}

import
  unittest2,
  chronos, web3/ethtypes,
  ssz_serialization/types as sszTypes,
  ../beacon_chain/spec/datatypes/merge,
  ../beacon_chain/spec/[digest, presets],
  ../beacon_chain/eth1/eth1_monitor,
  ./testutil

suite "Eth1 monitor":
  test "Rewrite HTTPS Infura URLs":
    var
      mainnetWssUrl = "wss://mainnet.infura.io/ws/v3/6224f3c792cc443fafb64e70a98f871e"
      mainnetHttpUrl = "http://mainnet.infura.io/v3/6224f3c792cc443fafb64e70a98f871e"
      mainnetHttpsUrl = "https://mainnet.infura.io/v3/6224f3c792cc443fafb64e70a98f871e"
      goerliWssUrl = "wss://goerli.infura.io/ws/v3/6224f3c792cc443fafb64e70a98f871e"
      goerliHttpUrl = "http://goerli.infura.io/v3/6224f3c792cc443fafb64e70a98f871e"
      goerliHttpsUrl = "https://goerli.infura.io/v3/6224f3c792cc443fafb64e70a98f871e"
      gethHttpUrl = "http://localhost:8545"
      gethHttpsUrl = "https://localhost:8545"
      gethWsUrl = "ws://localhost:8545"
      unspecifiedProtocolUrl = "localhost:8545"

    fixupWeb3Urls mainnetWssUrl
    fixupWeb3Urls mainnetHttpUrl
    fixupWeb3Urls mainnetHttpsUrl
    fixupWeb3Urls goerliWssUrl
    fixupWeb3Urls goerliHttpUrl
    fixupWeb3Urls goerliHttpsUrl
    fixupWeb3Urls gethHttpUrl
    fixupWeb3Urls gethHttpsUrl
    fixupWeb3Urls gethWsUrl
    fixupWeb3Urls unspecifiedProtocolUrl

    check:
      mainnetWssUrl == "wss://mainnet.infura.io/ws/v3/6224f3c792cc443fafb64e70a98f871e"
      mainnetHttpUrl == mainnetWssUrl
      mainnetHttpsUrl == mainnetWssUrl

      goerliWssUrl == "wss://goerli.infura.io/ws/v3/6224f3c792cc443fafb64e70a98f871e"
      goerliHttpUrl == goerliWssUrl
      goerliHttpsUrl == goerliWssUrl

      gethHttpUrl == gethWsUrl
      gethHttpsUrl == gethWsUrl
      unspecifiedProtocolUrl == gethWsUrl

      gethWsUrl == "ws://localhost:8545"

  test "Roundtrip engine RPC and consensus ExecutionPayload representations":
    # Each Eth2Digest field is chosen randomly. Each uint64 field is random,
    # with boosted probabilities for 0, 1, and high(uint64). There can be 0,
    # 1, 2, or 3 transactions uniformly. Each transaction is 0, 8, 13, or 16
    # bytes. fee_recipient and logs_bloom, both, are uniformly random. extra
    # bytes are random, with 0, 1, and 32 lengths' probabilities increased.
    const executionPayloads = [
      (merge.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x760d4d1fced29500a422c401a646ee5bb5d65a07efa1492856a72cff9948a434"),
        fee_recipient:    ExecutionAddress.fromHex("0x315f583fa44fc6684553d3c88c3d26e9ed7123d8"),
        state_root:       Eth2Digest.fromHex("0xa6975bac699618cc22c05b1ba8f47cbd162475669474316d7a79ea84bce3c690"),
        receipts_root:    Eth2Digest.fromHex("0x080d53a0fd22d93f669b06052413851469d63adeb301810d7ce7a51c90c8e8ce"),
        logs_bloom:       BloomLogs.fromHex("0x453a1f1c4f63bcf0be84e36a9ac233b551601bb2e5ab9450235bd83e41d2013f42c97044ac197a91da96efd6fb18f233bad2e884d76f0a63a6fbf7dbc714cc9aa497fb6d363feeba18447ecf799d5f8d769232553c375b21166c0176859dba63eb77f1a17e482ebac07c3cfd5281277f55f1e5c79cc675d501e1982816d31db7d73c89e855315d8f4e9fef1c9ebb322610235c44632a80341b42f05d207ac4869d08d98a3587a470f598095ebb932788fefacdd70e7749e0bd47ceff88a74ee1f006d9791350484149935d4521d86e644ebc4346154ca0bfa9fbb83120630867d878c12e53a04a879e993b755f02670c9c47f091acf1b3f593782ddaa98f0df4"),
        random:           Eth2Digest.fromHex("0xe19503a6fa6acde0b8f5981f29eb2e298ddff63e6243529d735bcfa42680a515"),
        block_number:     9937808397572497453'u64,
        gas_limit:        15517598874177925531'u64,
        gas_used:         3241597546384131838'u64,
        timestamp:        17932057306109702405'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[55'u8, 184'u8, 18'u8, 128'u8, 63'u8, 61'u8, 26'u8, 79'u8, 3'u8, 225'u8, 167'u8, 15'u8, 240'u8, 167'u8, 180'u8, 141'u8, 205'u8, 10'u8, 246'u8, 70'u8, 248'u8, 35'u8, 19'u8, 45'u8, 252'u8, 187'u8, 168'u8, 42'u8]),
        base_fee_per_gas: Eth2Digest.fromHex("0xaf8acbd8a0f0f8eeced9a1014333cdddbd2090d663a06cd919cf17529e9d7862"),
        block_hash:       Eth2Digest.fromHex("0x86b46255725b39af70a9e1a3096287d9772ccc635408fe06c34cc8b680977ff5"),
        transactions:     List[merge.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[])
      ),
      (merge.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x2cb54ddf357864102f4ab6bce57317a75cee972f303449bf7047f4e0e5809127"),
        fee_recipient:    ExecutionAddress.fromHex("0x92af67d9604b945fd2cbaccd29598e2b47ef5d2d"),
        state_root:       Eth2Digest.fromHex("0xc64221514816a2f87a29c2c474abf99547820b2a12e6e5956f160dd54579e521"),
        receipts_root:    Eth2Digest.fromHex("0x76c1ca0e483a557f6884d64bd891c62904c64c2fe69350278345c622cc50b0d7"),
        logs_bloom:       BloomLogs.fromHex("0x7afdc9a99777d76b713e960e9f12ad4fe46ecb7ea6d5b245c6d9ee11d3fd35e7ae33dd6062fb6578bc2c2f286f1c6a4aa6a44cc80a88a3678c7085c35a0f2e5334ea686e2098fe5d179bbbaf81cbc349a15e7a21aa27f0ddcad342d980d056a356694cdadcef8db3c7866b6cb087c28f2aeed7a5bc9b1294cef0da3ac3b46dbe72d7f164f1990bc32f755b709b96a96bdd8da2c9d9300e9f6906040347d337fc21b833ff0b80305b22ac64a2df2dede4c01c65c192884f161aacd12ba56dab9189477e6ae484a97ff96e0aba1f9b8d043896b8433779abeec091f16b94a013325fe11096d1f2d79b701ab5b46063ac99392a790e617555fe3286dfd7ec0cb9b6"),
        random:           Eth2Digest.fromHex("0xc4021ae781a3b3a1dfb1e4464b032a3bae5f5b68366beb555ede1f126920cd5c"),
        block_number:     11318858212743222111'u64,
        gas_limit:        2312263413099464025'u64,
        gas_used:         1,
        timestamp:        15461704461982808518'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[254'u8, 188'u8, 92'u8, 24'u8, 153'u8, 206'u8, 74'u8, 108'u8, 96'u8, 100'u8, 148'u8, 84'u8, 151'u8, 74'u8, 73'u8, 167'u8, 65'u8, 177'u8, 253'u8, 62'u8]),
        base_fee_per_gas: Eth2Digest.fromHex("0xb1c4b2bffcb38aaa1f98b483441aa212c9dd951d4706dd505a973fd5fd84796f"),
        block_hash:       Eth2Digest.fromHex("0x8b150d453d802fdbb19be0132621a5e8061e70cfe6668ee6a63e4ff217434999"),
        transactions:     List[merge.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[142'u8, 197'u8, 221'u8, 83'u8, 32'u8, 126'u8, 145'u8, 86'u8, 28'u8, 39'u8, 112'u8, 240'u8, 168'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[175'u8, 191'u8, 143'u8, 78'u8, 162'u8, 249'u8, 87'u8, 193'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[84'u8, 168'u8, 190'u8, 157'u8, 39'u8, 143'u8, 147'u8, 156'u8])])
      ),
      (merge.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xac5a7347865f503e1578d1b47271c8e60027b5ba24b0da8e7c3733bcdbeda220"),
        fee_recipient:    ExecutionAddress.fromHex("0x8b7fa656e67f6af2074ec3f16930ad742a69f189"),
        state_root:       Eth2Digest.fromHex("0xeb50f351f6945df8983cf4037ee264dcb2ceef3313ae452248571811d8a3a8cf"),
        receipts_root:    Eth2Digest.fromHex("0x860af6010832f64a5234327b653aabbd3898881a7b72ae42e08d4a1519166fba"),
        logs_bloom:       BloomLogs.fromHex("0x01a18d51076880a1a8ea86cc5dc5fb904ba0a3c285b7dff34ee5dbad9d64721f3849ad9f50b90ad4524eca6b0564f8a1a5827a7b476ea051c33a7c0e18db4cfb27b36476bbb1eacbc029dbc5009e5cea695045cfb34c868163514b784133f0f2998cf12e2caf9c74f69732ed3716396dc34d86725428aff48bf6b935ae88f5e4820b9a325bc670cf560dcb479723213a3156a9d7d0e7de0dc791d0eb94a691013624b8aa982ca3c9d5b49fcac8fafbb403c9fbceee5373f0fb2b77ff1bae8160fe2a47b01d792b088eb3fe24c53b5c6a8b4a3b59060d587ca7376f8baba58d57cf745b2a346f800a54d08545194e067ae260c73369a016b12d0fbc20abc78ba3"),
        random:           Eth2Digest.fromHex("0x330b7093023f617d2cb5f76cee4b078af002b68d81e3a5b5c9d37c4411871a95"),
        block_number:     18446744073709551615'u64,
        gas_limit:        13979513761871276914'u64,
        gas_used:         6199089254852634745'u64,
        timestamp:        7404562418233177323'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[220'u8, 149'u8, 177'u8, 36'u8, 228'u8, 88'u8, 47'u8, 149'u8, 211'u8, 213'u8, 170'u8, 40'u8, 207'u8, 145'u8, 137'u8, 64'u8, 153'u8, 22'u8]),
        base_fee_per_gas: Eth2Digest.fromHex("0xfc82d0e46d05b21aedab6f368183611d2885b28c52842f28f621ef6c631b6e6a"),
        block_hash:       Eth2Digest.fromHex("0xa8c6b2dcc2496f0230e796f8a69642126955ae6209a0d0c2dee2c925212f447e"),
        transactions:     List[merge.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[138'u8, 17'u8, 34'u8, 168'u8, 105'u8, 179'u8, 196'u8, 21'u8, 253'u8, 242'u8, 106'u8, 30'u8, 40'u8, 190'u8, 179'u8, 93'u8])])
      ),
      (merge.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xd3be9b45bfe67229afb47461ca2970505586cab8eb8e00f280ceb07a9d47866f"),
        fee_recipient:    ExecutionAddress.fromHex("0xde645d4a77f0a386a45c52357948e1d7eac5e780"),
        state_root:       Eth2Digest.fromHex("0x69b70e0188e7b88e38df90853b2dfd2e4c7181e83d82d77ab81c57d161216b92"),
        receipts_root:    Eth2Digest.fromHex("0xc01d94a01736268170a16196927029d4d8d7c65970ec78ece94c87304bed4568"),
        logs_bloom:       BloomLogs.fromHex("0x7f1ac5c77e3f0c8a1a103ee83dd7d0fd6fb13895aa1141de330445474b3216e2646c15c1cbf4ab4feb1e4e21c2e6970f4a6648675508b08111e00b62866b0f6cccd58afea87d2cd0a24c0384fa179dc33ae6d0db8c1b118a75fb442682b7cbecc2808fe8c812c3720ca54f6723a395fff5dd1720f41822c91b080503bbfeef21eea192d5b7c4160344996d017ab849fa97e862206caac8f8bfeba41865514b21a8d8fa9ce3dcc0daf5bf86fd2f07d222fc7a9d11fb4031b2cd72544d7f89eb95203a570bc179f9ba1f73f39d74049fe22b63939ea49d5d40f42c00c5f1bd429e84ade377475e432186acd9975914670052fea64453fca87317f62e29b550e88f"),
        random:           Eth2Digest.fromHex("0xce47da2b2a68186b78054be0894ccc9ae7213c18b9093c0ebc1b9ed011071a39"),
        block_number:     9014833350824993703'u64,
        gas_limit:        18446744073709551615'u64,
        gas_used:         7874274181221487360'u64,
        timestamp:        1,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[139'u8]),
        base_fee_per_gas: Eth2Digest.fromHex("0x1eb821a0ee3f9d2e5b49c64177db9ffc96ec6b06249cefa8c51d0ce7e664a3ae"),
        block_hash:       Eth2Digest.fromHex("0x99479be6429eac4a945ca8171d3d3ce42d7b5af298292e833e20462438e06229"),
        transactions:     List[merge.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[99'u8, 198'u8, 91'u8, 86'u8, 23'u8, 222'u8, 121'u8, 250'u8, 12'u8, 135'u8, 133'u8, 37'u8, 61'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[81'u8, 173'u8, 241'u8, 145'u8, 54'u8, 3'u8, 36'u8, 121'u8])])
      ),
      (merge.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x06504beb0dc3bae44ef75678d29ec5138d87da68d307ca7d43e259cede60fda6"),
        fee_recipient:    ExecutionAddress.fromHex("0x527ce602a0be18c0944dc27b2864c711a91f89a6"),
        state_root:       Eth2Digest.fromHex("0xad3bbef5d22bdc2429da09eb85137c881f85fe6e6b3ea207e5eaeb399c755055"),
        receipts_root:    Eth2Digest.fromHex("0xf94fdc52cde20532cfdee73e9cebb61d9f7160191345f9caf58b45501d8effbc"),
        logs_bloom:       BloomLogs.fromHex("0x0999cc50752006a2bc8e5485c239b9a41be6ea2fd8f0392884246ef7d33bccdf4bd326fadae385e3ecc309bf0f367ac1791767ffaee90ddfa7bee22d19f417708fded2b2b6b3be2b6007745fb1de940e7849761586953c04e3bec3c9b6342d1b91dd024980f469b484bd0befc4941a3846d027390d6256e4acf9933e0891dd558270eb35d3455f4e49c890479e970a8008b75ff4d33b4f7e5a8c19e75d8abd8673ebb859a8a24907584d88f0d68b3142b3c6952695fdd84581f5a070601a575a8e7bfa0bf7cf0fe9d70a051005f9dc594d09909e9d079d02a4e441e5b3f33388de8d46cbdcdf24f835415680e569f2ed29acdc01042a6a7ee701e4e6cace5c28"),
        random:           Eth2Digest.fromHex("0x7cef96d72498facdb399dfb5b6d7d69185f3edc70715540fdc7ef651c4685c6a"),
        block_number:     13066898984921201592'u64,
        gas_limit:        9241830338892723842'u64,
        gas_used:         8347984358275749670'u64,
        timestamp:        1,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[11'u8, 46'u8, 127'u8, 104'u8, 141'u8, 79'u8, 55'u8, 48'u8, 242'u8, 12'u8, 142'u8, 2'u8]),
        base_fee_per_gas: Eth2Digest.fromHex("0x6241db2a44a58a2c1aac93c4aa18aed5add30d1937c31078542bb544bf9ba2df"),
        block_hash:       Eth2Digest.fromHex("0xdc1756667e7c3f1615650cbbaae1117a6bac817c6579cf3f7afbc93277eb3ea1"),
        transactions:     List[merge.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[13'u8, 24'u8, 248'u8, 26'u8, 141'u8, 177'u8, 236'u8, 2'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[213'u8, 208'u8, 242'u8, 46'u8, 0'u8, 31'u8, 219'u8, 213'u8, 197'u8, 218'u8, 148'u8, 236'u8, 43'u8, 152'u8, 123'u8, 96'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[84'u8, 163'u8, 60'u8, 195'u8, 40'u8, 68'u8, 185'u8, 20'u8, 244'u8, 82'u8, 34'u8, 181'u8, 26'u8, 201'u8, 2'u8, 108'u8])])
      ),
      (merge.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xb5d4a5eae3a1ea004ed573b0b8f8a22c847616758c0faf1e7e9589f16e55415c"),
        fee_recipient:    ExecutionAddress.fromHex("0xf7ac0877fd8bcadde1e050f6c7ddad13688ec071"),
        state_root:       Eth2Digest.fromHex("0x7472f824376a723894f8d539743c7f93b69839772f28cf6a83e2102fde99c3c9"),
        receipts_root:    Eth2Digest.fromHex("0x750365b5d975460a64f07758abd0cdd44cee23cc2d4f06f2a047cf4c12c23db4"),
        logs_bloom:       BloomLogs.fromHex("0xe24d8452039bddd10e1252c1ebf9b9e81a22577f940e8708d200548717e8471e130a7066adc48785a8dea1dca05953d6be16504a57112c065e7909586cd611af9e0b840b81caf0532dbb2833ee5ac6a6eb7b6c990cba6ccf6f4ddec5a7c76f8296bd2a693cbbb43b1d86b66f6aa58888734d3fb21cf5e96f1b981f8ae2737bce1cad1cc458650291cf7a3d22c61fde6af3a07a44bf1b334b2c5dabbef16e5e73db75e87f04670cb3830f0a7badc702e7dd37a59ce02992f4473a909e57dee1fdd22cfc886f4fcb6ea205ec9234a8ec85ea134242748f9f10062534fd0528bc1b5b1e89511cdf91a1e7fb4f8c58c93d2a6c75e48a2d48235cb7de13040db8dc9c"),
        random:           Eth2Digest.fromHex("0x2410823a37c763e13b03a4c48e32f9e43b8440ca31ecfe8e0543a20a02c496c5"),
        block_number:     14920119354157670036'u64,
        gas_limit:        17193947846593799248'u64,
        gas_used:         2176791850599260430'u64,
        timestamp:        12670133468877091192'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[31'u8, 7'u8, 1'u8, 212'u8, 152'u8, 82'u8, 167'u8, 57'u8, 116'u8, 147'u8, 97'u8, 109'u8, 219'u8, 207'u8, 151'u8, 116'u8, 43'u8, 218'u8, 91'u8, 253'u8, 14'u8, 182'u8, 102'u8, 57'u8, 153'u8, 72'u8, 172'u8, 208'u8, 0'u8, 64'u8, 97'u8]),
        base_fee_per_gas: Eth2Digest.fromHex("0xf1daaa067663bf3277b9149aab162f4e330f988f0be8f83a556743a57ae5c8fd"),
        block_hash:       Eth2Digest.fromHex("0x5d462b4b243c6292b6a3b32f4e05849c0613d0a61954734c524f75f8df66cf8d"),
        transactions:     List[merge.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[])
      ),
      (merge.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x2629683cfc70198038837270bde3c60176c2a4aeeced0d4a4f14dc99a380c377"),
        fee_recipient:    ExecutionAddress.fromHex("0xd234af1937861b66ca84c334824763fb54347677"),
        state_root:       Eth2Digest.fromHex("0xf79f02d52d7f2a4be99eebba3dfb3bce74136ea739da515703d095a66ce203d5"),
        receipts_root:    Eth2Digest.fromHex("0xa97ae6fa5d6937f7754ff96766a54bb8ec082b046814e74f6c9c67147795f526"),
        logs_bloom:       BloomLogs.fromHex("0x5d2ef8bc2f58a84e4050e3a38985e4c267940707c8da3f687fefb9e22e4ae11a2f79a24456af3758e8b521d546dc178da5c85da869ebb2da551976488a769ca2940fa20853e4e1d1fcf8d5bbea0d16973c827d38c97c47c57835677590567829d119e8108f2ee3fa988b267ccfc3e58e5f81c18c775a9baf06d4d81aee405c5683fa4e5e891b58101a27e8f71c60d357a4ab8bd02e12fbbb0e363c4632b0a3c0de638de37448c9476c65a62f7f1dd9643fac6ff78ee431d18ab554b4c8a1984fb5fa0de3464d223f236eb8e8a8f59601221d2ab480ffcefaf4bf6471b40a14773ac0cdb43aea505941e4b0fa6fb26eb091adad77acce41e516fc743e5fdb045f"),
        random:           Eth2Digest.fromHex("0xbe44d7c5f844a2acb307a4371784d7742be482aece83368d94813ffa1c7bb60f"),
        block_number:     13524449277995212660'u64,
        gas_limit:        1,
        gas_used:         7976957374052242924'u64,
        timestamp:        1,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[57'u8]),
        base_fee_per_gas: Eth2Digest.fromHex("0x6c98d9ff36f1032fd55d8a6038d7b1f7c4e5f7c884b73f626fe43e687beeb46d"),
        block_hash:       Eth2Digest.fromHex("0x2c95101857b07bdda0502741da8cd9160ec0474929d132e9159098576f9a7c35"),
        transactions:     List[merge.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[75'u8, 85'u8, 130'u8, 87'u8, 90'u8, 172'u8, 176'u8, 44'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[207'u8, 150'u8, 64'u8, 87'u8, 15'u8, 18'u8, 3'u8, 236'u8, 232'u8, 87'u8, 174'u8, 192'u8, 29'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[23'u8, 37'u8, 57'u8, 158'u8, 137'u8, 222'u8, 53'u8, 111'u8, 63'u8, 13'u8, 69'u8, 110'u8, 175'u8, 108'u8, 16'u8, 207'u8])])
      ),
      (merge.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x190544155dd98bf86d3ed5ee94d01afd3a8e67b8476f94d90604706da0a7d340"),
        fee_recipient:    ExecutionAddress.fromHex("0x799d176d73d5d6d54d66941ad6cef8208677371c"),
        state_root:       Eth2Digest.fromHex("0x07e626b9c44b0ff14586d17acf79cb136ccc5d37fd7135da33cec516af168f43"),
        receipts_root:    Eth2Digest.fromHex("0xb8b100bc5c155fe6358b9a16756ec06880365f5fe89124cf9fea963e26d3770f"),
        logs_bloom:       BloomLogs.fromHex("0xc314d3d6ab41a3fce7433dc286ee5c9820d883ff572ee7dfd2f4ee745f11a71f6dbe142d8c14bd6cc76782f1bb2b3770e65a929b2187581956bad937907a124c92ba10686763ddc87ba5b4a4e9cf4b9a35255fad5f54b404aeed5ad9859b5f9fd3c137e9eb6ef394a10b8ad3fbba75ba38c2cbfb91fa793ac763e8cd31481fbecef02b3365b990f5120a2970f2779574c60769347ae334a9f39bb3d3ad35182f7dcd252bfe9663c4f54b44dea8d79e3bcd89877231e81a9e9f5c1eaf5da1f56ffc39c23fc3ae6c130281c792a31e7a60115d46abbe17807cd120038631ca7a6636c8c644b57719e386cc8ada32ce806f75110ad143522fb0b240213df4bab07e"),
        random:           Eth2Digest.fromHex("0x17e445793c0e354ee43381ded194220ebd87ccbacef83e3da5a1cd3c8c57bf49"),
        block_number:     5728529601694960312'u64,
        gas_limit:        9410734351409376782'u64,
        gas_used:         16470261240710401393'u64,
        timestamp:        8811957812590656903'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[95'u8, 124'u8, 151'u8, 79'u8, 76'u8, 171'u8, 74'u8, 213'u8, 207'u8, 202'u8, 63'u8, 2'u8, 182'u8, 32'u8, 115'u8, 65'u8, 90'u8, 186'u8, 34'u8, 63'u8, 241'u8, 191'u8, 88'u8, 10'u8, 197'u8, 52'u8, 33'u8, 98'u8, 78'u8, 210'u8]),
        base_fee_per_gas: Eth2Digest.fromHex("0x3c1ba8cf82268c828c1a7f249328741ae21f35a7659365efd7496df94dbb85e9"),
        block_hash:       Eth2Digest.fromHex("0xc2b2bc39ed0cf5764800d3c91401828ed32d0eea58f9d336c32f9e6f7200ac8d"),
        transactions:     List[merge.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[])])
      ),
      (merge.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x86d7b430f69b215ab5ae863998ce41f01a5016376c8bec7f5b7a6e16a2326d92"),
        fee_recipient:    ExecutionAddress.fromHex("0x73068946d757f5d145a38fe9de817b8b1e9d6c43"),
        state_root:       Eth2Digest.fromHex("0x312b4af4d3ca5960dda2f99531819f5c32624753cc0756c05d242f65dd605d92"),
        receipts_root:    Eth2Digest.fromHex("0xf3a1e8f784ee4bdb897d1511ce642276e2ecbc1f21bfde9caf7c4479b7fdf902"),
        logs_bloom:       BloomLogs.fromHex("0x633d228aa8b2b9f4b614c4b7c7aca616232d61bc6e06ca28f4b94bc39165cf3ca2e090cebbe8a5b66b161d92e65099503327f9f2adae6ec5a73463063a994d73f37e12caec8f6d439be7520b48b25ccfa8ff64e6884b7e240c8dfd0100a23f9f644da13f1628d989eef92806c9f936a71f470d710653355acd84fb23ff15910f1d2866d83b036246c46a681e762b9a19e72aab21b428c4710511d0a39cc5ec39ebf3aecb5c19096ab32135a629abc8cdec39b2b3631bf4e86bbfb824276fd728bef454ed981e5f9e8a4bb96b27f09f661c5c221f63a26945174162496496c9bbf38cd894c50fa69df0a8c722ab48d75044bf43468639ae9b61d0b5a2f9d819eb"),
        random:           Eth2Digest.fromHex("0x3a0689ac32c82a6b84d3230fdc6e2c1e89671fa3906336ccde9fb7cfd1811ac8"),
        block_number:     9465334901279616671'u64,
        gas_limit:        17844363972830076325'u64,
        gas_used:         9534663249377184661'u64,
        timestamp:        15490999633909732541'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[199'u8]),
        base_fee_per_gas: Eth2Digest.fromHex("0x9fc9f32819a67c4aebae259b0648e2b82f526ce8eef8fee33961f9fc69653b2b"),
        block_hash:       Eth2Digest.fromHex("0x1ac3f16da76520977c5e5d86f0c261d76e18413c202e8a46241951b3a80ca601"),
        transactions:     List[merge.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[223'u8, 37'u8, 18'u8, 125'u8, 208'u8, 57'u8, 114'u8, 113'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[137'u8, 181'u8, 143'u8, 219'u8, 145'u8, 77'u8, 39'u8, 126'u8, 173'u8, 30'u8, 59'u8, 70'u8, 205'u8, 51'u8, 16'u8, 213'u8])])
      ),
      (merge.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xc51bf481df9be981c6656081e3854ffcf27551e2b4fdaed4ab12b355f247f4e1"),
        fee_recipient:    ExecutionAddress.fromHex("0xd79098c25eed05c9f6d55e95f5f6f58c1472fb28"),
        state_root:       Eth2Digest.fromHex("0x1a6b1eb78e5ac155d4be247a3b48d8d8d8574a16fa846681553037629b97ffd0"),
        receipts_root:    Eth2Digest.fromHex("0x5e44d4a3621cd8e495edc0b208f977c8d3f8e79a78fa7ecfc4a0f6e436f67b71"),
        logs_bloom:       BloomLogs.fromHex("0xe2b0dcfd2341ceb9c4edbc7115dbd6ed5f1c54ca39bee191fdaaa34368acee93f48561094dd23a3985ea2c2b83d918ba9dc671cde7732a591b4f9abd2eacf9d6416ca8c8d556052a98df2cffdbb086315585004c51c76872a06cee7d318f4845c0ade4c907c7933d4d883bcc586885be04ca9149e05b1624856e69e1efe8c93cd55d840bf71279293a118d51d4391fcbf4e6abe6ee50492ff2de085069a3c7656eb3a749d6bf46f56a2acd93a6840eb78e09a42f23fdea69bfbf017f4fd6b4a8d17df1aa5147c1897fe5fda1f5e79121f2fefef97117e7871d1cbf5b0b0350b9fc497c5aba27cbc129d452d6a60effb76e08b890d0bb856115fcfe3966359fda"),
        random:           Eth2Digest.fromHex("0xcd6fd69596cdd7df95e0b68e8ade01541b12ed15caa2b59803a4c4e6791870d4"),
        block_number:     12264963829660560313'u64,
        gas_limit:        11775806146734810959'u64,
        gas_used:         1863395589678049593'u64,
        timestamp:        5625804670695895441'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[183'u8]),
        base_fee_per_gas: Eth2Digest.fromHex("0x1443705192ff4dc1a819be4f22b8dcd6e7802337e62082880b1090f44a27d0e2"),
        block_hash:       Eth2Digest.fromHex("0x68da52444eb5322f3a0bda6bdc9a3a11a540dbd22026bb2d24862bbc32af9460"),
        transactions:     List[merge.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[212'u8, 80'u8, 176'u8, 133'u8, 132'u8, 119'u8, 233'u8, 131'u8, 195'u8, 118'u8, 54'u8, 94'u8, 129'u8, 206'u8, 47'u8, 107'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[231'u8, 31'u8, 192'u8, 94'u8, 136'u8, 120'u8, 228'u8, 222'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[114'u8, 23'u8, 239'u8, 220'u8, 169'u8, 188'u8, 213'u8, 179'u8, 223'u8, 129'u8, 189'u8, 50'u8, 158'u8])])
      ),
      (merge.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x8b3e7e8d447527b9d00693389928260e7ea9da6855efd99369182bd9c213988a"),
        fee_recipient:    ExecutionAddress.fromHex("0xb45716c9aeddeb030c0b94202fcb97bd75a039b6"),
        state_root:       Eth2Digest.fromHex("0x8114b285e5f3277c04a66e660fef3b86295d6ca859dfa216df3309c0a7242f2d"),
        receipts_root:    Eth2Digest.fromHex("0x2a3ff38541ef83faad176c3c98ceb5c55622dec83fbfc5a19bdb27646849e852"),
        logs_bloom:       BloomLogs.fromHex("0x384a9b3d38d343af68d00c229e79aa31f2059e17c655f5e48d31d2b59b769660e91c1e5f386e4f7dc83f2570029a6f2b3351623fcb4dadd6b5b7b26e27de19e248ebd970a9678b69403ea8e16fe88562959586fcfdee3c407fcf623c94891a2270ba1829bf2ab77fa32913bb11c8a4a69e9baa6544ad336253637626b16d4a98884e7ac7d6c1e697a9435b1e5403b5122eebddec9c03c8a6c8fed0d8877888371e133fb837d33f073375f7e1536abf622610734b9b0aced8a891f02d5b35734e58b0ead66c49ed9f898b8f27e9415275c5d15051ec00cb006f8aef702a7414aefacfa9742cd3d8d34be817e0c731696e20b973cf2da66799121c0c6d12bc835d"),
        random:           Eth2Digest.fromHex("0x3bd54c7151dae2ad524b4df0d4283e3641ba787fc76f54221dba3a2aa556a1bb"),
        block_number:     18446744073709551615'u64,
        gas_limit:        637978774023867007'u64,
        gas_used:         15110835166938431016'u64,
        timestamp:        18065456863038184935'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[235'u8, 229'u8, 162'u8, 249'u8, 154'u8, 135'u8]),
        base_fee_per_gas: Eth2Digest.fromHex("0xbe93cc3dc2bb7e012db659df49e57653bf6ff21354c64eeb69c0002e9f933035"),
        block_hash:       Eth2Digest.fromHex("0x46cb3f590b2fbce372e67968a0d2ff4ce1b2c530fcc26b7a24ed6db054f52035"),
        transactions:     List[merge.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[16'u8, 66'u8, 215'u8, 40'u8, 223'u8, 195'u8, 43'u8, 228'u8, 225'u8, 244'u8, 34'u8, 14'u8, 117'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[92'u8, 46'u8, 215'u8, 218'u8, 71'u8, 99'u8, 115'u8, 119'u8])])
      ),
      (merge.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xa4854e346d2e9a921cc6b3c4ce9fc739c99795cf10002924089f9886f8624d59"),
        fee_recipient:    ExecutionAddress.fromHex("0xa88781cf69a1eed63bcc3a32b6f9aba35d4f5b5e"),
        state_root:       Eth2Digest.fromHex("0xdc06d9210fd2738b0fa9df6d68e4ffbfef0dd7d7d8093fdbcd97ff845318cf6b"),
        receipts_root:    Eth2Digest.fromHex("0xfe1b70c143066edc444f9b49e778cf6db0060bd4e9122564350cf23061830439"),
        logs_bloom:       BloomLogs.fromHex("0x095a57c3f2d97aad8692cd09dfdd8388f1bf9ef98a1c3223ecfd0aed17d8c7c3ef593d7f09ba86500644deaa676df811da501d572f342e3f7ee7b9b081992f344f71fa50b3b9635d7375f67dbd85a0b1ade3d8d4778118df55b90c44f7dd1114f2ebcea5778b32701ef94af9b3713d1fe00275e09c7e918d7c529a37aa9de3464eb6364812ec486464ccbf7df2523369fdeb1b28955e35e8685c16f07fbe342edd1bc044021ed480bf4ceffefb13eaf4550c67ef8a5079f3f612f07fff60193eda6ac11d39f3056c41ea4355ef5ef7f311493c415cc8c42cb30a73dd58098262acebe6d901e4bae26b6e1eba693c7dc596ea27b0cdd4fee2f6450ca8b50b1a70"),
        random:           Eth2Digest.fromHex("0xc52844ad11072faa2222ffe9cbff77dcc7f681367d2aef5f1c3b206140064195"),
        block_number:     767785029239287422'u64,
        gas_limit:        15062566578072747104'u64,
        gas_used:         7648884410596067087'u64,
        timestamp:        4380084205540210041'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[217'u8, 40'u8, 125'u8, 94'u8, 156'u8, 71'u8, 79'u8, 66'u8, 117'u8, 228'u8, 173'u8, 189'u8, 115'u8, 41'u8, 153'u8, 226'u8, 130'u8, 21'u8, 108'u8, 194'u8, 206'u8, 218'u8, 141'u8]),
        base_fee_per_gas: Eth2Digest.fromHex("0x436767990abff9288346859c6b85b8a972421619eab2253483385c8151cb2016"),
        block_hash:       Eth2Digest.fromHex("0xca4f05c33836d82aee8230ef660016b993bca4aaf9a7b6cad96c2a0193eb026c"),
        transactions:     List[merge.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[156'u8, 143'u8, 203'u8, 250'u8, 238'u8, 137'u8, 34'u8, 245'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[64'u8, 44'u8, 165'u8, 9'u8, 1'u8, 211'u8, 27'u8, 108'u8, 166'u8, 61'u8, 119'u8, 11'u8, 222'u8, 85'u8, 48'u8, 185'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[165'u8, 95'u8, 221'u8, 213'u8, 229'u8, 134'u8, 185'u8, 221'u8])])
      ),
      (merge.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x5e7b12465e0461e5dfa59a3254282378c55961b0e411023ce89d968bbdc33e9c"),
        fee_recipient:    ExecutionAddress.fromHex("0xbd1a1396ab49631cc933770944996b294da97d43"),
        state_root:       Eth2Digest.fromHex("0x74e6ccfb15da8afb94eebf28cb3ba3f9ce63e3354097f2f2527fe1cf978e76bf"),
        receipts_root:    Eth2Digest.fromHex("0x8e48bee56e149d1851cff0740ceab06767bd0e819261c5a2f75dbea382a110b6"),
        logs_bloom:       BloomLogs.fromHex("0x7894fbe58c624a153dbb160c516c9e82bd0cacf5f347f984efcca9450e9a20b50e058ed38e41c331df61114086f8a6b8a049467d7dafd812953aa593b2e9fbc056f0dba80973b2eaae8814b5e0804300eeea15613e59c8d34339f58e1b45599361497a3608c05140cf432e7983a30985aa0faf45dff56dce99eaa5ad3418722df17eaaa4e8df25ed1d9eedee1390e6440c4c37675182dcc07ff199d6dd015d3aa03194765e85fc0d4759d3c693fc2550e50835b88ba41d10fc33b58550d813abaa75bab39c0fbe419f1bde8fb82db9fcfb79894faeed84b2314f115a8fb9e276315ccbfb8e9650571add358f594ff2fb4ab9661afde76081bb2cfbfd2f26d212"),
        random:           Eth2Digest.fromHex("0xb9a9bce05e42cf3d2ffc2c2ea95164c9b215fc8e440dd2985ca24cff40e32780"),
        block_number:     14460352585391846826'u64,
        gas_limit:        2426408612341958329'u64,
        gas_used:         13656152006197676019'u64,
        timestamp:        6263571560389404595'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[177'u8, 36'u8, 79'u8, 26'u8, 164'u8, 59'u8, 182'u8, 88'u8, 223'u8, 22'u8, 79'u8, 197'u8, 109'u8, 53'u8, 53'u8, 134'u8, 244'u8, 84'u8, 146'u8, 158'u8, 234'u8, 252'u8, 188'u8, 175'u8, 69'u8, 51'u8, 118'u8, 101'u8, 242'u8, 0'u8, 51'u8, 103'u8]),
        base_fee_per_gas: Eth2Digest.fromHex("0x997e6c8ffbd1ea95e875612109843c6cdfd0c6bcaffa1e06ba303b3012b3c371"),
        block_hash:       Eth2Digest.fromHex("0x9a7f83cf6a64e153fc3316244fabd972a49ebf5dfb173d7e611bf3447a175c41"),
        transactions:     List[merge.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[137'u8, 103'u8, 164'u8, 112'u8, 136'u8, 91'u8, 170'u8, 241'u8])])
      ),
      (merge.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xa8f90a617f1f230506d200c6026bd60e38f599930ed04f90cdc320a6d45bb022"),
        fee_recipient:    ExecutionAddress.fromHex("0x3531157eaf2c185bd8720f3edfaf76829632f07d"),
        state_root:       Eth2Digest.fromHex("0xa16f8936e945ecd45a4ae107e46acd8530e438fa1bc8eb85aef62afaca1656da"),
        receipts_root:    Eth2Digest.fromHex("0x3e76522c8f3b7e8d8a63f4968ab15413b8bbd7af9782c4878b52213b0b3d13f8"),
        logs_bloom:       BloomLogs.fromHex("0xc13b59de763feaa39debf70d280364ec68eb578af8a90aba7e2cf3a6cee413a28836c674662a0283df8ff04964eb928de97a3883226950b584d773c9b4479d6d5bda6fd71951c0c846752ed688e13dccff947b7a6c81bfac198b6bf785bca7be28bcf9a208b983afe6e766b0536311c1c12b4d01c712cdaa167ecec5520395068b1c1f939d20962de1aba36454cdb36031fa0ba886a8ece71234654e8b081562452046a388ebcf3cfd975493833ff4e146d5e5ddb061d994461ab8b468cf1d6d491d78fd8923f9f6563e3fbfa72639de993701ff6214fd83cd3597e870dec1c1e788a4f01f881c48e57b07c5a217132658208d2221a86c7e9823159984d235b5"),
        random:           Eth2Digest.fromHex("0xbac4a9aa16b289584d13abe3c47a58dda713c4b479ee70e1ac7b3b698e8505af"),
        block_number:     4839752353493107669'u64,
        gas_limit:        4713453319947764960'u64,
        gas_used:         3470256075652600568'u64,
        timestamp:        13764471837770950237'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[60'u8, 109'u8, 153'u8, 55'u8, 17'u8, 196'u8, 17'u8, 96'u8, 202'u8, 173'u8, 16'u8, 189'u8, 165'u8, 107'u8, 68'u8, 230'u8, 238'u8, 62'u8, 199'u8, 211'u8, 244'u8, 83'u8, 88'u8]),
        base_fee_per_gas: Eth2Digest.fromHex("0x3adad83f48e34c6220dce41ecc0b09f9bb1ae4bda4466935c70e7c6cd54e185e"),
        block_hash:       Eth2Digest.fromHex("0x9183524f908425608c1e3a80d7c4ac2c539903af4b3a2f1b22c3283281706aba"),
        transactions:     List[merge.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[])
      ),
      (merge.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xc914f63464f3f1588a32d3751900d415bbf1fe002c42068650f5c7c588b1935c"),
        fee_recipient:    ExecutionAddress.fromHex("0x61523b6add59cc65d3c5b75c6f749fa601e157de"),
        state_root:       Eth2Digest.fromHex("0xe84ecb995f6c7e753355c8d2e24694441c528b65ef9b1d8c6f4e9d98d409342b"),
        receipts_root:    Eth2Digest.fromHex("0x887bdafa340c24acb58f36a7e3825ce39fb7e0caaba3a9b63f78d2186cc6994a"),
        logs_bloom:       BloomLogs.fromHex("0x1fbd358ad7e32eefe4489b6c72bafcf6dbac109970e5c103e329279cede3619faf1309faf266ba155496c19565b31562f31539c98b6256919d8950bb6eca937401d91fa5b3032b4400ce6dd60a8c1c6cc94331b7e78d7a350ebb5d6e04a2594af981f167a89227c7c902dbb8eac3d7b54177d85214a6ef57b50da82b6420cf914fd63171f0b7dff9233bfaa2069774b142a136c5183ed4f57cde2590735b19ef549ff5bc910477b98344e7557ffc440b03d56842f356a6e223fd052c6272e24f43dc9e64055c097d81b56ecfd6087238602a743e09c383ad4eae6ef449570febdfebfefa347f06f480f319ff06365bbfae16b62a950143f9acc3663510356f0c"),
        random:           Eth2Digest.fromHex("0xc755584f86084ab2e62bd58f25dfe54538c0171e6447e7e1a51cf05db94377da"),
        block_number:     9276126375553452674'u64,
        gas_limit:        9007257403963034102'u64,
        gas_used:         12806310385580231715'u64,
        timestamp:        9957937708118639445'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[]),
        base_fee_per_gas: Eth2Digest.fromHex("0xe2df33500d1162994934e9fa65fd5db641b0be2b61a6c302c7b9019f86042338"),
        block_hash:       Eth2Digest.fromHex("0xce58ef51926a6eb4cf2997c4ec771b54907737ae8fe9522fc316c97a1c7ee6d7"),
        transactions:     List[merge.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[])
      ),
      (merge.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x086322b79160568c7d096747ef351338ddc93f252dab1df3ef65aaf24723d2c3"),
        fee_recipient:    ExecutionAddress.fromHex("0x03c6998b5a3ff1c98538c2333d279f2b1cc59f7f"),
        state_root:       Eth2Digest.fromHex("0x446d99a7e9fd2c327fbd445dbfb3b3e3a895cdfa6f208496dd09c0f84f7ac0fd"),
        receipts_root:    Eth2Digest.fromHex("0xf4c74d5c59c46f1d9f916b32d8a12939cc2a379bae83153137de76415f6e5afe"),
        logs_bloom:       BloomLogs.fromHex("0x40f87c3729ba599c3e9bb749c48148ee0d5563db71cf0daaad3af95c45622d7b2a64204157a92a93cf0ffbe0052fb79eef83ba8389fe9d9e7646874b0636960e4eee86eeca00ba70f65b2046620264b795852def9beebb671f841e19ce07934b7c2f66301cc3c7dfa2606067cdeb04a564b87e56ff3650c7c6bbbc96b2de5ccf8e314ae74a26347371c315062532a1f1a2fe0c417ed5d12b6f81c3440c0d8b19d0cf8a030be83ee7ada6046d75098b6ee66664ead786a65ef5cdcb33c4634aa07cd7490abc0ea9ce722423a0cba1aecb379552e89483de43dd321cdaa8a005ab7e8e2a958038ca12e2b08709348a7f6daf34c488add1a0a21aed0da0b64251f9"),
        random:           Eth2Digest.fromHex("0x2ff08bd0b22bae8c3627f61b8da627fc367b3a60f93dbe48de1ca6f25ada489b"),
        block_number:     10605470807350562909'u64,
        gas_limit:        587854351728657338'u64,
        gas_used:         8799032544585725320'u64,
        timestamp:        18028498231539883963'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[]),
        base_fee_per_gas: Eth2Digest.fromHex("0xfbe348f0c77be2ddbd3ec038e3aad88107625dc6e96b1fb3bbfdba8c737a3d7e"),
        block_hash:       Eth2Digest.fromHex("0xc545e833aa2ee5d708e041f4dcb44bda654372b3f5f660c683d12230303da729"),
        transactions:     List[merge.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[89'u8, 59'u8, 131'u8, 146'u8, 186'u8, 180'u8, 208'u8, 76'u8, 69'u8, 40'u8, 29'u8, 211'u8, 97'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[208'u8, 136'u8, 157'u8, 0'u8, 120'u8, 231'u8, 99'u8, 33'u8, 31'u8, 210'u8, 80'u8, 203'u8, 24'u8])])
      ),
      (merge.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xcfba7f4aa4ff01d3d9de84dbe1761c79627a10c3188fb0a7c8adfa0d489e6441"),
        fee_recipient:    ExecutionAddress.fromHex("0x106b3bcaae4ff58dd837768be35c29c48571e4a4"),
        state_root:       Eth2Digest.fromHex("0xe6242399020361e70cb6b89701001fa8326251e6bae3b4ca1978eded8831d9a7"),
        receipts_root:    Eth2Digest.fromHex("0x3db0f9a05cc39be94414c3be28378d2b91ba3ff43ea2ea7e4e0a1874a0983f58"),
        logs_bloom:       BloomLogs.fromHex("0xd591169a3cc38e0837a76c4d7057f94c1ef08ad5af1778b1b06c3a0ec85201bfc659b18c49de831ce6b4a40f0d2800a9cc9001f74810c58473f9b973b720f84626cc9270b0428439b985043f5d9c3289ef8a794f5b8265e10e9fb9fa53a93887d270b8204f8f16cd968e295b0a06aa70e9f6f174733d251f3bfc644a7fb274b0138729f18c0e4382bd4bf0387870f633ed897a125ca854120c2885194f3180af4b62760db96da51f88ae1cd222f49b00fbbc1544eb0e98cea67e36368816f541723158d3691f3cf1509c65a51a8e68efb66c500dd6516ca1b02aeb4e0c13cf5bbead53672fb5a7a1863c8edfaf4eb9a4b4322a39d8643528bccf22493914fa01"),
        random:           Eth2Digest.fromHex("0x14fec0a1edb9c82dc9aa7fb7224791c51a3937e74e5da59646123867496460f2"),
        block_number:     6272046003849350913'u64,
        gas_limit:        15423951135645467684'u64,
        gas_used:         3743939155619454195'u64,
        timestamp:        8496536260448579184'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[152'u8]),
        base_fee_per_gas: Eth2Digest.fromHex("0xd8b104041bdc4c76a9735e2b4b45f0f3612e8962f672aaf511f06a94b48562c8"),
        block_hash:       Eth2Digest.fromHex("0x8ca67fec04b7e3bc5a01f5bb265b93b4488b58ec2ac7f2c3ced030311de2762e"),
        transactions:     List[merge.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[152'u8, 232'u8, 136'u8, 228'u8, 253'u8, 248'u8, 85'u8, 92'u8, 103'u8, 38'u8, 106'u8, 166'u8, 148'u8, 8'u8, 37'u8, 245'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[58'u8, 215'u8, 97'u8, 99'u8, 152'u8, 126'u8, 14'u8, 252'u8, 64'u8, 87'u8, 242'u8, 60'u8, 210'u8, 217'u8, 75'u8, 189'u8])])
      ),
      (merge.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x063bc56b731eeeff8bf1c33d88523a04a14fa0c745eb3c750139842d88244982"),
        fee_recipient:    ExecutionAddress.fromHex("0x415b1cd5b42709a3724ab2f6f50a6dab7399d7ca"),
        state_root:       Eth2Digest.fromHex("0xf261abf37066b8dc5c868946346c98aae445adbb48e6dd05969fbb49267a276e"),
        receipts_root:    Eth2Digest.fromHex("0x5a337b7ee29d98e22b461f43b7a87e52d89fda2e7a3487ea92873be04a49ea68"),
        logs_bloom:       BloomLogs.fromHex("0x01817fd642526acdd8b57b4fc2fb58aba269095ce220ae5770004055f550918778021eae3abeffff1b3fa9fba50ff8d532fd8e2e67da7bdcca1cf9505179f19f595f5d9f09b98d5bc7d1ecb22527255e8e161ca2124c5fedbb59527f91a242671177e33a6fa377d585ebdbd6d9ff2bf80bec3695657441e35da43861f14b9a7e65ed475c323ece62d84aed7262cf3fd2b06ba03695e2e26e5e58fc5b8b99d519fda879587e3764930e3921aa15b2ee8691ea0e738030acb8832ca353d3bb63fbc0150c532b842cd053abeae8238c9ffe6f4b2b7210dc862c48843ae2a9088ecdb8c258592a0feb5215b8c9ad494ad896379d86e0ac89e6cd8765003ac5c95cce"),
        random:           Eth2Digest.fromHex("0xb28f434f3f40e40693b0c1726a018e2b3bc13c41608a2ca71aa5c8bf61829287"),
        block_number:     14597257287993827247'u64,
        gas_limit:        9090926713872599867'u64,
        gas_used:         17391976671717618186'u64,
        timestamp:        13439825139187707720'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[73'u8, 163'u8, 138'u8, 201'u8, 62'u8, 1'u8, 37'u8, 90'u8, 157'u8]),
        base_fee_per_gas: Eth2Digest.fromHex("0x8a42339ef76757729ef6c4536b3b59255b18d7085d8ba786275b2076fc55b3c6"),
        block_hash:       Eth2Digest.fromHex("0xb3f6ec11b285a105833f5b68b67e8e23c85c28df2362a13a76db705f110fce8c"),
        transactions:     List[merge.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[])
      ),
      (merge.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xb31c41d39ef7e9a9b905cc93d82264415024d7daef48d886f1b3bc0fd6545edb"),
        fee_recipient:    ExecutionAddress.fromHex("0x5ad4b6c0d6b986e775f3a9ae2be73a330ba9f87c"),
        state_root:       Eth2Digest.fromHex("0x01dbc857a3d8994cf10cd1be3b2018be0e26ba54a5456e10a6e5729328a0b5f5"),
        receipts_root:    Eth2Digest.fromHex("0xa51e9cb9893bd7d73a8fd4e5267d80ddcb29d998814cfa9980dbae50ef101aff"),
        logs_bloom:       BloomLogs.fromHex("0xf1280db0ef6bb796e70dfef3b0bafa62690ef1e8f14a237856bae5dbe29dfd43ac789c53305ab5b0b7cc48ed53d1236ab9433a5352dac55b6e0a3ff90e9e815e2ce16fe5574c87f0066090c39b811996e2974da0bdb8bb59eb044bbb6bc2d7f8241093c7143a7c9892be85ea4284258ea2477f6a677d424efb6469724d641bbdc3f9254529b6af5cc5f5a77dad49c1a59ae37c19ffc69f6e331139b6ebac306ea09460dc0fc5791ef2cfb9e7bf29d662872e30b94384be90416df03bef5cf5a2339af4745f2f620fd1320d3fb79848692719cb8956b8efd427c9c0cc3ea6efb8f84feae0075ed10ec5c6243074e6004849712d8d1dd97ebb2948fcdf1d020c6e"),
        random:           Eth2Digest.fromHex("0xc8a27f0b7850de04e3d794b9e9d4f144c356f864401c3f802927faf4b88b47ac"),
        block_number:     10821099926525463598'u64,
        gas_limit:        7115919978619568727'u64,
        gas_used:         1,
        timestamp:        5900615379943209755'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[56'u8, 176'u8, 67'u8, 30'u8, 11'u8, 27'u8, 136'u8, 121'u8, 86'u8, 17'u8, 4'u8, 121'u8, 11'u8, 222'u8, 158'u8, 78'u8, 56'u8, 66'u8, 243'u8]),
        base_fee_per_gas: Eth2Digest.fromHex("0xfbaacdba879288838ff725df19b7a31148ec5a24e7989441544d6dec1c980034"),
        block_hash:       Eth2Digest.fromHex("0x04616c0808df7a1bc177bc48cb6ed865125fbbac2fa3e3c36f33a5f1c48a23fd"),
        transactions:     List[merge.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[])
      ),
      (merge.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xf6cba3ced37c08da230babbf9d1e360661e5a21ac235fefa75cbe756f15809de"),
        fee_recipient:    ExecutionAddress.fromHex("0x0c080349793b7f43fb3ee9101889e7d32e02c01d"),
        state_root:       Eth2Digest.fromHex("0x6a33580fc482e9783d66bee9276f42b74a2cbc2b7434fc408a6ba9df77db0ceb"),
        receipts_root:    Eth2Digest.fromHex("0xd896daff74ffd6ffcc088adba01aea52af82d861b7ff649265a750e5995dcf31"),
        logs_bloom:       BloomLogs.fromHex("0xec00c3385b735b6a4088ed066bdb088e7826a2830fd13a1a1525c4590eb08baeba81bb511bbf2db2c0547c69c10b5c6c1bf5c8e5a7931584e6ed8ed7357431e1e2391fc0e61a060baf8984a6fd5c04c68fe0f28f94281d0db663b1b2fdaad9b51d3a12bb9fba255c923dea5ce45dd68ec2c5afc9fd13a0e24d234a3c8c5f255e7d62d48a8e01fb5c1eaf0c7a68a616ac935416fe3332943d78eb28a48a180e2bee26e85d786583ae0609a8b98e1045738f054aa12bef97593cd16d8d795314bfff33c51b397afa2299a4a64244817e5a07cdcd75eb4c4c06e8e943d8d1db8e65f17368ab6175c3e14daad0b99fd0f1050feebadf9db8fe8f1c19ed867f4df676"),
        random:           Eth2Digest.fromHex("0xdcd37bc148c25afa7e320009ce19567108745ef5ed57781f55df1d73b707e26e"),
        block_number:     13754339262807377549'u64,
        gas_limit:        5250261236890759949'u64,
        gas_used:         1335844244115849195'u64,
        timestamp:        16758901654456753273'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[28'u8, 8'u8, 171'u8, 122'u8, 126'u8, 38'u8, 142'u8, 246'u8, 162'u8, 197'u8, 241'u8, 216'u8, 158'u8, 184'u8, 73'u8, 191'u8, 208'u8, 5'u8, 79'u8, 231'u8, 254'u8, 55'u8, 126'u8, 97'u8, 184'u8, 78'u8, 36'u8, 80'u8, 160'u8, 124'u8, 188'u8, 176'u8]),
        base_fee_per_gas: Eth2Digest.fromHex("0x0ea1185e0ac50d1e2cc0be7229c846528380def25f7d8860cf366e6edd793be0"),
        block_hash:       Eth2Digest.fromHex("0xb471874aa6e8987deee40902d59537fed8af3e9b6ae2f8b476ddb051629b3b09"),
        transactions:     List[merge.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[231'u8, 215'u8, 225'u8, 83'u8, 163'u8, 187'u8, 111'u8, 141'u8, 246'u8, 57'u8, 238'u8, 163'u8, 25'u8, 91'u8, 114'u8, 111'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[93'u8, 42'u8, 101'u8, 80'u8, 160'u8, 252'u8, 158'u8, 121'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[164'u8, 98'u8, 105'u8, 179'u8, 25'u8, 33'u8, 130'u8, 239'u8])])
      ),
      (merge.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x62ce6a6d68578309c4730f96f98a809d4b4225fc3d37a285daf26288b10f9590"),
        fee_recipient:    ExecutionAddress.fromHex("0x8c892b06f1e9c877c310b6eccefb20fcf5e00227"),
        state_root:       Eth2Digest.fromHex("0x578f93b83206e3239c69f51cc8e59cd89087260cda9f0efc892aa2ffb2bf386e"),
        receipts_root:    Eth2Digest.fromHex("0xa4ac657af8e0dad66ec74f4f66b246fe0089485e2810071fa556c09ea585059f"),
        logs_bloom:       BloomLogs.fromHex("0x18d67e640f9ad3a24deb7e3f8cbe0ba8224cf9cb9e67b2fd6c774fac7aa3f4adca2befe8322962cf000cb89c3e352433cf1aade51ceac9fe69966a8a89f7985030a301eb690e7eb20b5ac3b315930ee5397b6d65b03a1131b94e7f3505ef030877e460e9195b742e943716d9875a3e2e9998236d3565d622216af1721b658a12fe7d82a62619b4f2d042f146305ff1ad1bf394437340735eac9e962b3fe67597793d1151ec87fcb5f0056837c5813c75c4a0f94d91da71299b3780f250ee31eb9f106e3c443f0ba05213da05177238909fd9e60de9484e091b91dead82debc020929d1f14e79b610af3d15bf9c3757e62bb32a69523c1bd576e5c5d4bc2ef0a6"),
        random:           Eth2Digest.fromHex("0x552627eb969604e7d4ed1e631b74b2410dea7f4dbd49511bda390e3b9da8bf60"),
        block_number:     7763671958353664038'u64,
        gas_limit:        3930616259240751958'u64,
        gas_used:         7960068863134244743'u64,
        timestamp:        18446744073709551615'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[227'u8, 111'u8, 127'u8, 243'u8, 191'u8, 237'u8, 88'u8, 146'u8, 146'u8, 236'u8, 162'u8, 237'u8, 164'u8, 177'u8, 249'u8, 52'u8, 1'u8, 26'u8, 187'u8, 208'u8, 244'u8, 234'u8, 113'u8, 199'u8, 30'u8, 209'u8, 197'u8, 63'u8, 126'u8, 104'u8, 143'u8, 30'u8]),
        base_fee_per_gas: Eth2Digest.fromHex("0x6bcd9684e1bc8f4fc5d089e0bf5fed35a8bf3039808d030bb9eb1ff7147180b5"),
        block_hash:       Eth2Digest.fromHex("0x9e2505de9f245873565b553e7215abff698bdfcee1dbd93e40eb295dd84e7f45"),
        transactions:     List[merge.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[140'u8, 134'u8, 173'u8, 70'u8, 168'u8, 181'u8, 221'u8, 210'u8, 25'u8, 142'u8, 168'u8, 139'u8, 77'u8, 134'u8, 203'u8, 219'u8])])
      ),
      (merge.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x4f8251c361a23171de8648d1e96c91fea2cc5a691dcd884e3a957dc8f6a8802a"),
        fee_recipient:    ExecutionAddress.fromHex("0x7da9175abaf6e4e400e0ee516fd3ab07dd659f2a"),
        state_root:       Eth2Digest.fromHex("0x1bd3a5da4c266dd396b8209288e68be066176ebe64cd4c17c4c6cdccaf03577e"),
        receipts_root:    Eth2Digest.fromHex("0x16133c4fe31f0487e700514160acf9257458a6ee716be8043cb6c532f84ef614"),
        logs_bloom:       BloomLogs.fromHex("0x5ca3807e674d69536b33337d798deaeb9fa6c7cbab7aef1473e6a6614f6f2c74ef85ee3632612b9c1e78d2a63e0b2f58d48d71e8d62e38510bc2f307680497cb965153b43392b8aa2dcd91a766356eab3ff1b4a6c4b037d61df1a8a4c6d3fa0e3c57a299a1c0a7382052ac25c412f2d2356c302e326fa0cfb570354e31e2f8046b80e2690ba69ec7c284c2df8ad23d16764cbc0ba28516f3c31aa89da3e3286106dcecc835b3007a17f33c4962efc3c9b0f5bff14c783e414ba60d35b79ab33ccd0151c34a94efc461d0df0a994085373f33275a4cd6839603632409b670072a4554f1c9342c03cd403a6feb67b23d3a075707ca89b77bad64e24a6ab79446ad"),
        random:           Eth2Digest.fromHex("0x6353ec5b94b9112f25e66de48b532ff5610c63f34c50a02fdf64af6c9d0ef2f4"),
        block_number:     16866969889068542818'u64,
        gas_limit:        5116920640663397560'u64,
        gas_used:         13292402101416991817'u64,
        timestamp:        1,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[136'u8, 133'u8, 189'u8, 60'u8, 229'u8, 217'u8, 70'u8, 145'u8, 136'u8, 97'u8, 175'u8, 23'u8, 183'u8, 73'u8]),
        base_fee_per_gas: Eth2Digest.fromHex("0xe1307a28a2868b4d934aefdde7bbd09b0644b5c422d2c680770775cb44623512"),
        block_hash:       Eth2Digest.fromHex("0x11e23850b143b8b4dd8394ee1f2cebf073068502d04dde00000925cf23ff55cc"),
        transactions:     List[merge.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[])
      ),
      (merge.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x0c67b44b492590ffb9e6d2a63c84714821be7526ce1c337c06276e33a62b7b93"),
        fee_recipient:    ExecutionAddress.fromHex("0x1d16dbe66ead2ba8afb8594acaf8d536be08dac3"),
        state_root:       Eth2Digest.fromHex("0xeeb40e334aff8512435b5908a8dd3c06993cadca8bc44e9a6c28c6003162c6a9"),
        receipts_root:    Eth2Digest.fromHex("0xefa5b7de19da2333bfb7bfa814a306f904fef2ff4f8b1154314649a56fea3c8d"),
        logs_bloom:       BloomLogs.fromHex("0x4ebbaff6a56343a6bc0170aca2e2ba303f3e3f972c88539ef84e402740e3c9e21c6951d461baf56eec14c06ca0e95f4921079d0d82e9dd46e73f3fa76417246217ff9c5425f19b0f8b2a735ee522c1bc377a2b079099430d0f9316164f5930456245534bbe138d0a19ee58bb13a0d724723a6fa50e39b8a7ad5804f92ab43c24782e27dbb32789408cdd716af9a0b0cb1e2f3aee0bcb5aa4088c0cf1528fad466f3d71d906649becf25f405f619dead731e0831efb522b5faee7a39ca28128effc79977816d50ae23745ab96b80dc7f548aa5d43b0d5c331fdc1ce080a4d63e19942ecb4df8f56397b2ef67d017f2d2de9296e1fd8036ed8592f5a89553c4642"),
        random:           Eth2Digest.fromHex("0x5d3c3ac25330e1cd3a516003315ed24bd2dc6cd31d389639cce4b6ae4a3ac8cf"),
        block_number:     10891095348111649307'u64,
        gas_limit:        13670668340379820434'u64,
        gas_used:         1482104080767186829'u64,
        timestamp:        6602476120092784163'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[223'u8, 228'u8, 253'u8, 3'u8, 38'u8, 218'u8, 253'u8, 87'u8, 206'u8, 243'u8, 168'u8, 113'u8]),
        base_fee_per_gas: Eth2Digest.fromHex("0x972a01f27d586035ce5fb233118e52652ebbf89f6d39558a41b27c8840c849b1"),
        block_hash:       Eth2Digest.fromHex("0x9280fa96a569e7c25b2dfc12a141d3edd24acf2fbfa19ee72e5a1fd5dba25a11"),
        transactions:     List[merge.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[116'u8, 179'u8, 195'u8, 80'u8, 193'u8, 73'u8, 187'u8, 64'u8, 41'u8, 251'u8, 55'u8, 90'u8, 161'u8, 30'u8, 221'u8, 210'u8])])
      ),
      (merge.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x7a9d6ab34c0314959d5bdceb0bd80f142e59e5e2addedcd178612303897e7a8a"),
        fee_recipient:    ExecutionAddress.fromHex("0x3425bc529b4791f5fdb7dd365501199b2f81e578"),
        state_root:       Eth2Digest.fromHex("0x4eb1a9a3c4b9392325a14f3f8efbc0b3cc3bfc2d7e9992377abd84af6c556db5"),
        receipts_root:    Eth2Digest.fromHex("0x094e9114d3487925f6818140978e4db64d8306083a8e5c987657e21c3a1995bd"),
        logs_bloom:       BloomLogs.fromHex("0x0815701b4689d0bb7f80fb1485ad3255a66b890725a1d2d66b4fc66678e2d08784c21ef583401493d5dda1549eda32303b7d102edc72b9fe1d696ab459294a88db0d7263abdf982ddf59ce008b8ac734565de79c269dfc18a36709ca91a3cd50516725e9fa9d98302fa0322254382aab0cdf1f95f2397579f7219bd7ab096ef1f00d7b1131b0055bff65ae9954cb22959adbc40983840ae3b85358fd205bdf6ac6bcf723047ffc53a094a06c2039935b6ef579efc618bf4127a6e4e531f6d97c17789be639691ef87fa5540cf732a184a0e09d5c60866ecd0be0a04bc94317712c395d84c2cec90f43f4807048bf1a93e3e6520a1a7c59092e2e391abf9d2e68"),
        random:           Eth2Digest.fromHex("0x349eec90244f3d812002732cd833952969b27a463def04291051137344c89c41"),
        block_number:     5715688900321967041'u64,
        gas_limit:        17172684770312311722'u64,
        gas_used:         9286597649062725614'u64,
        timestamp:        195835912833125491'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[34'u8, 35'u8, 209'u8, 45'u8, 117'u8]),
        base_fee_per_gas: Eth2Digest.fromHex("0x7b5b4e48b3daadecb9724a74d426a86ffb5c5f8abd43469b4e3fe2a728b5a645"),
        block_hash:       Eth2Digest.fromHex("0xc71c294b5562af30b9e2b03e76cec0cc6d8b50694219404aaed2ace8f756a22e"),
        transactions:     List[merge.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[178'u8, 142'u8, 115'u8, 217'u8, 56'u8, 74'u8, 150'u8, 16'u8, 244'u8, 148'u8, 19'u8, 33'u8, 89'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[195'u8, 248'u8, 42'u8, 129'u8, 151'u8, 119'u8, 232'u8, 235'u8, 245'u8, 240'u8, 113'u8, 157'u8, 235'u8, 158'u8, 160'u8, 222'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[16'u8, 27'u8, 72'u8, 107'u8, 18'u8, 210'u8, 127'u8, 78'u8])])
      ),
      (merge.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x806a868f0f31e8f519fa6339ad18c414dba17feb03aaf6ca3775b152bac64f3b"),
        fee_recipient:    ExecutionAddress.fromHex("0xa2bcc8b793c4a5d4e0f68251d2f22e1ff4366d2c"),
        state_root:       Eth2Digest.fromHex("0x6979ac9545f31eaf7ed8bd227cd7cbd1017492b892bcc118f7417ea87d50d412"),
        receipts_root:    Eth2Digest.fromHex("0xca0ac1828fae211c9d0fd7ab763460d89f9da0669d082c68b9fdca3ca1b59123"),
        logs_bloom:       BloomLogs.fromHex("0x0656423dc7b375cee4f5c3bedc500eaff2da91d0dd5f4e695933c92a2a6af7441200a41177bcae7912839f993a733aa2bb82976f08180a901e63c588a26dc9ccc58f477eccbb08aa932d512bfc765a57527acd04c585af23f48f389420890d06877d8a0f523cb90be10dbc73cb5b11e808f5c6c90c6fc3a9434dab462f2977eacf79146b35ee2372aae8a6fe3628cbe21a8988fd9546b25581b6d998462f9af7f653d3a4702a4a63b9f26cc7d2f72e18a3918fa9b65ed81d23ac0a64dd8f3f878f745fcb4de9ad144ae9565288d7bf90e6d356f49cc242d000e988fe76e0196f0c5b24bdf9dc501222e54f64861e0d45dda2bdf09e5fb290a1ec6dce39b02883"),
        random:           Eth2Digest.fromHex("0xc986211f6550cb787e89140d8856531ec309f652e2a871e2715c1dd055448074"),
        block_number:     7781035717593646205'u64,
        gas_limit:        9088183223170031827'u64,
        gas_used:         0,
        timestamp:        1844848381084178223'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[]),
        base_fee_per_gas: Eth2Digest.fromHex("0xaac988479abbe95e03cc214e7b99795c4ec117bfe4da06e4624e94b262b015e2"),
        block_hash:       Eth2Digest.fromHex("0x14137d373f6e6110b3fe3c1d743a4f84547ad3d59d0b42598b794ff601e97e38"),
        transactions:     List[merge.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[10'u8, 28'u8, 79'u8, 238'u8, 85'u8, 206'u8, 161'u8, 222'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[144'u8, 222'u8, 190'u8, 14'u8, 247'u8, 119'u8, 95'u8, 48'u8, 238'u8, 50'u8, 180'u8, 12'u8, 216'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[])])
      )]

    for executionPayload in executionPayloads:
      check:
        executionPayload ==
          asConsensusExecutionPayload(
            asEngineExecutionPayload(executionPayload)[])[]
