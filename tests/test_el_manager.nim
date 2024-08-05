# beacon_chain
# Copyright (c) 2021-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  unittest2,
  ../beacon_chain/el/[el_conf, el_manager],
  ./testutil

from ssz_serialization/types import Limit, List, init
from stew/byteutils import hexToByteArray
from stint import UInt256
from ../beacon_chain/spec/datatypes/bellatrix import
  BloomLogs, ExecutionAddress, ExecutionPayload, fromHex
from ../beacon_chain/spec/datatypes/capella import ExecutionPayload
from ../beacon_chain/spec/datatypes/deneb import ExecutionPayload
from ../beacon_chain/spec/digest import Eth2Digest
from ../beacon_chain/spec/presets import
  MAX_BYTES_PER_TRANSACTION, MAX_EXTRA_DATA_BYTES, MAX_TRANSACTIONS_PER_PAYLOAD

suite "Eth1 monitor":
  test "Rewrite URLs":
    var
      gethHttpUrl = "http://localhost:8545"
      gethHttpsUrl = "https://localhost:8545"
      gethWsUrl = "ws://localhost:8545"
      unspecifiedProtocolUrl = "localhost:8545"

    fixupWeb3Urls gethHttpUrl
    fixupWeb3Urls gethHttpsUrl
    fixupWeb3Urls gethWsUrl
    fixupWeb3Urls unspecifiedProtocolUrl

    check:
      gethHttpUrl == "http://localhost:8545"
      gethHttpsUrl == "https://localhost:8545"
      unspecifiedProtocolUrl == "ws://localhost:8545"

      gethWsUrl == "ws://localhost:8545"

  test "Deposits chain":
    var
      chain = Eth1Chain()
      depositIndex = 0.uint64
    for i in 0 ..< (MAX_DEPOSITS + 1) * 3:
      var deposits = newSeqOfCap[DepositData](i)
      for _ in 0 ..< i mod (MAX_DEPOSITS + 1):
        deposits.add DepositData(amount: depositIndex.Gwei)
        inc depositIndex

      const interval = defaultRuntimeConfig.SECONDS_PER_ETH1_BLOCK
      chain.blocks.addLast Eth1Block(
        number: i.Eth1BlockNumber,
        timestamp: i.Eth1BlockTimestamp * interval,
        deposits: deposits,
        depositCount: depositIndex)

    proc doTest(first, last: uint64) =
      var idx = first
      for data in chain.getDepositsRange(first, last):
        check data.amount == idx.Gwei
        inc idx
      check idx == last

    for i in 0 .. depositIndex:
      for j in i .. depositIndex:
        doTest(i, j)

  test "Roundtrip engine RPC V1 and bellatrix ExecutionPayload representations":
    # Each Eth2Digest field is chosen randomly. Each uint64 field is random,
    # with boosted probabilities for 0, 1, and high(uint64). There can be 0,
    # 1, 2, or 3 transactions uniformly. Each transaction is 0, 8, 13, or 16
    # bytes. fee_recipient and logs_bloom, both, are uniformly random. extra
    # bytes are random, with 0, 1, and 32 lengths' probabilities increased.
    const executionPayloads = [
      (bellatrix.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x760d4d1fced29500a422c401a646ee5bb5d65a07efa1492856a72cff9948a434"),
        fee_recipient:    ExecutionAddress.fromHex("0x315f583fa44fc6684553d3c88c3d26e9ed7123d8"),
        state_root:       Eth2Digest.fromHex("0xa6975bac699618cc22c05b1ba8f47cbd162475669474316d7a79ea84bce3c690"),
        receipts_root:    Eth2Digest.fromHex("0x080d53a0fd22d93f669b06052413851469d63adeb301810d7ce7a51c90c8e8ce"),
        logs_bloom:       BloomLogs.fromHex("0x453a1f1c4f63bcf0be84e36a9ac233b551601bb2e5ab9450235bd83e41d2013f42c97044ac197a91da96efd6fb18f233bad2e884d76f0a63a6fbf7dbc714cc9aa497fb6d363feeba18447ecf799d5f8d769232553c375b21166c0176859dba63eb77f1a17e482ebac07c3cfd5281277f55f1e5c79cc675d501e1982816d31db7d73c89e855315d8f4e9fef1c9ebb322610235c44632a80341b42f05d207ac4869d08d98a3587a470f598095ebb932788fefacdd70e7749e0bd47ceff88a74ee1f006d9791350484149935d4521d86e644ebc4346154ca0bfa9fbb83120630867d878c12e53a04a879e993b755f02670c9c47f091acf1b3f593782ddaa98f0df4"),
        prev_randao:      Eth2Digest.fromHex("0xe19503a6fa6acde0b8f5981f29eb2e298ddff63e6243529d735bcfa42680a515"),
        block_number:     9937808397572497453'u64,
        gas_limit:        15517598874177925531'u64,
        gas_used:         3241597546384131838'u64,
        timestamp:        17932057306109702405'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[55'u8, 184'u8, 18'u8, 128'u8, 63'u8, 61'u8, 26'u8, 79'u8, 3'u8, 225'u8, 167'u8, 15'u8, 240'u8, 167'u8, 180'u8, 141'u8, 205'u8, 10'u8, 246'u8, 70'u8, 248'u8, 35'u8, 19'u8, 45'u8, 252'u8, 187'u8, 168'u8, 42'u8]),
        base_fee_per_gas: UInt256.fromHex("0xaf8acbd8a0f0f8eeced9a1014333cdddbd2090d663a06cd919cf17529e9d7862"),
        block_hash:       Eth2Digest.fromHex("0x86b46255725b39af70a9e1a3096287d9772ccc635408fe06c34cc8b680977ff5"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[])
      ),
      (bellatrix.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x2cb54ddf357864102f4ab6bce57317a75cee972f303449bf7047f4e0e5809127"),
        fee_recipient:    ExecutionAddress.fromHex("0x92af67d9604b945fd2cbaccd29598e2b47ef5d2d"),
        state_root:       Eth2Digest.fromHex("0xc64221514816a2f87a29c2c474abf99547820b2a12e6e5956f160dd54579e521"),
        receipts_root:    Eth2Digest.fromHex("0x76c1ca0e483a557f6884d64bd891c62904c64c2fe69350278345c622cc50b0d7"),
        logs_bloom:       BloomLogs.fromHex("0x7afdc9a99777d76b713e960e9f12ad4fe46ecb7ea6d5b245c6d9ee11d3fd35e7ae33dd6062fb6578bc2c2f286f1c6a4aa6a44cc80a88a3678c7085c35a0f2e5334ea686e2098fe5d179bbbaf81cbc349a15e7a21aa27f0ddcad342d980d056a356694cdadcef8db3c7866b6cb087c28f2aeed7a5bc9b1294cef0da3ac3b46dbe72d7f164f1990bc32f755b709b96a96bdd8da2c9d9300e9f6906040347d337fc21b833ff0b80305b22ac64a2df2dede4c01c65c192884f161aacd12ba56dab9189477e6ae484a97ff96e0aba1f9b8d043896b8433779abeec091f16b94a013325fe11096d1f2d79b701ab5b46063ac99392a790e617555fe3286dfd7ec0cb9b6"),
        prev_randao:      Eth2Digest.fromHex("0xc4021ae781a3b3a1dfb1e4464b032a3bae5f5b68366beb555ede1f126920cd5c"),
        block_number:     11318858212743222111'u64,
        gas_limit:        2312263413099464025'u64,
        gas_used:         1,
        timestamp:        15461704461982808518'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[254'u8, 188'u8, 92'u8, 24'u8, 153'u8, 206'u8, 74'u8, 108'u8, 96'u8, 100'u8, 148'u8, 84'u8, 151'u8, 74'u8, 73'u8, 167'u8, 65'u8, 177'u8, 253'u8, 62'u8]),
        base_fee_per_gas: UInt256.fromHex("0xb1c4b2bffcb38aaa1f98b483441aa212c9dd951d4706dd505a973fd5fd84796f"),
        block_hash:       Eth2Digest.fromHex("0x8b150d453d802fdbb19be0132621a5e8061e70cfe6668ee6a63e4ff217434999"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[142'u8, 197'u8, 221'u8, 83'u8, 32'u8, 126'u8, 145'u8, 86'u8, 28'u8, 39'u8, 112'u8, 240'u8, 168'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[175'u8, 191'u8, 143'u8, 78'u8, 162'u8, 249'u8, 87'u8, 193'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[84'u8, 168'u8, 190'u8, 157'u8, 39'u8, 143'u8, 147'u8, 156'u8])])
      ),
      (bellatrix.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xac5a7347865f503e1578d1b47271c8e60027b5ba24b0da8e7c3733bcdbeda220"),
        fee_recipient:    ExecutionAddress.fromHex("0x8b7fa656e67f6af2074ec3f16930ad742a69f189"),
        state_root:       Eth2Digest.fromHex("0xeb50f351f6945df8983cf4037ee264dcb2ceef3313ae452248571811d8a3a8cf"),
        receipts_root:    Eth2Digest.fromHex("0x860af6010832f64a5234327b653aabbd3898881a7b72ae42e08d4a1519166fba"),
        logs_bloom:       BloomLogs.fromHex("0x01a18d51076880a1a8ea86cc5dc5fb904ba0a3c285b7dff34ee5dbad9d64721f3849ad9f50b90ad4524eca6b0564f8a1a5827a7b476ea051c33a7c0e18db4cfb27b36476bbb1eacbc029dbc5009e5cea695045cfb34c868163514b784133f0f2998cf12e2caf9c74f69732ed3716396dc34d86725428aff48bf6b935ae88f5e4820b9a325bc670cf560dcb479723213a3156a9d7d0e7de0dc791d0eb94a691013624b8aa982ca3c9d5b49fcac8fafbb403c9fbceee5373f0fb2b77ff1bae8160fe2a47b01d792b088eb3fe24c53b5c6a8b4a3b59060d587ca7376f8baba58d57cf745b2a346f800a54d08545194e067ae260c73369a016b12d0fbc20abc78ba3"),
        prev_randao:      Eth2Digest.fromHex("0x330b7093023f617d2cb5f76cee4b078af002b68d81e3a5b5c9d37c4411871a95"),
        block_number:     18446744073709551615'u64,
        gas_limit:        13979513761871276914'u64,
        gas_used:         6199089254852634745'u64,
        timestamp:        7404562418233177323'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[220'u8, 149'u8, 177'u8, 36'u8, 228'u8, 88'u8, 47'u8, 149'u8, 211'u8, 213'u8, 170'u8, 40'u8, 207'u8, 145'u8, 137'u8, 64'u8, 153'u8, 22'u8]),
        base_fee_per_gas: UInt256.fromHex("0xfc82d0e46d05b21aedab6f368183611d2885b28c52842f28f621ef6c631b6e6a"),
        block_hash:       Eth2Digest.fromHex("0xa8c6b2dcc2496f0230e796f8a69642126955ae6209a0d0c2dee2c925212f447e"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[138'u8, 17'u8, 34'u8, 168'u8, 105'u8, 179'u8, 196'u8, 21'u8, 253'u8, 242'u8, 106'u8, 30'u8, 40'u8, 190'u8, 179'u8, 93'u8])])
      ),
      (bellatrix.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xd3be9b45bfe67229afb47461ca2970505586cab8eb8e00f280ceb07a9d47866f"),
        fee_recipient:    ExecutionAddress.fromHex("0xde645d4a77f0a386a45c52357948e1d7eac5e780"),
        state_root:       Eth2Digest.fromHex("0x69b70e0188e7b88e38df90853b2dfd2e4c7181e83d82d77ab81c57d161216b92"),
        receipts_root:    Eth2Digest.fromHex("0xc01d94a01736268170a16196927029d4d8d7c65970ec78ece94c87304bed4568"),
        logs_bloom:       BloomLogs.fromHex("0x7f1ac5c77e3f0c8a1a103ee83dd7d0fd6fb13895aa1141de330445474b3216e2646c15c1cbf4ab4feb1e4e21c2e6970f4a6648675508b08111e00b62866b0f6cccd58afea87d2cd0a24c0384fa179dc33ae6d0db8c1b118a75fb442682b7cbecc2808fe8c812c3720ca54f6723a395fff5dd1720f41822c91b080503bbfeef21eea192d5b7c4160344996d017ab849fa97e862206caac8f8bfeba41865514b21a8d8fa9ce3dcc0daf5bf86fd2f07d222fc7a9d11fb4031b2cd72544d7f89eb95203a570bc179f9ba1f73f39d74049fe22b63939ea49d5d40f42c00c5f1bd429e84ade377475e432186acd9975914670052fea64453fca87317f62e29b550e88f"),
        prev_randao:      Eth2Digest.fromHex("0xce47da2b2a68186b78054be0894ccc9ae7213c18b9093c0ebc1b9ed011071a39"),
        block_number:     9014833350824993703'u64,
        gas_limit:        18446744073709551615'u64,
        gas_used:         7874274181221487360'u64,
        timestamp:        1,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[139'u8]),
        base_fee_per_gas: UInt256.fromHex("0x1eb821a0ee3f9d2e5b49c64177db9ffc96ec6b06249cefa8c51d0ce7e664a3ae"),
        block_hash:       Eth2Digest.fromHex("0x99479be6429eac4a945ca8171d3d3ce42d7b5af298292e833e20462438e06229"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[99'u8, 198'u8, 91'u8, 86'u8, 23'u8, 222'u8, 121'u8, 250'u8, 12'u8, 135'u8, 133'u8, 37'u8, 61'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[81'u8, 173'u8, 241'u8, 145'u8, 54'u8, 3'u8, 36'u8, 121'u8])])
      ),
      (bellatrix.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x06504beb0dc3bae44ef75678d29ec5138d87da68d307ca7d43e259cede60fda6"),
        fee_recipient:    ExecutionAddress.fromHex("0x527ce602a0be18c0944dc27b2864c711a91f89a6"),
        state_root:       Eth2Digest.fromHex("0xad3bbef5d22bdc2429da09eb85137c881f85fe6e6b3ea207e5eaeb399c755055"),
        receipts_root:    Eth2Digest.fromHex("0xf94fdc52cde20532cfdee73e9cebb61d9f7160191345f9caf58b45501d8effbc"),
        logs_bloom:       BloomLogs.fromHex("0x0999cc50752006a2bc8e5485c239b9a41be6ea2fd8f0392884246ef7d33bccdf4bd326fadae385e3ecc309bf0f367ac1791767ffaee90ddfa7bee22d19f417708fded2b2b6b3be2b6007745fb1de940e7849761586953c04e3bec3c9b6342d1b91dd024980f469b484bd0befc4941a3846d027390d6256e4acf9933e0891dd558270eb35d3455f4e49c890479e970a8008b75ff4d33b4f7e5a8c19e75d8abd8673ebb859a8a24907584d88f0d68b3142b3c6952695fdd84581f5a070601a575a8e7bfa0bf7cf0fe9d70a051005f9dc594d09909e9d079d02a4e441e5b3f33388de8d46cbdcdf24f835415680e569f2ed29acdc01042a6a7ee701e4e6cace5c28"),
        prev_randao:      Eth2Digest.fromHex("0x7cef96d72498facdb399dfb5b6d7d69185f3edc70715540fdc7ef651c4685c6a"),
        block_number:     13066898984921201592'u64,
        gas_limit:        9241830338892723842'u64,
        gas_used:         8347984358275749670'u64,
        timestamp:        1,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[11'u8, 46'u8, 127'u8, 104'u8, 141'u8, 79'u8, 55'u8, 48'u8, 242'u8, 12'u8, 142'u8, 2'u8]),
        base_fee_per_gas: UInt256.fromHex("0x6241db2a44a58a2c1aac93c4aa18aed5add30d1937c31078542bb544bf9ba2df"),
        block_hash:       Eth2Digest.fromHex("0xdc1756667e7c3f1615650cbbaae1117a6bac817c6579cf3f7afbc93277eb3ea1"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[13'u8, 24'u8, 248'u8, 26'u8, 141'u8, 177'u8, 236'u8, 2'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[213'u8, 208'u8, 242'u8, 46'u8, 0'u8, 31'u8, 219'u8, 213'u8, 197'u8, 218'u8, 148'u8, 236'u8, 43'u8, 152'u8, 123'u8, 96'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[84'u8, 163'u8, 60'u8, 195'u8, 40'u8, 68'u8, 185'u8, 20'u8, 244'u8, 82'u8, 34'u8, 181'u8, 26'u8, 201'u8, 2'u8, 108'u8])])
      ),
      (bellatrix.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xb5d4a5eae3a1ea004ed573b0b8f8a22c847616758c0faf1e7e9589f16e55415c"),
        fee_recipient:    ExecutionAddress.fromHex("0xf7ac0877fd8bcadde1e050f6c7ddad13688ec071"),
        state_root:       Eth2Digest.fromHex("0x7472f824376a723894f8d539743c7f93b69839772f28cf6a83e2102fde99c3c9"),
        receipts_root:    Eth2Digest.fromHex("0x750365b5d975460a64f07758abd0cdd44cee23cc2d4f06f2a047cf4c12c23db4"),
        logs_bloom:       BloomLogs.fromHex("0xe24d8452039bddd10e1252c1ebf9b9e81a22577f940e8708d200548717e8471e130a7066adc48785a8dea1dca05953d6be16504a57112c065e7909586cd611af9e0b840b81caf0532dbb2833ee5ac6a6eb7b6c990cba6ccf6f4ddec5a7c76f8296bd2a693cbbb43b1d86b66f6aa58888734d3fb21cf5e96f1b981f8ae2737bce1cad1cc458650291cf7a3d22c61fde6af3a07a44bf1b334b2c5dabbef16e5e73db75e87f04670cb3830f0a7badc702e7dd37a59ce02992f4473a909e57dee1fdd22cfc886f4fcb6ea205ec9234a8ec85ea134242748f9f10062534fd0528bc1b5b1e89511cdf91a1e7fb4f8c58c93d2a6c75e48a2d48235cb7de13040db8dc9c"),
        prev_randao:      Eth2Digest.fromHex("0x2410823a37c763e13b03a4c48e32f9e43b8440ca31ecfe8e0543a20a02c496c5"),
        block_number:     14920119354157670036'u64,
        gas_limit:        17193947846593799248'u64,
        gas_used:         2176791850599260430'u64,
        timestamp:        12670133468877091192'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[31'u8, 7'u8, 1'u8, 212'u8, 152'u8, 82'u8, 167'u8, 57'u8, 116'u8, 147'u8, 97'u8, 109'u8, 219'u8, 207'u8, 151'u8, 116'u8, 43'u8, 218'u8, 91'u8, 253'u8, 14'u8, 182'u8, 102'u8, 57'u8, 153'u8, 72'u8, 172'u8, 208'u8, 0'u8, 64'u8, 97'u8]),
        base_fee_per_gas: UInt256.fromHex("0xf1daaa067663bf3277b9149aab162f4e330f988f0be8f83a556743a57ae5c8fd"),
        block_hash:       Eth2Digest.fromHex("0x5d462b4b243c6292b6a3b32f4e05849c0613d0a61954734c524f75f8df66cf8d"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[])
      ),
      (bellatrix.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x2629683cfc70198038837270bde3c60176c2a4aeeced0d4a4f14dc99a380c377"),
        fee_recipient:    ExecutionAddress.fromHex("0xd234af1937861b66ca84c334824763fb54347677"),
        state_root:       Eth2Digest.fromHex("0xf79f02d52d7f2a4be99eebba3dfb3bce74136ea739da515703d095a66ce203d5"),
        receipts_root:    Eth2Digest.fromHex("0xa97ae6fa5d6937f7754ff96766a54bb8ec082b046814e74f6c9c67147795f526"),
        logs_bloom:       BloomLogs.fromHex("0x5d2ef8bc2f58a84e4050e3a38985e4c267940707c8da3f687fefb9e22e4ae11a2f79a24456af3758e8b521d546dc178da5c85da869ebb2da551976488a769ca2940fa20853e4e1d1fcf8d5bbea0d16973c827d38c97c47c57835677590567829d119e8108f2ee3fa988b267ccfc3e58e5f81c18c775a9baf06d4d81aee405c5683fa4e5e891b58101a27e8f71c60d357a4ab8bd02e12fbbb0e363c4632b0a3c0de638de37448c9476c65a62f7f1dd9643fac6ff78ee431d18ab554b4c8a1984fb5fa0de3464d223f236eb8e8a8f59601221d2ab480ffcefaf4bf6471b40a14773ac0cdb43aea505941e4b0fa6fb26eb091adad77acce41e516fc743e5fdb045f"),
        prev_randao:      Eth2Digest.fromHex("0xbe44d7c5f844a2acb307a4371784d7742be482aece83368d94813ffa1c7bb60f"),
        block_number:     13524449277995212660'u64,
        gas_limit:        1,
        gas_used:         7976957374052242924'u64,
        timestamp:        1,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[57'u8]),
        base_fee_per_gas: UInt256.fromHex("0x6c98d9ff36f1032fd55d8a6038d7b1f7c4e5f7c884b73f626fe43e687beeb46d"),
        block_hash:       Eth2Digest.fromHex("0x2c95101857b07bdda0502741da8cd9160ec0474929d132e9159098576f9a7c35"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[75'u8, 85'u8, 130'u8, 87'u8, 90'u8, 172'u8, 176'u8, 44'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[207'u8, 150'u8, 64'u8, 87'u8, 15'u8, 18'u8, 3'u8, 236'u8, 232'u8, 87'u8, 174'u8, 192'u8, 29'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[23'u8, 37'u8, 57'u8, 158'u8, 137'u8, 222'u8, 53'u8, 111'u8, 63'u8, 13'u8, 69'u8, 110'u8, 175'u8, 108'u8, 16'u8, 207'u8])])
      ),
      (bellatrix.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x190544155dd98bf86d3ed5ee94d01afd3a8e67b8476f94d90604706da0a7d340"),
        fee_recipient:    ExecutionAddress.fromHex("0x799d176d73d5d6d54d66941ad6cef8208677371c"),
        state_root:       Eth2Digest.fromHex("0x07e626b9c44b0ff14586d17acf79cb136ccc5d37fd7135da33cec516af168f43"),
        receipts_root:    Eth2Digest.fromHex("0xb8b100bc5c155fe6358b9a16756ec06880365f5fe89124cf9fea963e26d3770f"),
        logs_bloom:       BloomLogs.fromHex("0xc314d3d6ab41a3fce7433dc286ee5c9820d883ff572ee7dfd2f4ee745f11a71f6dbe142d8c14bd6cc76782f1bb2b3770e65a929b2187581956bad937907a124c92ba10686763ddc87ba5b4a4e9cf4b9a35255fad5f54b404aeed5ad9859b5f9fd3c137e9eb6ef394a10b8ad3fbba75ba38c2cbfb91fa793ac763e8cd31481fbecef02b3365b990f5120a2970f2779574c60769347ae334a9f39bb3d3ad35182f7dcd252bfe9663c4f54b44dea8d79e3bcd89877231e81a9e9f5c1eaf5da1f56ffc39c23fc3ae6c130281c792a31e7a60115d46abbe17807cd120038631ca7a6636c8c644b57719e386cc8ada32ce806f75110ad143522fb0b240213df4bab07e"),
        prev_randao:      Eth2Digest.fromHex("0x17e445793c0e354ee43381ded194220ebd87ccbacef83e3da5a1cd3c8c57bf49"),
        block_number:     5728529601694960312'u64,
        gas_limit:        9410734351409376782'u64,
        gas_used:         16470261240710401393'u64,
        timestamp:        8811957812590656903'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[95'u8, 124'u8, 151'u8, 79'u8, 76'u8, 171'u8, 74'u8, 213'u8, 207'u8, 202'u8, 63'u8, 2'u8, 182'u8, 32'u8, 115'u8, 65'u8, 90'u8, 186'u8, 34'u8, 63'u8, 241'u8, 191'u8, 88'u8, 10'u8, 197'u8, 52'u8, 33'u8, 98'u8, 78'u8, 210'u8]),
        base_fee_per_gas: UInt256.fromHex("0x3c1ba8cf82268c828c1a7f249328741ae21f35a7659365efd7496df94dbb85e9"),
        block_hash:       Eth2Digest.fromHex("0xc2b2bc39ed0cf5764800d3c91401828ed32d0eea58f9d336c32f9e6f7200ac8d"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[])])
      ),
      (bellatrix.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x86d7b430f69b215ab5ae863998ce41f01a5016376c8bec7f5b7a6e16a2326d92"),
        fee_recipient:    ExecutionAddress.fromHex("0x73068946d757f5d145a38fe9de817b8b1e9d6c43"),
        state_root:       Eth2Digest.fromHex("0x312b4af4d3ca5960dda2f99531819f5c32624753cc0756c05d242f65dd605d92"),
        receipts_root:    Eth2Digest.fromHex("0xf3a1e8f784ee4bdb897d1511ce642276e2ecbc1f21bfde9caf7c4479b7fdf902"),
        logs_bloom:       BloomLogs.fromHex("0x633d228aa8b2b9f4b614c4b7c7aca616232d61bc6e06ca28f4b94bc39165cf3ca2e090cebbe8a5b66b161d92e65099503327f9f2adae6ec5a73463063a994d73f37e12caec8f6d439be7520b48b25ccfa8ff64e6884b7e240c8dfd0100a23f9f644da13f1628d989eef92806c9f936a71f470d710653355acd84fb23ff15910f1d2866d83b036246c46a681e762b9a19e72aab21b428c4710511d0a39cc5ec39ebf3aecb5c19096ab32135a629abc8cdec39b2b3631bf4e86bbfb824276fd728bef454ed981e5f9e8a4bb96b27f09f661c5c221f63a26945174162496496c9bbf38cd894c50fa69df0a8c722ab48d75044bf43468639ae9b61d0b5a2f9d819eb"),
        prev_randao:      Eth2Digest.fromHex("0x3a0689ac32c82a6b84d3230fdc6e2c1e89671fa3906336ccde9fb7cfd1811ac8"),
        block_number:     9465334901279616671'u64,
        gas_limit:        17844363972830076325'u64,
        gas_used:         9534663249377184661'u64,
        timestamp:        15490999633909732541'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[199'u8]),
        base_fee_per_gas: UInt256.fromHex("0x9fc9f32819a67c4aebae259b0648e2b82f526ce8eef8fee33961f9fc69653b2b"),
        block_hash:       Eth2Digest.fromHex("0x1ac3f16da76520977c5e5d86f0c261d76e18413c202e8a46241951b3a80ca601"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[223'u8, 37'u8, 18'u8, 125'u8, 208'u8, 57'u8, 114'u8, 113'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[137'u8, 181'u8, 143'u8, 219'u8, 145'u8, 77'u8, 39'u8, 126'u8, 173'u8, 30'u8, 59'u8, 70'u8, 205'u8, 51'u8, 16'u8, 213'u8])])
      ),
      (bellatrix.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xc51bf481df9be981c6656081e3854ffcf27551e2b4fdaed4ab12b355f247f4e1"),
        fee_recipient:    ExecutionAddress.fromHex("0xd79098c25eed05c9f6d55e95f5f6f58c1472fb28"),
        state_root:       Eth2Digest.fromHex("0x1a6b1eb78e5ac155d4be247a3b48d8d8d8574a16fa846681553037629b97ffd0"),
        receipts_root:    Eth2Digest.fromHex("0x5e44d4a3621cd8e495edc0b208f977c8d3f8e79a78fa7ecfc4a0f6e436f67b71"),
        logs_bloom:       BloomLogs.fromHex("0xe2b0dcfd2341ceb9c4edbc7115dbd6ed5f1c54ca39bee191fdaaa34368acee93f48561094dd23a3985ea2c2b83d918ba9dc671cde7732a591b4f9abd2eacf9d6416ca8c8d556052a98df2cffdbb086315585004c51c76872a06cee7d318f4845c0ade4c907c7933d4d883bcc586885be04ca9149e05b1624856e69e1efe8c93cd55d840bf71279293a118d51d4391fcbf4e6abe6ee50492ff2de085069a3c7656eb3a749d6bf46f56a2acd93a6840eb78e09a42f23fdea69bfbf017f4fd6b4a8d17df1aa5147c1897fe5fda1f5e79121f2fefef97117e7871d1cbf5b0b0350b9fc497c5aba27cbc129d452d6a60effb76e08b890d0bb856115fcfe3966359fda"),
        prev_randao:      Eth2Digest.fromHex("0xcd6fd69596cdd7df95e0b68e8ade01541b12ed15caa2b59803a4c4e6791870d4"),
        block_number:     12264963829660560313'u64,
        gas_limit:        11775806146734810959'u64,
        gas_used:         1863395589678049593'u64,
        timestamp:        5625804670695895441'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[183'u8]),
        base_fee_per_gas: UInt256.fromHex("0x1443705192ff4dc1a819be4f22b8dcd6e7802337e62082880b1090f44a27d0e2"),
        block_hash:       Eth2Digest.fromHex("0x68da52444eb5322f3a0bda6bdc9a3a11a540dbd22026bb2d24862bbc32af9460"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[212'u8, 80'u8, 176'u8, 133'u8, 132'u8, 119'u8, 233'u8, 131'u8, 195'u8, 118'u8, 54'u8, 94'u8, 129'u8, 206'u8, 47'u8, 107'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[231'u8, 31'u8, 192'u8, 94'u8, 136'u8, 120'u8, 228'u8, 222'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[114'u8, 23'u8, 239'u8, 220'u8, 169'u8, 188'u8, 213'u8, 179'u8, 223'u8, 129'u8, 189'u8, 50'u8, 158'u8])])
      ),
      (bellatrix.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x8b3e7e8d447527b9d00693389928260e7ea9da6855efd99369182bd9c213988a"),
        fee_recipient:    ExecutionAddress.fromHex("0xb45716c9aeddeb030c0b94202fcb97bd75a039b6"),
        state_root:       Eth2Digest.fromHex("0x8114b285e5f3277c04a66e660fef3b86295d6ca859dfa216df3309c0a7242f2d"),
        receipts_root:    Eth2Digest.fromHex("0x2a3ff38541ef83faad176c3c98ceb5c55622dec83fbfc5a19bdb27646849e852"),
        logs_bloom:       BloomLogs.fromHex("0x384a9b3d38d343af68d00c229e79aa31f2059e17c655f5e48d31d2b59b769660e91c1e5f386e4f7dc83f2570029a6f2b3351623fcb4dadd6b5b7b26e27de19e248ebd970a9678b69403ea8e16fe88562959586fcfdee3c407fcf623c94891a2270ba1829bf2ab77fa32913bb11c8a4a69e9baa6544ad336253637626b16d4a98884e7ac7d6c1e697a9435b1e5403b5122eebddec9c03c8a6c8fed0d8877888371e133fb837d33f073375f7e1536abf622610734b9b0aced8a891f02d5b35734e58b0ead66c49ed9f898b8f27e9415275c5d15051ec00cb006f8aef702a7414aefacfa9742cd3d8d34be817e0c731696e20b973cf2da66799121c0c6d12bc835d"),
        prev_randao:      Eth2Digest.fromHex("0x3bd54c7151dae2ad524b4df0d4283e3641ba787fc76f54221dba3a2aa556a1bb"),
        block_number:     18446744073709551615'u64,
        gas_limit:        637978774023867007'u64,
        gas_used:         15110835166938431016'u64,
        timestamp:        18065456863038184935'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[235'u8, 229'u8, 162'u8, 249'u8, 154'u8, 135'u8]),
        base_fee_per_gas: UInt256.fromHex("0xbe93cc3dc2bb7e012db659df49e57653bf6ff21354c64eeb69c0002e9f933035"),
        block_hash:       Eth2Digest.fromHex("0x46cb3f590b2fbce372e67968a0d2ff4ce1b2c530fcc26b7a24ed6db054f52035"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[16'u8, 66'u8, 215'u8, 40'u8, 223'u8, 195'u8, 43'u8, 228'u8, 225'u8, 244'u8, 34'u8, 14'u8, 117'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[92'u8, 46'u8, 215'u8, 218'u8, 71'u8, 99'u8, 115'u8, 119'u8])])
      ),
      (bellatrix.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xa4854e346d2e9a921cc6b3c4ce9fc739c99795cf10002924089f9886f8624d59"),
        fee_recipient:    ExecutionAddress.fromHex("0xa88781cf69a1eed63bcc3a32b6f9aba35d4f5b5e"),
        state_root:       Eth2Digest.fromHex("0xdc06d9210fd2738b0fa9df6d68e4ffbfef0dd7d7d8093fdbcd97ff845318cf6b"),
        receipts_root:    Eth2Digest.fromHex("0xfe1b70c143066edc444f9b49e778cf6db0060bd4e9122564350cf23061830439"),
        logs_bloom:       BloomLogs.fromHex("0x095a57c3f2d97aad8692cd09dfdd8388f1bf9ef98a1c3223ecfd0aed17d8c7c3ef593d7f09ba86500644deaa676df811da501d572f342e3f7ee7b9b081992f344f71fa50b3b9635d7375f67dbd85a0b1ade3d8d4778118df55b90c44f7dd1114f2ebcea5778b32701ef94af9b3713d1fe00275e09c7e918d7c529a37aa9de3464eb6364812ec486464ccbf7df2523369fdeb1b28955e35e8685c16f07fbe342edd1bc044021ed480bf4ceffefb13eaf4550c67ef8a5079f3f612f07fff60193eda6ac11d39f3056c41ea4355ef5ef7f311493c415cc8c42cb30a73dd58098262acebe6d901e4bae26b6e1eba693c7dc596ea27b0cdd4fee2f6450ca8b50b1a70"),
        prev_randao:      Eth2Digest.fromHex("0xc52844ad11072faa2222ffe9cbff77dcc7f681367d2aef5f1c3b206140064195"),
        block_number:     767785029239287422'u64,
        gas_limit:        15062566578072747104'u64,
        gas_used:         7648884410596067087'u64,
        timestamp:        4380084205540210041'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[217'u8, 40'u8, 125'u8, 94'u8, 156'u8, 71'u8, 79'u8, 66'u8, 117'u8, 228'u8, 173'u8, 189'u8, 115'u8, 41'u8, 153'u8, 226'u8, 130'u8, 21'u8, 108'u8, 194'u8, 206'u8, 218'u8, 141'u8]),
        base_fee_per_gas: UInt256.fromHex("0x436767990abff9288346859c6b85b8a972421619eab2253483385c8151cb2016"),
        block_hash:       Eth2Digest.fromHex("0xca4f05c33836d82aee8230ef660016b993bca4aaf9a7b6cad96c2a0193eb026c"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[156'u8, 143'u8, 203'u8, 250'u8, 238'u8, 137'u8, 34'u8, 245'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[64'u8, 44'u8, 165'u8, 9'u8, 1'u8, 211'u8, 27'u8, 108'u8, 166'u8, 61'u8, 119'u8, 11'u8, 222'u8, 85'u8, 48'u8, 185'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[165'u8, 95'u8, 221'u8, 213'u8, 229'u8, 134'u8, 185'u8, 221'u8])])
      ),
      (bellatrix.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x5e7b12465e0461e5dfa59a3254282378c55961b0e411023ce89d968bbdc33e9c"),
        fee_recipient:    ExecutionAddress.fromHex("0xbd1a1396ab49631cc933770944996b294da97d43"),
        state_root:       Eth2Digest.fromHex("0x74e6ccfb15da8afb94eebf28cb3ba3f9ce63e3354097f2f2527fe1cf978e76bf"),
        receipts_root:    Eth2Digest.fromHex("0x8e48bee56e149d1851cff0740ceab06767bd0e819261c5a2f75dbea382a110b6"),
        logs_bloom:       BloomLogs.fromHex("0x7894fbe58c624a153dbb160c516c9e82bd0cacf5f347f984efcca9450e9a20b50e058ed38e41c331df61114086f8a6b8a049467d7dafd812953aa593b2e9fbc056f0dba80973b2eaae8814b5e0804300eeea15613e59c8d34339f58e1b45599361497a3608c05140cf432e7983a30985aa0faf45dff56dce99eaa5ad3418722df17eaaa4e8df25ed1d9eedee1390e6440c4c37675182dcc07ff199d6dd015d3aa03194765e85fc0d4759d3c693fc2550e50835b88ba41d10fc33b58550d813abaa75bab39c0fbe419f1bde8fb82db9fcfb79894faeed84b2314f115a8fb9e276315ccbfb8e9650571add358f594ff2fb4ab9661afde76081bb2cfbfd2f26d212"),
        prev_randao:      Eth2Digest.fromHex("0xb9a9bce05e42cf3d2ffc2c2ea95164c9b215fc8e440dd2985ca24cff40e32780"),
        block_number:     14460352585391846826'u64,
        gas_limit:        2426408612341958329'u64,
        gas_used:         13656152006197676019'u64,
        timestamp:        6263571560389404595'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[177'u8, 36'u8, 79'u8, 26'u8, 164'u8, 59'u8, 182'u8, 88'u8, 223'u8, 22'u8, 79'u8, 197'u8, 109'u8, 53'u8, 53'u8, 134'u8, 244'u8, 84'u8, 146'u8, 158'u8, 234'u8, 252'u8, 188'u8, 175'u8, 69'u8, 51'u8, 118'u8, 101'u8, 242'u8, 0'u8, 51'u8, 103'u8]),
        base_fee_per_gas: UInt256.fromHex("0x997e6c8ffbd1ea95e875612109843c6cdfd0c6bcaffa1e06ba303b3012b3c371"),
        block_hash:       Eth2Digest.fromHex("0x9a7f83cf6a64e153fc3316244fabd972a49ebf5dfb173d7e611bf3447a175c41"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[137'u8, 103'u8, 164'u8, 112'u8, 136'u8, 91'u8, 170'u8, 241'u8])])
      ),
      (bellatrix.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xa8f90a617f1f230506d200c6026bd60e38f599930ed04f90cdc320a6d45bb022"),
        fee_recipient:    ExecutionAddress.fromHex("0x3531157eaf2c185bd8720f3edfaf76829632f07d"),
        state_root:       Eth2Digest.fromHex("0xa16f8936e945ecd45a4ae107e46acd8530e438fa1bc8eb85aef62afaca1656da"),
        receipts_root:    Eth2Digest.fromHex("0x3e76522c8f3b7e8d8a63f4968ab15413b8bbd7af9782c4878b52213b0b3d13f8"),
        logs_bloom:       BloomLogs.fromHex("0xc13b59de763feaa39debf70d280364ec68eb578af8a90aba7e2cf3a6cee413a28836c674662a0283df8ff04964eb928de97a3883226950b584d773c9b4479d6d5bda6fd71951c0c846752ed688e13dccff947b7a6c81bfac198b6bf785bca7be28bcf9a208b983afe6e766b0536311c1c12b4d01c712cdaa167ecec5520395068b1c1f939d20962de1aba36454cdb36031fa0ba886a8ece71234654e8b081562452046a388ebcf3cfd975493833ff4e146d5e5ddb061d994461ab8b468cf1d6d491d78fd8923f9f6563e3fbfa72639de993701ff6214fd83cd3597e870dec1c1e788a4f01f881c48e57b07c5a217132658208d2221a86c7e9823159984d235b5"),
        prev_randao:      Eth2Digest.fromHex("0xbac4a9aa16b289584d13abe3c47a58dda713c4b479ee70e1ac7b3b698e8505af"),
        block_number:     4839752353493107669'u64,
        gas_limit:        4713453319947764960'u64,
        gas_used:         3470256075652600568'u64,
        timestamp:        13764471837770950237'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[60'u8, 109'u8, 153'u8, 55'u8, 17'u8, 196'u8, 17'u8, 96'u8, 202'u8, 173'u8, 16'u8, 189'u8, 165'u8, 107'u8, 68'u8, 230'u8, 238'u8, 62'u8, 199'u8, 211'u8, 244'u8, 83'u8, 88'u8]),
        base_fee_per_gas: UInt256.fromHex("0x3adad83f48e34c6220dce41ecc0b09f9bb1ae4bda4466935c70e7c6cd54e185e"),
        block_hash:       Eth2Digest.fromHex("0x9183524f908425608c1e3a80d7c4ac2c539903af4b3a2f1b22c3283281706aba"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[])
      ),
      (bellatrix.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xc914f63464f3f1588a32d3751900d415bbf1fe002c42068650f5c7c588b1935c"),
        fee_recipient:    ExecutionAddress.fromHex("0x61523b6add59cc65d3c5b75c6f749fa601e157de"),
        state_root:       Eth2Digest.fromHex("0xe84ecb995f6c7e753355c8d2e24694441c528b65ef9b1d8c6f4e9d98d409342b"),
        receipts_root:    Eth2Digest.fromHex("0x887bdafa340c24acb58f36a7e3825ce39fb7e0caaba3a9b63f78d2186cc6994a"),
        logs_bloom:       BloomLogs.fromHex("0x1fbd358ad7e32eefe4489b6c72bafcf6dbac109970e5c103e329279cede3619faf1309faf266ba155496c19565b31562f31539c98b6256919d8950bb6eca937401d91fa5b3032b4400ce6dd60a8c1c6cc94331b7e78d7a350ebb5d6e04a2594af981f167a89227c7c902dbb8eac3d7b54177d85214a6ef57b50da82b6420cf914fd63171f0b7dff9233bfaa2069774b142a136c5183ed4f57cde2590735b19ef549ff5bc910477b98344e7557ffc440b03d56842f356a6e223fd052c6272e24f43dc9e64055c097d81b56ecfd6087238602a743e09c383ad4eae6ef449570febdfebfefa347f06f480f319ff06365bbfae16b62a950143f9acc3663510356f0c"),
        prev_randao:      Eth2Digest.fromHex("0xc755584f86084ab2e62bd58f25dfe54538c0171e6447e7e1a51cf05db94377da"),
        block_number:     9276126375553452674'u64,
        gas_limit:        9007257403963034102'u64,
        gas_used:         12806310385580231715'u64,
        timestamp:        9957937708118639445'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[]),
        base_fee_per_gas: UInt256.fromHex("0xe2df33500d1162994934e9fa65fd5db641b0be2b61a6c302c7b9019f86042338"),
        block_hash:       Eth2Digest.fromHex("0xce58ef51926a6eb4cf2997c4ec771b54907737ae8fe9522fc316c97a1c7ee6d7"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[])
      ),
      (bellatrix.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x086322b79160568c7d096747ef351338ddc93f252dab1df3ef65aaf24723d2c3"),
        fee_recipient:    ExecutionAddress.fromHex("0x03c6998b5a3ff1c98538c2333d279f2b1cc59f7f"),
        state_root:       Eth2Digest.fromHex("0x446d99a7e9fd2c327fbd445dbfb3b3e3a895cdfa6f208496dd09c0f84f7ac0fd"),
        receipts_root:    Eth2Digest.fromHex("0xf4c74d5c59c46f1d9f916b32d8a12939cc2a379bae83153137de76415f6e5afe"),
        logs_bloom:       BloomLogs.fromHex("0x40f87c3729ba599c3e9bb749c48148ee0d5563db71cf0daaad3af95c45622d7b2a64204157a92a93cf0ffbe0052fb79eef83ba8389fe9d9e7646874b0636960e4eee86eeca00ba70f65b2046620264b795852def9beebb671f841e19ce07934b7c2f66301cc3c7dfa2606067cdeb04a564b87e56ff3650c7c6bbbc96b2de5ccf8e314ae74a26347371c315062532a1f1a2fe0c417ed5d12b6f81c3440c0d8b19d0cf8a030be83ee7ada6046d75098b6ee66664ead786a65ef5cdcb33c4634aa07cd7490abc0ea9ce722423a0cba1aecb379552e89483de43dd321cdaa8a005ab7e8e2a958038ca12e2b08709348a7f6daf34c488add1a0a21aed0da0b64251f9"),
        prev_randao:      Eth2Digest.fromHex("0x2ff08bd0b22bae8c3627f61b8da627fc367b3a60f93dbe48de1ca6f25ada489b"),
        block_number:     10605470807350562909'u64,
        gas_limit:        587854351728657338'u64,
        gas_used:         8799032544585725320'u64,
        timestamp:        18028498231539883963'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[]),
        base_fee_per_gas: UInt256.fromHex("0xfbe348f0c77be2ddbd3ec038e3aad88107625dc6e96b1fb3bbfdba8c737a3d7e"),
        block_hash:       Eth2Digest.fromHex("0xc545e833aa2ee5d708e041f4dcb44bda654372b3f5f660c683d12230303da729"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[89'u8, 59'u8, 131'u8, 146'u8, 186'u8, 180'u8, 208'u8, 76'u8, 69'u8, 40'u8, 29'u8, 211'u8, 97'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[208'u8, 136'u8, 157'u8, 0'u8, 120'u8, 231'u8, 99'u8, 33'u8, 31'u8, 210'u8, 80'u8, 203'u8, 24'u8])])
      ),
      (bellatrix.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xcfba7f4aa4ff01d3d9de84dbe1761c79627a10c3188fb0a7c8adfa0d489e6441"),
        fee_recipient:    ExecutionAddress.fromHex("0x106b3bcaae4ff58dd837768be35c29c48571e4a4"),
        state_root:       Eth2Digest.fromHex("0xe6242399020361e70cb6b89701001fa8326251e6bae3b4ca1978eded8831d9a7"),
        receipts_root:    Eth2Digest.fromHex("0x3db0f9a05cc39be94414c3be28378d2b91ba3ff43ea2ea7e4e0a1874a0983f58"),
        logs_bloom:       BloomLogs.fromHex("0xd591169a3cc38e0837a76c4d7057f94c1ef08ad5af1778b1b06c3a0ec85201bfc659b18c49de831ce6b4a40f0d2800a9cc9001f74810c58473f9b973b720f84626cc9270b0428439b985043f5d9c3289ef8a794f5b8265e10e9fb9fa53a93887d270b8204f8f16cd968e295b0a06aa70e9f6f174733d251f3bfc644a7fb274b0138729f18c0e4382bd4bf0387870f633ed897a125ca854120c2885194f3180af4b62760db96da51f88ae1cd222f49b00fbbc1544eb0e98cea67e36368816f541723158d3691f3cf1509c65a51a8e68efb66c500dd6516ca1b02aeb4e0c13cf5bbead53672fb5a7a1863c8edfaf4eb9a4b4322a39d8643528bccf22493914fa01"),
        prev_randao:      Eth2Digest.fromHex("0x14fec0a1edb9c82dc9aa7fb7224791c51a3937e74e5da59646123867496460f2"),
        block_number:     6272046003849350913'u64,
        gas_limit:        15423951135645467684'u64,
        gas_used:         3743939155619454195'u64,
        timestamp:        8496536260448579184'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[152'u8]),
        base_fee_per_gas: UInt256.fromHex("0xd8b104041bdc4c76a9735e2b4b45f0f3612e8962f672aaf511f06a94b48562c8"),
        block_hash:       Eth2Digest.fromHex("0x8ca67fec04b7e3bc5a01f5bb265b93b4488b58ec2ac7f2c3ced030311de2762e"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[152'u8, 232'u8, 136'u8, 228'u8, 253'u8, 248'u8, 85'u8, 92'u8, 103'u8, 38'u8, 106'u8, 166'u8, 148'u8, 8'u8, 37'u8, 245'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[58'u8, 215'u8, 97'u8, 99'u8, 152'u8, 126'u8, 14'u8, 252'u8, 64'u8, 87'u8, 242'u8, 60'u8, 210'u8, 217'u8, 75'u8, 189'u8])])
      ),
      (bellatrix.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x063bc56b731eeeff8bf1c33d88523a04a14fa0c745eb3c750139842d88244982"),
        fee_recipient:    ExecutionAddress.fromHex("0x415b1cd5b42709a3724ab2f6f50a6dab7399d7ca"),
        state_root:       Eth2Digest.fromHex("0xf261abf37066b8dc5c868946346c98aae445adbb48e6dd05969fbb49267a276e"),
        receipts_root:    Eth2Digest.fromHex("0x5a337b7ee29d98e22b461f43b7a87e52d89fda2e7a3487ea92873be04a49ea68"),
        logs_bloom:       BloomLogs.fromHex("0x01817fd642526acdd8b57b4fc2fb58aba269095ce220ae5770004055f550918778021eae3abeffff1b3fa9fba50ff8d532fd8e2e67da7bdcca1cf9505179f19f595f5d9f09b98d5bc7d1ecb22527255e8e161ca2124c5fedbb59527f91a242671177e33a6fa377d585ebdbd6d9ff2bf80bec3695657441e35da43861f14b9a7e65ed475c323ece62d84aed7262cf3fd2b06ba03695e2e26e5e58fc5b8b99d519fda879587e3764930e3921aa15b2ee8691ea0e738030acb8832ca353d3bb63fbc0150c532b842cd053abeae8238c9ffe6f4b2b7210dc862c48843ae2a9088ecdb8c258592a0feb5215b8c9ad494ad896379d86e0ac89e6cd8765003ac5c95cce"),
        prev_randao:      Eth2Digest.fromHex("0xb28f434f3f40e40693b0c1726a018e2b3bc13c41608a2ca71aa5c8bf61829287"),
        block_number:     14597257287993827247'u64,
        gas_limit:        9090926713872599867'u64,
        gas_used:         17391976671717618186'u64,
        timestamp:        13439825139187707720'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[73'u8, 163'u8, 138'u8, 201'u8, 62'u8, 1'u8, 37'u8, 90'u8, 157'u8]),
        base_fee_per_gas: UInt256.fromHex("0x8a42339ef76757729ef6c4536b3b59255b18d7085d8ba786275b2076fc55b3c6"),
        block_hash:       Eth2Digest.fromHex("0xb3f6ec11b285a105833f5b68b67e8e23c85c28df2362a13a76db705f110fce8c"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[])
      ),
      (bellatrix.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xb31c41d39ef7e9a9b905cc93d82264415024d7daef48d886f1b3bc0fd6545edb"),
        fee_recipient:    ExecutionAddress.fromHex("0x5ad4b6c0d6b986e775f3a9ae2be73a330ba9f87c"),
        state_root:       Eth2Digest.fromHex("0x01dbc857a3d8994cf10cd1be3b2018be0e26ba54a5456e10a6e5729328a0b5f5"),
        receipts_root:    Eth2Digest.fromHex("0xa51e9cb9893bd7d73a8fd4e5267d80ddcb29d998814cfa9980dbae50ef101aff"),
        logs_bloom:       BloomLogs.fromHex("0xf1280db0ef6bb796e70dfef3b0bafa62690ef1e8f14a237856bae5dbe29dfd43ac789c53305ab5b0b7cc48ed53d1236ab9433a5352dac55b6e0a3ff90e9e815e2ce16fe5574c87f0066090c39b811996e2974da0bdb8bb59eb044bbb6bc2d7f8241093c7143a7c9892be85ea4284258ea2477f6a677d424efb6469724d641bbdc3f9254529b6af5cc5f5a77dad49c1a59ae37c19ffc69f6e331139b6ebac306ea09460dc0fc5791ef2cfb9e7bf29d662872e30b94384be90416df03bef5cf5a2339af4745f2f620fd1320d3fb79848692719cb8956b8efd427c9c0cc3ea6efb8f84feae0075ed10ec5c6243074e6004849712d8d1dd97ebb2948fcdf1d020c6e"),
        prev_randao:      Eth2Digest.fromHex("0xc8a27f0b7850de04e3d794b9e9d4f144c356f864401c3f802927faf4b88b47ac"),
        block_number:     10821099926525463598'u64,
        gas_limit:        7115919978619568727'u64,
        gas_used:         1,
        timestamp:        5900615379943209755'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[56'u8, 176'u8, 67'u8, 30'u8, 11'u8, 27'u8, 136'u8, 121'u8, 86'u8, 17'u8, 4'u8, 121'u8, 11'u8, 222'u8, 158'u8, 78'u8, 56'u8, 66'u8, 243'u8]),
        base_fee_per_gas: UInt256.fromHex("0xfbaacdba879288838ff725df19b7a31148ec5a24e7989441544d6dec1c980034"),
        block_hash:       Eth2Digest.fromHex("0x04616c0808df7a1bc177bc48cb6ed865125fbbac2fa3e3c36f33a5f1c48a23fd"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[])
      ),
      (bellatrix.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xf6cba3ced37c08da230babbf9d1e360661e5a21ac235fefa75cbe756f15809de"),
        fee_recipient:    ExecutionAddress.fromHex("0x0c080349793b7f43fb3ee9101889e7d32e02c01d"),
        state_root:       Eth2Digest.fromHex("0x6a33580fc482e9783d66bee9276f42b74a2cbc2b7434fc408a6ba9df77db0ceb"),
        receipts_root:    Eth2Digest.fromHex("0xd896daff74ffd6ffcc088adba01aea52af82d861b7ff649265a750e5995dcf31"),
        logs_bloom:       BloomLogs.fromHex("0xec00c3385b735b6a4088ed066bdb088e7826a2830fd13a1a1525c4590eb08baeba81bb511bbf2db2c0547c69c10b5c6c1bf5c8e5a7931584e6ed8ed7357431e1e2391fc0e61a060baf8984a6fd5c04c68fe0f28f94281d0db663b1b2fdaad9b51d3a12bb9fba255c923dea5ce45dd68ec2c5afc9fd13a0e24d234a3c8c5f255e7d62d48a8e01fb5c1eaf0c7a68a616ac935416fe3332943d78eb28a48a180e2bee26e85d786583ae0609a8b98e1045738f054aa12bef97593cd16d8d795314bfff33c51b397afa2299a4a64244817e5a07cdcd75eb4c4c06e8e943d8d1db8e65f17368ab6175c3e14daad0b99fd0f1050feebadf9db8fe8f1c19ed867f4df676"),
        prev_randao:      Eth2Digest.fromHex("0xdcd37bc148c25afa7e320009ce19567108745ef5ed57781f55df1d73b707e26e"),
        block_number:     13754339262807377549'u64,
        gas_limit:        5250261236890759949'u64,
        gas_used:         1335844244115849195'u64,
        timestamp:        16758901654456753273'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[28'u8, 8'u8, 171'u8, 122'u8, 126'u8, 38'u8, 142'u8, 246'u8, 162'u8, 197'u8, 241'u8, 216'u8, 158'u8, 184'u8, 73'u8, 191'u8, 208'u8, 5'u8, 79'u8, 231'u8, 254'u8, 55'u8, 126'u8, 97'u8, 184'u8, 78'u8, 36'u8, 80'u8, 160'u8, 124'u8, 188'u8, 176'u8]),
        base_fee_per_gas: UInt256.fromHex("0x0ea1185e0ac50d1e2cc0be7229c846528380def25f7d8860cf366e6edd793be0"),
        block_hash:       Eth2Digest.fromHex("0xb471874aa6e8987deee40902d59537fed8af3e9b6ae2f8b476ddb051629b3b09"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[231'u8, 215'u8, 225'u8, 83'u8, 163'u8, 187'u8, 111'u8, 141'u8, 246'u8, 57'u8, 238'u8, 163'u8, 25'u8, 91'u8, 114'u8, 111'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[93'u8, 42'u8, 101'u8, 80'u8, 160'u8, 252'u8, 158'u8, 121'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[164'u8, 98'u8, 105'u8, 179'u8, 25'u8, 33'u8, 130'u8, 239'u8])])
      ),
      (bellatrix.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x62ce6a6d68578309c4730f96f98a809d4b4225fc3d37a285daf26288b10f9590"),
        fee_recipient:    ExecutionAddress.fromHex("0x8c892b06f1e9c877c310b6eccefb20fcf5e00227"),
        state_root:       Eth2Digest.fromHex("0x578f93b83206e3239c69f51cc8e59cd89087260cda9f0efc892aa2ffb2bf386e"),
        receipts_root:    Eth2Digest.fromHex("0xa4ac657af8e0dad66ec74f4f66b246fe0089485e2810071fa556c09ea585059f"),
        logs_bloom:       BloomLogs.fromHex("0x18d67e640f9ad3a24deb7e3f8cbe0ba8224cf9cb9e67b2fd6c774fac7aa3f4adca2befe8322962cf000cb89c3e352433cf1aade51ceac9fe69966a8a89f7985030a301eb690e7eb20b5ac3b315930ee5397b6d65b03a1131b94e7f3505ef030877e460e9195b742e943716d9875a3e2e9998236d3565d622216af1721b658a12fe7d82a62619b4f2d042f146305ff1ad1bf394437340735eac9e962b3fe67597793d1151ec87fcb5f0056837c5813c75c4a0f94d91da71299b3780f250ee31eb9f106e3c443f0ba05213da05177238909fd9e60de9484e091b91dead82debc020929d1f14e79b610af3d15bf9c3757e62bb32a69523c1bd576e5c5d4bc2ef0a6"),
        prev_randao:      Eth2Digest.fromHex("0x552627eb969604e7d4ed1e631b74b2410dea7f4dbd49511bda390e3b9da8bf60"),
        block_number:     7763671958353664038'u64,
        gas_limit:        3930616259240751958'u64,
        gas_used:         7960068863134244743'u64,
        timestamp:        18446744073709551615'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[227'u8, 111'u8, 127'u8, 243'u8, 191'u8, 237'u8, 88'u8, 146'u8, 146'u8, 236'u8, 162'u8, 237'u8, 164'u8, 177'u8, 249'u8, 52'u8, 1'u8, 26'u8, 187'u8, 208'u8, 244'u8, 234'u8, 113'u8, 199'u8, 30'u8, 209'u8, 197'u8, 63'u8, 126'u8, 104'u8, 143'u8, 30'u8]),
        base_fee_per_gas: UInt256.fromHex("0x6bcd9684e1bc8f4fc5d089e0bf5fed35a8bf3039808d030bb9eb1ff7147180b5"),
        block_hash:       Eth2Digest.fromHex("0x9e2505de9f245873565b553e7215abff698bdfcee1dbd93e40eb295dd84e7f45"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[140'u8, 134'u8, 173'u8, 70'u8, 168'u8, 181'u8, 221'u8, 210'u8, 25'u8, 142'u8, 168'u8, 139'u8, 77'u8, 134'u8, 203'u8, 219'u8])])
      ),
      (bellatrix.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x4f8251c361a23171de8648d1e96c91fea2cc5a691dcd884e3a957dc8f6a8802a"),
        fee_recipient:    ExecutionAddress.fromHex("0x7da9175abaf6e4e400e0ee516fd3ab07dd659f2a"),
        state_root:       Eth2Digest.fromHex("0x1bd3a5da4c266dd396b8209288e68be066176ebe64cd4c17c4c6cdccaf03577e"),
        receipts_root:    Eth2Digest.fromHex("0x16133c4fe31f0487e700514160acf9257458a6ee716be8043cb6c532f84ef614"),
        logs_bloom:       BloomLogs.fromHex("0x5ca3807e674d69536b33337d798deaeb9fa6c7cbab7aef1473e6a6614f6f2c74ef85ee3632612b9c1e78d2a63e0b2f58d48d71e8d62e38510bc2f307680497cb965153b43392b8aa2dcd91a766356eab3ff1b4a6c4b037d61df1a8a4c6d3fa0e3c57a299a1c0a7382052ac25c412f2d2356c302e326fa0cfb570354e31e2f8046b80e2690ba69ec7c284c2df8ad23d16764cbc0ba28516f3c31aa89da3e3286106dcecc835b3007a17f33c4962efc3c9b0f5bff14c783e414ba60d35b79ab33ccd0151c34a94efc461d0df0a994085373f33275a4cd6839603632409b670072a4554f1c9342c03cd403a6feb67b23d3a075707ca89b77bad64e24a6ab79446ad"),
        prev_randao:      Eth2Digest.fromHex("0x6353ec5b94b9112f25e66de48b532ff5610c63f34c50a02fdf64af6c9d0ef2f4"),
        block_number:     16866969889068542818'u64,
        gas_limit:        5116920640663397560'u64,
        gas_used:         13292402101416991817'u64,
        timestamp:        1,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[136'u8, 133'u8, 189'u8, 60'u8, 229'u8, 217'u8, 70'u8, 145'u8, 136'u8, 97'u8, 175'u8, 23'u8, 183'u8, 73'u8]),
        base_fee_per_gas: UInt256.fromHex("0xe1307a28a2868b4d934aefdde7bbd09b0644b5c422d2c680770775cb44623512"),
        block_hash:       Eth2Digest.fromHex("0x11e23850b143b8b4dd8394ee1f2cebf073068502d04dde00000925cf23ff55cc"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[])
      ),
      (bellatrix.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x0c67b44b492590ffb9e6d2a63c84714821be7526ce1c337c06276e33a62b7b93"),
        fee_recipient:    ExecutionAddress.fromHex("0x1d16dbe66ead2ba8afb8594acaf8d536be08dac3"),
        state_root:       Eth2Digest.fromHex("0xeeb40e334aff8512435b5908a8dd3c06993cadca8bc44e9a6c28c6003162c6a9"),
        receipts_root:    Eth2Digest.fromHex("0xefa5b7de19da2333bfb7bfa814a306f904fef2ff4f8b1154314649a56fea3c8d"),
        logs_bloom:       BloomLogs.fromHex("0x4ebbaff6a56343a6bc0170aca2e2ba303f3e3f972c88539ef84e402740e3c9e21c6951d461baf56eec14c06ca0e95f4921079d0d82e9dd46e73f3fa76417246217ff9c5425f19b0f8b2a735ee522c1bc377a2b079099430d0f9316164f5930456245534bbe138d0a19ee58bb13a0d724723a6fa50e39b8a7ad5804f92ab43c24782e27dbb32789408cdd716af9a0b0cb1e2f3aee0bcb5aa4088c0cf1528fad466f3d71d906649becf25f405f619dead731e0831efb522b5faee7a39ca28128effc79977816d50ae23745ab96b80dc7f548aa5d43b0d5c331fdc1ce080a4d63e19942ecb4df8f56397b2ef67d017f2d2de9296e1fd8036ed8592f5a89553c4642"),
        prev_randao:      Eth2Digest.fromHex("0x5d3c3ac25330e1cd3a516003315ed24bd2dc6cd31d389639cce4b6ae4a3ac8cf"),
        block_number:     10891095348111649307'u64,
        gas_limit:        13670668340379820434'u64,
        gas_used:         1482104080767186829'u64,
        timestamp:        6602476120092784163'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[223'u8, 228'u8, 253'u8, 3'u8, 38'u8, 218'u8, 253'u8, 87'u8, 206'u8, 243'u8, 168'u8, 113'u8]),
        base_fee_per_gas: UInt256.fromHex("0x972a01f27d586035ce5fb233118e52652ebbf89f6d39558a41b27c8840c849b1"),
        block_hash:       Eth2Digest.fromHex("0x9280fa96a569e7c25b2dfc12a141d3edd24acf2fbfa19ee72e5a1fd5dba25a11"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[116'u8, 179'u8, 195'u8, 80'u8, 193'u8, 73'u8, 187'u8, 64'u8, 41'u8, 251'u8, 55'u8, 90'u8, 161'u8, 30'u8, 221'u8, 210'u8])])
      ),
      (bellatrix.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x7a9d6ab34c0314959d5bdceb0bd80f142e59e5e2addedcd178612303897e7a8a"),
        fee_recipient:    ExecutionAddress.fromHex("0x3425bc529b4791f5fdb7dd365501199b2f81e578"),
        state_root:       Eth2Digest.fromHex("0x4eb1a9a3c4b9392325a14f3f8efbc0b3cc3bfc2d7e9992377abd84af6c556db5"),
        receipts_root:    Eth2Digest.fromHex("0x094e9114d3487925f6818140978e4db64d8306083a8e5c987657e21c3a1995bd"),
        logs_bloom:       BloomLogs.fromHex("0x0815701b4689d0bb7f80fb1485ad3255a66b890725a1d2d66b4fc66678e2d08784c21ef583401493d5dda1549eda32303b7d102edc72b9fe1d696ab459294a88db0d7263abdf982ddf59ce008b8ac734565de79c269dfc18a36709ca91a3cd50516725e9fa9d98302fa0322254382aab0cdf1f95f2397579f7219bd7ab096ef1f00d7b1131b0055bff65ae9954cb22959adbc40983840ae3b85358fd205bdf6ac6bcf723047ffc53a094a06c2039935b6ef579efc618bf4127a6e4e531f6d97c17789be639691ef87fa5540cf732a184a0e09d5c60866ecd0be0a04bc94317712c395d84c2cec90f43f4807048bf1a93e3e6520a1a7c59092e2e391abf9d2e68"),
        prev_randao:      Eth2Digest.fromHex("0x349eec90244f3d812002732cd833952969b27a463def04291051137344c89c41"),
        block_number:     5715688900321967041'u64,
        gas_limit:        17172684770312311722'u64,
        gas_used:         9286597649062725614'u64,
        timestamp:        195835912833125491'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[34'u8, 35'u8, 209'u8, 45'u8, 117'u8]),
        base_fee_per_gas: UInt256.fromHex("0x7b5b4e48b3daadecb9724a74d426a86ffb5c5f8abd43469b4e3fe2a728b5a645"),
        block_hash:       Eth2Digest.fromHex("0xc71c294b5562af30b9e2b03e76cec0cc6d8b50694219404aaed2ace8f756a22e"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[178'u8, 142'u8, 115'u8, 217'u8, 56'u8, 74'u8, 150'u8, 16'u8, 244'u8, 148'u8, 19'u8, 33'u8, 89'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[195'u8, 248'u8, 42'u8, 129'u8, 151'u8, 119'u8, 232'u8, 235'u8, 245'u8, 240'u8, 113'u8, 157'u8, 235'u8, 158'u8, 160'u8, 222'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[16'u8, 27'u8, 72'u8, 107'u8, 18'u8, 210'u8, 127'u8, 78'u8])])
      ),
      (bellatrix.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x806a868f0f31e8f519fa6339ad18c414dba17feb03aaf6ca3775b152bac64f3b"),
        fee_recipient:    ExecutionAddress.fromHex("0xa2bcc8b793c4a5d4e0f68251d2f22e1ff4366d2c"),
        state_root:       Eth2Digest.fromHex("0x6979ac9545f31eaf7ed8bd227cd7cbd1017492b892bcc118f7417ea87d50d412"),
        receipts_root:    Eth2Digest.fromHex("0xca0ac1828fae211c9d0fd7ab763460d89f9da0669d082c68b9fdca3ca1b59123"),
        logs_bloom:       BloomLogs.fromHex("0x0656423dc7b375cee4f5c3bedc500eaff2da91d0dd5f4e695933c92a2a6af7441200a41177bcae7912839f993a733aa2bb82976f08180a901e63c588a26dc9ccc58f477eccbb08aa932d512bfc765a57527acd04c585af23f48f389420890d06877d8a0f523cb90be10dbc73cb5b11e808f5c6c90c6fc3a9434dab462f2977eacf79146b35ee2372aae8a6fe3628cbe21a8988fd9546b25581b6d998462f9af7f653d3a4702a4a63b9f26cc7d2f72e18a3918fa9b65ed81d23ac0a64dd8f3f878f745fcb4de9ad144ae9565288d7bf90e6d356f49cc242d000e988fe76e0196f0c5b24bdf9dc501222e54f64861e0d45dda2bdf09e5fb290a1ec6dce39b02883"),
        prev_randao:      Eth2Digest.fromHex("0xc986211f6550cb787e89140d8856531ec309f652e2a871e2715c1dd055448074"),
        block_number:     7781035717593646205'u64,
        gas_limit:        9088183223170031827'u64,
        gas_used:         0,
        timestamp:        1844848381084178223'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[]),
        base_fee_per_gas: UInt256.fromHex("0xaac988479abbe95e03cc214e7b99795c4ec117bfe4da06e4624e94b262b015e2"),
        block_hash:       Eth2Digest.fromHex("0x14137d373f6e6110b3fe3c1d743a4f84547ad3d59d0b42598b794ff601e97e38"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[10'u8, 28'u8, 79'u8, 238'u8, 85'u8, 206'u8, 161'u8, 222'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[144'u8, 222'u8, 190'u8, 14'u8, 247'u8, 119'u8, 95'u8, 48'u8, 238'u8, 50'u8, 180'u8, 12'u8, 216'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[])])
      )]

    for executionPayload in executionPayloads:
      check:
        executionPayload == asConsensusType(
          asEngineExecutionPayload(executionPayload))

  test "Roundtrip engine RPC V2 and capella ExecutionPayload representations":
    # Each Eth2Digest field is chosen randomly. Each uint64 field is random,
    # with boosted probabilities for 0, 1, and high(uint64). There can be 0,
    # 1, 2, or 3 transactions uniformly. Each transaction is 0, 8, 13, or 16
    # bytes. fee_recipient and logs_bloom, both, are uniformly random. extra
    # bytes are random, with 0, 1, and 32 lengths' probabilities increased.
    #
    # For withdrawals, many possible values are nonsensical (e.g., sufficiently
    # high withdrawal indexes or validator indexes), but should be supported in
    # this layer regardless, so sample across entire domain.
    const executionPayloads = [
      (capella.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x760d4d1fced29500a422c401a646ee5bb5d65a07efa1492856a72cff9948a434"),
        fee_recipient:    ExecutionAddress.fromHex("0x315f583fa44fc6684553d3c88c3d26e9ed7123d8"),
        state_root:       Eth2Digest.fromHex("0xa6975bac699618cc22c05b1ba8f47cbd162475669474316d7a79ea84bce3c690"),
        receipts_root:    Eth2Digest.fromHex("0x080d53a0fd22d93f669b06052413851469d63adeb301810d7ce7a51c90c8e8ce"),
        logs_bloom:       BloomLogs.fromHex("0x453a1f1c4f63bcf0be84e36a9ac233b551601bb2e5ab9450235bd83e41d2013f42c97044ac197a91da96efd6fb18f233bad2e884d76f0a63a6fbf7dbc714cc9aa497fb6d363feeba18447ecf799d5f8d769232553c375b21166c0176859dba63eb77f1a17e482ebac07c3cfd5281277f55f1e5c79cc675d501e1982816d31db7d73c89e855315d8f4e9fef1c9ebb322610235c44632a80341b42f05d207ac4869d08d98a3587a470f598095ebb932788fefacdd70e7749e0bd47ceff88a74ee1f006d9791350484149935d4521d86e644ebc4346154ca0bfa9fbb83120630867d878c12e53a04a879e993b755f02670c9c47f091acf1b3f593782ddaa98f0df4"),
        prev_randao:      Eth2Digest.fromHex("0xe19503a6fa6acde0b8f5981f29eb2e298ddff63e6243529d735bcfa42680a515"),
        block_number:     9937808397572497453'u64,
        gas_limit:        15517598874177925531'u64,
        gas_used:         3241597546384131838'u64,
        timestamp:        17932057306109702405'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[55'u8, 184'u8, 18'u8, 128'u8, 63'u8, 61'u8, 26'u8, 79'u8, 3'u8, 225'u8, 167'u8, 15'u8, 240'u8, 167'u8, 180'u8, 141'u8, 205'u8, 10'u8, 246'u8, 70'u8, 248'u8, 35'u8, 19'u8, 45'u8, 252'u8, 187'u8, 168'u8, 42'u8]),
        base_fee_per_gas: UInt256.fromHex("0xaf8acbd8a0f0f8eeced9a1014333cdddbd2090d663a06cd919cf17529e9d7862"),
        block_hash:       Eth2Digest.fromHex("0x86b46255725b39af70a9e1a3096287d9772ccc635408fe06c34cc8b680977ff5"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 98780'u64, validator_index: 8610867051145053792'u64, address: ExecutionAddress.fromHex("0x0c33e909ef375bd3ab33961b5ea767b4f1c8bce0"), amount: 671269'u64.Gwei),
          capella.Withdrawal(index: 18446744073709551615'u64, validator_index: 500164'u64, address: ExecutionAddress.fromHex("0x271215240885828779da36212489170f19a8f5bb"), amount: 2071087476832314128'u64.Gwei),
          capella.Withdrawal(index: 26148315722507923'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0x340bd9f489ec124b8a879673f12969b14d0b5555"), amount: 9486787560616102568'u64.Gwei),
          capella.Withdrawal(index: 4839737623914146930'u64, validator_index: 273755626242170824'u64, address: ExecutionAddress.fromHex("0xcacc573cfc0ad561aae27f7be1c38b8dd6fab2cc"), amount: 9475975971913976804'u64.Gwei),
        ])
      ),
      (capella.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x2cb54ddf357864102f4ab6bce57317a75cee972f303449bf7047f4e0e5809127"),
        fee_recipient:    ExecutionAddress.fromHex("0x92af67d9604b945fd2cbaccd29598e2b47ef5d2d"),
        state_root:       Eth2Digest.fromHex("0xc64221514816a2f87a29c2c474abf99547820b2a12e6e5956f160dd54579e521"),
        receipts_root:    Eth2Digest.fromHex("0x76c1ca0e483a557f6884d64bd891c62904c64c2fe69350278345c622cc50b0d7"),
        logs_bloom:       BloomLogs.fromHex("0x7afdc9a99777d76b713e960e9f12ad4fe46ecb7ea6d5b245c6d9ee11d3fd35e7ae33dd6062fb6578bc2c2f286f1c6a4aa6a44cc80a88a3678c7085c35a0f2e5334ea686e2098fe5d179bbbaf81cbc349a15e7a21aa27f0ddcad342d980d056a356694cdadcef8db3c7866b6cb087c28f2aeed7a5bc9b1294cef0da3ac3b46dbe72d7f164f1990bc32f755b709b96a96bdd8da2c9d9300e9f6906040347d337fc21b833ff0b80305b22ac64a2df2dede4c01c65c192884f161aacd12ba56dab9189477e6ae484a97ff96e0aba1f9b8d043896b8433779abeec091f16b94a013325fe11096d1f2d79b701ab5b46063ac99392a790e617555fe3286dfd7ec0cb9b6"),
        prev_randao:      Eth2Digest.fromHex("0xc4021ae781a3b3a1dfb1e4464b032a3bae5f5b68366beb555ede1f126920cd5c"),
        block_number:     11318858212743222111'u64,
        gas_limit:        2312263413099464025'u64,
        gas_used:         1,
        timestamp:        15461704461982808518'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[254'u8, 188'u8, 92'u8, 24'u8, 153'u8, 206'u8, 74'u8, 108'u8, 96'u8, 100'u8, 148'u8, 84'u8, 151'u8, 74'u8, 73'u8, 167'u8, 65'u8, 177'u8, 253'u8, 62'u8]),
        base_fee_per_gas: UInt256.fromHex("0xb1c4b2bffcb38aaa1f98b483441aa212c9dd951d4706dd505a973fd5fd84796f"),
        block_hash:       Eth2Digest.fromHex("0x8b150d453d802fdbb19be0132621a5e8061e70cfe6668ee6a63e4ff217434999"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[142'u8, 197'u8, 221'u8, 83'u8, 32'u8, 126'u8, 145'u8, 86'u8, 28'u8, 39'u8, 112'u8, 240'u8, 168'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[175'u8, 191'u8, 143'u8, 78'u8, 162'u8, 249'u8, 87'u8, 193'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[84'u8, 168'u8, 190'u8, 157'u8, 39'u8, 143'u8, 147'u8, 156'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 11497754023538902580'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0xb0b680a6d93e520fa32e399ded64871d99c1f2c6"), amount: 15592017597077727306'u64.Gwei),
          capella.Withdrawal(index: 18446744073709551615'u64, validator_index: 14269483352942387358'u64, address: ExecutionAddress.fromHex("0x97e4451d09c9af077dc9081e5081563aa26e4c51"), amount: 18446744073709551615'u64.Gwei),
          capella.Withdrawal(index: 9664968187979079659'u64, validator_index: 750818'u64, address: ExecutionAddress.fromHex("0x1e4bc6f12efe96b9f5ca549b77a3d62c5f5403d8"), amount: 18446744073709551615'u64.Gwei),
          capella.Withdrawal(index: 727020'u64, validator_index: 10133766089843653238'u64, address: ExecutionAddress.fromHex("0x6a1ed64277cf1eba8c96281531d2799d1fa7c409"), amount: 130469'u64.Gwei),
        ])
      ),
      (capella.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xac5a7347865f503e1578d1b47271c8e60027b5ba24b0da8e7c3733bcdbeda220"),
        fee_recipient:    ExecutionAddress.fromHex("0x8b7fa656e67f6af2074ec3f16930ad742a69f189"),
        state_root:       Eth2Digest.fromHex("0xeb50f351f6945df8983cf4037ee264dcb2ceef3313ae452248571811d8a3a8cf"),
        receipts_root:    Eth2Digest.fromHex("0x860af6010832f64a5234327b653aabbd3898881a7b72ae42e08d4a1519166fba"),
        logs_bloom:       BloomLogs.fromHex("0x01a18d51076880a1a8ea86cc5dc5fb904ba0a3c285b7dff34ee5dbad9d64721f3849ad9f50b90ad4524eca6b0564f8a1a5827a7b476ea051c33a7c0e18db4cfb27b36476bbb1eacbc029dbc5009e5cea695045cfb34c868163514b784133f0f2998cf12e2caf9c74f69732ed3716396dc34d86725428aff48bf6b935ae88f5e4820b9a325bc670cf560dcb479723213a3156a9d7d0e7de0dc791d0eb94a691013624b8aa982ca3c9d5b49fcac8fafbb403c9fbceee5373f0fb2b77ff1bae8160fe2a47b01d792b088eb3fe24c53b5c6a8b4a3b59060d587ca7376f8baba58d57cf745b2a346f800a54d08545194e067ae260c73369a016b12d0fbc20abc78ba3"),
        prev_randao:      Eth2Digest.fromHex("0x330b7093023f617d2cb5f76cee4b078af002b68d81e3a5b5c9d37c4411871a95"),
        block_number:     18446744073709551615'u64,
        gas_limit:        13979513761871276914'u64,
        gas_used:         6199089254852634745'u64,
        timestamp:        7404562418233177323'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[220'u8, 149'u8, 177'u8, 36'u8, 228'u8, 88'u8, 47'u8, 149'u8, 211'u8, 213'u8, 170'u8, 40'u8, 207'u8, 145'u8, 137'u8, 64'u8, 153'u8, 22'u8]),
        base_fee_per_gas: UInt256.fromHex("0xfc82d0e46d05b21aedab6f368183611d2885b28c52842f28f621ef6c631b6e6a"),
        block_hash:       Eth2Digest.fromHex("0xa8c6b2dcc2496f0230e796f8a69642126955ae6209a0d0c2dee2c925212f447e"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[138'u8, 17'u8, 34'u8, 168'u8, 105'u8, 179'u8, 196'u8, 21'u8, 253'u8, 242'u8, 106'u8, 30'u8, 40'u8, 190'u8, 179'u8, 93'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 1'u64, validator_index: 239183'u64, address: ExecutionAddress.fromHex("0x75efb2a04b5f25ae56ff7256ee9f4fdc4e25baf3"), amount: 402148'u64.Gwei),
        ])
      ),
      (capella.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xd3be9b45bfe67229afb47461ca2970505586cab8eb8e00f280ceb07a9d47866f"),
        fee_recipient:    ExecutionAddress.fromHex("0xde645d4a77f0a386a45c52357948e1d7eac5e780"),
        state_root:       Eth2Digest.fromHex("0x69b70e0188e7b88e38df90853b2dfd2e4c7181e83d82d77ab81c57d161216b92"),
        receipts_root:    Eth2Digest.fromHex("0xc01d94a01736268170a16196927029d4d8d7c65970ec78ece94c87304bed4568"),
        logs_bloom:       BloomLogs.fromHex("0x7f1ac5c77e3f0c8a1a103ee83dd7d0fd6fb13895aa1141de330445474b3216e2646c15c1cbf4ab4feb1e4e21c2e6970f4a6648675508b08111e00b62866b0f6cccd58afea87d2cd0a24c0384fa179dc33ae6d0db8c1b118a75fb442682b7cbecc2808fe8c812c3720ca54f6723a395fff5dd1720f41822c91b080503bbfeef21eea192d5b7c4160344996d017ab849fa97e862206caac8f8bfeba41865514b21a8d8fa9ce3dcc0daf5bf86fd2f07d222fc7a9d11fb4031b2cd72544d7f89eb95203a570bc179f9ba1f73f39d74049fe22b63939ea49d5d40f42c00c5f1bd429e84ade377475e432186acd9975914670052fea64453fca87317f62e29b550e88f"),
        prev_randao:      Eth2Digest.fromHex("0xce47da2b2a68186b78054be0894ccc9ae7213c18b9093c0ebc1b9ed011071a39"),
        block_number:     9014833350824993703'u64,
        gas_limit:        18446744073709551615'u64,
        gas_used:         7874274181221487360'u64,
        timestamp:        1,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[139'u8]),
        base_fee_per_gas: UInt256.fromHex("0x1eb821a0ee3f9d2e5b49c64177db9ffc96ec6b06249cefa8c51d0ce7e664a3ae"),
        block_hash:       Eth2Digest.fromHex("0x99479be6429eac4a945ca8171d3d3ce42d7b5af298292e833e20462438e06229"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[99'u8, 198'u8, 91'u8, 86'u8, 23'u8, 222'u8, 121'u8, 250'u8, 12'u8, 135'u8, 133'u8, 37'u8, 61'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[81'u8, 173'u8, 241'u8, 145'u8, 54'u8, 3'u8, 36'u8, 121'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[])
      ),
      (capella.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x06504beb0dc3bae44ef75678d29ec5138d87da68d307ca7d43e259cede60fda6"),
        fee_recipient:    ExecutionAddress.fromHex("0x527ce602a0be18c0944dc27b2864c711a91f89a6"),
        state_root:       Eth2Digest.fromHex("0xad3bbef5d22bdc2429da09eb85137c881f85fe6e6b3ea207e5eaeb399c755055"),
        receipts_root:    Eth2Digest.fromHex("0xf94fdc52cde20532cfdee73e9cebb61d9f7160191345f9caf58b45501d8effbc"),
        logs_bloom:       BloomLogs.fromHex("0x0999cc50752006a2bc8e5485c239b9a41be6ea2fd8f0392884246ef7d33bccdf4bd326fadae385e3ecc309bf0f367ac1791767ffaee90ddfa7bee22d19f417708fded2b2b6b3be2b6007745fb1de940e7849761586953c04e3bec3c9b6342d1b91dd024980f469b484bd0befc4941a3846d027390d6256e4acf9933e0891dd558270eb35d3455f4e49c890479e970a8008b75ff4d33b4f7e5a8c19e75d8abd8673ebb859a8a24907584d88f0d68b3142b3c6952695fdd84581f5a070601a575a8e7bfa0bf7cf0fe9d70a051005f9dc594d09909e9d079d02a4e441e5b3f33388de8d46cbdcdf24f835415680e569f2ed29acdc01042a6a7ee701e4e6cace5c28"),
        prev_randao:      Eth2Digest.fromHex("0x7cef96d72498facdb399dfb5b6d7d69185f3edc70715540fdc7ef651c4685c6a"),
        block_number:     13066898984921201592'u64,
        gas_limit:        9241830338892723842'u64,
        gas_used:         8347984358275749670'u64,
        timestamp:        1,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[11'u8, 46'u8, 127'u8, 104'u8, 141'u8, 79'u8, 55'u8, 48'u8, 242'u8, 12'u8, 142'u8, 2'u8]),
        base_fee_per_gas: UInt256.fromHex("0x6241db2a44a58a2c1aac93c4aa18aed5add30d1937c31078542bb544bf9ba2df"),
        block_hash:       Eth2Digest.fromHex("0xdc1756667e7c3f1615650cbbaae1117a6bac817c6579cf3f7afbc93277eb3ea1"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[13'u8, 24'u8, 248'u8, 26'u8, 141'u8, 177'u8, 236'u8, 2'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[213'u8, 208'u8, 242'u8, 46'u8, 0'u8, 31'u8, 219'u8, 213'u8, 197'u8, 218'u8, 148'u8, 236'u8, 43'u8, 152'u8, 123'u8, 96'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[84'u8, 163'u8, 60'u8, 195'u8, 40'u8, 68'u8, 185'u8, 20'u8, 244'u8, 82'u8, 34'u8, 181'u8, 26'u8, 201'u8, 2'u8, 108'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 18446744073709551615'u64, validator_index: 15531362396155364476'u64, address: ExecutionAddress.fromHex("0x063b2e1de01c4dad4402641553c7c60ea990ab30"), amount: 106054'u64.Gwei),
        ])
      ),
      (capella.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xb5d4a5eae3a1ea004ed573b0b8f8a22c847616758c0faf1e7e9589f16e55415c"),
        fee_recipient:    ExecutionAddress.fromHex("0xf7ac0877fd8bcadde1e050f6c7ddad13688ec071"),
        state_root:       Eth2Digest.fromHex("0x7472f824376a723894f8d539743c7f93b69839772f28cf6a83e2102fde99c3c9"),
        receipts_root:    Eth2Digest.fromHex("0x750365b5d975460a64f07758abd0cdd44cee23cc2d4f06f2a047cf4c12c23db4"),
        logs_bloom:       BloomLogs.fromHex("0xe24d8452039bddd10e1252c1ebf9b9e81a22577f940e8708d200548717e8471e130a7066adc48785a8dea1dca05953d6be16504a57112c065e7909586cd611af9e0b840b81caf0532dbb2833ee5ac6a6eb7b6c990cba6ccf6f4ddec5a7c76f8296bd2a693cbbb43b1d86b66f6aa58888734d3fb21cf5e96f1b981f8ae2737bce1cad1cc458650291cf7a3d22c61fde6af3a07a44bf1b334b2c5dabbef16e5e73db75e87f04670cb3830f0a7badc702e7dd37a59ce02992f4473a909e57dee1fdd22cfc886f4fcb6ea205ec9234a8ec85ea134242748f9f10062534fd0528bc1b5b1e89511cdf91a1e7fb4f8c58c93d2a6c75e48a2d48235cb7de13040db8dc9c"),
        prev_randao:      Eth2Digest.fromHex("0x2410823a37c763e13b03a4c48e32f9e43b8440ca31ecfe8e0543a20a02c496c5"),
        block_number:     14920119354157670036'u64,
        gas_limit:        17193947846593799248'u64,
        gas_used:         2176791850599260430'u64,
        timestamp:        12670133468877091192'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[31'u8, 7'u8, 1'u8, 212'u8, 152'u8, 82'u8, 167'u8, 57'u8, 116'u8, 147'u8, 97'u8, 109'u8, 219'u8, 207'u8, 151'u8, 116'u8, 43'u8, 218'u8, 91'u8, 253'u8, 14'u8, 182'u8, 102'u8, 57'u8, 153'u8, 72'u8, 172'u8, 208'u8, 0'u8, 64'u8, 97'u8]),
        base_fee_per_gas: UInt256.fromHex("0xf1daaa067663bf3277b9149aab162f4e330f988f0be8f83a556743a57ae5c8fd"),
        block_hash:       Eth2Digest.fromHex("0x5d462b4b243c6292b6a3b32f4e05849c0613d0a61954734c524f75f8df66cf8d"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 5416630176463173042'u64, validator_index: 0'u64, address: ExecutionAddress.fromHex("0xd7b1d18e4eb7b5041b4b08bae2ce8e22982d6e6c"), amount: 911474'u64.Gwei),
        ])
      ),
      (capella.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x2629683cfc70198038837270bde3c60176c2a4aeeced0d4a4f14dc99a380c377"),
        fee_recipient:    ExecutionAddress.fromHex("0xd234af1937861b66ca84c334824763fb54347677"),
        state_root:       Eth2Digest.fromHex("0xf79f02d52d7f2a4be99eebba3dfb3bce74136ea739da515703d095a66ce203d5"),
        receipts_root:    Eth2Digest.fromHex("0xa97ae6fa5d6937f7754ff96766a54bb8ec082b046814e74f6c9c67147795f526"),
        logs_bloom:       BloomLogs.fromHex("0x5d2ef8bc2f58a84e4050e3a38985e4c267940707c8da3f687fefb9e22e4ae11a2f79a24456af3758e8b521d546dc178da5c85da869ebb2da551976488a769ca2940fa20853e4e1d1fcf8d5bbea0d16973c827d38c97c47c57835677590567829d119e8108f2ee3fa988b267ccfc3e58e5f81c18c775a9baf06d4d81aee405c5683fa4e5e891b58101a27e8f71c60d357a4ab8bd02e12fbbb0e363c4632b0a3c0de638de37448c9476c65a62f7f1dd9643fac6ff78ee431d18ab554b4c8a1984fb5fa0de3464d223f236eb8e8a8f59601221d2ab480ffcefaf4bf6471b40a14773ac0cdb43aea505941e4b0fa6fb26eb091adad77acce41e516fc743e5fdb045f"),
        prev_randao:      Eth2Digest.fromHex("0xbe44d7c5f844a2acb307a4371784d7742be482aece83368d94813ffa1c7bb60f"),
        block_number:     13524449277995212660'u64,
        gas_limit:        1,
        gas_used:         7976957374052242924'u64,
        timestamp:        1,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[57'u8]),
        base_fee_per_gas: UInt256.fromHex("0x6c98d9ff36f1032fd55d8a6038d7b1f7c4e5f7c884b73f626fe43e687beeb46d"),
        block_hash:       Eth2Digest.fromHex("0x2c95101857b07bdda0502741da8cd9160ec0474929d132e9159098576f9a7c35"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[75'u8, 85'u8, 130'u8, 87'u8, 90'u8, 172'u8, 176'u8, 44'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[207'u8, 150'u8, 64'u8, 87'u8, 15'u8, 18'u8, 3'u8, 236'u8, 232'u8, 87'u8, 174'u8, 192'u8, 29'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[23'u8, 37'u8, 57'u8, 158'u8, 137'u8, 222'u8, 53'u8, 111'u8, 63'u8, 13'u8, 69'u8, 110'u8, 175'u8, 108'u8, 16'u8, 207'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 1071093368516669975'u64, validator_index: 15999188653672167093'u64, address: ExecutionAddress.fromHex("0x368b0ae1a6bfc3312460f212017e8bb32aae55bf"), amount: 13132185675616884508'u64.Gwei),
          capella.Withdrawal(index: 18446744073709551615'u64, validator_index: 1251419977457119333'u64, address: ExecutionAddress.fromHex("0x0a4d18e47c5ec0c639ff29d8f8c9be0b60f00452"), amount: 1'u64.Gwei),
          capella.Withdrawal(index: 2046299652899032730'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0x44bfe00f98603a5e8363030de4202ba50c7e8138"), amount: 15403504672180847702'u64.Gwei),
        ])
      ),
      (capella.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x190544155dd98bf86d3ed5ee94d01afd3a8e67b8476f94d90604706da0a7d340"),
        fee_recipient:    ExecutionAddress.fromHex("0x799d176d73d5d6d54d66941ad6cef8208677371c"),
        state_root:       Eth2Digest.fromHex("0x07e626b9c44b0ff14586d17acf79cb136ccc5d37fd7135da33cec516af168f43"),
        receipts_root:    Eth2Digest.fromHex("0xb8b100bc5c155fe6358b9a16756ec06880365f5fe89124cf9fea963e26d3770f"),
        logs_bloom:       BloomLogs.fromHex("0xc314d3d6ab41a3fce7433dc286ee5c9820d883ff572ee7dfd2f4ee745f11a71f6dbe142d8c14bd6cc76782f1bb2b3770e65a929b2187581956bad937907a124c92ba10686763ddc87ba5b4a4e9cf4b9a35255fad5f54b404aeed5ad9859b5f9fd3c137e9eb6ef394a10b8ad3fbba75ba38c2cbfb91fa793ac763e8cd31481fbecef02b3365b990f5120a2970f2779574c60769347ae334a9f39bb3d3ad35182f7dcd252bfe9663c4f54b44dea8d79e3bcd89877231e81a9e9f5c1eaf5da1f56ffc39c23fc3ae6c130281c792a31e7a60115d46abbe17807cd120038631ca7a6636c8c644b57719e386cc8ada32ce806f75110ad143522fb0b240213df4bab07e"),
        prev_randao:      Eth2Digest.fromHex("0x17e445793c0e354ee43381ded194220ebd87ccbacef83e3da5a1cd3c8c57bf49"),
        block_number:     5728529601694960312'u64,
        gas_limit:        9410734351409376782'u64,
        gas_used:         16470261240710401393'u64,
        timestamp:        8811957812590656903'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[95'u8, 124'u8, 151'u8, 79'u8, 76'u8, 171'u8, 74'u8, 213'u8, 207'u8, 202'u8, 63'u8, 2'u8, 182'u8, 32'u8, 115'u8, 65'u8, 90'u8, 186'u8, 34'u8, 63'u8, 241'u8, 191'u8, 88'u8, 10'u8, 197'u8, 52'u8, 33'u8, 98'u8, 78'u8, 210'u8]),
        base_fee_per_gas: UInt256.fromHex("0x3c1ba8cf82268c828c1a7f249328741ae21f35a7659365efd7496df94dbb85e9"),
        block_hash:       Eth2Digest.fromHex("0xc2b2bc39ed0cf5764800d3c91401828ed32d0eea58f9d336c32f9e6f7200ac8d"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 802141'u64, validator_index: 7520769587588158114'u64, address: ExecutionAddress.fromHex("0xce1fcedcc47b22d7e38f76c1cba49c2c20da09eb"), amount: 5845756482608800263'u64.Gwei),
          capella.Withdrawal(index: 4169028257817284566'u64, validator_index: 496485'u64, address: ExecutionAddress.fromHex("0xf99805deece4ff418b55557b45060e88035f755a"), amount: 4870783513883486430'u64.Gwei),
          capella.Withdrawal(index: 10410265605811982468'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0x31e886453fa4e7fcec6ce6094ad22950637d41a1"), amount: 157748'u64.Gwei),
          capella.Withdrawal(index: 10622085591419415519'u64, validator_index: 8179967808007927229'u64, address: ExecutionAddress.fromHex("0x03d2493395b71bb181db626a99c24dbc1d07065f"), amount: 18446744073709551615'u64.Gwei),
        ])
      ),
      (capella.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x86d7b430f69b215ab5ae863998ce41f01a5016376c8bec7f5b7a6e16a2326d92"),
        fee_recipient:    ExecutionAddress.fromHex("0x73068946d757f5d145a38fe9de817b8b1e9d6c43"),
        state_root:       Eth2Digest.fromHex("0x312b4af4d3ca5960dda2f99531819f5c32624753cc0756c05d242f65dd605d92"),
        receipts_root:    Eth2Digest.fromHex("0xf3a1e8f784ee4bdb897d1511ce642276e2ecbc1f21bfde9caf7c4479b7fdf902"),
        logs_bloom:       BloomLogs.fromHex("0x633d228aa8b2b9f4b614c4b7c7aca616232d61bc6e06ca28f4b94bc39165cf3ca2e090cebbe8a5b66b161d92e65099503327f9f2adae6ec5a73463063a994d73f37e12caec8f6d439be7520b48b25ccfa8ff64e6884b7e240c8dfd0100a23f9f644da13f1628d989eef92806c9f936a71f470d710653355acd84fb23ff15910f1d2866d83b036246c46a681e762b9a19e72aab21b428c4710511d0a39cc5ec39ebf3aecb5c19096ab32135a629abc8cdec39b2b3631bf4e86bbfb824276fd728bef454ed981e5f9e8a4bb96b27f09f661c5c221f63a26945174162496496c9bbf38cd894c50fa69df0a8c722ab48d75044bf43468639ae9b61d0b5a2f9d819eb"),
        prev_randao:      Eth2Digest.fromHex("0x3a0689ac32c82a6b84d3230fdc6e2c1e89671fa3906336ccde9fb7cfd1811ac8"),
        block_number:     9465334901279616671'u64,
        gas_limit:        17844363972830076325'u64,
        gas_used:         9534663249377184661'u64,
        timestamp:        15490999633909732541'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[199'u8]),
        base_fee_per_gas: UInt256.fromHex("0x9fc9f32819a67c4aebae259b0648e2b82f526ce8eef8fee33961f9fc69653b2b"),
        block_hash:       Eth2Digest.fromHex("0x1ac3f16da76520977c5e5d86f0c261d76e18413c202e8a46241951b3a80ca601"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[223'u8, 37'u8, 18'u8, 125'u8, 208'u8, 57'u8, 114'u8, 113'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[137'u8, 181'u8, 143'u8, 219'u8, 145'u8, 77'u8, 39'u8, 126'u8, 173'u8, 30'u8, 59'u8, 70'u8, 205'u8, 51'u8, 16'u8, 213'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 0'u64, validator_index: 7432737887980948854'u64, address: ExecutionAddress.fromHex("0x1a99860ddeecae3195a051bc0a0fcc37d0135e37"), amount: 921585'u64.Gwei),
          capella.Withdrawal(index: 8891974894683849035'u64, validator_index: 18060634568259374245'u64, address: ExecutionAddress.fromHex("0x53a6cc4c3996f0181cfe62be861900f56cb75a87"), amount: 235145'u64.Gwei),
          capella.Withdrawal(index: 11531749110606308043'u64, validator_index: 9858359378531619375'u64, address: ExecutionAddress.fromHex("0x6b7a4bc00868b077f1c4aa53369e893162bcc384"), amount: 18446744073709551615'u64.Gwei),
          capella.Withdrawal(index: 530041'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0x4b7853973d34b1efe7722be5c688589b49c1aaa9"), amount: 18446744073709551615'u64.Gwei),
        ])
      ),
      (capella.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xc51bf481df9be981c6656081e3854ffcf27551e2b4fdaed4ab12b355f247f4e1"),
        fee_recipient:    ExecutionAddress.fromHex("0xd79098c25eed05c9f6d55e95f5f6f58c1472fb28"),
        state_root:       Eth2Digest.fromHex("0x1a6b1eb78e5ac155d4be247a3b48d8d8d8574a16fa846681553037629b97ffd0"),
        receipts_root:    Eth2Digest.fromHex("0x5e44d4a3621cd8e495edc0b208f977c8d3f8e79a78fa7ecfc4a0f6e436f67b71"),
        logs_bloom:       BloomLogs.fromHex("0xe2b0dcfd2341ceb9c4edbc7115dbd6ed5f1c54ca39bee191fdaaa34368acee93f48561094dd23a3985ea2c2b83d918ba9dc671cde7732a591b4f9abd2eacf9d6416ca8c8d556052a98df2cffdbb086315585004c51c76872a06cee7d318f4845c0ade4c907c7933d4d883bcc586885be04ca9149e05b1624856e69e1efe8c93cd55d840bf71279293a118d51d4391fcbf4e6abe6ee50492ff2de085069a3c7656eb3a749d6bf46f56a2acd93a6840eb78e09a42f23fdea69bfbf017f4fd6b4a8d17df1aa5147c1897fe5fda1f5e79121f2fefef97117e7871d1cbf5b0b0350b9fc497c5aba27cbc129d452d6a60effb76e08b890d0bb856115fcfe3966359fda"),
        prev_randao:      Eth2Digest.fromHex("0xcd6fd69596cdd7df95e0b68e8ade01541b12ed15caa2b59803a4c4e6791870d4"),
        block_number:     12264963829660560313'u64,
        gas_limit:        11775806146734810959'u64,
        gas_used:         1863395589678049593'u64,
        timestamp:        5625804670695895441'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[183'u8]),
        base_fee_per_gas: UInt256.fromHex("0x1443705192ff4dc1a819be4f22b8dcd6e7802337e62082880b1090f44a27d0e2"),
        block_hash:       Eth2Digest.fromHex("0x68da52444eb5322f3a0bda6bdc9a3a11a540dbd22026bb2d24862bbc32af9460"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[212'u8, 80'u8, 176'u8, 133'u8, 132'u8, 119'u8, 233'u8, 131'u8, 195'u8, 118'u8, 54'u8, 94'u8, 129'u8, 206'u8, 47'u8, 107'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[231'u8, 31'u8, 192'u8, 94'u8, 136'u8, 120'u8, 228'u8, 222'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[114'u8, 23'u8, 239'u8, 220'u8, 169'u8, 188'u8, 213'u8, 179'u8, 223'u8, 129'u8, 189'u8, 50'u8, 158'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 18446744073709551615'u64, validator_index: 109465'u64, address: ExecutionAddress.fromHex("0x30376c1737df493e34318acb7efa0aadd3d78738"), amount: 419309'u64.Gwei),
          capella.Withdrawal(index: 3744271566165938073'u64, validator_index: 162930'u64, address: ExecutionAddress.fromHex("0x9a3eee4729cf5ef57a1c4aeb474636461991270a"), amount: 9043308530560640624'u64.Gwei),
          capella.Withdrawal(index: 10893292846301120513'u64, validator_index: 15952780188276928656'u64, address: ExecutionAddress.fromHex("0xfccc1279aa3dde74ea08b699fecb4481c777f259"), amount: 5614376920521492084'u64.Gwei),
          capella.Withdrawal(index: 18446744073709551615'u64, validator_index: 2895353066704396409'u64, address: ExecutionAddress.fromHex("0x7e8b34a029236dc0d15db19153165d1eccab05a8"), amount: 3749025806369957542'u64.Gwei),
        ])
      ),
      (capella.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x8b3e7e8d447527b9d00693389928260e7ea9da6855efd99369182bd9c213988a"),
        fee_recipient:    ExecutionAddress.fromHex("0xb45716c9aeddeb030c0b94202fcb97bd75a039b6"),
        state_root:       Eth2Digest.fromHex("0x8114b285e5f3277c04a66e660fef3b86295d6ca859dfa216df3309c0a7242f2d"),
        receipts_root:    Eth2Digest.fromHex("0x2a3ff38541ef83faad176c3c98ceb5c55622dec83fbfc5a19bdb27646849e852"),
        logs_bloom:       BloomLogs.fromHex("0x384a9b3d38d343af68d00c229e79aa31f2059e17c655f5e48d31d2b59b769660e91c1e5f386e4f7dc83f2570029a6f2b3351623fcb4dadd6b5b7b26e27de19e248ebd970a9678b69403ea8e16fe88562959586fcfdee3c407fcf623c94891a2270ba1829bf2ab77fa32913bb11c8a4a69e9baa6544ad336253637626b16d4a98884e7ac7d6c1e697a9435b1e5403b5122eebddec9c03c8a6c8fed0d8877888371e133fb837d33f073375f7e1536abf622610734b9b0aced8a891f02d5b35734e58b0ead66c49ed9f898b8f27e9415275c5d15051ec00cb006f8aef702a7414aefacfa9742cd3d8d34be817e0c731696e20b973cf2da66799121c0c6d12bc835d"),
        prev_randao:      Eth2Digest.fromHex("0x3bd54c7151dae2ad524b4df0d4283e3641ba787fc76f54221dba3a2aa556a1bb"),
        block_number:     18446744073709551615'u64,
        gas_limit:        637978774023867007'u64,
        gas_used:         15110835166938431016'u64,
        timestamp:        18065456863038184935'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[235'u8, 229'u8, 162'u8, 249'u8, 154'u8, 135'u8]),
        base_fee_per_gas: UInt256.fromHex("0xbe93cc3dc2bb7e012db659df49e57653bf6ff21354c64eeb69c0002e9f933035"),
        block_hash:       Eth2Digest.fromHex("0x46cb3f590b2fbce372e67968a0d2ff4ce1b2c530fcc26b7a24ed6db054f52035"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[16'u8, 66'u8, 215'u8, 40'u8, 223'u8, 195'u8, 43'u8, 228'u8, 225'u8, 244'u8, 34'u8, 14'u8, 117'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[92'u8, 46'u8, 215'u8, 218'u8, 71'u8, 99'u8, 115'u8, 119'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[])
      ),
      (capella.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xa4854e346d2e9a921cc6b3c4ce9fc739c99795cf10002924089f9886f8624d59"),
        fee_recipient:    ExecutionAddress.fromHex("0xa88781cf69a1eed63bcc3a32b6f9aba35d4f5b5e"),
        state_root:       Eth2Digest.fromHex("0xdc06d9210fd2738b0fa9df6d68e4ffbfef0dd7d7d8093fdbcd97ff845318cf6b"),
        receipts_root:    Eth2Digest.fromHex("0xfe1b70c143066edc444f9b49e778cf6db0060bd4e9122564350cf23061830439"),
        logs_bloom:       BloomLogs.fromHex("0x095a57c3f2d97aad8692cd09dfdd8388f1bf9ef98a1c3223ecfd0aed17d8c7c3ef593d7f09ba86500644deaa676df811da501d572f342e3f7ee7b9b081992f344f71fa50b3b9635d7375f67dbd85a0b1ade3d8d4778118df55b90c44f7dd1114f2ebcea5778b32701ef94af9b3713d1fe00275e09c7e918d7c529a37aa9de3464eb6364812ec486464ccbf7df2523369fdeb1b28955e35e8685c16f07fbe342edd1bc044021ed480bf4ceffefb13eaf4550c67ef8a5079f3f612f07fff60193eda6ac11d39f3056c41ea4355ef5ef7f311493c415cc8c42cb30a73dd58098262acebe6d901e4bae26b6e1eba693c7dc596ea27b0cdd4fee2f6450ca8b50b1a70"),
        prev_randao:      Eth2Digest.fromHex("0xc52844ad11072faa2222ffe9cbff77dcc7f681367d2aef5f1c3b206140064195"),
        block_number:     767785029239287422'u64,
        gas_limit:        15062566578072747104'u64,
        gas_used:         7648884410596067087'u64,
        timestamp:        4380084205540210041'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[217'u8, 40'u8, 125'u8, 94'u8, 156'u8, 71'u8, 79'u8, 66'u8, 117'u8, 228'u8, 173'u8, 189'u8, 115'u8, 41'u8, 153'u8, 226'u8, 130'u8, 21'u8, 108'u8, 194'u8, 206'u8, 218'u8, 141'u8]),
        base_fee_per_gas: UInt256.fromHex("0x436767990abff9288346859c6b85b8a972421619eab2253483385c8151cb2016"),
        block_hash:       Eth2Digest.fromHex("0xca4f05c33836d82aee8230ef660016b993bca4aaf9a7b6cad96c2a0193eb026c"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[156'u8, 143'u8, 203'u8, 250'u8, 238'u8, 137'u8, 34'u8, 245'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[64'u8, 44'u8, 165'u8, 9'u8, 1'u8, 211'u8, 27'u8, 108'u8, 166'u8, 61'u8, 119'u8, 11'u8, 222'u8, 85'u8, 48'u8, 185'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[165'u8, 95'u8, 221'u8, 213'u8, 229'u8, 134'u8, 185'u8, 221'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 373208'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0x1ef66a8127bdbf1302c13af1b2a3fde17f1e421e"), amount: 12972917955689502470'u64.Gwei),
          capella.Withdrawal(index: 7007268656739027478'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0xca30e17b5a7925b1a5afa06710d6cffb4681d2fb"), amount: 13141021224557402822'u64.Gwei),
          capella.Withdrawal(index: 10730268187610256048'u64, validator_index: 7483561449283560970'u64, address: ExecutionAddress.fromHex("0x84e755db228c9399912364a239227c467477e076"), amount: 16091384671148001130'u64.Gwei),
          capella.Withdrawal(index: 861292'u64, validator_index: 101133'u64, address: ExecutionAddress.fromHex("0x70e7126e6288dd8559b6bf8946b98fe02bc53e8f"), amount: 5439105246644982514'u64.Gwei),
        ])
      ),
      (capella.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x5e7b12465e0461e5dfa59a3254282378c55961b0e411023ce89d968bbdc33e9c"),
        fee_recipient:    ExecutionAddress.fromHex("0xbd1a1396ab49631cc933770944996b294da97d43"),
        state_root:       Eth2Digest.fromHex("0x74e6ccfb15da8afb94eebf28cb3ba3f9ce63e3354097f2f2527fe1cf978e76bf"),
        receipts_root:    Eth2Digest.fromHex("0x8e48bee56e149d1851cff0740ceab06767bd0e819261c5a2f75dbea382a110b6"),
        logs_bloom:       BloomLogs.fromHex("0x7894fbe58c624a153dbb160c516c9e82bd0cacf5f347f984efcca9450e9a20b50e058ed38e41c331df61114086f8a6b8a049467d7dafd812953aa593b2e9fbc056f0dba80973b2eaae8814b5e0804300eeea15613e59c8d34339f58e1b45599361497a3608c05140cf432e7983a30985aa0faf45dff56dce99eaa5ad3418722df17eaaa4e8df25ed1d9eedee1390e6440c4c37675182dcc07ff199d6dd015d3aa03194765e85fc0d4759d3c693fc2550e50835b88ba41d10fc33b58550d813abaa75bab39c0fbe419f1bde8fb82db9fcfb79894faeed84b2314f115a8fb9e276315ccbfb8e9650571add358f594ff2fb4ab9661afde76081bb2cfbfd2f26d212"),
        prev_randao:      Eth2Digest.fromHex("0xb9a9bce05e42cf3d2ffc2c2ea95164c9b215fc8e440dd2985ca24cff40e32780"),
        block_number:     14460352585391846826'u64,
        gas_limit:        2426408612341958329'u64,
        gas_used:         13656152006197676019'u64,
        timestamp:        6263571560389404595'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[177'u8, 36'u8, 79'u8, 26'u8, 164'u8, 59'u8, 182'u8, 88'u8, 223'u8, 22'u8, 79'u8, 197'u8, 109'u8, 53'u8, 53'u8, 134'u8, 244'u8, 84'u8, 146'u8, 158'u8, 234'u8, 252'u8, 188'u8, 175'u8, 69'u8, 51'u8, 118'u8, 101'u8, 242'u8, 0'u8, 51'u8, 103'u8]),
        base_fee_per_gas: UInt256.fromHex("0x997e6c8ffbd1ea95e875612109843c6cdfd0c6bcaffa1e06ba303b3012b3c371"),
        block_hash:       Eth2Digest.fromHex("0x9a7f83cf6a64e153fc3316244fabd972a49ebf5dfb173d7e611bf3447a175c41"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[137'u8, 103'u8, 164'u8, 112'u8, 136'u8, 91'u8, 170'u8, 241'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 12452742873210027116'u64, validator_index: 163643'u64, address: ExecutionAddress.fromHex("0x5d09dd69d2b2370e11b21d758bc82c2a73ee00d0"), amount: 12246034467900494037'u64.Gwei),
          capella.Withdrawal(index: 256915780184525584'u64, validator_index: 364410'u64, address: ExecutionAddress.fromHex("0x40a55ad4a156caf112e2abe789554520814e48a1"), amount: 297315'u64.Gwei),
        ])
      ),
      (capella.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xa8f90a617f1f230506d200c6026bd60e38f599930ed04f90cdc320a6d45bb022"),
        fee_recipient:    ExecutionAddress.fromHex("0x3531157eaf2c185bd8720f3edfaf76829632f07d"),
        state_root:       Eth2Digest.fromHex("0xa16f8936e945ecd45a4ae107e46acd8530e438fa1bc8eb85aef62afaca1656da"),
        receipts_root:    Eth2Digest.fromHex("0x3e76522c8f3b7e8d8a63f4968ab15413b8bbd7af9782c4878b52213b0b3d13f8"),
        logs_bloom:       BloomLogs.fromHex("0xc13b59de763feaa39debf70d280364ec68eb578af8a90aba7e2cf3a6cee413a28836c674662a0283df8ff04964eb928de97a3883226950b584d773c9b4479d6d5bda6fd71951c0c846752ed688e13dccff947b7a6c81bfac198b6bf785bca7be28bcf9a208b983afe6e766b0536311c1c12b4d01c712cdaa167ecec5520395068b1c1f939d20962de1aba36454cdb36031fa0ba886a8ece71234654e8b081562452046a388ebcf3cfd975493833ff4e146d5e5ddb061d994461ab8b468cf1d6d491d78fd8923f9f6563e3fbfa72639de993701ff6214fd83cd3597e870dec1c1e788a4f01f881c48e57b07c5a217132658208d2221a86c7e9823159984d235b5"),
        prev_randao:      Eth2Digest.fromHex("0xbac4a9aa16b289584d13abe3c47a58dda713c4b479ee70e1ac7b3b698e8505af"),
        block_number:     4839752353493107669'u64,
        gas_limit:        4713453319947764960'u64,
        gas_used:         3470256075652600568'u64,
        timestamp:        13764471837770950237'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[60'u8, 109'u8, 153'u8, 55'u8, 17'u8, 196'u8, 17'u8, 96'u8, 202'u8, 173'u8, 16'u8, 189'u8, 165'u8, 107'u8, 68'u8, 230'u8, 238'u8, 62'u8, 199'u8, 211'u8, 244'u8, 83'u8, 88'u8]),
        base_fee_per_gas: UInt256.fromHex("0x3adad83f48e34c6220dce41ecc0b09f9bb1ae4bda4466935c70e7c6cd54e185e"),
        block_hash:       Eth2Digest.fromHex("0x9183524f908425608c1e3a80d7c4ac2c539903af4b3a2f1b22c3283281706aba"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 645596'u64, validator_index: 248698'u64, address: ExecutionAddress.fromHex("0x124e32ea8d0363647a58a5511b6de35bdd50236e"), amount: 18446744073709551615'u64.Gwei),
        ])
      ),
      (capella.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xc914f63464f3f1588a32d3751900d415bbf1fe002c42068650f5c7c588b1935c"),
        fee_recipient:    ExecutionAddress.fromHex("0x61523b6add59cc65d3c5b75c6f749fa601e157de"),
        state_root:       Eth2Digest.fromHex("0xe84ecb995f6c7e753355c8d2e24694441c528b65ef9b1d8c6f4e9d98d409342b"),
        receipts_root:    Eth2Digest.fromHex("0x887bdafa340c24acb58f36a7e3825ce39fb7e0caaba3a9b63f78d2186cc6994a"),
        logs_bloom:       BloomLogs.fromHex("0x1fbd358ad7e32eefe4489b6c72bafcf6dbac109970e5c103e329279cede3619faf1309faf266ba155496c19565b31562f31539c98b6256919d8950bb6eca937401d91fa5b3032b4400ce6dd60a8c1c6cc94331b7e78d7a350ebb5d6e04a2594af981f167a89227c7c902dbb8eac3d7b54177d85214a6ef57b50da82b6420cf914fd63171f0b7dff9233bfaa2069774b142a136c5183ed4f57cde2590735b19ef549ff5bc910477b98344e7557ffc440b03d56842f356a6e223fd052c6272e24f43dc9e64055c097d81b56ecfd6087238602a743e09c383ad4eae6ef449570febdfebfefa347f06f480f319ff06365bbfae16b62a950143f9acc3663510356f0c"),
        prev_randao:      Eth2Digest.fromHex("0xc755584f86084ab2e62bd58f25dfe54538c0171e6447e7e1a51cf05db94377da"),
        block_number:     9276126375553452674'u64,
        gas_limit:        9007257403963034102'u64,
        gas_used:         12806310385580231715'u64,
        timestamp:        9957937708118639445'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[]),
        base_fee_per_gas: UInt256.fromHex("0xe2df33500d1162994934e9fa65fd5db641b0be2b61a6c302c7b9019f86042338"),
        block_hash:       Eth2Digest.fromHex("0xce58ef51926a6eb4cf2997c4ec771b54907737ae8fe9522fc316c97a1c7ee6d7"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 16986670237072862757'u64, validator_index: 701065'u64, address: ExecutionAddress.fromHex("0x50371592a27339f868b9ef63f6c02e8c1e72ce94"), amount: 3561319411833205205'u64.Gwei),
          capella.Withdrawal(index: 2402770018709110103'u64, validator_index: 798632'u64, address: ExecutionAddress.fromHex("0x9d42c6c10cbc0b04e3f2e74f63c777802d4ca064"), amount: 898967'u64.Gwei),
          capella.Withdrawal(index: 944680'u64, validator_index: 507423'u64, address: ExecutionAddress.fromHex("0x640d578aeed6b8a9acc83f13343f3139fe8f4a15"), amount: 941781'u64.Gwei),
        ])
      ),
      (capella.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x086322b79160568c7d096747ef351338ddc93f252dab1df3ef65aaf24723d2c3"),
        fee_recipient:    ExecutionAddress.fromHex("0x03c6998b5a3ff1c98538c2333d279f2b1cc59f7f"),
        state_root:       Eth2Digest.fromHex("0x446d99a7e9fd2c327fbd445dbfb3b3e3a895cdfa6f208496dd09c0f84f7ac0fd"),
        receipts_root:    Eth2Digest.fromHex("0xf4c74d5c59c46f1d9f916b32d8a12939cc2a379bae83153137de76415f6e5afe"),
        logs_bloom:       BloomLogs.fromHex("0x40f87c3729ba599c3e9bb749c48148ee0d5563db71cf0daaad3af95c45622d7b2a64204157a92a93cf0ffbe0052fb79eef83ba8389fe9d9e7646874b0636960e4eee86eeca00ba70f65b2046620264b795852def9beebb671f841e19ce07934b7c2f66301cc3c7dfa2606067cdeb04a564b87e56ff3650c7c6bbbc96b2de5ccf8e314ae74a26347371c315062532a1f1a2fe0c417ed5d12b6f81c3440c0d8b19d0cf8a030be83ee7ada6046d75098b6ee66664ead786a65ef5cdcb33c4634aa07cd7490abc0ea9ce722423a0cba1aecb379552e89483de43dd321cdaa8a005ab7e8e2a958038ca12e2b08709348a7f6daf34c488add1a0a21aed0da0b64251f9"),
        prev_randao:      Eth2Digest.fromHex("0x2ff08bd0b22bae8c3627f61b8da627fc367b3a60f93dbe48de1ca6f25ada489b"),
        block_number:     10605470807350562909'u64,
        gas_limit:        587854351728657338'u64,
        gas_used:         8799032544585725320'u64,
        timestamp:        18028498231539883963'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[]),
        base_fee_per_gas: UInt256.fromHex("0xfbe348f0c77be2ddbd3ec038e3aad88107625dc6e96b1fb3bbfdba8c737a3d7e"),
        block_hash:       Eth2Digest.fromHex("0xc545e833aa2ee5d708e041f4dcb44bda654372b3f5f660c683d12230303da729"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[89'u8, 59'u8, 131'u8, 146'u8, 186'u8, 180'u8, 208'u8, 76'u8, 69'u8, 40'u8, 29'u8, 211'u8, 97'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[208'u8, 136'u8, 157'u8, 0'u8, 120'u8, 231'u8, 99'u8, 33'u8, 31'u8, 210'u8, 80'u8, 203'u8, 24'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 225873861246030158'u64, validator_index: 3132710425326779052'u64, address: ExecutionAddress.fromHex("0x4d2573288e7949201c806877449e441801ba62c5"), amount: 9096383177302198854'u64.Gwei),
          capella.Withdrawal(index: 2816791477401799195'u64, validator_index: 12199871733060832130'u64, address: ExecutionAddress.fromHex("0xd4e21e668d5e8b1c097cb250dc862bfd7f8a2b76"), amount: 7278220627858832735'u64.Gwei),
          capella.Withdrawal(index: 12003547154719720523'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0xe888b3288bfaf8f979c93699cbabef6c1f156f19"), amount: 18446744073709551615'u64.Gwei),
        ])
      ),
      (capella.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xcfba7f4aa4ff01d3d9de84dbe1761c79627a10c3188fb0a7c8adfa0d489e6441"),
        fee_recipient:    ExecutionAddress.fromHex("0x106b3bcaae4ff58dd837768be35c29c48571e4a4"),
        state_root:       Eth2Digest.fromHex("0xe6242399020361e70cb6b89701001fa8326251e6bae3b4ca1978eded8831d9a7"),
        receipts_root:    Eth2Digest.fromHex("0x3db0f9a05cc39be94414c3be28378d2b91ba3ff43ea2ea7e4e0a1874a0983f58"),
        logs_bloom:       BloomLogs.fromHex("0xd591169a3cc38e0837a76c4d7057f94c1ef08ad5af1778b1b06c3a0ec85201bfc659b18c49de831ce6b4a40f0d2800a9cc9001f74810c58473f9b973b720f84626cc9270b0428439b985043f5d9c3289ef8a794f5b8265e10e9fb9fa53a93887d270b8204f8f16cd968e295b0a06aa70e9f6f174733d251f3bfc644a7fb274b0138729f18c0e4382bd4bf0387870f633ed897a125ca854120c2885194f3180af4b62760db96da51f88ae1cd222f49b00fbbc1544eb0e98cea67e36368816f541723158d3691f3cf1509c65a51a8e68efb66c500dd6516ca1b02aeb4e0c13cf5bbead53672fb5a7a1863c8edfaf4eb9a4b4322a39d8643528bccf22493914fa01"),
        prev_randao:      Eth2Digest.fromHex("0x14fec0a1edb9c82dc9aa7fb7224791c51a3937e74e5da59646123867496460f2"),
        block_number:     6272046003849350913'u64,
        gas_limit:        15423951135645467684'u64,
        gas_used:         3743939155619454195'u64,
        timestamp:        8496536260448579184'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[152'u8]),
        base_fee_per_gas: UInt256.fromHex("0xd8b104041bdc4c76a9735e2b4b45f0f3612e8962f672aaf511f06a94b48562c8"),
        block_hash:       Eth2Digest.fromHex("0x8ca67fec04b7e3bc5a01f5bb265b93b4488b58ec2ac7f2c3ced030311de2762e"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[152'u8, 232'u8, 136'u8, 228'u8, 253'u8, 248'u8, 85'u8, 92'u8, 103'u8, 38'u8, 106'u8, 166'u8, 148'u8, 8'u8, 37'u8, 245'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[58'u8, 215'u8, 97'u8, 99'u8, 152'u8, 126'u8, 14'u8, 252'u8, 64'u8, 87'u8, 242'u8, 60'u8, 210'u8, 217'u8, 75'u8, 189'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 18405055677765556765'u64, validator_index: 13513833286292305941'u64, address: ExecutionAddress.fromHex("0xfe53af2bf3560b2157a683a545d4f898354f4d55"), amount: 911502'u64.Gwei),
        ])
      ),
      (capella.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x063bc56b731eeeff8bf1c33d88523a04a14fa0c745eb3c750139842d88244982"),
        fee_recipient:    ExecutionAddress.fromHex("0x415b1cd5b42709a3724ab2f6f50a6dab7399d7ca"),
        state_root:       Eth2Digest.fromHex("0xf261abf37066b8dc5c868946346c98aae445adbb48e6dd05969fbb49267a276e"),
        receipts_root:    Eth2Digest.fromHex("0x5a337b7ee29d98e22b461f43b7a87e52d89fda2e7a3487ea92873be04a49ea68"),
        logs_bloom:       BloomLogs.fromHex("0x01817fd642526acdd8b57b4fc2fb58aba269095ce220ae5770004055f550918778021eae3abeffff1b3fa9fba50ff8d532fd8e2e67da7bdcca1cf9505179f19f595f5d9f09b98d5bc7d1ecb22527255e8e161ca2124c5fedbb59527f91a242671177e33a6fa377d585ebdbd6d9ff2bf80bec3695657441e35da43861f14b9a7e65ed475c323ece62d84aed7262cf3fd2b06ba03695e2e26e5e58fc5b8b99d519fda879587e3764930e3921aa15b2ee8691ea0e738030acb8832ca353d3bb63fbc0150c532b842cd053abeae8238c9ffe6f4b2b7210dc862c48843ae2a9088ecdb8c258592a0feb5215b8c9ad494ad896379d86e0ac89e6cd8765003ac5c95cce"),
        prev_randao:      Eth2Digest.fromHex("0xb28f434f3f40e40693b0c1726a018e2b3bc13c41608a2ca71aa5c8bf61829287"),
        block_number:     14597257287993827247'u64,
        gas_limit:        9090926713872599867'u64,
        gas_used:         17391976671717618186'u64,
        timestamp:        13439825139187707720'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[73'u8, 163'u8, 138'u8, 201'u8, 62'u8, 1'u8, 37'u8, 90'u8, 157'u8]),
        base_fee_per_gas: UInt256.fromHex("0x8a42339ef76757729ef6c4536b3b59255b18d7085d8ba786275b2076fc55b3c6"),
        block_hash:       Eth2Digest.fromHex("0xb3f6ec11b285a105833f5b68b67e8e23c85c28df2362a13a76db705f110fce8c"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 5477557954669138518'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0x4b840b26a19377c64b870be600aa336a40ae46ed"), amount: 42381'u64.Gwei),
          capella.Withdrawal(index: 0'u64, validator_index: 1'u64, address: ExecutionAddress.fromHex("0x3d22a723824a2944ea9accc8653002bf7d61a10a"), amount: 2799163561369818755'u64.Gwei),
        ])
      ),
      (capella.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xb31c41d39ef7e9a9b905cc93d82264415024d7daef48d886f1b3bc0fd6545edb"),
        fee_recipient:    ExecutionAddress.fromHex("0x5ad4b6c0d6b986e775f3a9ae2be73a330ba9f87c"),
        state_root:       Eth2Digest.fromHex("0x01dbc857a3d8994cf10cd1be3b2018be0e26ba54a5456e10a6e5729328a0b5f5"),
        receipts_root:    Eth2Digest.fromHex("0xa51e9cb9893bd7d73a8fd4e5267d80ddcb29d998814cfa9980dbae50ef101aff"),
        logs_bloom:       BloomLogs.fromHex("0xf1280db0ef6bb796e70dfef3b0bafa62690ef1e8f14a237856bae5dbe29dfd43ac789c53305ab5b0b7cc48ed53d1236ab9433a5352dac55b6e0a3ff90e9e815e2ce16fe5574c87f0066090c39b811996e2974da0bdb8bb59eb044bbb6bc2d7f8241093c7143a7c9892be85ea4284258ea2477f6a677d424efb6469724d641bbdc3f9254529b6af5cc5f5a77dad49c1a59ae37c19ffc69f6e331139b6ebac306ea09460dc0fc5791ef2cfb9e7bf29d662872e30b94384be90416df03bef5cf5a2339af4745f2f620fd1320d3fb79848692719cb8956b8efd427c9c0cc3ea6efb8f84feae0075ed10ec5c6243074e6004849712d8d1dd97ebb2948fcdf1d020c6e"),
        prev_randao:      Eth2Digest.fromHex("0xc8a27f0b7850de04e3d794b9e9d4f144c356f864401c3f802927faf4b88b47ac"),
        block_number:     10821099926525463598'u64,
        gas_limit:        7115919978619568727'u64,
        gas_used:         1,
        timestamp:        5900615379943209755'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[56'u8, 176'u8, 67'u8, 30'u8, 11'u8, 27'u8, 136'u8, 121'u8, 86'u8, 17'u8, 4'u8, 121'u8, 11'u8, 222'u8, 158'u8, 78'u8, 56'u8, 66'u8, 243'u8]),
        base_fee_per_gas: UInt256.fromHex("0xfbaacdba879288838ff725df19b7a31148ec5a24e7989441544d6dec1c980034"),
        block_hash:       Eth2Digest.fromHex("0x04616c0808df7a1bc177bc48cb6ed865125fbbac2fa3e3c36f33a5f1c48a23fd"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 143666'u64, validator_index: 849676'u64, address: ExecutionAddress.fromHex("0xbf06178f996afec7c9d3cb488e812f32aafe4242"), amount: 18446744073709551615'u64.Gwei),
          capella.Withdrawal(index: 560588584813483246'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0x1a1b89bf52af0d4a8eff759986ffd93cf4464114"), amount: 13046900622089392610'u64.Gwei),
        ])
      ),
      (capella.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xf6cba3ced37c08da230babbf9d1e360661e5a21ac235fefa75cbe756f15809de"),
        fee_recipient:    ExecutionAddress.fromHex("0x0c080349793b7f43fb3ee9101889e7d32e02c01d"),
        state_root:       Eth2Digest.fromHex("0x6a33580fc482e9783d66bee9276f42b74a2cbc2b7434fc408a6ba9df77db0ceb"),
        receipts_root:    Eth2Digest.fromHex("0xd896daff74ffd6ffcc088adba01aea52af82d861b7ff649265a750e5995dcf31"),
        logs_bloom:       BloomLogs.fromHex("0xec00c3385b735b6a4088ed066bdb088e7826a2830fd13a1a1525c4590eb08baeba81bb511bbf2db2c0547c69c10b5c6c1bf5c8e5a7931584e6ed8ed7357431e1e2391fc0e61a060baf8984a6fd5c04c68fe0f28f94281d0db663b1b2fdaad9b51d3a12bb9fba255c923dea5ce45dd68ec2c5afc9fd13a0e24d234a3c8c5f255e7d62d48a8e01fb5c1eaf0c7a68a616ac935416fe3332943d78eb28a48a180e2bee26e85d786583ae0609a8b98e1045738f054aa12bef97593cd16d8d795314bfff33c51b397afa2299a4a64244817e5a07cdcd75eb4c4c06e8e943d8d1db8e65f17368ab6175c3e14daad0b99fd0f1050feebadf9db8fe8f1c19ed867f4df676"),
        prev_randao:      Eth2Digest.fromHex("0xdcd37bc148c25afa7e320009ce19567108745ef5ed57781f55df1d73b707e26e"),
        block_number:     13754339262807377549'u64,
        gas_limit:        5250261236890759949'u64,
        gas_used:         1335844244115849195'u64,
        timestamp:        16758901654456753273'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[28'u8, 8'u8, 171'u8, 122'u8, 126'u8, 38'u8, 142'u8, 246'u8, 162'u8, 197'u8, 241'u8, 216'u8, 158'u8, 184'u8, 73'u8, 191'u8, 208'u8, 5'u8, 79'u8, 231'u8, 254'u8, 55'u8, 126'u8, 97'u8, 184'u8, 78'u8, 36'u8, 80'u8, 160'u8, 124'u8, 188'u8, 176'u8]),
        base_fee_per_gas: UInt256.fromHex("0x0ea1185e0ac50d1e2cc0be7229c846528380def25f7d8860cf366e6edd793be0"),
        block_hash:       Eth2Digest.fromHex("0xb471874aa6e8987deee40902d59537fed8af3e9b6ae2f8b476ddb051629b3b09"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[231'u8, 215'u8, 225'u8, 83'u8, 163'u8, 187'u8, 111'u8, 141'u8, 246'u8, 57'u8, 238'u8, 163'u8, 25'u8, 91'u8, 114'u8, 111'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[93'u8, 42'u8, 101'u8, 80'u8, 160'u8, 252'u8, 158'u8, 121'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[164'u8, 98'u8, 105'u8, 179'u8, 25'u8, 33'u8, 130'u8, 239'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 5378768050415100863'u64, validator_index: 0'u64, address: ExecutionAddress.fromHex("0x3d84c03e4c18979ee8288bd58b24989580f0a590"), amount: 815393520574223128'u64.Gwei),
          capella.Withdrawal(index: 17328504288784263137'u64, validator_index: 305278'u64, address: ExecutionAddress.fromHex("0xa00491dfbee05f23fc7ddcfcb1b27b2855334e81"), amount: 7734460020873819187'u64.Gwei),
          capella.Withdrawal(index: 0'u64, validator_index: 444647'u64, address: ExecutionAddress.fromHex("0x0689ed39160f4b4c20138f300b3b2502e6d6ab5a"), amount: 18446744073709551615'u64.Gwei),
          capella.Withdrawal(index: 834083'u64, validator_index: 10715076713456342424'u64, address: ExecutionAddress.fromHex("0x07ee24f650e7254d10d61b832db7174128bf22b4"), amount: 17794546242151296198'u64.Gwei),
        ])
      ),
      (capella.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x62ce6a6d68578309c4730f96f98a809d4b4225fc3d37a285daf26288b10f9590"),
        fee_recipient:    ExecutionAddress.fromHex("0x8c892b06f1e9c877c310b6eccefb20fcf5e00227"),
        state_root:       Eth2Digest.fromHex("0x578f93b83206e3239c69f51cc8e59cd89087260cda9f0efc892aa2ffb2bf386e"),
        receipts_root:    Eth2Digest.fromHex("0xa4ac657af8e0dad66ec74f4f66b246fe0089485e2810071fa556c09ea585059f"),
        logs_bloom:       BloomLogs.fromHex("0x18d67e640f9ad3a24deb7e3f8cbe0ba8224cf9cb9e67b2fd6c774fac7aa3f4adca2befe8322962cf000cb89c3e352433cf1aade51ceac9fe69966a8a89f7985030a301eb690e7eb20b5ac3b315930ee5397b6d65b03a1131b94e7f3505ef030877e460e9195b742e943716d9875a3e2e9998236d3565d622216af1721b658a12fe7d82a62619b4f2d042f146305ff1ad1bf394437340735eac9e962b3fe67597793d1151ec87fcb5f0056837c5813c75c4a0f94d91da71299b3780f250ee31eb9f106e3c443f0ba05213da05177238909fd9e60de9484e091b91dead82debc020929d1f14e79b610af3d15bf9c3757e62bb32a69523c1bd576e5c5d4bc2ef0a6"),
        prev_randao:      Eth2Digest.fromHex("0x552627eb969604e7d4ed1e631b74b2410dea7f4dbd49511bda390e3b9da8bf60"),
        block_number:     7763671958353664038'u64,
        gas_limit:        3930616259240751958'u64,
        gas_used:         7960068863134244743'u64,
        timestamp:        18446744073709551615'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[227'u8, 111'u8, 127'u8, 243'u8, 191'u8, 237'u8, 88'u8, 146'u8, 146'u8, 236'u8, 162'u8, 237'u8, 164'u8, 177'u8, 249'u8, 52'u8, 1'u8, 26'u8, 187'u8, 208'u8, 244'u8, 234'u8, 113'u8, 199'u8, 30'u8, 209'u8, 197'u8, 63'u8, 126'u8, 104'u8, 143'u8, 30'u8]),
        base_fee_per_gas: UInt256.fromHex("0x6bcd9684e1bc8f4fc5d089e0bf5fed35a8bf3039808d030bb9eb1ff7147180b5"),
        block_hash:       Eth2Digest.fromHex("0x9e2505de9f245873565b553e7215abff698bdfcee1dbd93e40eb295dd84e7f45"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[140'u8, 134'u8, 173'u8, 70'u8, 168'u8, 181'u8, 221'u8, 210'u8, 25'u8, 142'u8, 168'u8, 139'u8, 77'u8, 134'u8, 203'u8, 219'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 0'u64, validator_index: 780337'u64, address: ExecutionAddress.fromHex("0xf0ab5949e96d8befa8090fe5612d9c45beea0c8f"), amount: 2246589958612652012'u64.Gwei),
        ])
      ),
      (capella.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x4f8251c361a23171de8648d1e96c91fea2cc5a691dcd884e3a957dc8f6a8802a"),
        fee_recipient:    ExecutionAddress.fromHex("0x7da9175abaf6e4e400e0ee516fd3ab07dd659f2a"),
        state_root:       Eth2Digest.fromHex("0x1bd3a5da4c266dd396b8209288e68be066176ebe64cd4c17c4c6cdccaf03577e"),
        receipts_root:    Eth2Digest.fromHex("0x16133c4fe31f0487e700514160acf9257458a6ee716be8043cb6c532f84ef614"),
        logs_bloom:       BloomLogs.fromHex("0x5ca3807e674d69536b33337d798deaeb9fa6c7cbab7aef1473e6a6614f6f2c74ef85ee3632612b9c1e78d2a63e0b2f58d48d71e8d62e38510bc2f307680497cb965153b43392b8aa2dcd91a766356eab3ff1b4a6c4b037d61df1a8a4c6d3fa0e3c57a299a1c0a7382052ac25c412f2d2356c302e326fa0cfb570354e31e2f8046b80e2690ba69ec7c284c2df8ad23d16764cbc0ba28516f3c31aa89da3e3286106dcecc835b3007a17f33c4962efc3c9b0f5bff14c783e414ba60d35b79ab33ccd0151c34a94efc461d0df0a994085373f33275a4cd6839603632409b670072a4554f1c9342c03cd403a6feb67b23d3a075707ca89b77bad64e24a6ab79446ad"),
        prev_randao:      Eth2Digest.fromHex("0x6353ec5b94b9112f25e66de48b532ff5610c63f34c50a02fdf64af6c9d0ef2f4"),
        block_number:     16866969889068542818'u64,
        gas_limit:        5116920640663397560'u64,
        gas_used:         13292402101416991817'u64,
        timestamp:        1,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[136'u8, 133'u8, 189'u8, 60'u8, 229'u8, 217'u8, 70'u8, 145'u8, 136'u8, 97'u8, 175'u8, 23'u8, 183'u8, 73'u8]),
        base_fee_per_gas: UInt256.fromHex("0xe1307a28a2868b4d934aefdde7bbd09b0644b5c422d2c680770775cb44623512"),
        block_hash:       Eth2Digest.fromHex("0x11e23850b143b8b4dd8394ee1f2cebf073068502d04dde00000925cf23ff55cc"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[])
      ),
      (capella.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x0c67b44b492590ffb9e6d2a63c84714821be7526ce1c337c06276e33a62b7b93"),
        fee_recipient:    ExecutionAddress.fromHex("0x1d16dbe66ead2ba8afb8594acaf8d536be08dac3"),
        state_root:       Eth2Digest.fromHex("0xeeb40e334aff8512435b5908a8dd3c06993cadca8bc44e9a6c28c6003162c6a9"),
        receipts_root:    Eth2Digest.fromHex("0xefa5b7de19da2333bfb7bfa814a306f904fef2ff4f8b1154314649a56fea3c8d"),
        logs_bloom:       BloomLogs.fromHex("0x4ebbaff6a56343a6bc0170aca2e2ba303f3e3f972c88539ef84e402740e3c9e21c6951d461baf56eec14c06ca0e95f4921079d0d82e9dd46e73f3fa76417246217ff9c5425f19b0f8b2a735ee522c1bc377a2b079099430d0f9316164f5930456245534bbe138d0a19ee58bb13a0d724723a6fa50e39b8a7ad5804f92ab43c24782e27dbb32789408cdd716af9a0b0cb1e2f3aee0bcb5aa4088c0cf1528fad466f3d71d906649becf25f405f619dead731e0831efb522b5faee7a39ca28128effc79977816d50ae23745ab96b80dc7f548aa5d43b0d5c331fdc1ce080a4d63e19942ecb4df8f56397b2ef67d017f2d2de9296e1fd8036ed8592f5a89553c4642"),
        prev_randao:      Eth2Digest.fromHex("0x5d3c3ac25330e1cd3a516003315ed24bd2dc6cd31d389639cce4b6ae4a3ac8cf"),
        block_number:     10891095348111649307'u64,
        gas_limit:        13670668340379820434'u64,
        gas_used:         1482104080767186829'u64,
        timestamp:        6602476120092784163'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[223'u8, 228'u8, 253'u8, 3'u8, 38'u8, 218'u8, 253'u8, 87'u8, 206'u8, 243'u8, 168'u8, 113'u8]),
        base_fee_per_gas: UInt256.fromHex("0x972a01f27d586035ce5fb233118e52652ebbf89f6d39558a41b27c8840c849b1"),
        block_hash:       Eth2Digest.fromHex("0x9280fa96a569e7c25b2dfc12a141d3edd24acf2fbfa19ee72e5a1fd5dba25a11"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[116'u8, 179'u8, 195'u8, 80'u8, 193'u8, 73'u8, 187'u8, 64'u8, 41'u8, 251'u8, 55'u8, 90'u8, 161'u8, 30'u8, 221'u8, 210'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 820354'u64, validator_index: 626992'u64, address: ExecutionAddress.fromHex("0x4abb3f9a694bf6b27be97e24290ca6826b23c5d0"), amount: 100271'u64.Gwei),
        ])
      ),
      (capella.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x7a9d6ab34c0314959d5bdceb0bd80f142e59e5e2addedcd178612303897e7a8a"),
        fee_recipient:    ExecutionAddress.fromHex("0x3425bc529b4791f5fdb7dd365501199b2f81e578"),
        state_root:       Eth2Digest.fromHex("0x4eb1a9a3c4b9392325a14f3f8efbc0b3cc3bfc2d7e9992377abd84af6c556db5"),
        receipts_root:    Eth2Digest.fromHex("0x094e9114d3487925f6818140978e4db64d8306083a8e5c987657e21c3a1995bd"),
        logs_bloom:       BloomLogs.fromHex("0x0815701b4689d0bb7f80fb1485ad3255a66b890725a1d2d66b4fc66678e2d08784c21ef583401493d5dda1549eda32303b7d102edc72b9fe1d696ab459294a88db0d7263abdf982ddf59ce008b8ac734565de79c269dfc18a36709ca91a3cd50516725e9fa9d98302fa0322254382aab0cdf1f95f2397579f7219bd7ab096ef1f00d7b1131b0055bff65ae9954cb22959adbc40983840ae3b85358fd205bdf6ac6bcf723047ffc53a094a06c2039935b6ef579efc618bf4127a6e4e531f6d97c17789be639691ef87fa5540cf732a184a0e09d5c60866ecd0be0a04bc94317712c395d84c2cec90f43f4807048bf1a93e3e6520a1a7c59092e2e391abf9d2e68"),
        prev_randao:      Eth2Digest.fromHex("0x349eec90244f3d812002732cd833952969b27a463def04291051137344c89c41"),
        block_number:     5715688900321967041'u64,
        gas_limit:        17172684770312311722'u64,
        gas_used:         9286597649062725614'u64,
        timestamp:        195835912833125491'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[34'u8, 35'u8, 209'u8, 45'u8, 117'u8]),
        base_fee_per_gas: UInt256.fromHex("0x7b5b4e48b3daadecb9724a74d426a86ffb5c5f8abd43469b4e3fe2a728b5a645"),
        block_hash:       Eth2Digest.fromHex("0xc71c294b5562af30b9e2b03e76cec0cc6d8b50694219404aaed2ace8f756a22e"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[178'u8, 142'u8, 115'u8, 217'u8, 56'u8, 74'u8, 150'u8, 16'u8, 244'u8, 148'u8, 19'u8, 33'u8, 89'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[195'u8, 248'u8, 42'u8, 129'u8, 151'u8, 119'u8, 232'u8, 235'u8, 245'u8, 240'u8, 113'u8, 157'u8, 235'u8, 158'u8, 160'u8, 222'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[16'u8, 27'u8, 72'u8, 107'u8, 18'u8, 210'u8, 127'u8, 78'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 5186085670428433087'u64, validator_index: 156817'u64, address: ExecutionAddress.fromHex("0xf8d93a548c4b243e66f4f73b29da342a0fab04de"), amount: 18446744073709551615'u64.Gwei),
          capella.Withdrawal(index: 9475052657186699106'u64, validator_index: 759532'u64, address: ExecutionAddress.fromHex("0x97559fac3168c6ee81b0f0b0b88563080ca24769"), amount: 4852567582077527137'u64.Gwei),
        ])
      ),
      (capella.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x806a868f0f31e8f519fa6339ad18c414dba17feb03aaf6ca3775b152bac64f3b"),
        fee_recipient:    ExecutionAddress.fromHex("0xa2bcc8b793c4a5d4e0f68251d2f22e1ff4366d2c"),
        state_root:       Eth2Digest.fromHex("0x6979ac9545f31eaf7ed8bd227cd7cbd1017492b892bcc118f7417ea87d50d412"),
        receipts_root:    Eth2Digest.fromHex("0xca0ac1828fae211c9d0fd7ab763460d89f9da0669d082c68b9fdca3ca1b59123"),
        logs_bloom:       BloomLogs.fromHex("0x0656423dc7b375cee4f5c3bedc500eaff2da91d0dd5f4e695933c92a2a6af7441200a41177bcae7912839f993a733aa2bb82976f08180a901e63c588a26dc9ccc58f477eccbb08aa932d512bfc765a57527acd04c585af23f48f389420890d06877d8a0f523cb90be10dbc73cb5b11e808f5c6c90c6fc3a9434dab462f2977eacf79146b35ee2372aae8a6fe3628cbe21a8988fd9546b25581b6d998462f9af7f653d3a4702a4a63b9f26cc7d2f72e18a3918fa9b65ed81d23ac0a64dd8f3f878f745fcb4de9ad144ae9565288d7bf90e6d356f49cc242d000e988fe76e0196f0c5b24bdf9dc501222e54f64861e0d45dda2bdf09e5fb290a1ec6dce39b02883"),
        prev_randao:      Eth2Digest.fromHex("0xc986211f6550cb787e89140d8856531ec309f652e2a871e2715c1dd055448074"),
        block_number:     7781035717593646205'u64,
        gas_limit:        9088183223170031827'u64,
        gas_used:         0,
        timestamp:        1844848381084178223'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[]),
        base_fee_per_gas: UInt256.fromHex("0xaac988479abbe95e03cc214e7b99795c4ec117bfe4da06e4624e94b262b015e2"),
        block_hash:       Eth2Digest.fromHex("0x14137d373f6e6110b3fe3c1d743a4f84547ad3d59d0b42598b794ff601e97e38"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[10'u8, 28'u8, 79'u8, 238'u8, 85'u8, 206'u8, 161'u8, 222'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[144'u8, 222'u8, 190'u8, 14'u8, 247'u8, 119'u8, 95'u8, 48'u8, 238'u8, 50'u8, 180'u8, 12'u8, 216'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 428032'u64, validator_index: 18218455002493563835'u64, address: ExecutionAddress.fromHex("0x389fe5e57a13de364b852d7e2cebc2add2cb7510"), amount: 726634'u64.Gwei),
          capella.Withdrawal(index: 18446744073709551615'u64, validator_index: 0'u64, address: ExecutionAddress.fromHex("0xc6a0db1d09160cec69bda14b444c46745e09c96b"), amount: 742028'u64.Gwei),
          capella.Withdrawal(index: 858390'u64, validator_index: 326055'u64, address: ExecutionAddress.fromHex("0x6a861508a89443c763d5daf15dab44a8a45147fc"), amount: 597242'u64.Gwei),
          capella.Withdrawal(index: 18446744073709551615'u64, validator_index: 17239721441660215355'u64, address: ExecutionAddress.fromHex("0x1450447dc71e28e312c7de7034523cd322eabc98"), amount: 18446744073709551615'u64.Gwei),
        ])
      )]

    for executionPayload in executionPayloads:
      check:
        executionPayload == asConsensusType(
          asEngineExecutionPayload(executionPayload))

  test "Roundtrip engine RPC V3 and deneb ExecutionPayload representations":
    # Each Eth2Digest field is chosen randomly. Each uint64 field is random,
    # with boosted probabilities for 0, 1, and high(uint64). There can be 0,
    # 1, 2, or 3 transactions uniformly. Each transaction is 0, 8, 13, or 16
    # bytes. fee_recipient and logs_bloom, both, are uniformly random. extra
    # bytes are random, with 0, 1, and 32 lengths' probabilities increased.
    #
    # For withdrawals, many possible values are nonsensical (e.g., sufficiently
    # high withdrawal indexes or validator indexes), but should be supported in
    # this layer regardless, so sample across entire domain.
    const executionPayloads = [
      (deneb.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x760d4d1fced29500a422c401a646ee5bb5d65a07efa1492856a72cff9948a434"),
        fee_recipient:    ExecutionAddress.fromHex("0x315f583fa44fc6684553d3c88c3d26e9ed7123d8"),
        state_root:       Eth2Digest.fromHex("0xa6975bac699618cc22c05b1ba8f47cbd162475669474316d7a79ea84bce3c690"),
        receipts_root:    Eth2Digest.fromHex("0x080d53a0fd22d93f669b06052413851469d63adeb301810d7ce7a51c90c8e8ce"),
        logs_bloom:       BloomLogs.fromHex("0x453a1f1c4f63bcf0be84e36a9ac233b551601bb2e5ab9450235bd83e41d2013f42c97044ac197a91da96efd6fb18f233bad2e884d76f0a63a6fbf7dbc714cc9aa497fb6d363feeba18447ecf799d5f8d769232553c375b21166c0176859dba63eb77f1a17e482ebac07c3cfd5281277f55f1e5c79cc675d501e1982816d31db7d73c89e855315d8f4e9fef1c9ebb322610235c44632a80341b42f05d207ac4869d08d98a3587a470f598095ebb932788fefacdd70e7749e0bd47ceff88a74ee1f006d9791350484149935d4521d86e644ebc4346154ca0bfa9fbb83120630867d878c12e53a04a879e993b755f02670c9c47f091acf1b3f593782ddaa98f0df4"),
        prev_randao:      Eth2Digest.fromHex("0xe19503a6fa6acde0b8f5981f29eb2e298ddff63e6243529d735bcfa42680a515"),
        block_number:     9937808397572497453'u64,
        gas_limit:        15517598874177925531'u64,
        gas_used:         3241597546384131838'u64,
        timestamp:        17932057306109702405'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[55'u8, 184'u8, 18'u8, 128'u8, 63'u8, 61'u8, 26'u8, 79'u8, 3'u8, 225'u8, 167'u8, 15'u8, 240'u8, 167'u8, 180'u8, 141'u8, 205'u8, 10'u8, 246'u8, 70'u8, 248'u8, 35'u8, 19'u8, 45'u8, 252'u8, 187'u8, 168'u8, 42'u8]),
        base_fee_per_gas: UInt256.fromHex("0xaf8acbd8a0f0f8eeced9a1014333cdddbd2090d663a06cd919cf17529e9d7862"),
        block_hash:       Eth2Digest.fromHex("0x86b46255725b39af70a9e1a3096287d9772ccc635408fe06c34cc8b680977ff5"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 98780'u64, validator_index: 8610867051145053792'u64, address: ExecutionAddress.fromHex("0x0c33e909ef375bd3ab33961b5ea767b4f1c8bce0"), amount: 671269'u64.Gwei),
          capella.Withdrawal(index: 18446744073709551615'u64, validator_index: 500164'u64, address: ExecutionAddress.fromHex("0x271215240885828779da36212489170f19a8f5bb"), amount: 2071087476832314128'u64.Gwei),
          capella.Withdrawal(index: 26148315722507923'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0x340bd9f489ec124b8a879673f12969b14d0b5555"), amount: 9486787560616102568'u64.Gwei),
          capella.Withdrawal(index: 4839737623914146930'u64, validator_index: 273755626242170824'u64, address: ExecutionAddress.fromHex("0xcacc573cfc0ad561aae27f7be1c38b8dd6fab2cc"), amount: 9475975971913976804'u64.Gwei),
        ]),
        blob_gas_used:    4401258332680664954'u64,
        excess_blob_gas:  12834012644793671460'u64
      ),
      (deneb.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x2cb54ddf357864102f4ab6bce57317a75cee972f303449bf7047f4e0e5809127"),
        fee_recipient:    ExecutionAddress.fromHex("0x92af67d9604b945fd2cbaccd29598e2b47ef5d2d"),
        state_root:       Eth2Digest.fromHex("0xc64221514816a2f87a29c2c474abf99547820b2a12e6e5956f160dd54579e521"),
        receipts_root:    Eth2Digest.fromHex("0x76c1ca0e483a557f6884d64bd891c62904c64c2fe69350278345c622cc50b0d7"),
        logs_bloom:       BloomLogs.fromHex("0x7afdc9a99777d76b713e960e9f12ad4fe46ecb7ea6d5b245c6d9ee11d3fd35e7ae33dd6062fb6578bc2c2f286f1c6a4aa6a44cc80a88a3678c7085c35a0f2e5334ea686e2098fe5d179bbbaf81cbc349a15e7a21aa27f0ddcad342d980d056a356694cdadcef8db3c7866b6cb087c28f2aeed7a5bc9b1294cef0da3ac3b46dbe72d7f164f1990bc32f755b709b96a96bdd8da2c9d9300e9f6906040347d337fc21b833ff0b80305b22ac64a2df2dede4c01c65c192884f161aacd12ba56dab9189477e6ae484a97ff96e0aba1f9b8d043896b8433779abeec091f16b94a013325fe11096d1f2d79b701ab5b46063ac99392a790e617555fe3286dfd7ec0cb9b6"),
        prev_randao:      Eth2Digest.fromHex("0xc4021ae781a3b3a1dfb1e4464b032a3bae5f5b68366beb555ede1f126920cd5c"),
        block_number:     11318858212743222111'u64,
        gas_limit:        2312263413099464025'u64,
        gas_used:         1,
        timestamp:        15461704461982808518'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[254'u8, 188'u8, 92'u8, 24'u8, 153'u8, 206'u8, 74'u8, 108'u8, 96'u8, 100'u8, 148'u8, 84'u8, 151'u8, 74'u8, 73'u8, 167'u8, 65'u8, 177'u8, 253'u8, 62'u8]),
        base_fee_per_gas: UInt256.fromHex("0xb1c4b2bffcb38aaa1f98b483441aa212c9dd951d4706dd505a973fd5fd84796f"),
        block_hash:       Eth2Digest.fromHex("0x8b150d453d802fdbb19be0132621a5e8061e70cfe6668ee6a63e4ff217434999"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[142'u8, 197'u8, 221'u8, 83'u8, 32'u8, 126'u8, 145'u8, 86'u8, 28'u8, 39'u8, 112'u8, 240'u8, 168'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[175'u8, 191'u8, 143'u8, 78'u8, 162'u8, 249'u8, 87'u8, 193'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[84'u8, 168'u8, 190'u8, 157'u8, 39'u8, 143'u8, 147'u8, 156'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 11497754023538902580'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0xb0b680a6d93e520fa32e399ded64871d99c1f2c6"), amount: 15592017597077727306'u64.Gwei),
          capella.Withdrawal(index: 18446744073709551615'u64, validator_index: 14269483352942387358'u64, address: ExecutionAddress.fromHex("0x97e4451d09c9af077dc9081e5081563aa26e4c51"), amount: 18446744073709551615'u64.Gwei),
          capella.Withdrawal(index: 9664968187979079659'u64, validator_index: 750818'u64, address: ExecutionAddress.fromHex("0x1e4bc6f12efe96b9f5ca549b77a3d62c5f5403d8"), amount: 18446744073709551615'u64.Gwei),
          capella.Withdrawal(index: 727020'u64, validator_index: 10133766089843653238'u64, address: ExecutionAddress.fromHex("0x6a1ed64277cf1eba8c96281531d2799d1fa7c409"), amount: 130469'u64.Gwei),
        ]),
        blob_gas_used:    4810756443599845432'u64,
        excess_blob_gas:  1435200597189175983'u64
      ),
      (deneb.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xac5a7347865f503e1578d1b47271c8e60027b5ba24b0da8e7c3733bcdbeda220"),
        fee_recipient:    ExecutionAddress.fromHex("0x8b7fa656e67f6af2074ec3f16930ad742a69f189"),
        state_root:       Eth2Digest.fromHex("0xeb50f351f6945df8983cf4037ee264dcb2ceef3313ae452248571811d8a3a8cf"),
        receipts_root:    Eth2Digest.fromHex("0x860af6010832f64a5234327b653aabbd3898881a7b72ae42e08d4a1519166fba"),
        logs_bloom:       BloomLogs.fromHex("0x01a18d51076880a1a8ea86cc5dc5fb904ba0a3c285b7dff34ee5dbad9d64721f3849ad9f50b90ad4524eca6b0564f8a1a5827a7b476ea051c33a7c0e18db4cfb27b36476bbb1eacbc029dbc5009e5cea695045cfb34c868163514b784133f0f2998cf12e2caf9c74f69732ed3716396dc34d86725428aff48bf6b935ae88f5e4820b9a325bc670cf560dcb479723213a3156a9d7d0e7de0dc791d0eb94a691013624b8aa982ca3c9d5b49fcac8fafbb403c9fbceee5373f0fb2b77ff1bae8160fe2a47b01d792b088eb3fe24c53b5c6a8b4a3b59060d587ca7376f8baba58d57cf745b2a346f800a54d08545194e067ae260c73369a016b12d0fbc20abc78ba3"),
        prev_randao:      Eth2Digest.fromHex("0x330b7093023f617d2cb5f76cee4b078af002b68d81e3a5b5c9d37c4411871a95"),
        block_number:     18446744073709551615'u64,
        gas_limit:        13979513761871276914'u64,
        gas_used:         6199089254852634745'u64,
        timestamp:        7404562418233177323'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[220'u8, 149'u8, 177'u8, 36'u8, 228'u8, 88'u8, 47'u8, 149'u8, 211'u8, 213'u8, 170'u8, 40'u8, 207'u8, 145'u8, 137'u8, 64'u8, 153'u8, 22'u8]),
        base_fee_per_gas: UInt256.fromHex("0xfc82d0e46d05b21aedab6f368183611d2885b28c52842f28f621ef6c631b6e6a"),
        block_hash:       Eth2Digest.fromHex("0xa8c6b2dcc2496f0230e796f8a69642126955ae6209a0d0c2dee2c925212f447e"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[138'u8, 17'u8, 34'u8, 168'u8, 105'u8, 179'u8, 196'u8, 21'u8, 253'u8, 242'u8, 106'u8, 30'u8, 40'u8, 190'u8, 179'u8, 93'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 1'u64, validator_index: 239183'u64, address: ExecutionAddress.fromHex("0x75efb2a04b5f25ae56ff7256ee9f4fdc4e25baf3"), amount: 402148'u64.Gwei),
        ]),
        blob_gas_used:    723464856451065691'u64,
        excess_blob_gas:  11231138371511965912'u64
      ),
      (deneb.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xd3be9b45bfe67229afb47461ca2970505586cab8eb8e00f280ceb07a9d47866f"),
        fee_recipient:    ExecutionAddress.fromHex("0xde645d4a77f0a386a45c52357948e1d7eac5e780"),
        state_root:       Eth2Digest.fromHex("0x69b70e0188e7b88e38df90853b2dfd2e4c7181e83d82d77ab81c57d161216b92"),
        receipts_root:    Eth2Digest.fromHex("0xc01d94a01736268170a16196927029d4d8d7c65970ec78ece94c87304bed4568"),
        logs_bloom:       BloomLogs.fromHex("0x7f1ac5c77e3f0c8a1a103ee83dd7d0fd6fb13895aa1141de330445474b3216e2646c15c1cbf4ab4feb1e4e21c2e6970f4a6648675508b08111e00b62866b0f6cccd58afea87d2cd0a24c0384fa179dc33ae6d0db8c1b118a75fb442682b7cbecc2808fe8c812c3720ca54f6723a395fff5dd1720f41822c91b080503bbfeef21eea192d5b7c4160344996d017ab849fa97e862206caac8f8bfeba41865514b21a8d8fa9ce3dcc0daf5bf86fd2f07d222fc7a9d11fb4031b2cd72544d7f89eb95203a570bc179f9ba1f73f39d74049fe22b63939ea49d5d40f42c00c5f1bd429e84ade377475e432186acd9975914670052fea64453fca87317f62e29b550e88f"),
        prev_randao:      Eth2Digest.fromHex("0xce47da2b2a68186b78054be0894ccc9ae7213c18b9093c0ebc1b9ed011071a39"),
        block_number:     9014833350824993703'u64,
        gas_limit:        18446744073709551615'u64,
        gas_used:         7874274181221487360'u64,
        timestamp:        1,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[139'u8]),
        base_fee_per_gas: UInt256.fromHex("0x1eb821a0ee3f9d2e5b49c64177db9ffc96ec6b06249cefa8c51d0ce7e664a3ae"),
        block_hash:       Eth2Digest.fromHex("0x99479be6429eac4a945ca8171d3d3ce42d7b5af298292e833e20462438e06229"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[99'u8, 198'u8, 91'u8, 86'u8, 23'u8, 222'u8, 121'u8, 250'u8, 12'u8, 135'u8, 133'u8, 37'u8, 61'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[81'u8, 173'u8, 241'u8, 145'u8, 54'u8, 3'u8, 36'u8, 121'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[]),
        blob_gas_used:    1936360613980595982'u64,
        excess_blob_gas:  525438497879148955'u64
      ),
      (deneb.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x06504beb0dc3bae44ef75678d29ec5138d87da68d307ca7d43e259cede60fda6"),
        fee_recipient:    ExecutionAddress.fromHex("0x527ce602a0be18c0944dc27b2864c711a91f89a6"),
        state_root:       Eth2Digest.fromHex("0xad3bbef5d22bdc2429da09eb85137c881f85fe6e6b3ea207e5eaeb399c755055"),
        receipts_root:    Eth2Digest.fromHex("0xf94fdc52cde20532cfdee73e9cebb61d9f7160191345f9caf58b45501d8effbc"),
        logs_bloom:       BloomLogs.fromHex("0x0999cc50752006a2bc8e5485c239b9a41be6ea2fd8f0392884246ef7d33bccdf4bd326fadae385e3ecc309bf0f367ac1791767ffaee90ddfa7bee22d19f417708fded2b2b6b3be2b6007745fb1de940e7849761586953c04e3bec3c9b6342d1b91dd024980f469b484bd0befc4941a3846d027390d6256e4acf9933e0891dd558270eb35d3455f4e49c890479e970a8008b75ff4d33b4f7e5a8c19e75d8abd8673ebb859a8a24907584d88f0d68b3142b3c6952695fdd84581f5a070601a575a8e7bfa0bf7cf0fe9d70a051005f9dc594d09909e9d079d02a4e441e5b3f33388de8d46cbdcdf24f835415680e569f2ed29acdc01042a6a7ee701e4e6cace5c28"),
        prev_randao:      Eth2Digest.fromHex("0x7cef96d72498facdb399dfb5b6d7d69185f3edc70715540fdc7ef651c4685c6a"),
        block_number:     13066898984921201592'u64,
        gas_limit:        9241830338892723842'u64,
        gas_used:         8347984358275749670'u64,
        timestamp:        1,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[11'u8, 46'u8, 127'u8, 104'u8, 141'u8, 79'u8, 55'u8, 48'u8, 242'u8, 12'u8, 142'u8, 2'u8]),
        base_fee_per_gas: UInt256.fromHex("0x6241db2a44a58a2c1aac93c4aa18aed5add30d1937c31078542bb544bf9ba2df"),
        block_hash:       Eth2Digest.fromHex("0xdc1756667e7c3f1615650cbbaae1117a6bac817c6579cf3f7afbc93277eb3ea1"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[13'u8, 24'u8, 248'u8, 26'u8, 141'u8, 177'u8, 236'u8, 2'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[213'u8, 208'u8, 242'u8, 46'u8, 0'u8, 31'u8, 219'u8, 213'u8, 197'u8, 218'u8, 148'u8, 236'u8, 43'u8, 152'u8, 123'u8, 96'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[84'u8, 163'u8, 60'u8, 195'u8, 40'u8, 68'u8, 185'u8, 20'u8, 244'u8, 82'u8, 34'u8, 181'u8, 26'u8, 201'u8, 2'u8, 108'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 18446744073709551615'u64, validator_index: 15531362396155364476'u64, address: ExecutionAddress.fromHex("0x063b2e1de01c4dad4402641553c7c60ea990ab30"), amount: 106054'u64.Gwei),
        ]),
        blob_gas_used:    0,
        excess_blob_gas:  11830672376638423068'u64
      ),
      (deneb.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xb5d4a5eae3a1ea004ed573b0b8f8a22c847616758c0faf1e7e9589f16e55415c"),
        fee_recipient:    ExecutionAddress.fromHex("0xf7ac0877fd8bcadde1e050f6c7ddad13688ec071"),
        state_root:       Eth2Digest.fromHex("0x7472f824376a723894f8d539743c7f93b69839772f28cf6a83e2102fde99c3c9"),
        receipts_root:    Eth2Digest.fromHex("0x750365b5d975460a64f07758abd0cdd44cee23cc2d4f06f2a047cf4c12c23db4"),
        logs_bloom:       BloomLogs.fromHex("0xe24d8452039bddd10e1252c1ebf9b9e81a22577f940e8708d200548717e8471e130a7066adc48785a8dea1dca05953d6be16504a57112c065e7909586cd611af9e0b840b81caf0532dbb2833ee5ac6a6eb7b6c990cba6ccf6f4ddec5a7c76f8296bd2a693cbbb43b1d86b66f6aa58888734d3fb21cf5e96f1b981f8ae2737bce1cad1cc458650291cf7a3d22c61fde6af3a07a44bf1b334b2c5dabbef16e5e73db75e87f04670cb3830f0a7badc702e7dd37a59ce02992f4473a909e57dee1fdd22cfc886f4fcb6ea205ec9234a8ec85ea134242748f9f10062534fd0528bc1b5b1e89511cdf91a1e7fb4f8c58c93d2a6c75e48a2d48235cb7de13040db8dc9c"),
        prev_randao:      Eth2Digest.fromHex("0x2410823a37c763e13b03a4c48e32f9e43b8440ca31ecfe8e0543a20a02c496c5"),
        block_number:     14920119354157670036'u64,
        gas_limit:        17193947846593799248'u64,
        gas_used:         2176791850599260430'u64,
        timestamp:        12670133468877091192'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[31'u8, 7'u8, 1'u8, 212'u8, 152'u8, 82'u8, 167'u8, 57'u8, 116'u8, 147'u8, 97'u8, 109'u8, 219'u8, 207'u8, 151'u8, 116'u8, 43'u8, 218'u8, 91'u8, 253'u8, 14'u8, 182'u8, 102'u8, 57'u8, 153'u8, 72'u8, 172'u8, 208'u8, 0'u8, 64'u8, 97'u8]),
        base_fee_per_gas: UInt256.fromHex("0xf1daaa067663bf3277b9149aab162f4e330f988f0be8f83a556743a57ae5c8fd"),
        block_hash:       Eth2Digest.fromHex("0x5d462b4b243c6292b6a3b32f4e05849c0613d0a61954734c524f75f8df66cf8d"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 5416630176463173042'u64, validator_index: 0'u64, address: ExecutionAddress.fromHex("0xd7b1d18e4eb7b5041b4b08bae2ce8e22982d6e6c"), amount: 911474'u64.Gwei),
        ]),
        blob_gas_used:    17909098553568904023'u64,
        excess_blob_gas:  2561776469828429184'u64
      ),
      (deneb.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x2629683cfc70198038837270bde3c60176c2a4aeeced0d4a4f14dc99a380c377"),
        fee_recipient:    ExecutionAddress.fromHex("0xd234af1937861b66ca84c334824763fb54347677"),
        state_root:       Eth2Digest.fromHex("0xf79f02d52d7f2a4be99eebba3dfb3bce74136ea739da515703d095a66ce203d5"),
        receipts_root:    Eth2Digest.fromHex("0xa97ae6fa5d6937f7754ff96766a54bb8ec082b046814e74f6c9c67147795f526"),
        logs_bloom:       BloomLogs.fromHex("0x5d2ef8bc2f58a84e4050e3a38985e4c267940707c8da3f687fefb9e22e4ae11a2f79a24456af3758e8b521d546dc178da5c85da869ebb2da551976488a769ca2940fa20853e4e1d1fcf8d5bbea0d16973c827d38c97c47c57835677590567829d119e8108f2ee3fa988b267ccfc3e58e5f81c18c775a9baf06d4d81aee405c5683fa4e5e891b58101a27e8f71c60d357a4ab8bd02e12fbbb0e363c4632b0a3c0de638de37448c9476c65a62f7f1dd9643fac6ff78ee431d18ab554b4c8a1984fb5fa0de3464d223f236eb8e8a8f59601221d2ab480ffcefaf4bf6471b40a14773ac0cdb43aea505941e4b0fa6fb26eb091adad77acce41e516fc743e5fdb045f"),
        prev_randao:      Eth2Digest.fromHex("0xbe44d7c5f844a2acb307a4371784d7742be482aece83368d94813ffa1c7bb60f"),
        block_number:     13524449277995212660'u64,
        gas_limit:        1,
        gas_used:         7976957374052242924'u64,
        timestamp:        1,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[57'u8]),
        base_fee_per_gas: UInt256.fromHex("0x6c98d9ff36f1032fd55d8a6038d7b1f7c4e5f7c884b73f626fe43e687beeb46d"),
        block_hash:       Eth2Digest.fromHex("0x2c95101857b07bdda0502741da8cd9160ec0474929d132e9159098576f9a7c35"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[75'u8, 85'u8, 130'u8, 87'u8, 90'u8, 172'u8, 176'u8, 44'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[207'u8, 150'u8, 64'u8, 87'u8, 15'u8, 18'u8, 3'u8, 236'u8, 232'u8, 87'u8, 174'u8, 192'u8, 29'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[23'u8, 37'u8, 57'u8, 158'u8, 137'u8, 222'u8, 53'u8, 111'u8, 63'u8, 13'u8, 69'u8, 110'u8, 175'u8, 108'u8, 16'u8, 207'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 1071093368516669975'u64, validator_index: 15999188653672167093'u64, address: ExecutionAddress.fromHex("0x368b0ae1a6bfc3312460f212017e8bb32aae55bf"), amount: 13132185675616884508'u64.Gwei),
          capella.Withdrawal(index: 18446744073709551615'u64, validator_index: 1251419977457119333'u64, address: ExecutionAddress.fromHex("0x0a4d18e47c5ec0c639ff29d8f8c9be0b60f00452"), amount: 1'u64.Gwei),
          capella.Withdrawal(index: 2046299652899032730'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0x44bfe00f98603a5e8363030de4202ba50c7e8138"), amount: 15403504672180847702'u64.Gwei),
        ]),
        blob_gas_used:    819823383278806839'u64,
        excess_blob_gas:  5121347703897393436'u64
      ),
      (deneb.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x190544155dd98bf86d3ed5ee94d01afd3a8e67b8476f94d90604706da0a7d340"),
        fee_recipient:    ExecutionAddress.fromHex("0x799d176d73d5d6d54d66941ad6cef8208677371c"),
        state_root:       Eth2Digest.fromHex("0x07e626b9c44b0ff14586d17acf79cb136ccc5d37fd7135da33cec516af168f43"),
        receipts_root:    Eth2Digest.fromHex("0xb8b100bc5c155fe6358b9a16756ec06880365f5fe89124cf9fea963e26d3770f"),
        logs_bloom:       BloomLogs.fromHex("0xc314d3d6ab41a3fce7433dc286ee5c9820d883ff572ee7dfd2f4ee745f11a71f6dbe142d8c14bd6cc76782f1bb2b3770e65a929b2187581956bad937907a124c92ba10686763ddc87ba5b4a4e9cf4b9a35255fad5f54b404aeed5ad9859b5f9fd3c137e9eb6ef394a10b8ad3fbba75ba38c2cbfb91fa793ac763e8cd31481fbecef02b3365b990f5120a2970f2779574c60769347ae334a9f39bb3d3ad35182f7dcd252bfe9663c4f54b44dea8d79e3bcd89877231e81a9e9f5c1eaf5da1f56ffc39c23fc3ae6c130281c792a31e7a60115d46abbe17807cd120038631ca7a6636c8c644b57719e386cc8ada32ce806f75110ad143522fb0b240213df4bab07e"),
        prev_randao:      Eth2Digest.fromHex("0x17e445793c0e354ee43381ded194220ebd87ccbacef83e3da5a1cd3c8c57bf49"),
        block_number:     5728529601694960312'u64,
        gas_limit:        9410734351409376782'u64,
        gas_used:         16470261240710401393'u64,
        timestamp:        8811957812590656903'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[95'u8, 124'u8, 151'u8, 79'u8, 76'u8, 171'u8, 74'u8, 213'u8, 207'u8, 202'u8, 63'u8, 2'u8, 182'u8, 32'u8, 115'u8, 65'u8, 90'u8, 186'u8, 34'u8, 63'u8, 241'u8, 191'u8, 88'u8, 10'u8, 197'u8, 52'u8, 33'u8, 98'u8, 78'u8, 210'u8]),
        base_fee_per_gas: UInt256.fromHex("0x3c1ba8cf82268c828c1a7f249328741ae21f35a7659365efd7496df94dbb85e9"),
        block_hash:       Eth2Digest.fromHex("0xc2b2bc39ed0cf5764800d3c91401828ed32d0eea58f9d336c32f9e6f7200ac8d"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 802141'u64, validator_index: 7520769587588158114'u64, address: ExecutionAddress.fromHex("0xce1fcedcc47b22d7e38f76c1cba49c2c20da09eb"), amount: 5845756482608800263'u64.Gwei),
          capella.Withdrawal(index: 4169028257817284566'u64, validator_index: 496485'u64, address: ExecutionAddress.fromHex("0xf99805deece4ff418b55557b45060e88035f755a"), amount: 4870783513883486430'u64.Gwei),
          capella.Withdrawal(index: 10410265605811982468'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0x31e886453fa4e7fcec6ce6094ad22950637d41a1"), amount: 157748'u64.Gwei),
          capella.Withdrawal(index: 10622085591419415519'u64, validator_index: 8179967808007927229'u64, address: ExecutionAddress.fromHex("0x03d2493395b71bb181db626a99c24dbc1d07065f"), amount: 18446744073709551615'u64.Gwei),
        ]),
        blob_gas_used:    14543409578714974146'u64,
        excess_blob_gas:  0
      ),
      (deneb.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x86d7b430f69b215ab5ae863998ce41f01a5016376c8bec7f5b7a6e16a2326d92"),
        fee_recipient:    ExecutionAddress.fromHex("0x73068946d757f5d145a38fe9de817b8b1e9d6c43"),
        state_root:       Eth2Digest.fromHex("0x312b4af4d3ca5960dda2f99531819f5c32624753cc0756c05d242f65dd605d92"),
        receipts_root:    Eth2Digest.fromHex("0xf3a1e8f784ee4bdb897d1511ce642276e2ecbc1f21bfde9caf7c4479b7fdf902"),
        logs_bloom:       BloomLogs.fromHex("0x633d228aa8b2b9f4b614c4b7c7aca616232d61bc6e06ca28f4b94bc39165cf3ca2e090cebbe8a5b66b161d92e65099503327f9f2adae6ec5a73463063a994d73f37e12caec8f6d439be7520b48b25ccfa8ff64e6884b7e240c8dfd0100a23f9f644da13f1628d989eef92806c9f936a71f470d710653355acd84fb23ff15910f1d2866d83b036246c46a681e762b9a19e72aab21b428c4710511d0a39cc5ec39ebf3aecb5c19096ab32135a629abc8cdec39b2b3631bf4e86bbfb824276fd728bef454ed981e5f9e8a4bb96b27f09f661c5c221f63a26945174162496496c9bbf38cd894c50fa69df0a8c722ab48d75044bf43468639ae9b61d0b5a2f9d819eb"),
        prev_randao:      Eth2Digest.fromHex("0x3a0689ac32c82a6b84d3230fdc6e2c1e89671fa3906336ccde9fb7cfd1811ac8"),
        block_number:     9465334901279616671'u64,
        gas_limit:        17844363972830076325'u64,
        gas_used:         9534663249377184661'u64,
        timestamp:        15490999633909732541'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[199'u8]),
        base_fee_per_gas: UInt256.fromHex("0x9fc9f32819a67c4aebae259b0648e2b82f526ce8eef8fee33961f9fc69653b2b"),
        block_hash:       Eth2Digest.fromHex("0x1ac3f16da76520977c5e5d86f0c261d76e18413c202e8a46241951b3a80ca601"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[223'u8, 37'u8, 18'u8, 125'u8, 208'u8, 57'u8, 114'u8, 113'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[137'u8, 181'u8, 143'u8, 219'u8, 145'u8, 77'u8, 39'u8, 126'u8, 173'u8, 30'u8, 59'u8, 70'u8, 205'u8, 51'u8, 16'u8, 213'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 0'u64, validator_index: 7432737887980948854'u64, address: ExecutionAddress.fromHex("0x1a99860ddeecae3195a051bc0a0fcc37d0135e37"), amount: 921585'u64.Gwei),
          capella.Withdrawal(index: 8891974894683849035'u64, validator_index: 18060634568259374245'u64, address: ExecutionAddress.fromHex("0x53a6cc4c3996f0181cfe62be861900f56cb75a87"), amount: 235145'u64.Gwei),
          capella.Withdrawal(index: 11531749110606308043'u64, validator_index: 9858359378531619375'u64, address: ExecutionAddress.fromHex("0x6b7a4bc00868b077f1c4aa53369e893162bcc384"), amount: 18446744073709551615'u64.Gwei),
          capella.Withdrawal(index: 530041'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0x4b7853973d34b1efe7722be5c688589b49c1aaa9"), amount: 18446744073709551615'u64.Gwei),
        ]),
        blob_gas_used:    9156166815001018661'u64,
        excess_blob_gas:  13354810927429053716'u64
      ),
      (deneb.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xc51bf481df9be981c6656081e3854ffcf27551e2b4fdaed4ab12b355f247f4e1"),
        fee_recipient:    ExecutionAddress.fromHex("0xd79098c25eed05c9f6d55e95f5f6f58c1472fb28"),
        state_root:       Eth2Digest.fromHex("0x1a6b1eb78e5ac155d4be247a3b48d8d8d8574a16fa846681553037629b97ffd0"),
        receipts_root:    Eth2Digest.fromHex("0x5e44d4a3621cd8e495edc0b208f977c8d3f8e79a78fa7ecfc4a0f6e436f67b71"),
        logs_bloom:       BloomLogs.fromHex("0xe2b0dcfd2341ceb9c4edbc7115dbd6ed5f1c54ca39bee191fdaaa34368acee93f48561094dd23a3985ea2c2b83d918ba9dc671cde7732a591b4f9abd2eacf9d6416ca8c8d556052a98df2cffdbb086315585004c51c76872a06cee7d318f4845c0ade4c907c7933d4d883bcc586885be04ca9149e05b1624856e69e1efe8c93cd55d840bf71279293a118d51d4391fcbf4e6abe6ee50492ff2de085069a3c7656eb3a749d6bf46f56a2acd93a6840eb78e09a42f23fdea69bfbf017f4fd6b4a8d17df1aa5147c1897fe5fda1f5e79121f2fefef97117e7871d1cbf5b0b0350b9fc497c5aba27cbc129d452d6a60effb76e08b890d0bb856115fcfe3966359fda"),
        prev_randao:      Eth2Digest.fromHex("0xcd6fd69596cdd7df95e0b68e8ade01541b12ed15caa2b59803a4c4e6791870d4"),
        block_number:     12264963829660560313'u64,
        gas_limit:        11775806146734810959'u64,
        gas_used:         1863395589678049593'u64,
        timestamp:        5625804670695895441'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[183'u8]),
        base_fee_per_gas: UInt256.fromHex("0x1443705192ff4dc1a819be4f22b8dcd6e7802337e62082880b1090f44a27d0e2"),
        block_hash:       Eth2Digest.fromHex("0x68da52444eb5322f3a0bda6bdc9a3a11a540dbd22026bb2d24862bbc32af9460"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[212'u8, 80'u8, 176'u8, 133'u8, 132'u8, 119'u8, 233'u8, 131'u8, 195'u8, 118'u8, 54'u8, 94'u8, 129'u8, 206'u8, 47'u8, 107'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[231'u8, 31'u8, 192'u8, 94'u8, 136'u8, 120'u8, 228'u8, 222'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[114'u8, 23'u8, 239'u8, 220'u8, 169'u8, 188'u8, 213'u8, 179'u8, 223'u8, 129'u8, 189'u8, 50'u8, 158'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 18446744073709551615'u64, validator_index: 109465'u64, address: ExecutionAddress.fromHex("0x30376c1737df493e34318acb7efa0aadd3d78738"), amount: 419309'u64.Gwei),
          capella.Withdrawal(index: 3744271566165938073'u64, validator_index: 162930'u64, address: ExecutionAddress.fromHex("0x9a3eee4729cf5ef57a1c4aeb474636461991270a"), amount: 9043308530560640624'u64.Gwei),
          capella.Withdrawal(index: 10893292846301120513'u64, validator_index: 15952780188276928656'u64, address: ExecutionAddress.fromHex("0xfccc1279aa3dde74ea08b699fecb4481c777f259"), amount: 5614376920521492084'u64.Gwei),
          capella.Withdrawal(index: 18446744073709551615'u64, validator_index: 2895353066704396409'u64, address: ExecutionAddress.fromHex("0x7e8b34a029236dc0d15db19153165d1eccab05a8"), amount: 3749025806369957542'u64.Gwei),
        ]),
        blob_gas_used:    0,
        excess_blob_gas:  1597862542620394734'u64
      ),
      (deneb.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x8b3e7e8d447527b9d00693389928260e7ea9da6855efd99369182bd9c213988a"),
        fee_recipient:    ExecutionAddress.fromHex("0xb45716c9aeddeb030c0b94202fcb97bd75a039b6"),
        state_root:       Eth2Digest.fromHex("0x8114b285e5f3277c04a66e660fef3b86295d6ca859dfa216df3309c0a7242f2d"),
        receipts_root:    Eth2Digest.fromHex("0x2a3ff38541ef83faad176c3c98ceb5c55622dec83fbfc5a19bdb27646849e852"),
        logs_bloom:       BloomLogs.fromHex("0x384a9b3d38d343af68d00c229e79aa31f2059e17c655f5e48d31d2b59b769660e91c1e5f386e4f7dc83f2570029a6f2b3351623fcb4dadd6b5b7b26e27de19e248ebd970a9678b69403ea8e16fe88562959586fcfdee3c407fcf623c94891a2270ba1829bf2ab77fa32913bb11c8a4a69e9baa6544ad336253637626b16d4a98884e7ac7d6c1e697a9435b1e5403b5122eebddec9c03c8a6c8fed0d8877888371e133fb837d33f073375f7e1536abf622610734b9b0aced8a891f02d5b35734e58b0ead66c49ed9f898b8f27e9415275c5d15051ec00cb006f8aef702a7414aefacfa9742cd3d8d34be817e0c731696e20b973cf2da66799121c0c6d12bc835d"),
        prev_randao:      Eth2Digest.fromHex("0x3bd54c7151dae2ad524b4df0d4283e3641ba787fc76f54221dba3a2aa556a1bb"),
        block_number:     18446744073709551615'u64,
        gas_limit:        637978774023867007'u64,
        gas_used:         15110835166938431016'u64,
        timestamp:        18065456863038184935'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[235'u8, 229'u8, 162'u8, 249'u8, 154'u8, 135'u8]),
        base_fee_per_gas: UInt256.fromHex("0xbe93cc3dc2bb7e012db659df49e57653bf6ff21354c64eeb69c0002e9f933035"),
        block_hash:       Eth2Digest.fromHex("0x46cb3f590b2fbce372e67968a0d2ff4ce1b2c530fcc26b7a24ed6db054f52035"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[16'u8, 66'u8, 215'u8, 40'u8, 223'u8, 195'u8, 43'u8, 228'u8, 225'u8, 244'u8, 34'u8, 14'u8, 117'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[92'u8, 46'u8, 215'u8, 218'u8, 71'u8, 99'u8, 115'u8, 119'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[]),
        blob_gas_used:    1,
        excess_blob_gas:  1
      ),
      (deneb.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xa4854e346d2e9a921cc6b3c4ce9fc739c99795cf10002924089f9886f8624d59"),
        fee_recipient:    ExecutionAddress.fromHex("0xa88781cf69a1eed63bcc3a32b6f9aba35d4f5b5e"),
        state_root:       Eth2Digest.fromHex("0xdc06d9210fd2738b0fa9df6d68e4ffbfef0dd7d7d8093fdbcd97ff845318cf6b"),
        receipts_root:    Eth2Digest.fromHex("0xfe1b70c143066edc444f9b49e778cf6db0060bd4e9122564350cf23061830439"),
        logs_bloom:       BloomLogs.fromHex("0x095a57c3f2d97aad8692cd09dfdd8388f1bf9ef98a1c3223ecfd0aed17d8c7c3ef593d7f09ba86500644deaa676df811da501d572f342e3f7ee7b9b081992f344f71fa50b3b9635d7375f67dbd85a0b1ade3d8d4778118df55b90c44f7dd1114f2ebcea5778b32701ef94af9b3713d1fe00275e09c7e918d7c529a37aa9de3464eb6364812ec486464ccbf7df2523369fdeb1b28955e35e8685c16f07fbe342edd1bc044021ed480bf4ceffefb13eaf4550c67ef8a5079f3f612f07fff60193eda6ac11d39f3056c41ea4355ef5ef7f311493c415cc8c42cb30a73dd58098262acebe6d901e4bae26b6e1eba693c7dc596ea27b0cdd4fee2f6450ca8b50b1a70"),
        prev_randao:      Eth2Digest.fromHex("0xc52844ad11072faa2222ffe9cbff77dcc7f681367d2aef5f1c3b206140064195"),
        block_number:     767785029239287422'u64,
        gas_limit:        15062566578072747104'u64,
        gas_used:         7648884410596067087'u64,
        timestamp:        4380084205540210041'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[217'u8, 40'u8, 125'u8, 94'u8, 156'u8, 71'u8, 79'u8, 66'u8, 117'u8, 228'u8, 173'u8, 189'u8, 115'u8, 41'u8, 153'u8, 226'u8, 130'u8, 21'u8, 108'u8, 194'u8, 206'u8, 218'u8, 141'u8]),
        base_fee_per_gas: UInt256.fromHex("0x436767990abff9288346859c6b85b8a972421619eab2253483385c8151cb2016"),
        block_hash:       Eth2Digest.fromHex("0xca4f05c33836d82aee8230ef660016b993bca4aaf9a7b6cad96c2a0193eb026c"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[156'u8, 143'u8, 203'u8, 250'u8, 238'u8, 137'u8, 34'u8, 245'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[64'u8, 44'u8, 165'u8, 9'u8, 1'u8, 211'u8, 27'u8, 108'u8, 166'u8, 61'u8, 119'u8, 11'u8, 222'u8, 85'u8, 48'u8, 185'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[165'u8, 95'u8, 221'u8, 213'u8, 229'u8, 134'u8, 185'u8, 221'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 373208'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0x1ef66a8127bdbf1302c13af1b2a3fde17f1e421e"), amount: 12972917955689502470'u64.Gwei),
          capella.Withdrawal(index: 7007268656739027478'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0xca30e17b5a7925b1a5afa06710d6cffb4681d2fb"), amount: 13141021224557402822'u64.Gwei),
          capella.Withdrawal(index: 10730268187610256048'u64, validator_index: 7483561449283560970'u64, address: ExecutionAddress.fromHex("0x84e755db228c9399912364a239227c467477e076"), amount: 16091384671148001130'u64.Gwei),
          capella.Withdrawal(index: 861292'u64, validator_index: 101133'u64, address: ExecutionAddress.fromHex("0x70e7126e6288dd8559b6bf8946b98fe02bc53e8f"), amount: 5439105246644982514'u64.Gwei),
        ]),
        blob_gas_used:    2533380168586417970'u64,
        excess_blob_gas:  307516487526704997'u64
      ),
      (deneb.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x5e7b12465e0461e5dfa59a3254282378c55961b0e411023ce89d968bbdc33e9c"),
        fee_recipient:    ExecutionAddress.fromHex("0xbd1a1396ab49631cc933770944996b294da97d43"),
        state_root:       Eth2Digest.fromHex("0x74e6ccfb15da8afb94eebf28cb3ba3f9ce63e3354097f2f2527fe1cf978e76bf"),
        receipts_root:    Eth2Digest.fromHex("0x8e48bee56e149d1851cff0740ceab06767bd0e819261c5a2f75dbea382a110b6"),
        logs_bloom:       BloomLogs.fromHex("0x7894fbe58c624a153dbb160c516c9e82bd0cacf5f347f984efcca9450e9a20b50e058ed38e41c331df61114086f8a6b8a049467d7dafd812953aa593b2e9fbc056f0dba80973b2eaae8814b5e0804300eeea15613e59c8d34339f58e1b45599361497a3608c05140cf432e7983a30985aa0faf45dff56dce99eaa5ad3418722df17eaaa4e8df25ed1d9eedee1390e6440c4c37675182dcc07ff199d6dd015d3aa03194765e85fc0d4759d3c693fc2550e50835b88ba41d10fc33b58550d813abaa75bab39c0fbe419f1bde8fb82db9fcfb79894faeed84b2314f115a8fb9e276315ccbfb8e9650571add358f594ff2fb4ab9661afde76081bb2cfbfd2f26d212"),
        prev_randao:      Eth2Digest.fromHex("0xb9a9bce05e42cf3d2ffc2c2ea95164c9b215fc8e440dd2985ca24cff40e32780"),
        block_number:     14460352585391846826'u64,
        gas_limit:        2426408612341958329'u64,
        gas_used:         13656152006197676019'u64,
        timestamp:        6263571560389404595'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[177'u8, 36'u8, 79'u8, 26'u8, 164'u8, 59'u8, 182'u8, 88'u8, 223'u8, 22'u8, 79'u8, 197'u8, 109'u8, 53'u8, 53'u8, 134'u8, 244'u8, 84'u8, 146'u8, 158'u8, 234'u8, 252'u8, 188'u8, 175'u8, 69'u8, 51'u8, 118'u8, 101'u8, 242'u8, 0'u8, 51'u8, 103'u8]),
        base_fee_per_gas: UInt256.fromHex("0x997e6c8ffbd1ea95e875612109843c6cdfd0c6bcaffa1e06ba303b3012b3c371"),
        block_hash:       Eth2Digest.fromHex("0x9a7f83cf6a64e153fc3316244fabd972a49ebf5dfb173d7e611bf3447a175c41"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[137'u8, 103'u8, 164'u8, 112'u8, 136'u8, 91'u8, 170'u8, 241'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 12452742873210027116'u64, validator_index: 163643'u64, address: ExecutionAddress.fromHex("0x5d09dd69d2b2370e11b21d758bc82c2a73ee00d0"), amount: 12246034467900494037'u64.Gwei),
          capella.Withdrawal(index: 256915780184525584'u64, validator_index: 364410'u64, address: ExecutionAddress.fromHex("0x40a55ad4a156caf112e2abe789554520814e48a1"), amount: 297315'u64.Gwei),
        ]),
        blob_gas_used:    3541847679255581458'u64,
        excess_blob_gas:  1
      ),
      (deneb.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xa8f90a617f1f230506d200c6026bd60e38f599930ed04f90cdc320a6d45bb022"),
        fee_recipient:    ExecutionAddress.fromHex("0x3531157eaf2c185bd8720f3edfaf76829632f07d"),
        state_root:       Eth2Digest.fromHex("0xa16f8936e945ecd45a4ae107e46acd8530e438fa1bc8eb85aef62afaca1656da"),
        receipts_root:    Eth2Digest.fromHex("0x3e76522c8f3b7e8d8a63f4968ab15413b8bbd7af9782c4878b52213b0b3d13f8"),
        logs_bloom:       BloomLogs.fromHex("0xc13b59de763feaa39debf70d280364ec68eb578af8a90aba7e2cf3a6cee413a28836c674662a0283df8ff04964eb928de97a3883226950b584d773c9b4479d6d5bda6fd71951c0c846752ed688e13dccff947b7a6c81bfac198b6bf785bca7be28bcf9a208b983afe6e766b0536311c1c12b4d01c712cdaa167ecec5520395068b1c1f939d20962de1aba36454cdb36031fa0ba886a8ece71234654e8b081562452046a388ebcf3cfd975493833ff4e146d5e5ddb061d994461ab8b468cf1d6d491d78fd8923f9f6563e3fbfa72639de993701ff6214fd83cd3597e870dec1c1e788a4f01f881c48e57b07c5a217132658208d2221a86c7e9823159984d235b5"),
        prev_randao:      Eth2Digest.fromHex("0xbac4a9aa16b289584d13abe3c47a58dda713c4b479ee70e1ac7b3b698e8505af"),
        block_number:     4839752353493107669'u64,
        gas_limit:        4713453319947764960'u64,
        gas_used:         3470256075652600568'u64,
        timestamp:        13764471837770950237'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[60'u8, 109'u8, 153'u8, 55'u8, 17'u8, 196'u8, 17'u8, 96'u8, 202'u8, 173'u8, 16'u8, 189'u8, 165'u8, 107'u8, 68'u8, 230'u8, 238'u8, 62'u8, 199'u8, 211'u8, 244'u8, 83'u8, 88'u8]),
        base_fee_per_gas: UInt256.fromHex("0x3adad83f48e34c6220dce41ecc0b09f9bb1ae4bda4466935c70e7c6cd54e185e"),
        block_hash:       Eth2Digest.fromHex("0x9183524f908425608c1e3a80d7c4ac2c539903af4b3a2f1b22c3283281706aba"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 645596'u64, validator_index: 248698'u64, address: ExecutionAddress.fromHex("0x124e32ea8d0363647a58a5511b6de35bdd50236e"), amount: 18446744073709551615'u64.Gwei),
        ]),
        blob_gas_used:    3410596457491766161'u64,
        excess_blob_gas:  0
      ),
      (deneb.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xc914f63464f3f1588a32d3751900d415bbf1fe002c42068650f5c7c588b1935c"),
        fee_recipient:    ExecutionAddress.fromHex("0x61523b6add59cc65d3c5b75c6f749fa601e157de"),
        state_root:       Eth2Digest.fromHex("0xe84ecb995f6c7e753355c8d2e24694441c528b65ef9b1d8c6f4e9d98d409342b"),
        receipts_root:    Eth2Digest.fromHex("0x887bdafa340c24acb58f36a7e3825ce39fb7e0caaba3a9b63f78d2186cc6994a"),
        logs_bloom:       BloomLogs.fromHex("0x1fbd358ad7e32eefe4489b6c72bafcf6dbac109970e5c103e329279cede3619faf1309faf266ba155496c19565b31562f31539c98b6256919d8950bb6eca937401d91fa5b3032b4400ce6dd60a8c1c6cc94331b7e78d7a350ebb5d6e04a2594af981f167a89227c7c902dbb8eac3d7b54177d85214a6ef57b50da82b6420cf914fd63171f0b7dff9233bfaa2069774b142a136c5183ed4f57cde2590735b19ef549ff5bc910477b98344e7557ffc440b03d56842f356a6e223fd052c6272e24f43dc9e64055c097d81b56ecfd6087238602a743e09c383ad4eae6ef449570febdfebfefa347f06f480f319ff06365bbfae16b62a950143f9acc3663510356f0c"),
        prev_randao:      Eth2Digest.fromHex("0xc755584f86084ab2e62bd58f25dfe54538c0171e6447e7e1a51cf05db94377da"),
        block_number:     9276126375553452674'u64,
        gas_limit:        9007257403963034102'u64,
        gas_used:         12806310385580231715'u64,
        timestamp:        9957937708118639445'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[]),
        base_fee_per_gas: UInt256.fromHex("0xe2df33500d1162994934e9fa65fd5db641b0be2b61a6c302c7b9019f86042338"),
        block_hash:       Eth2Digest.fromHex("0xce58ef51926a6eb4cf2997c4ec771b54907737ae8fe9522fc316c97a1c7ee6d7"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 16986670237072862757'u64, validator_index: 701065'u64, address: ExecutionAddress.fromHex("0x50371592a27339f868b9ef63f6c02e8c1e72ce94"), amount: 3561319411833205205'u64.Gwei),
          capella.Withdrawal(index: 2402770018709110103'u64, validator_index: 798632'u64, address: ExecutionAddress.fromHex("0x9d42c6c10cbc0b04e3f2e74f63c777802d4ca064"), amount: 898967'u64.Gwei),
          capella.Withdrawal(index: 944680'u64, validator_index: 507423'u64, address: ExecutionAddress.fromHex("0x640d578aeed6b8a9acc83f13343f3139fe8f4a15"), amount: 941781'u64.Gwei),
        ]),
        blob_gas_used:    15366131400223670470'u64,
        excess_blob_gas:  13352270791962864689'u64
      ),
      (deneb.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x086322b79160568c7d096747ef351338ddc93f252dab1df3ef65aaf24723d2c3"),
        fee_recipient:    ExecutionAddress.fromHex("0x03c6998b5a3ff1c98538c2333d279f2b1cc59f7f"),
        state_root:       Eth2Digest.fromHex("0x446d99a7e9fd2c327fbd445dbfb3b3e3a895cdfa6f208496dd09c0f84f7ac0fd"),
        receipts_root:    Eth2Digest.fromHex("0xf4c74d5c59c46f1d9f916b32d8a12939cc2a379bae83153137de76415f6e5afe"),
        logs_bloom:       BloomLogs.fromHex("0x40f87c3729ba599c3e9bb749c48148ee0d5563db71cf0daaad3af95c45622d7b2a64204157a92a93cf0ffbe0052fb79eef83ba8389fe9d9e7646874b0636960e4eee86eeca00ba70f65b2046620264b795852def9beebb671f841e19ce07934b7c2f66301cc3c7dfa2606067cdeb04a564b87e56ff3650c7c6bbbc96b2de5ccf8e314ae74a26347371c315062532a1f1a2fe0c417ed5d12b6f81c3440c0d8b19d0cf8a030be83ee7ada6046d75098b6ee66664ead786a65ef5cdcb33c4634aa07cd7490abc0ea9ce722423a0cba1aecb379552e89483de43dd321cdaa8a005ab7e8e2a958038ca12e2b08709348a7f6daf34c488add1a0a21aed0da0b64251f9"),
        prev_randao:      Eth2Digest.fromHex("0x2ff08bd0b22bae8c3627f61b8da627fc367b3a60f93dbe48de1ca6f25ada489b"),
        block_number:     10605470807350562909'u64,
        gas_limit:        587854351728657338'u64,
        gas_used:         8799032544585725320'u64,
        timestamp:        18028498231539883963'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[]),
        base_fee_per_gas: UInt256.fromHex("0xfbe348f0c77be2ddbd3ec038e3aad88107625dc6e96b1fb3bbfdba8c737a3d7e"),
        block_hash:       Eth2Digest.fromHex("0xc545e833aa2ee5d708e041f4dcb44bda654372b3f5f660c683d12230303da729"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[89'u8, 59'u8, 131'u8, 146'u8, 186'u8, 180'u8, 208'u8, 76'u8, 69'u8, 40'u8, 29'u8, 211'u8, 97'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[208'u8, 136'u8, 157'u8, 0'u8, 120'u8, 231'u8, 99'u8, 33'u8, 31'u8, 210'u8, 80'u8, 203'u8, 24'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 225873861246030158'u64, validator_index: 3132710425326779052'u64, address: ExecutionAddress.fromHex("0x4d2573288e7949201c806877449e441801ba62c5"), amount: 9096383177302198854'u64.Gwei),
          capella.Withdrawal(index: 2816791477401799195'u64, validator_index: 12199871733060832130'u64, address: ExecutionAddress.fromHex("0xd4e21e668d5e8b1c097cb250dc862bfd7f8a2b76"), amount: 7278220627858832735'u64.Gwei),
          capella.Withdrawal(index: 12003547154719720523'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0xe888b3288bfaf8f979c93699cbabef6c1f156f19"), amount: 18446744073709551615'u64.Gwei),
        ]),
        blob_gas_used:    0,
        excess_blob_gas:  1233408100755176706'u64
      ),
      (deneb.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xcfba7f4aa4ff01d3d9de84dbe1761c79627a10c3188fb0a7c8adfa0d489e6441"),
        fee_recipient:    ExecutionAddress.fromHex("0x106b3bcaae4ff58dd837768be35c29c48571e4a4"),
        state_root:       Eth2Digest.fromHex("0xe6242399020361e70cb6b89701001fa8326251e6bae3b4ca1978eded8831d9a7"),
        receipts_root:    Eth2Digest.fromHex("0x3db0f9a05cc39be94414c3be28378d2b91ba3ff43ea2ea7e4e0a1874a0983f58"),
        logs_bloom:       BloomLogs.fromHex("0xd591169a3cc38e0837a76c4d7057f94c1ef08ad5af1778b1b06c3a0ec85201bfc659b18c49de831ce6b4a40f0d2800a9cc9001f74810c58473f9b973b720f84626cc9270b0428439b985043f5d9c3289ef8a794f5b8265e10e9fb9fa53a93887d270b8204f8f16cd968e295b0a06aa70e9f6f174733d251f3bfc644a7fb274b0138729f18c0e4382bd4bf0387870f633ed897a125ca854120c2885194f3180af4b62760db96da51f88ae1cd222f49b00fbbc1544eb0e98cea67e36368816f541723158d3691f3cf1509c65a51a8e68efb66c500dd6516ca1b02aeb4e0c13cf5bbead53672fb5a7a1863c8edfaf4eb9a4b4322a39d8643528bccf22493914fa01"),
        prev_randao:      Eth2Digest.fromHex("0x14fec0a1edb9c82dc9aa7fb7224791c51a3937e74e5da59646123867496460f2"),
        block_number:     6272046003849350913'u64,
        gas_limit:        15423951135645467684'u64,
        gas_used:         3743939155619454195'u64,
        timestamp:        8496536260448579184'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[152'u8]),
        base_fee_per_gas: UInt256.fromHex("0xd8b104041bdc4c76a9735e2b4b45f0f3612e8962f672aaf511f06a94b48562c8"),
        block_hash:       Eth2Digest.fromHex("0x8ca67fec04b7e3bc5a01f5bb265b93b4488b58ec2ac7f2c3ced030311de2762e"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[152'u8, 232'u8, 136'u8, 228'u8, 253'u8, 248'u8, 85'u8, 92'u8, 103'u8, 38'u8, 106'u8, 166'u8, 148'u8, 8'u8, 37'u8, 245'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[58'u8, 215'u8, 97'u8, 99'u8, 152'u8, 126'u8, 14'u8, 252'u8, 64'u8, 87'u8, 242'u8, 60'u8, 210'u8, 217'u8, 75'u8, 189'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 18405055677765556765'u64, validator_index: 13513833286292305941'u64, address: ExecutionAddress.fromHex("0xfe53af2bf3560b2157a683a545d4f898354f4d55"), amount: 911502'u64.Gwei),
        ]),
        blob_gas_used:    11215270247452431947'u64,
        excess_blob_gas:  0
      ),
      (deneb.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x063bc56b731eeeff8bf1c33d88523a04a14fa0c745eb3c750139842d88244982"),
        fee_recipient:    ExecutionAddress.fromHex("0x415b1cd5b42709a3724ab2f6f50a6dab7399d7ca"),
        state_root:       Eth2Digest.fromHex("0xf261abf37066b8dc5c868946346c98aae445adbb48e6dd05969fbb49267a276e"),
        receipts_root:    Eth2Digest.fromHex("0x5a337b7ee29d98e22b461f43b7a87e52d89fda2e7a3487ea92873be04a49ea68"),
        logs_bloom:       BloomLogs.fromHex("0x01817fd642526acdd8b57b4fc2fb58aba269095ce220ae5770004055f550918778021eae3abeffff1b3fa9fba50ff8d532fd8e2e67da7bdcca1cf9505179f19f595f5d9f09b98d5bc7d1ecb22527255e8e161ca2124c5fedbb59527f91a242671177e33a6fa377d585ebdbd6d9ff2bf80bec3695657441e35da43861f14b9a7e65ed475c323ece62d84aed7262cf3fd2b06ba03695e2e26e5e58fc5b8b99d519fda879587e3764930e3921aa15b2ee8691ea0e738030acb8832ca353d3bb63fbc0150c532b842cd053abeae8238c9ffe6f4b2b7210dc862c48843ae2a9088ecdb8c258592a0feb5215b8c9ad494ad896379d86e0ac89e6cd8765003ac5c95cce"),
        prev_randao:      Eth2Digest.fromHex("0xb28f434f3f40e40693b0c1726a018e2b3bc13c41608a2ca71aa5c8bf61829287"),
        block_number:     14597257287993827247'u64,
        gas_limit:        9090926713872599867'u64,
        gas_used:         17391976671717618186'u64,
        timestamp:        13439825139187707720'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[73'u8, 163'u8, 138'u8, 201'u8, 62'u8, 1'u8, 37'u8, 90'u8, 157'u8]),
        base_fee_per_gas: UInt256.fromHex("0x8a42339ef76757729ef6c4536b3b59255b18d7085d8ba786275b2076fc55b3c6"),
        block_hash:       Eth2Digest.fromHex("0xb3f6ec11b285a105833f5b68b67e8e23c85c28df2362a13a76db705f110fce8c"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 5477557954669138518'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0x4b840b26a19377c64b870be600aa336a40ae46ed"), amount: 42381'u64.Gwei),
          capella.Withdrawal(index: 0'u64, validator_index: 1'u64, address: ExecutionAddress.fromHex("0x3d22a723824a2944ea9accc8653002bf7d61a10a"), amount: 2799163561369818755'u64.Gwei),
        ]),
        blob_gas_used:    69111814634726666'u64,
        excess_blob_gas:  10785611890433610477'u64
      ),
      (deneb.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xb31c41d39ef7e9a9b905cc93d82264415024d7daef48d886f1b3bc0fd6545edb"),
        fee_recipient:    ExecutionAddress.fromHex("0x5ad4b6c0d6b986e775f3a9ae2be73a330ba9f87c"),
        state_root:       Eth2Digest.fromHex("0x01dbc857a3d8994cf10cd1be3b2018be0e26ba54a5456e10a6e5729328a0b5f5"),
        receipts_root:    Eth2Digest.fromHex("0xa51e9cb9893bd7d73a8fd4e5267d80ddcb29d998814cfa9980dbae50ef101aff"),
        logs_bloom:       BloomLogs.fromHex("0xf1280db0ef6bb796e70dfef3b0bafa62690ef1e8f14a237856bae5dbe29dfd43ac789c53305ab5b0b7cc48ed53d1236ab9433a5352dac55b6e0a3ff90e9e815e2ce16fe5574c87f0066090c39b811996e2974da0bdb8bb59eb044bbb6bc2d7f8241093c7143a7c9892be85ea4284258ea2477f6a677d424efb6469724d641bbdc3f9254529b6af5cc5f5a77dad49c1a59ae37c19ffc69f6e331139b6ebac306ea09460dc0fc5791ef2cfb9e7bf29d662872e30b94384be90416df03bef5cf5a2339af4745f2f620fd1320d3fb79848692719cb8956b8efd427c9c0cc3ea6efb8f84feae0075ed10ec5c6243074e6004849712d8d1dd97ebb2948fcdf1d020c6e"),
        prev_randao:      Eth2Digest.fromHex("0xc8a27f0b7850de04e3d794b9e9d4f144c356f864401c3f802927faf4b88b47ac"),
        block_number:     10821099926525463598'u64,
        gas_limit:        7115919978619568727'u64,
        gas_used:         1,
        timestamp:        5900615379943209755'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[56'u8, 176'u8, 67'u8, 30'u8, 11'u8, 27'u8, 136'u8, 121'u8, 86'u8, 17'u8, 4'u8, 121'u8, 11'u8, 222'u8, 158'u8, 78'u8, 56'u8, 66'u8, 243'u8]),
        base_fee_per_gas: UInt256.fromHex("0xfbaacdba879288838ff725df19b7a31148ec5a24e7989441544d6dec1c980034"),
        block_hash:       Eth2Digest.fromHex("0x04616c0808df7a1bc177bc48cb6ed865125fbbac2fa3e3c36f33a5f1c48a23fd"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 143666'u64, validator_index: 849676'u64, address: ExecutionAddress.fromHex("0xbf06178f996afec7c9d3cb488e812f32aafe4242"), amount: 18446744073709551615'u64.Gwei),
          capella.Withdrawal(index: 560588584813483246'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0x1a1b89bf52af0d4a8eff759986ffd93cf4464114"), amount: 13046900622089392610'u64.Gwei),
        ]),
        blob_gas_used:    1,
        excess_blob_gas:  10155937412879977460'u64
      ),
      (deneb.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xf6cba3ced37c08da230babbf9d1e360661e5a21ac235fefa75cbe756f15809de"),
        fee_recipient:    ExecutionAddress.fromHex("0x0c080349793b7f43fb3ee9101889e7d32e02c01d"),
        state_root:       Eth2Digest.fromHex("0x6a33580fc482e9783d66bee9276f42b74a2cbc2b7434fc408a6ba9df77db0ceb"),
        receipts_root:    Eth2Digest.fromHex("0xd896daff74ffd6ffcc088adba01aea52af82d861b7ff649265a750e5995dcf31"),
        logs_bloom:       BloomLogs.fromHex("0xec00c3385b735b6a4088ed066bdb088e7826a2830fd13a1a1525c4590eb08baeba81bb511bbf2db2c0547c69c10b5c6c1bf5c8e5a7931584e6ed8ed7357431e1e2391fc0e61a060baf8984a6fd5c04c68fe0f28f94281d0db663b1b2fdaad9b51d3a12bb9fba255c923dea5ce45dd68ec2c5afc9fd13a0e24d234a3c8c5f255e7d62d48a8e01fb5c1eaf0c7a68a616ac935416fe3332943d78eb28a48a180e2bee26e85d786583ae0609a8b98e1045738f054aa12bef97593cd16d8d795314bfff33c51b397afa2299a4a64244817e5a07cdcd75eb4c4c06e8e943d8d1db8e65f17368ab6175c3e14daad0b99fd0f1050feebadf9db8fe8f1c19ed867f4df676"),
        prev_randao:      Eth2Digest.fromHex("0xdcd37bc148c25afa7e320009ce19567108745ef5ed57781f55df1d73b707e26e"),
        block_number:     13754339262807377549'u64,
        gas_limit:        5250261236890759949'u64,
        gas_used:         1335844244115849195'u64,
        timestamp:        16758901654456753273'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[28'u8, 8'u8, 171'u8, 122'u8, 126'u8, 38'u8, 142'u8, 246'u8, 162'u8, 197'u8, 241'u8, 216'u8, 158'u8, 184'u8, 73'u8, 191'u8, 208'u8, 5'u8, 79'u8, 231'u8, 254'u8, 55'u8, 126'u8, 97'u8, 184'u8, 78'u8, 36'u8, 80'u8, 160'u8, 124'u8, 188'u8, 176'u8]),
        base_fee_per_gas: UInt256.fromHex("0x0ea1185e0ac50d1e2cc0be7229c846528380def25f7d8860cf366e6edd793be0"),
        block_hash:       Eth2Digest.fromHex("0xb471874aa6e8987deee40902d59537fed8af3e9b6ae2f8b476ddb051629b3b09"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[231'u8, 215'u8, 225'u8, 83'u8, 163'u8, 187'u8, 111'u8, 141'u8, 246'u8, 57'u8, 238'u8, 163'u8, 25'u8, 91'u8, 114'u8, 111'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[93'u8, 42'u8, 101'u8, 80'u8, 160'u8, 252'u8, 158'u8, 121'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[164'u8, 98'u8, 105'u8, 179'u8, 25'u8, 33'u8, 130'u8, 239'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 5378768050415100863'u64, validator_index: 0'u64, address: ExecutionAddress.fromHex("0x3d84c03e4c18979ee8288bd58b24989580f0a590"), amount: 815393520574223128'u64.Gwei),
          capella.Withdrawal(index: 17328504288784263137'u64, validator_index: 305278'u64, address: ExecutionAddress.fromHex("0xa00491dfbee05f23fc7ddcfcb1b27b2855334e81"), amount: 7734460020873819187'u64.Gwei),
          capella.Withdrawal(index: 0'u64, validator_index: 444647'u64, address: ExecutionAddress.fromHex("0x0689ed39160f4b4c20138f300b3b2502e6d6ab5a"), amount: 18446744073709551615'u64.Gwei),
          capella.Withdrawal(index: 834083'u64, validator_index: 10715076713456342424'u64, address: ExecutionAddress.fromHex("0x07ee24f650e7254d10d61b832db7174128bf22b4"), amount: 17794546242151296198'u64.Gwei),
        ]),
        blob_gas_used:    7080212387270627767'u64,
        excess_blob_gas:  17322910515629142083'u64
      ),
      (deneb.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x62ce6a6d68578309c4730f96f98a809d4b4225fc3d37a285daf26288b10f9590"),
        fee_recipient:    ExecutionAddress.fromHex("0x8c892b06f1e9c877c310b6eccefb20fcf5e00227"),
        state_root:       Eth2Digest.fromHex("0x578f93b83206e3239c69f51cc8e59cd89087260cda9f0efc892aa2ffb2bf386e"),
        receipts_root:    Eth2Digest.fromHex("0xa4ac657af8e0dad66ec74f4f66b246fe0089485e2810071fa556c09ea585059f"),
        logs_bloom:       BloomLogs.fromHex("0x18d67e640f9ad3a24deb7e3f8cbe0ba8224cf9cb9e67b2fd6c774fac7aa3f4adca2befe8322962cf000cb89c3e352433cf1aade51ceac9fe69966a8a89f7985030a301eb690e7eb20b5ac3b315930ee5397b6d65b03a1131b94e7f3505ef030877e460e9195b742e943716d9875a3e2e9998236d3565d622216af1721b658a12fe7d82a62619b4f2d042f146305ff1ad1bf394437340735eac9e962b3fe67597793d1151ec87fcb5f0056837c5813c75c4a0f94d91da71299b3780f250ee31eb9f106e3c443f0ba05213da05177238909fd9e60de9484e091b91dead82debc020929d1f14e79b610af3d15bf9c3757e62bb32a69523c1bd576e5c5d4bc2ef0a6"),
        prev_randao:      Eth2Digest.fromHex("0x552627eb969604e7d4ed1e631b74b2410dea7f4dbd49511bda390e3b9da8bf60"),
        block_number:     7763671958353664038'u64,
        gas_limit:        3930616259240751958'u64,
        gas_used:         7960068863134244743'u64,
        timestamp:        18446744073709551615'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[227'u8, 111'u8, 127'u8, 243'u8, 191'u8, 237'u8, 88'u8, 146'u8, 146'u8, 236'u8, 162'u8, 237'u8, 164'u8, 177'u8, 249'u8, 52'u8, 1'u8, 26'u8, 187'u8, 208'u8, 244'u8, 234'u8, 113'u8, 199'u8, 30'u8, 209'u8, 197'u8, 63'u8, 126'u8, 104'u8, 143'u8, 30'u8]),
        base_fee_per_gas: UInt256.fromHex("0x6bcd9684e1bc8f4fc5d089e0bf5fed35a8bf3039808d030bb9eb1ff7147180b5"),
        block_hash:       Eth2Digest.fromHex("0x9e2505de9f245873565b553e7215abff698bdfcee1dbd93e40eb295dd84e7f45"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[140'u8, 134'u8, 173'u8, 70'u8, 168'u8, 181'u8, 221'u8, 210'u8, 25'u8, 142'u8, 168'u8, 139'u8, 77'u8, 134'u8, 203'u8, 219'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 0'u64, validator_index: 780337'u64, address: ExecutionAddress.fromHex("0xf0ab5949e96d8befa8090fe5612d9c45beea0c8f"), amount: 2246589958612652012'u64.Gwei),
        ]),
        blob_gas_used:    0,
        excess_blob_gas:  9638659159857567769'u64
      ),
      (deneb.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x4f8251c361a23171de8648d1e96c91fea2cc5a691dcd884e3a957dc8f6a8802a"),
        fee_recipient:    ExecutionAddress.fromHex("0x7da9175abaf6e4e400e0ee516fd3ab07dd659f2a"),
        state_root:       Eth2Digest.fromHex("0x1bd3a5da4c266dd396b8209288e68be066176ebe64cd4c17c4c6cdccaf03577e"),
        receipts_root:    Eth2Digest.fromHex("0x16133c4fe31f0487e700514160acf9257458a6ee716be8043cb6c532f84ef614"),
        logs_bloom:       BloomLogs.fromHex("0x5ca3807e674d69536b33337d798deaeb9fa6c7cbab7aef1473e6a6614f6f2c74ef85ee3632612b9c1e78d2a63e0b2f58d48d71e8d62e38510bc2f307680497cb965153b43392b8aa2dcd91a766356eab3ff1b4a6c4b037d61df1a8a4c6d3fa0e3c57a299a1c0a7382052ac25c412f2d2356c302e326fa0cfb570354e31e2f8046b80e2690ba69ec7c284c2df8ad23d16764cbc0ba28516f3c31aa89da3e3286106dcecc835b3007a17f33c4962efc3c9b0f5bff14c783e414ba60d35b79ab33ccd0151c34a94efc461d0df0a994085373f33275a4cd6839603632409b670072a4554f1c9342c03cd403a6feb67b23d3a075707ca89b77bad64e24a6ab79446ad"),
        prev_randao:      Eth2Digest.fromHex("0x6353ec5b94b9112f25e66de48b532ff5610c63f34c50a02fdf64af6c9d0ef2f4"),
        block_number:     16866969889068542818'u64,
        gas_limit:        5116920640663397560'u64,
        gas_used:         13292402101416991817'u64,
        timestamp:        1,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[136'u8, 133'u8, 189'u8, 60'u8, 229'u8, 217'u8, 70'u8, 145'u8, 136'u8, 97'u8, 175'u8, 23'u8, 183'u8, 73'u8]),
        base_fee_per_gas: UInt256.fromHex("0xe1307a28a2868b4d934aefdde7bbd09b0644b5c422d2c680770775cb44623512"),
        block_hash:       Eth2Digest.fromHex("0x11e23850b143b8b4dd8394ee1f2cebf073068502d04dde00000925cf23ff55cc"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[]),
        blob_gas_used:    4954178403284176013'u64,
        excess_blob_gas:  1
      ),
      (deneb.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x0c67b44b492590ffb9e6d2a63c84714821be7526ce1c337c06276e33a62b7b93"),
        fee_recipient:    ExecutionAddress.fromHex("0x1d16dbe66ead2ba8afb8594acaf8d536be08dac3"),
        state_root:       Eth2Digest.fromHex("0xeeb40e334aff8512435b5908a8dd3c06993cadca8bc44e9a6c28c6003162c6a9"),
        receipts_root:    Eth2Digest.fromHex("0xefa5b7de19da2333bfb7bfa814a306f904fef2ff4f8b1154314649a56fea3c8d"),
        logs_bloom:       BloomLogs.fromHex("0x4ebbaff6a56343a6bc0170aca2e2ba303f3e3f972c88539ef84e402740e3c9e21c6951d461baf56eec14c06ca0e95f4921079d0d82e9dd46e73f3fa76417246217ff9c5425f19b0f8b2a735ee522c1bc377a2b079099430d0f9316164f5930456245534bbe138d0a19ee58bb13a0d724723a6fa50e39b8a7ad5804f92ab43c24782e27dbb32789408cdd716af9a0b0cb1e2f3aee0bcb5aa4088c0cf1528fad466f3d71d906649becf25f405f619dead731e0831efb522b5faee7a39ca28128effc79977816d50ae23745ab96b80dc7f548aa5d43b0d5c331fdc1ce080a4d63e19942ecb4df8f56397b2ef67d017f2d2de9296e1fd8036ed8592f5a89553c4642"),
        prev_randao:      Eth2Digest.fromHex("0x5d3c3ac25330e1cd3a516003315ed24bd2dc6cd31d389639cce4b6ae4a3ac8cf"),
        block_number:     10891095348111649307'u64,
        gas_limit:        13670668340379820434'u64,
        gas_used:         1482104080767186829'u64,
        timestamp:        6602476120092784163'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[223'u8, 228'u8, 253'u8, 3'u8, 38'u8, 218'u8, 253'u8, 87'u8, 206'u8, 243'u8, 168'u8, 113'u8]),
        base_fee_per_gas: UInt256.fromHex("0x972a01f27d586035ce5fb233118e52652ebbf89f6d39558a41b27c8840c849b1"),
        block_hash:       Eth2Digest.fromHex("0x9280fa96a569e7c25b2dfc12a141d3edd24acf2fbfa19ee72e5a1fd5dba25a11"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[116'u8, 179'u8, 195'u8, 80'u8, 193'u8, 73'u8, 187'u8, 64'u8, 41'u8, 251'u8, 55'u8, 90'u8, 161'u8, 30'u8, 221'u8, 210'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 820354'u64, validator_index: 626992'u64, address: ExecutionAddress.fromHex("0x4abb3f9a694bf6b27be97e24290ca6826b23c5d0"), amount: 100271'u64.Gwei),
        ]),
        blob_gas_used:    0,
        excess_blob_gas:  4396492484488695305'u64
      ),
      (deneb.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x7a9d6ab34c0314959d5bdceb0bd80f142e59e5e2addedcd178612303897e7a8a"),
        fee_recipient:    ExecutionAddress.fromHex("0x3425bc529b4791f5fdb7dd365501199b2f81e578"),
        state_root:       Eth2Digest.fromHex("0x4eb1a9a3c4b9392325a14f3f8efbc0b3cc3bfc2d7e9992377abd84af6c556db5"),
        receipts_root:    Eth2Digest.fromHex("0x094e9114d3487925f6818140978e4db64d8306083a8e5c987657e21c3a1995bd"),
        logs_bloom:       BloomLogs.fromHex("0x0815701b4689d0bb7f80fb1485ad3255a66b890725a1d2d66b4fc66678e2d08784c21ef583401493d5dda1549eda32303b7d102edc72b9fe1d696ab459294a88db0d7263abdf982ddf59ce008b8ac734565de79c269dfc18a36709ca91a3cd50516725e9fa9d98302fa0322254382aab0cdf1f95f2397579f7219bd7ab096ef1f00d7b1131b0055bff65ae9954cb22959adbc40983840ae3b85358fd205bdf6ac6bcf723047ffc53a094a06c2039935b6ef579efc618bf4127a6e4e531f6d97c17789be639691ef87fa5540cf732a184a0e09d5c60866ecd0be0a04bc94317712c395d84c2cec90f43f4807048bf1a93e3e6520a1a7c59092e2e391abf9d2e68"),
        prev_randao:      Eth2Digest.fromHex("0x349eec90244f3d812002732cd833952969b27a463def04291051137344c89c41"),
        block_number:     5715688900321967041'u64,
        gas_limit:        17172684770312311722'u64,
        gas_used:         9286597649062725614'u64,
        timestamp:        195835912833125491'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[34'u8, 35'u8, 209'u8, 45'u8, 117'u8]),
        base_fee_per_gas: UInt256.fromHex("0x7b5b4e48b3daadecb9724a74d426a86ffb5c5f8abd43469b4e3fe2a728b5a645"),
        block_hash:       Eth2Digest.fromHex("0xc71c294b5562af30b9e2b03e76cec0cc6d8b50694219404aaed2ace8f756a22e"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[178'u8, 142'u8, 115'u8, 217'u8, 56'u8, 74'u8, 150'u8, 16'u8, 244'u8, 148'u8, 19'u8, 33'u8, 89'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[195'u8, 248'u8, 42'u8, 129'u8, 151'u8, 119'u8, 232'u8, 235'u8, 245'u8, 240'u8, 113'u8, 157'u8, 235'u8, 158'u8, 160'u8, 222'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[16'u8, 27'u8, 72'u8, 107'u8, 18'u8, 210'u8, 127'u8, 78'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 5186085670428433087'u64, validator_index: 156817'u64, address: ExecutionAddress.fromHex("0xf8d93a548c4b243e66f4f73b29da342a0fab04de"), amount: 18446744073709551615'u64.Gwei),
          capella.Withdrawal(index: 9475052657186699106'u64, validator_index: 759532'u64, address: ExecutionAddress.fromHex("0x97559fac3168c6ee81b0f0b0b88563080ca24769"), amount: 4852567582077527137'u64.Gwei),
        ]),
        blob_gas_used:    11199168226748373856'u64,
        excess_blob_gas:  13194543368024635634'u64
      ),
      (deneb.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x806a868f0f31e8f519fa6339ad18c414dba17feb03aaf6ca3775b152bac64f3b"),
        fee_recipient:    ExecutionAddress.fromHex("0xa2bcc8b793c4a5d4e0f68251d2f22e1ff4366d2c"),
        state_root:       Eth2Digest.fromHex("0x6979ac9545f31eaf7ed8bd227cd7cbd1017492b892bcc118f7417ea87d50d412"),
        receipts_root:    Eth2Digest.fromHex("0xca0ac1828fae211c9d0fd7ab763460d89f9da0669d082c68b9fdca3ca1b59123"),
        logs_bloom:       BloomLogs.fromHex("0x0656423dc7b375cee4f5c3bedc500eaff2da91d0dd5f4e695933c92a2a6af7441200a41177bcae7912839f993a733aa2bb82976f08180a901e63c588a26dc9ccc58f477eccbb08aa932d512bfc765a57527acd04c585af23f48f389420890d06877d8a0f523cb90be10dbc73cb5b11e808f5c6c90c6fc3a9434dab462f2977eacf79146b35ee2372aae8a6fe3628cbe21a8988fd9546b25581b6d998462f9af7f653d3a4702a4a63b9f26cc7d2f72e18a3918fa9b65ed81d23ac0a64dd8f3f878f745fcb4de9ad144ae9565288d7bf90e6d356f49cc242d000e988fe76e0196f0c5b24bdf9dc501222e54f64861e0d45dda2bdf09e5fb290a1ec6dce39b02883"),
        prev_randao:      Eth2Digest.fromHex("0xc986211f6550cb787e89140d8856531ec309f652e2a871e2715c1dd055448074"),
        block_number:     7781035717593646205'u64,
        gas_limit:        9088183223170031827'u64,
        gas_used:         0,
        timestamp:        1844848381084178223'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[]),
        base_fee_per_gas: UInt256.fromHex("0xaac988479abbe95e03cc214e7b99795c4ec117bfe4da06e4624e94b262b015e2"),
        block_hash:       Eth2Digest.fromHex("0x14137d373f6e6110b3fe3c1d743a4f84547ad3d59d0b42598b794ff601e97e38"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[10'u8, 28'u8, 79'u8, 238'u8, 85'u8, 206'u8, 161'u8, 222'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[144'u8, 222'u8, 190'u8, 14'u8, 247'u8, 119'u8, 95'u8, 48'u8, 238'u8, 50'u8, 180'u8, 12'u8, 216'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 428032'u64, validator_index: 18218455002493563835'u64, address: ExecutionAddress.fromHex("0x389fe5e57a13de364b852d7e2cebc2add2cb7510"), amount: 726634'u64.Gwei),
          capella.Withdrawal(index: 18446744073709551615'u64, validator_index: 0'u64, address: ExecutionAddress.fromHex("0xc6a0db1d09160cec69bda14b444c46745e09c96b"), amount: 742028'u64.Gwei),
          capella.Withdrawal(index: 858390'u64, validator_index: 326055'u64, address: ExecutionAddress.fromHex("0x6a861508a89443c763d5daf15dab44a8a45147fc"), amount: 597242'u64.Gwei),
          capella.Withdrawal(index: 18446744073709551615'u64, validator_index: 17239721441660215355'u64, address: ExecutionAddress.fromHex("0x1450447dc71e28e312c7de7034523cd322eabc98"), amount: 18446744073709551615'u64.Gwei),
        ]),
        blob_gas_used:    6943026604784588438'u64,
        excess_blob_gas:  4081254329996628499'u64
      )]

    for executionPayload in executionPayloads:
      check:
        executionPayload == asConsensusType(
          asEngineExecutionPayload(executionPayload))

  test "Roundtrip engine RPC V4 and electra ExecutionPayload representations":
    # Each Eth2Digest field is chosen randomly. Each uint64 field is random,
    # with boosted probabilities for 0, 1, and high(uint64). There can be 0,
    # 1, 2, or 3 transactions uniformly. Each transaction is 0, 8, 13, or 16
    # bytes. fee_recipient and logs_bloom, both, are uniformly random. extra
    # bytes are random, with 0, 1, and 32 lengths' probabilities increased.
    #
    # For withdrawals, many possible values are nonsensical (e.g., sufficiently
    # high withdrawal indexes or validator indexes), but should be supported in
    # this layer regardless, so sample across entire domain.
    const executionPayloads = [
      (electra.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x760d4d1fced29500a422c401a646ee5bb5d65a07efa1492856a72cff9948a434"),
        fee_recipient:    ExecutionAddress.fromHex("0x315f583fa44fc6684553d3c88c3d26e9ed7123d8"),
        state_root:       Eth2Digest.fromHex("0xa6975bac699618cc22c05b1ba8f47cbd162475669474316d7a79ea84bce3c690"),
        receipts_root:    Eth2Digest.fromHex("0x080d53a0fd22d93f669b06052413851469d63adeb301810d7ce7a51c90c8e8ce"),
        logs_bloom:       BloomLogs.fromHex("0x453a1f1c4f63bcf0be84e36a9ac233b551601bb2e5ab9450235bd83e41d2013f42c97044ac197a91da96efd6fb18f233bad2e884d76f0a63a6fbf7dbc714cc9aa497fb6d363feeba18447ecf799d5f8d769232553c375b21166c0176859dba63eb77f1a17e482ebac07c3cfd5281277f55f1e5c79cc675d501e1982816d31db7d73c89e855315d8f4e9fef1c9ebb322610235c44632a80341b42f05d207ac4869d08d98a3587a470f598095ebb932788fefacdd70e7749e0bd47ceff88a74ee1f006d9791350484149935d4521d86e644ebc4346154ca0bfa9fbb83120630867d878c12e53a04a879e993b755f02670c9c47f091acf1b3f593782ddaa98f0df4"),
        prev_randao:      Eth2Digest.fromHex("0xe19503a6fa6acde0b8f5981f29eb2e298ddff63e6243529d735bcfa42680a515"),
        block_number:     9937808397572497453'u64,
        gas_limit:        15517598874177925531'u64,
        gas_used:         3241597546384131838'u64,
        timestamp:        17932057306109702405'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[55'u8, 184'u8, 18'u8, 128'u8, 63'u8, 61'u8, 26'u8, 79'u8, 3'u8, 225'u8, 167'u8, 15'u8, 240'u8, 167'u8, 180'u8, 141'u8, 205'u8, 10'u8, 246'u8, 70'u8, 248'u8, 35'u8, 19'u8, 45'u8, 252'u8, 187'u8, 168'u8, 42'u8]),
        base_fee_per_gas: UInt256.fromHex("0xaf8acbd8a0f0f8eeced9a1014333cdddbd2090d663a06cd919cf17529e9d7862"),
        block_hash:       Eth2Digest.fromHex("0x86b46255725b39af70a9e1a3096287d9772ccc635408fe06c34cc8b680977ff5"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 98780'u64, validator_index: 8610867051145053792'u64, address: ExecutionAddress.fromHex("0x0c33e909ef375bd3ab33961b5ea767b4f1c8bce0"), amount: 671269'u64.Gwei),
          capella.Withdrawal(index: 18446744073709551615'u64, validator_index: 500164'u64, address: ExecutionAddress.fromHex("0x271215240885828779da36212489170f19a8f5bb"), amount: 2071087476832314128'u64.Gwei),
          capella.Withdrawal(index: 26148315722507923'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0x340bd9f489ec124b8a879673f12969b14d0b5555"), amount: 9486787560616102568'u64.Gwei),
          capella.Withdrawal(index: 4839737623914146930'u64, validator_index: 273755626242170824'u64, address: ExecutionAddress.fromHex("0xcacc573cfc0ad561aae27f7be1c38b8dd6fab2cc"), amount: 9475975971913976804'u64.Gwei),
        ]),
        blob_gas_used:    4401258332680664954'u64,
        excess_blob_gas:  12834012644793671460'u64,
        deposit_requests: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD].init(@[
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x814b12b95f9846e3d69ee46e6a47a26d6cc8613641a1352f35395a15de56043ef451726e797757b9768657a9e9787a83")),
            withdrawal_credentials: Eth2Digest.fromHex("0x241d63159f0cde42aeec7610900762ad2016f5bc0270250d7086b173bf6e4181"),
            amount:                 12638322094749964200'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x10244d58594ff86b3548ae04b3c193756c7cf2e9830da492c6021259f8bce7ac6ea62d93a9b78adc77a168b91865876ac68ef7f05564cac91353e400fa5c44317789d2d93d6a6cba9155db29b7857562a6d9316454d1a9c5178e2ce5c75fa5bb")),
            index:                  8139570810318771243'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0xb7721c98fe1ae6beaf0e486d2d951a307a3d3265cf6f2b16bd8b40f2dbfbc6e4e20e3f75c29e70a0432af0385a997eaf")),
            withdrawal_credentials: Eth2Digest.fromHex("0x0aae47c8d21e2ff63a5b341c1bf209f5176762d522d16d2f7b9a595cc327a3a6"),
            amount:                 15018910798502483977'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0xa6d248e93991eff0b001418667e718204216d88fce9933fcce52e4daa026e8c47f9863a77d675fecd6def721d194684c28823350fe80429356c57792c70b22571e7d3219b9a8a35d3a552dd5eb6ffdd01ee5a1fcd2d14ad82038f7ca00a22ca8")),
            index:                  13899393201735021181'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0xbced475462c8676eb79a8e288f1f7759b621192b2a5f41162473affe3219663fa1e9d78f0ce94c556e4bfa1dfd3f0f9f")),
            withdrawal_credentials: Eth2Digest.fromHex("0x245144c69624ec1ff4feefd0d9080e016fcab37726bf712df06ebe512bd11fc3"),
            amount:                 8365809466950819313'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x806f5cb96d5cabc2ecfe96fd92816e1e86ea1e86229675bbdd6de141461bfbf3d358094f41ddb91cab075a67950af6016a326697be18d38a2056aab597d40cb216b642b5d6c6f4edacd4a4a89a7c342f3d11f18a1f4f7783ea25251a1f355009")),
            index:                  17214334124209319458'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x22189bc4bc3f45eb3d6d8a5bc6b85aa8f680c5f9cd1aba686757faee3d31bec7bff6af52671fdb767ea7ccaf14ac2ae1")),
            withdrawal_credentials: Eth2Digest.fromHex("0x25993e69ef274cd8b703d25cd3932b117e08123578b20365aeae8a244a625355"),
            amount:                 12258289723293669412'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0xce7d46dc7f0b4ad54417dd50800761161dee1abb2e20af7c4cad314a6921768f7b89ba17bc7b51497c67a14255c31aa19d19bdad1d572f88c598ffdbe7be5d8cbe1ceb83836948512448725ca56ba834626a8f42aa110c7b272524707e514fab")),
            index:                  13244611922088961185'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x0b1cd7defa0a00c8714ab2ab6a1da006d469c725042c589890c9e5c21070d5289a5b33357f9dd8a79e6364fc4e012440")),
            withdrawal_credentials: Eth2Digest.fromHex("0x4b07a81b5612a02914cfd99571711c78cbaa3e0f1fbb23c4a0a51e04c263a659"),
            amount:                 16282163526662133088'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x943c3c3818d5aa98fbf8344ef4cdc9c13cdabfdeb7762efc8bb32d2ea32d3bbb4ef069a254f5f35325f48609fad7bbafb6389e204767a9b3bbe46a04f8baa850bfd4d3747aaf2816c7e18fc2ebe4fa41088d195d09c761819c7a2e57a3451148")),
            index:                  900883336538271514'u64),
        ]),
        withdrawal_requests: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD].init(@[
        ]),
        consolidation_requests: List[ConsolidationRequest, Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD].init(@[
          ]),
      ),
      (electra.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x2cb54ddf357864102f4ab6bce57317a75cee972f303449bf7047f4e0e5809127"),
        fee_recipient:    ExecutionAddress.fromHex("0x92af67d9604b945fd2cbaccd29598e2b47ef5d2d"),
        state_root:       Eth2Digest.fromHex("0xc64221514816a2f87a29c2c474abf99547820b2a12e6e5956f160dd54579e521"),
        receipts_root:    Eth2Digest.fromHex("0x76c1ca0e483a557f6884d64bd891c62904c64c2fe69350278345c622cc50b0d7"),
        logs_bloom:       BloomLogs.fromHex("0x7afdc9a99777d76b713e960e9f12ad4fe46ecb7ea6d5b245c6d9ee11d3fd35e7ae33dd6062fb6578bc2c2f286f1c6a4aa6a44cc80a88a3678c7085c35a0f2e5334ea686e2098fe5d179bbbaf81cbc349a15e7a21aa27f0ddcad342d980d056a356694cdadcef8db3c7866b6cb087c28f2aeed7a5bc9b1294cef0da3ac3b46dbe72d7f164f1990bc32f755b709b96a96bdd8da2c9d9300e9f6906040347d337fc21b833ff0b80305b22ac64a2df2dede4c01c65c192884f161aacd12ba56dab9189477e6ae484a97ff96e0aba1f9b8d043896b8433779abeec091f16b94a013325fe11096d1f2d79b701ab5b46063ac99392a790e617555fe3286dfd7ec0cb9b6"),
        prev_randao:      Eth2Digest.fromHex("0xc4021ae781a3b3a1dfb1e4464b032a3bae5f5b68366beb555ede1f126920cd5c"),
        block_number:     11318858212743222111'u64,
        gas_limit:        2312263413099464025'u64,
        gas_used:         1,
        timestamp:        15461704461982808518'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[254'u8, 188'u8, 92'u8, 24'u8, 153'u8, 206'u8, 74'u8, 108'u8, 96'u8, 100'u8, 148'u8, 84'u8, 151'u8, 74'u8, 73'u8, 167'u8, 65'u8, 177'u8, 253'u8, 62'u8]),
        base_fee_per_gas: UInt256.fromHex("0xb1c4b2bffcb38aaa1f98b483441aa212c9dd951d4706dd505a973fd5fd84796f"),
        block_hash:       Eth2Digest.fromHex("0x8b150d453d802fdbb19be0132621a5e8061e70cfe6668ee6a63e4ff217434999"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[142'u8, 197'u8, 221'u8, 83'u8, 32'u8, 126'u8, 145'u8, 86'u8, 28'u8, 39'u8, 112'u8, 240'u8, 168'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[175'u8, 191'u8, 143'u8, 78'u8, 162'u8, 249'u8, 87'u8, 193'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[84'u8, 168'u8, 190'u8, 157'u8, 39'u8, 143'u8, 147'u8, 156'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 11497754023538902580'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0xb0b680a6d93e520fa32e399ded64871d99c1f2c6"), amount: 15592017597077727306'u64.Gwei),
          capella.Withdrawal(index: 18446744073709551615'u64, validator_index: 14269483352942387358'u64, address: ExecutionAddress.fromHex("0x97e4451d09c9af077dc9081e5081563aa26e4c51"), amount: 18446744073709551615'u64.Gwei),
          capella.Withdrawal(index: 9664968187979079659'u64, validator_index: 750818'u64, address: ExecutionAddress.fromHex("0x1e4bc6f12efe96b9f5ca549b77a3d62c5f5403d8"), amount: 18446744073709551615'u64.Gwei),
          capella.Withdrawal(index: 727020'u64, validator_index: 10133766089843653238'u64, address: ExecutionAddress.fromHex("0x6a1ed64277cf1eba8c96281531d2799d1fa7c409"), amount: 130469'u64.Gwei),
        ]),
        blob_gas_used:    4810756443599845432'u64,
        excess_blob_gas:  1435200597189175983'u64,
        deposit_requests: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD].init(@[
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x8fa8ea53febdf07bd7f832be8c965a4aca37c3340b4cfd75624c125f4eb5946a404e9cc35d74f55048c1fcfadde3551e")),
            withdrawal_credentials: Eth2Digest.fromHex("0x7647368d6b5580fc677b463d57d4cc9dda93117e9c8604cda4679030cd4956e4"),
            amount:                 11838169110820399795'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x84ed920f689cda2883afa0c5d12db16206abca7d0319047c2542b9fc6c0e5fb9cf945e76c34da4448bf06a90cf51686393af3b80feebef058a8cf98762439bf748c7394083edcb3b4b20390c00415046f84885a8fc60d873318ed08f7e420d7b")),
            index:                  14081768455144986910'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0xae3d89af9e4d6caa6e9746a13f9bba9886c7fb75669af29e089799bf94614d722a776006b4b2fc347e54c88ddebdb5df")),
            withdrawal_credentials: Eth2Digest.fromHex("0x0548c33677c9d3d11898e1b1cb7e8546b5d28c09626aeb43fe77609ef8eb709c"),
            amount:                 0.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x8beef976488318fe3577aaa2686096377805c1486c3598c5a01202884ac1b68013cdc02e1bda7cc5fcd649c76cb57df4d8bde53f119e2c9f7699653f4686c12ce909b508fc92a063773da4319bc9ec52f1605c7a4c220a1d3bf182e80b7a5949")),
            index:                  7396750296380130136'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0xd3abc92b8a163a56e35c545a528eaa0c5bdbfcc5de8a1be80231d2a33ef1249a31c3638771f7a3e764fee81f6c95d433")),
            withdrawal_credentials: Eth2Digest.fromHex("0x074fa7f5af43e713a8ee7f09fb46ef4f05b23a060486141b5d9e9d273c7fbe56"),
            amount:                 1209689892101089592'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x01b42eaad61c4f658526ff4d64bb49f19276a698b34870245109c24f6f59dcaf87ab2275526c665d2493ea6c77f2bfb86e77d0375f4f63ce4cb3dbe5632442453fb4c73558d3569b62f1a6ecd5821daa85d6762a8a24c0eba6b8e51c9b0acb8f")),
            index:                  16259922695017953678'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0xf18bdc121a076ebb642352c940b5c0cd9c60ea4d3b8188b9f7b446efcabbc5af2f0a2672632b0474c5147d17427bf526")),
            withdrawal_credentials: Eth2Digest.fromHex("0x80de1f7b69ecf34465e463b30e49453c36e65684ce3004a082ffd84bf4c0441e"),
            amount:                 4622244708907095023'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x426dc233d2195c02283140b3d90a50da4d6d5bce3f7c3894a910d891ed835c2cb1dd8ba1e5f82dd214a322abd50e3043408d6f7a04499b2bdf6fcc5b4cda0400d557df79bba2aea31de06de9c8a1e069666a3b71577809480f82fce4a12882fd")),
            index:                  9250544134833432385'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x809a16fa8c9e34875aaac4939775bb6b0034b2fb7f5db570567ef604b11485c878544dc6e6878f4ad921fce8cdcc7273")),
            withdrawal_credentials: Eth2Digest.fromHex("0xcf05474e4f86279a6faec8fd6987ac10c4aa6595e6d061fe7217a68d5fcaf5d3"),
            amount:                 4509592030421891894'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x0d543b0e9b934586fb877615c8d2551e11998f020bce6b96901fb8045ef42eb41f6039e813136043fe5c63d91a11e1e15e5c4063d1775f95ae1715cb87b21b7690b44ec38efd1a825e1e3ac68d21940f772b3309edb3ddebb24204e06d4924c2")),
            index:                  12423850076890731216'u64),
        ]),
        withdrawal_requests: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD].init(@[
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x39554fbddf13facd81344d536c08ed5769304749"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0xc4f5b2c07cc2f6758dd8eaef217247f767bcd88a8f5c93b030023d420568f47735d113df344627759f4ea1b56c53136f"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x243c496e83f955ef23dc3d121b3cbe5f56305d73"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0xe9a3d62cdf9acae4966e5682958d0cc9223065b4d68ed3b12a024a56744ab9656736326061f9fb41a8f15564cb4d241f"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x462f156d8d950c7ffd40d7ba149bcc34093bbdb7"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0xd6d7f2281c2b9c98a8a5dc0b7f41783eb91b838973207239852e817ed412e164e330003ac9ab0e96bc65886e15b5cbe9"))),
        ]),
        consolidation_requests: List[ConsolidationRequest, Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD].init(@[
          ]),
      ),
      (electra.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xac5a7347865f503e1578d1b47271c8e60027b5ba24b0da8e7c3733bcdbeda220"),
        fee_recipient:    ExecutionAddress.fromHex("0x8b7fa656e67f6af2074ec3f16930ad742a69f189"),
        state_root:       Eth2Digest.fromHex("0xeb50f351f6945df8983cf4037ee264dcb2ceef3313ae452248571811d8a3a8cf"),
        receipts_root:    Eth2Digest.fromHex("0x860af6010832f64a5234327b653aabbd3898881a7b72ae42e08d4a1519166fba"),
        logs_bloom:       BloomLogs.fromHex("0x01a18d51076880a1a8ea86cc5dc5fb904ba0a3c285b7dff34ee5dbad9d64721f3849ad9f50b90ad4524eca6b0564f8a1a5827a7b476ea051c33a7c0e18db4cfb27b36476bbb1eacbc029dbc5009e5cea695045cfb34c868163514b784133f0f2998cf12e2caf9c74f69732ed3716396dc34d86725428aff48bf6b935ae88f5e4820b9a325bc670cf560dcb479723213a3156a9d7d0e7de0dc791d0eb94a691013624b8aa982ca3c9d5b49fcac8fafbb403c9fbceee5373f0fb2b77ff1bae8160fe2a47b01d792b088eb3fe24c53b5c6a8b4a3b59060d587ca7376f8baba58d57cf745b2a346f800a54d08545194e067ae260c73369a016b12d0fbc20abc78ba3"),
        prev_randao:      Eth2Digest.fromHex("0x330b7093023f617d2cb5f76cee4b078af002b68d81e3a5b5c9d37c4411871a95"),
        block_number:     18446744073709551615'u64,
        gas_limit:        13979513761871276914'u64,
        gas_used:         6199089254852634745'u64,
        timestamp:        7404562418233177323'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[220'u8, 149'u8, 177'u8, 36'u8, 228'u8, 88'u8, 47'u8, 149'u8, 211'u8, 213'u8, 170'u8, 40'u8, 207'u8, 145'u8, 137'u8, 64'u8, 153'u8, 22'u8]),
        base_fee_per_gas: UInt256.fromHex("0xfc82d0e46d05b21aedab6f368183611d2885b28c52842f28f621ef6c631b6e6a"),
        block_hash:       Eth2Digest.fromHex("0xa8c6b2dcc2496f0230e796f8a69642126955ae6209a0d0c2dee2c925212f447e"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[138'u8, 17'u8, 34'u8, 168'u8, 105'u8, 179'u8, 196'u8, 21'u8, 253'u8, 242'u8, 106'u8, 30'u8, 40'u8, 190'u8, 179'u8, 93'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 1'u64, validator_index: 239183'u64, address: ExecutionAddress.fromHex("0x75efb2a04b5f25ae56ff7256ee9f4fdc4e25baf3"), amount: 402148'u64.Gwei),
        ]),
        blob_gas_used:    723464856451065691'u64,
        excess_blob_gas:  11231138371511965912'u64,
        deposit_requests: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD].init(@[
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0xd82ed23e86d1d22165bcbed4e01b2548997769f369344a4f347772108782d77c20cdaa614c57457726d3e5d384a7d09b")),
            withdrawal_credentials: Eth2Digest.fromHex("0x2acf0fdd7ca651a467899a928ffd036d88dd86301808ccd2a06d5002daa35d15"),
            amount:                 15437169017045689073'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x143a1a4dcac6db342901feb541dc0c95830a4ca1aca9c3fcb55e2dcb9a5b31e2bd9214b1a3a12e17e140d37ba7ebfd11d6d8a38eea5d0755402dd400386aaefcc70d12fb1409f92797923bf964bea3f916b562f3ff2b522c48b748c8e8c632d4")),
            index:                  15872726372973140071'u64),
        ]),
        withdrawal_requests: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD].init(@[
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x3a8a707225d47dbddb01c1ca39181af823d57d97"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x9cf008ca8159512ffffa1fe56de68bb9e44f9c4bb3c2c4924f5d7bf1bb810cc807b155f11ddd55a4972346f8e75f06ab"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x7c55f3e4f648bcfb47db2122233b25881785709b"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0xb9e559b137b8ab79ddfbc6ea2fb44d96d1925c2b7b6e4c0e1b69f66d82b656065af06bd62e8fe9210276a116ad78c382"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0xcf25ed583b463f3a57acd97c398e27877b9bf6a6"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0xa14ac0d85ae38dd91a9f7da12b6c7cb4e879f78effc5ac0da8f9ee56059460f31152009fc1b88d0e0a0bf576950f45e0"))),
        ]),
      ),
      (electra.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xd3be9b45bfe67229afb47461ca2970505586cab8eb8e00f280ceb07a9d47866f"),
        fee_recipient:    ExecutionAddress.fromHex("0xde645d4a77f0a386a45c52357948e1d7eac5e780"),
        state_root:       Eth2Digest.fromHex("0x69b70e0188e7b88e38df90853b2dfd2e4c7181e83d82d77ab81c57d161216b92"),
        receipts_root:    Eth2Digest.fromHex("0xc01d94a01736268170a16196927029d4d8d7c65970ec78ece94c87304bed4568"),
        logs_bloom:       BloomLogs.fromHex("0x7f1ac5c77e3f0c8a1a103ee83dd7d0fd6fb13895aa1141de330445474b3216e2646c15c1cbf4ab4feb1e4e21c2e6970f4a6648675508b08111e00b62866b0f6cccd58afea87d2cd0a24c0384fa179dc33ae6d0db8c1b118a75fb442682b7cbecc2808fe8c812c3720ca54f6723a395fff5dd1720f41822c91b080503bbfeef21eea192d5b7c4160344996d017ab849fa97e862206caac8f8bfeba41865514b21a8d8fa9ce3dcc0daf5bf86fd2f07d222fc7a9d11fb4031b2cd72544d7f89eb95203a570bc179f9ba1f73f39d74049fe22b63939ea49d5d40f42c00c5f1bd429e84ade377475e432186acd9975914670052fea64453fca87317f62e29b550e88f"),
        prev_randao:      Eth2Digest.fromHex("0xce47da2b2a68186b78054be0894ccc9ae7213c18b9093c0ebc1b9ed011071a39"),
        block_number:     9014833350824993703'u64,
        gas_limit:        18446744073709551615'u64,
        gas_used:         7874274181221487360'u64,
        timestamp:        1,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[139'u8]),
        base_fee_per_gas: UInt256.fromHex("0x1eb821a0ee3f9d2e5b49c64177db9ffc96ec6b06249cefa8c51d0ce7e664a3ae"),
        block_hash:       Eth2Digest.fromHex("0x99479be6429eac4a945ca8171d3d3ce42d7b5af298292e833e20462438e06229"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[99'u8, 198'u8, 91'u8, 86'u8, 23'u8, 222'u8, 121'u8, 250'u8, 12'u8, 135'u8, 133'u8, 37'u8, 61'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[81'u8, 173'u8, 241'u8, 145'u8, 54'u8, 3'u8, 36'u8, 121'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[]),
        blob_gas_used:    1936360613980595982'u64,
        excess_blob_gas:  525438497879148955'u64,
        deposit_requests: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD].init(@[
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x2dc5c92e3d525d69b07de9f2e0fb3db26b05c966b029e38fa736bb60b49d6abe86d4dc61255de43e9bd012c1677a7adc")),
            withdrawal_credentials: Eth2Digest.fromHex("0xa85cff9568bd1244836733549567286eaa0aef139c416c235555551772e2ae29"),
            amount:                 5525246068348642244'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x4f2e42e2305bd30fdbdc8c2b0e8f9c57c544f097cfdc2fb2335df422a14c5c827d91c586384a2d14f64bbd98124046506388058414766674bbb59bfefe2c701c05a5e9c135d60617830ac5d60788712587220964a78a632cde4e124b7692ce62")),
            index:                  0),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x6ecff72c568c0e272157ac48bd047406c8117cc60e531a3acd46531da9b140c91ae684c72def7839e6d84b6f190877e0")),
            withdrawal_credentials: Eth2Digest.fromHex("0x0946aa245e0435cb321fd0e166c31cb363fc2f264bbb2d67be9fe89d07b2037c"),
            amount:                 13283742386908495031'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0xf683f76e5a79d2248248f701d87327b35705ae31284d8e7602a1470a239d35f9622c5c39812a933ca586f724af4f10b58cea183b8c127dada1abda2eb0879e1aa49f7a9bd89ab76f7d5f33d2ad80c9f058ace2bd83c224520f8d02b0942ed985")),
            index:                  789807770712130412'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x9c696094074fb290b6f8558c7ebe08b8595859aabfe521a7307c3179b21dc8df0a63f0970f89bfe3197373a92630c3c7")),
            withdrawal_credentials: Eth2Digest.fromHex("0x650cc685a706fd441937753efc42e243339d62c6866f83b00c0ae2becc8882db"),
            amount:                 2716675895799004971'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x79e01ad75396043b9343d83587ccf1dbc7928a8f520e92b2840fa40cb086b04964b8fda19176d22d643c5afe0703884487fc40a14b7a7100c96d4811ea7af08046fd0d7aab8a1f73e05fa598f5be976696109312b26ea8b629ee984be7a7077f")),
            index:                  1321141240653182102'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0xcc2fd5c9cec6e09329e140efd4ee508de16b2af020d8ed8b1323f166c3c6cc0ceacefccbb9867cd5681610749050429e")),
            withdrawal_credentials: Eth2Digest.fromHex("0x89a95d7a2fa26fb6db447d53a508f92f997823f95a6caa25e04196bfb3749f5d"),
            amount:                 18351003704404188995'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x351d11b34c55e1d947d5ce132e02ef1f3765136d14945b3fa297569465d057fb593df173d99e690c7dc8f6455add6b6abc87e4ea88a68fc396ad9189f3c56bf642ccd5dcb42dbcd67b8d6c3ba6627bc2a51d776cc35adbfacb7bd5e84948995d")),
            index:                  16817584575889190379'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0xca1819f056ebd22a08689e4d40a195116b68e56a1c9b0914499801f7015f1e2696a9d3fbc17a5c2641b0429eb7bf2124")),
            withdrawal_credentials: Eth2Digest.fromHex("0x83b7ec99b4e424a17228b43057b9bc8ae387fbc075f1dc692b0e1765629e2494"),
            amount:                 18420683568430679261'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x94cb986143fdae936c832d08977520c41a6a9b1569b012a8486678571ea5ce2e913f55c9d5631a8f02d1b75aca414969c56f22cf0b6e5193f7ac3568b09c9ae955581c69095908ccab9c5ff5c47b2edef262f2843ccc7cbc69eb35b14c66886c")),
            index:                  11423537419700559218'u64),
        ]),
        withdrawal_requests: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD].init(@[
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x44754b90f7b23eee1dddafa745ac723dcc147404"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x8d13edc45159cdcf6ed780fc7b93e74434fa392b0842dfa92458cc59515aaac127317df24def9701eb6d5ea060eaffea"))),
        ]),
        consolidation_requests: List[ConsolidationRequest, Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD].init(@[
          ]),
      ),
      (electra.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x06504beb0dc3bae44ef75678d29ec5138d87da68d307ca7d43e259cede60fda6"),
        fee_recipient:    ExecutionAddress.fromHex("0x527ce602a0be18c0944dc27b2864c711a91f89a6"),
        state_root:       Eth2Digest.fromHex("0xad3bbef5d22bdc2429da09eb85137c881f85fe6e6b3ea207e5eaeb399c755055"),
        receipts_root:    Eth2Digest.fromHex("0xf94fdc52cde20532cfdee73e9cebb61d9f7160191345f9caf58b45501d8effbc"),
        logs_bloom:       BloomLogs.fromHex("0x0999cc50752006a2bc8e5485c239b9a41be6ea2fd8f0392884246ef7d33bccdf4bd326fadae385e3ecc309bf0f367ac1791767ffaee90ddfa7bee22d19f417708fded2b2b6b3be2b6007745fb1de940e7849761586953c04e3bec3c9b6342d1b91dd024980f469b484bd0befc4941a3846d027390d6256e4acf9933e0891dd558270eb35d3455f4e49c890479e970a8008b75ff4d33b4f7e5a8c19e75d8abd8673ebb859a8a24907584d88f0d68b3142b3c6952695fdd84581f5a070601a575a8e7bfa0bf7cf0fe9d70a051005f9dc594d09909e9d079d02a4e441e5b3f33388de8d46cbdcdf24f835415680e569f2ed29acdc01042a6a7ee701e4e6cace5c28"),
        prev_randao:      Eth2Digest.fromHex("0x7cef96d72498facdb399dfb5b6d7d69185f3edc70715540fdc7ef651c4685c6a"),
        block_number:     13066898984921201592'u64,
        gas_limit:        9241830338892723842'u64,
        gas_used:         8347984358275749670'u64,
        timestamp:        1,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[11'u8, 46'u8, 127'u8, 104'u8, 141'u8, 79'u8, 55'u8, 48'u8, 242'u8, 12'u8, 142'u8, 2'u8]),
        base_fee_per_gas: UInt256.fromHex("0x6241db2a44a58a2c1aac93c4aa18aed5add30d1937c31078542bb544bf9ba2df"),
        block_hash:       Eth2Digest.fromHex("0xdc1756667e7c3f1615650cbbaae1117a6bac817c6579cf3f7afbc93277eb3ea1"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[13'u8, 24'u8, 248'u8, 26'u8, 141'u8, 177'u8, 236'u8, 2'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[213'u8, 208'u8, 242'u8, 46'u8, 0'u8, 31'u8, 219'u8, 213'u8, 197'u8, 218'u8, 148'u8, 236'u8, 43'u8, 152'u8, 123'u8, 96'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[84'u8, 163'u8, 60'u8, 195'u8, 40'u8, 68'u8, 185'u8, 20'u8, 244'u8, 82'u8, 34'u8, 181'u8, 26'u8, 201'u8, 2'u8, 108'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 18446744073709551615'u64, validator_index: 15531362396155364476'u64, address: ExecutionAddress.fromHex("0x063b2e1de01c4dad4402641553c7c60ea990ab30"), amount: 106054'u64.Gwei),
        ]),
        blob_gas_used:    0,
        excess_blob_gas:  11830672376638423068'u64,
        deposit_requests: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD].init(@[
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x09902c0e95be295a0b550efdeca632b9e9628760737ef80afda66a830d3b3695891d94f7c0504e9d5f7ece9b244ff8cf")),
            withdrawal_credentials: Eth2Digest.fromHex("0x0cc2bc536712049ab8303dbc403542bf5ae5b2308c6859420ed950ed9b221567"),
            amount:                 13281242819623749583'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x08c9aa65cb03faed07e92003192d98e83a9026d2c8b31ebdaeb70a21809d93e87351482aa9f49b039a1de250ae1a0a2cf9104c23165ed658e433062e7b8cfb26aecd8d73be477745f9e7f4da7927dfb300ef82157a66936b78582344f58468f0")),
            index:                  16878503552918350820'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0xb49156fdde58af27ac558dcf697f2eb2f2c92efd5b455ff736ca88258d9c2e7b77989585dd562da6eed32b228e8510ea")),
            withdrawal_credentials: Eth2Digest.fromHex("0x4e922c8a3cc2bc7f5ebf9733c67d76f338e7902653c28248ef967047a9875835"),
            amount:                 4089107267451814479'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x9e2864164d275e436ed45120245d2063dbedc87d555cceabe8c18622fe462411ecbe7fa4a262989a45795efea09d21f8e4254cedd5c787bf80211be0a3c6ffc1bcc5f364387f32f746647e0194a599653f3af5f6e1151244df02bb7b3f7270cc")),
            index:                  1665528005288012054'u64),
        ]),
        withdrawal_requests: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD].init(@[
        ]),
        consolidation_requests: List[ConsolidationRequest, Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD].init(@[
          ]),
      ),
      (electra.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xb5d4a5eae3a1ea004ed573b0b8f8a22c847616758c0faf1e7e9589f16e55415c"),
        fee_recipient:    ExecutionAddress.fromHex("0xf7ac0877fd8bcadde1e050f6c7ddad13688ec071"),
        state_root:       Eth2Digest.fromHex("0x7472f824376a723894f8d539743c7f93b69839772f28cf6a83e2102fde99c3c9"),
        receipts_root:    Eth2Digest.fromHex("0x750365b5d975460a64f07758abd0cdd44cee23cc2d4f06f2a047cf4c12c23db4"),
        logs_bloom:       BloomLogs.fromHex("0xe24d8452039bddd10e1252c1ebf9b9e81a22577f940e8708d200548717e8471e130a7066adc48785a8dea1dca05953d6be16504a57112c065e7909586cd611af9e0b840b81caf0532dbb2833ee5ac6a6eb7b6c990cba6ccf6f4ddec5a7c76f8296bd2a693cbbb43b1d86b66f6aa58888734d3fb21cf5e96f1b981f8ae2737bce1cad1cc458650291cf7a3d22c61fde6af3a07a44bf1b334b2c5dabbef16e5e73db75e87f04670cb3830f0a7badc702e7dd37a59ce02992f4473a909e57dee1fdd22cfc886f4fcb6ea205ec9234a8ec85ea134242748f9f10062534fd0528bc1b5b1e89511cdf91a1e7fb4f8c58c93d2a6c75e48a2d48235cb7de13040db8dc9c"),
        prev_randao:      Eth2Digest.fromHex("0x2410823a37c763e13b03a4c48e32f9e43b8440ca31ecfe8e0543a20a02c496c5"),
        block_number:     14920119354157670036'u64,
        gas_limit:        17193947846593799248'u64,
        gas_used:         2176791850599260430'u64,
        timestamp:        12670133468877091192'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[31'u8, 7'u8, 1'u8, 212'u8, 152'u8, 82'u8, 167'u8, 57'u8, 116'u8, 147'u8, 97'u8, 109'u8, 219'u8, 207'u8, 151'u8, 116'u8, 43'u8, 218'u8, 91'u8, 253'u8, 14'u8, 182'u8, 102'u8, 57'u8, 153'u8, 72'u8, 172'u8, 208'u8, 0'u8, 64'u8, 97'u8]),
        base_fee_per_gas: UInt256.fromHex("0xf1daaa067663bf3277b9149aab162f4e330f988f0be8f83a556743a57ae5c8fd"),
        block_hash:       Eth2Digest.fromHex("0x5d462b4b243c6292b6a3b32f4e05849c0613d0a61954734c524f75f8df66cf8d"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 5416630176463173042'u64, validator_index: 0'u64, address: ExecutionAddress.fromHex("0xd7b1d18e4eb7b5041b4b08bae2ce8e22982d6e6c"), amount: 911474'u64.Gwei),
        ]),
        blob_gas_used:    17909098553568904023'u64,
        excess_blob_gas:  2561776469828429184'u64,
        deposit_requests: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD].init(@[
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0xab3432ddf2af63c4fab5af4cc8bd2e73aadf316f2899b88ac2d81cce54476a401f2c6692b95a049a559134c160ea9588")),
            withdrawal_credentials: Eth2Digest.fromHex("0x4efa2bd51acb05fda811629ca1fd71fb77f4523a26087e25f8f6faeea76619f4"),
            amount:                 0.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x2303cdb9d265dfd2ac3923c45ac94797eaec8188c244c8b9c7480d55db3d0e33876c14abd1cce784c18d07ed474ab7911b29e5d0343377d923a21c6a4ef6b0d302075a1aa9e7341e22aba6aa5b139b754a3b99b80ecc5c39771eec11d456f210")),
            index:                  17835217878031055704'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0xc6d41b4862a8b3c4dffa9a2550fedd5598417ab02715a841d91e13688bb2a3f30e22a1bc60363a77dc95b6bf0d7e0df3")),
            withdrawal_credentials: Eth2Digest.fromHex("0x771668e08e36fb5974e56502c56bfe6a9b4976e6954e845b416fbed33c18c26d"),
            amount:                 0.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0xdb8c8b42b6796c13f5737484f6da27b7eb3ddc3f03195be0cf6a484f34bb5e5da5ab4276222ce48b84f2b80e3f40604ec0b20ae0b451f4f25e598f483fd99d5b158ca0dc102de8c11c2713992997d7bafda9bd719c7ca70480174915d76bfe73")),
            index:                  13902730600946299592'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x6b841e43fc2268f72a78f0c77d57c4cc6d0b87686a435813c3f9af9a87a01b21b5ca1c6b54ebcaf5e861c7cd66244ac9")),
            withdrawal_credentials: Eth2Digest.fromHex("0xbb1071d3f5aa5125b1d01442d9d82812dff796db2d8d36b590c1ea66ec945c33"),
            amount:                 16549762982203261123'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x6d18d257618a085090dc37a79c3f02b6a7145f27d72736abf90cc4a1fde6a00b2670d86243ee71efbe5819360b53dc2263784457be537b0325e7b080507d78f0b18b839acbde966f3bd5567ebab939978b00b5b996f1632d6ef5aafefd3c8e6e")),
            index:                  3347786845438227400'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0xd424dc39bd77478209cee2c04bd9dedcf60823c4fabf724d0aba4a2d401a14a9b5e0cc0b6a2058e8165177c70fde7767")),
            withdrawal_credentials: Eth2Digest.fromHex("0xe02ee40d601028257747b8a429c224fd401ac674454ace65280f169eca07cec6"),
            amount:                 7324985409398823338'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0xca03e6b82cd3df289ed574c2deca216a089928bc944abd3efd26ee3124c45b22e7f541c02cc95f71ea8b52f0fed044ca14863b651c07b6e52abbce8afb500556a32e33a5f57a33ca6103237aa1c5bc409f4a2745b9828d6eff5360a2ba63d162")),
            index:                  18335046601207607970'u64),
        ]),
        withdrawal_requests: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD].init(@[
        ]),
        consolidation_requests: List[ConsolidationRequest, Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD].init(@[
          ConsolidationRequest(
            source_address: ExecutionAddress.fromHex("0xf059ccccbe2c2c647c9eb7443e500f59b185a682"),
            source_pubkey:  ValidatorPubKey(blob: hexToByteArray[48]("0xebb87808992003e0482b3e56df9b966fb33c46798b637a6663239157d19655d48f1e553905f7bc49f61d1f42223bb475")),
            target_pubkey:  ValidatorPubKey(blob: hexToByteArray[48]("0xb5ff2f18bf7efc34ee68ecfae0ff51611f382e9fc7dc34634f32a1b4387c3010e996dbdee44e26f591aa2e69c3b58f8c")))
          ]),
      ),
      (electra.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x2629683cfc70198038837270bde3c60176c2a4aeeced0d4a4f14dc99a380c377"),
        fee_recipient:    ExecutionAddress.fromHex("0xd234af1937861b66ca84c334824763fb54347677"),
        state_root:       Eth2Digest.fromHex("0xf79f02d52d7f2a4be99eebba3dfb3bce74136ea739da515703d095a66ce203d5"),
        receipts_root:    Eth2Digest.fromHex("0xa97ae6fa5d6937f7754ff96766a54bb8ec082b046814e74f6c9c67147795f526"),
        logs_bloom:       BloomLogs.fromHex("0x5d2ef8bc2f58a84e4050e3a38985e4c267940707c8da3f687fefb9e22e4ae11a2f79a24456af3758e8b521d546dc178da5c85da869ebb2da551976488a769ca2940fa20853e4e1d1fcf8d5bbea0d16973c827d38c97c47c57835677590567829d119e8108f2ee3fa988b267ccfc3e58e5f81c18c775a9baf06d4d81aee405c5683fa4e5e891b58101a27e8f71c60d357a4ab8bd02e12fbbb0e363c4632b0a3c0de638de37448c9476c65a62f7f1dd9643fac6ff78ee431d18ab554b4c8a1984fb5fa0de3464d223f236eb8e8a8f59601221d2ab480ffcefaf4bf6471b40a14773ac0cdb43aea505941e4b0fa6fb26eb091adad77acce41e516fc743e5fdb045f"),
        prev_randao:      Eth2Digest.fromHex("0xbe44d7c5f844a2acb307a4371784d7742be482aece83368d94813ffa1c7bb60f"),
        block_number:     13524449277995212660'u64,
        gas_limit:        1,
        gas_used:         7976957374052242924'u64,
        timestamp:        1,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[57'u8]),
        base_fee_per_gas: UInt256.fromHex("0x6c98d9ff36f1032fd55d8a6038d7b1f7c4e5f7c884b73f626fe43e687beeb46d"),
        block_hash:       Eth2Digest.fromHex("0x2c95101857b07bdda0502741da8cd9160ec0474929d132e9159098576f9a7c35"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[75'u8, 85'u8, 130'u8, 87'u8, 90'u8, 172'u8, 176'u8, 44'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[207'u8, 150'u8, 64'u8, 87'u8, 15'u8, 18'u8, 3'u8, 236'u8, 232'u8, 87'u8, 174'u8, 192'u8, 29'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[23'u8, 37'u8, 57'u8, 158'u8, 137'u8, 222'u8, 53'u8, 111'u8, 63'u8, 13'u8, 69'u8, 110'u8, 175'u8, 108'u8, 16'u8, 207'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 1071093368516669975'u64, validator_index: 15999188653672167093'u64, address: ExecutionAddress.fromHex("0x368b0ae1a6bfc3312460f212017e8bb32aae55bf"), amount: 13132185675616884508'u64.Gwei),
          capella.Withdrawal(index: 18446744073709551615'u64, validator_index: 1251419977457119333'u64, address: ExecutionAddress.fromHex("0x0a4d18e47c5ec0c639ff29d8f8c9be0b60f00452"), amount: 1'u64.Gwei),
          capella.Withdrawal(index: 2046299652899032730'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0x44bfe00f98603a5e8363030de4202ba50c7e8138"), amount: 15403504672180847702'u64.Gwei),
        ]),
        blob_gas_used:    819823383278806839'u64,
        excess_blob_gas:  5121347703897393436'u64
      ),
      (electra.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x190544155dd98bf86d3ed5ee94d01afd3a8e67b8476f94d90604706da0a7d340"),
        fee_recipient:    ExecutionAddress.fromHex("0x799d176d73d5d6d54d66941ad6cef8208677371c"),
        state_root:       Eth2Digest.fromHex("0x07e626b9c44b0ff14586d17acf79cb136ccc5d37fd7135da33cec516af168f43"),
        receipts_root:    Eth2Digest.fromHex("0xb8b100bc5c155fe6358b9a16756ec06880365f5fe89124cf9fea963e26d3770f"),
        logs_bloom:       BloomLogs.fromHex("0xc314d3d6ab41a3fce7433dc286ee5c9820d883ff572ee7dfd2f4ee745f11a71f6dbe142d8c14bd6cc76782f1bb2b3770e65a929b2187581956bad937907a124c92ba10686763ddc87ba5b4a4e9cf4b9a35255fad5f54b404aeed5ad9859b5f9fd3c137e9eb6ef394a10b8ad3fbba75ba38c2cbfb91fa793ac763e8cd31481fbecef02b3365b990f5120a2970f2779574c60769347ae334a9f39bb3d3ad35182f7dcd252bfe9663c4f54b44dea8d79e3bcd89877231e81a9e9f5c1eaf5da1f56ffc39c23fc3ae6c130281c792a31e7a60115d46abbe17807cd120038631ca7a6636c8c644b57719e386cc8ada32ce806f75110ad143522fb0b240213df4bab07e"),
        prev_randao:      Eth2Digest.fromHex("0x17e445793c0e354ee43381ded194220ebd87ccbacef83e3da5a1cd3c8c57bf49"),
        block_number:     5728529601694960312'u64,
        gas_limit:        9410734351409376782'u64,
        gas_used:         16470261240710401393'u64,
        timestamp:        8811957812590656903'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[95'u8, 124'u8, 151'u8, 79'u8, 76'u8, 171'u8, 74'u8, 213'u8, 207'u8, 202'u8, 63'u8, 2'u8, 182'u8, 32'u8, 115'u8, 65'u8, 90'u8, 186'u8, 34'u8, 63'u8, 241'u8, 191'u8, 88'u8, 10'u8, 197'u8, 52'u8, 33'u8, 98'u8, 78'u8, 210'u8]),
        base_fee_per_gas: UInt256.fromHex("0x3c1ba8cf82268c828c1a7f249328741ae21f35a7659365efd7496df94dbb85e9"),
        block_hash:       Eth2Digest.fromHex("0xc2b2bc39ed0cf5764800d3c91401828ed32d0eea58f9d336c32f9e6f7200ac8d"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 802141'u64, validator_index: 7520769587588158114'u64, address: ExecutionAddress.fromHex("0xce1fcedcc47b22d7e38f76c1cba49c2c20da09eb"), amount: 5845756482608800263'u64.Gwei),
          capella.Withdrawal(index: 4169028257817284566'u64, validator_index: 496485'u64, address: ExecutionAddress.fromHex("0xf99805deece4ff418b55557b45060e88035f755a"), amount: 4870783513883486430'u64.Gwei),
          capella.Withdrawal(index: 10410265605811982468'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0x31e886453fa4e7fcec6ce6094ad22950637d41a1"), amount: 157748'u64.Gwei),
          capella.Withdrawal(index: 10622085591419415519'u64, validator_index: 8179967808007927229'u64, address: ExecutionAddress.fromHex("0x03d2493395b71bb181db626a99c24dbc1d07065f"), amount: 18446744073709551615'u64.Gwei),
        ]),
        blob_gas_used:    14543409578714974146'u64,
        excess_blob_gas:  0,
        deposit_requests: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD].init(@[
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x7ad7353de5ad5fcef75b9e4c275970a4ad4cd5221ac692d5ee7f51d26a35a927f5a67d3540c5d08667772f78284a4987")),
            withdrawal_credentials: Eth2Digest.fromHex("0x1320977c1ca99dc4970e49e5d49c5f81fb3bbbf17ccf5b7963c070ac31bb893f"),
            amount:                 0.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x42a5b14b6d5018eedf1dc9bb07cd64ae2d25f583ad805d58d89b4c8381db8740fe188a70f1a1d2eb0e486807cefff900f93ebed94fbe2539edddf06f91bf347281f9dcc891db49d6107c2f88d678d32e5e9849a2be7b082919edb769b7c70abf")),
            index:                  16997402741851403011'u64),
        ]),
        withdrawal_requests: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD].init(@[
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x4bd763bcdfcf9fd2ce667c75408bc1157fa9730a"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0xdf62e8946d1457a50ce017fae0c36e5dc5177e642c18b74dd6df192620f8a32bef5f02453f0835583f6082f213df7245"))),
        ]),
        consolidation_requests: List[ConsolidationRequest, Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD].init(@[
          ]),
      ),
      (electra.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x86d7b430f69b215ab5ae863998ce41f01a5016376c8bec7f5b7a6e16a2326d92"),
        fee_recipient:    ExecutionAddress.fromHex("0x73068946d757f5d145a38fe9de817b8b1e9d6c43"),
        state_root:       Eth2Digest.fromHex("0x312b4af4d3ca5960dda2f99531819f5c32624753cc0756c05d242f65dd605d92"),
        receipts_root:    Eth2Digest.fromHex("0xf3a1e8f784ee4bdb897d1511ce642276e2ecbc1f21bfde9caf7c4479b7fdf902"),
        logs_bloom:       BloomLogs.fromHex("0x633d228aa8b2b9f4b614c4b7c7aca616232d61bc6e06ca28f4b94bc39165cf3ca2e090cebbe8a5b66b161d92e65099503327f9f2adae6ec5a73463063a994d73f37e12caec8f6d439be7520b48b25ccfa8ff64e6884b7e240c8dfd0100a23f9f644da13f1628d989eef92806c9f936a71f470d710653355acd84fb23ff15910f1d2866d83b036246c46a681e762b9a19e72aab21b428c4710511d0a39cc5ec39ebf3aecb5c19096ab32135a629abc8cdec39b2b3631bf4e86bbfb824276fd728bef454ed981e5f9e8a4bb96b27f09f661c5c221f63a26945174162496496c9bbf38cd894c50fa69df0a8c722ab48d75044bf43468639ae9b61d0b5a2f9d819eb"),
        prev_randao:      Eth2Digest.fromHex("0x3a0689ac32c82a6b84d3230fdc6e2c1e89671fa3906336ccde9fb7cfd1811ac8"),
        block_number:     9465334901279616671'u64,
        gas_limit:        17844363972830076325'u64,
        gas_used:         9534663249377184661'u64,
        timestamp:        15490999633909732541'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[199'u8]),
        base_fee_per_gas: UInt256.fromHex("0x9fc9f32819a67c4aebae259b0648e2b82f526ce8eef8fee33961f9fc69653b2b"),
        block_hash:       Eth2Digest.fromHex("0x1ac3f16da76520977c5e5d86f0c261d76e18413c202e8a46241951b3a80ca601"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[223'u8, 37'u8, 18'u8, 125'u8, 208'u8, 57'u8, 114'u8, 113'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[137'u8, 181'u8, 143'u8, 219'u8, 145'u8, 77'u8, 39'u8, 126'u8, 173'u8, 30'u8, 59'u8, 70'u8, 205'u8, 51'u8, 16'u8, 213'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 0'u64, validator_index: 7432737887980948854'u64, address: ExecutionAddress.fromHex("0x1a99860ddeecae3195a051bc0a0fcc37d0135e37"), amount: 921585'u64.Gwei),
          capella.Withdrawal(index: 8891974894683849035'u64, validator_index: 18060634568259374245'u64, address: ExecutionAddress.fromHex("0x53a6cc4c3996f0181cfe62be861900f56cb75a87"), amount: 235145'u64.Gwei),
          capella.Withdrawal(index: 11531749110606308043'u64, validator_index: 9858359378531619375'u64, address: ExecutionAddress.fromHex("0x6b7a4bc00868b077f1c4aa53369e893162bcc384"), amount: 18446744073709551615'u64.Gwei),
          capella.Withdrawal(index: 530041'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0x4b7853973d34b1efe7722be5c688589b49c1aaa9"), amount: 18446744073709551615'u64.Gwei),
        ]),
        blob_gas_used:    9156166815001018661'u64,
        excess_blob_gas:  13354810927429053716'u64,
        deposit_requests: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD].init(@[
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x6ce4fb12127809ce5bee8b8bcd25790df1df55b636f64ac7cf646af8d20e4cf3712a03e55b77f37be494658cc79beecd")),
            withdrawal_credentials: Eth2Digest.fromHex("0xf4192de759e26b7fafdb9342168586029f4526dc67ee8b161dab7e057d060176"),
            amount:                 6209827226225403552'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0xa829b6d810883c32466e2bb858bfbce89865f1d3fd71883e4e8b8d7df83c6a18e96e477249a22f0a7b16efd177b982e043f3cce23127c95fdf4e809903a5a906103c25ea6fd36df3f61c3d7feb00ad49937ace39c5ea44767d7f627d25572156")),
            index:                  6407923788439683512'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x5d0d1f7e35e59873d58f7a723c510186deb7f03b3fc0074d1d6ba90f49ccedfe7b262b18c7f362a7ef81acc98437e188")),
            withdrawal_credentials: Eth2Digest.fromHex("0x0221b17586adfb32e428829e7c90c7e5d8af40f26534a1e82658d887358de265"),
            amount:                 3864819260875678713'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0xfec65da38278820cfe4168de78631f7b100146cec2d4aa3002ca3a783e81ca95954351666be524ce681e4a5799f6fc47a092baca86727cbb024013415c832f8a45346e30759753c39bc6e5e17d963f7b7483f4bbd3cdaf7707ee5b51448c2516")),
            index:                  0),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x2ffd86a5a167ed01e994b0b42077e5df2d9703560c6e8d986a8025f28c316ab4f91bcf3d0fb285c66bd9558e32165f8f")),
            withdrawal_credentials: Eth2Digest.fromHex("0xf2afb039d649f80905f7b2f37927be964d1c8be69ff51afefb87d597d03cfacb"),
            amount:                 0.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x7132e4495443a0542cabf627dd5952ad0e38d000d166045c92b3360835de266511383429cc8980eb54730d8f4ced119e95452d3fc53c8a6f02da22239376356ed9bef153b632b928314835175d493dfb402f4d07ad262e9330baf5f3cef7b000")),
            index:                  8224197877093273527'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0xa6ffac664fa1f64295679cbf163ad8f1716be062460e2a645c87d11368a4119d4138311d45506867c8c75d89aeb905dd")),
            withdrawal_credentials: Eth2Digest.fromHex("0x7cb1f70fdb82a4c7b8415df98d90140ec58fa6422b7066b2da2d4bee20d95d65"),
            amount:                 6485560087895553151'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0xbd837ceae239191f7e958fabc91efc7b3830da9814f4d888ec278ed0fbf870e811db948bf81377fd53339db9095f3c71b36de09b6f5b38a18caba6d3e8f337bbcb107380ee3d50058e3d266653860b1c6a9309eb60f142948f53041a07109f4d")),
            index:                  2237248193846176262'u64),
        ]),
        withdrawal_requests: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD].init(@[
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x614d16bedf5dfe9d06171e3ef50671e66fadfce4"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x9f92a4aa0e58f82ff2ec0bbe4aca6d338fd08ffff3213f64bef81148f7dbb163eb25add8ccc540ec0dd1bf9d237e26f9"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x4cff44c8f0353fa6dee31f6c87e4b8c3bcaf1c38"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x3166f8e41daae4a0af1549a00b95ad9280d73e91a882d49c827bc078c88300264e7171cbbf50e3598da77bcdb175a203"))),
        ]),
        consolidation_requests: List[ConsolidationRequest, Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD].init(@[
          ConsolidationRequest(
            source_address: ExecutionAddress.fromHex("0x6a8481544d310f4ab07679dc86cff400e403f789"),
            source_pubkey:  ValidatorPubKey(blob: hexToByteArray[48]("0x5a89a8355effbeee155130234f8cb602f5648a01290f216272d532cf8a6c2996a55875a804012d4dd2217d4f11353b94")),
            target_pubkey:  ValidatorPubKey(blob: hexToByteArray[48]("0x9fe9b12de144e810792b4a82bcbaa538249fd5809df54b5a83f32fc9f290b4ce222575e589d59291cc9c0adc4ccedb8f")))
          ]),
      ),
      (electra.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xc51bf481df9be981c6656081e3854ffcf27551e2b4fdaed4ab12b355f247f4e1"),
        fee_recipient:    ExecutionAddress.fromHex("0xd79098c25eed05c9f6d55e95f5f6f58c1472fb28"),
        state_root:       Eth2Digest.fromHex("0x1a6b1eb78e5ac155d4be247a3b48d8d8d8574a16fa846681553037629b97ffd0"),
        receipts_root:    Eth2Digest.fromHex("0x5e44d4a3621cd8e495edc0b208f977c8d3f8e79a78fa7ecfc4a0f6e436f67b71"),
        logs_bloom:       BloomLogs.fromHex("0xe2b0dcfd2341ceb9c4edbc7115dbd6ed5f1c54ca39bee191fdaaa34368acee93f48561094dd23a3985ea2c2b83d918ba9dc671cde7732a591b4f9abd2eacf9d6416ca8c8d556052a98df2cffdbb086315585004c51c76872a06cee7d318f4845c0ade4c907c7933d4d883bcc586885be04ca9149e05b1624856e69e1efe8c93cd55d840bf71279293a118d51d4391fcbf4e6abe6ee50492ff2de085069a3c7656eb3a749d6bf46f56a2acd93a6840eb78e09a42f23fdea69bfbf017f4fd6b4a8d17df1aa5147c1897fe5fda1f5e79121f2fefef97117e7871d1cbf5b0b0350b9fc497c5aba27cbc129d452d6a60effb76e08b890d0bb856115fcfe3966359fda"),
        prev_randao:      Eth2Digest.fromHex("0xcd6fd69596cdd7df95e0b68e8ade01541b12ed15caa2b59803a4c4e6791870d4"),
        block_number:     12264963829660560313'u64,
        gas_limit:        11775806146734810959'u64,
        gas_used:         1863395589678049593'u64,
        timestamp:        5625804670695895441'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[183'u8]),
        base_fee_per_gas: UInt256.fromHex("0x1443705192ff4dc1a819be4f22b8dcd6e7802337e62082880b1090f44a27d0e2"),
        block_hash:       Eth2Digest.fromHex("0x68da52444eb5322f3a0bda6bdc9a3a11a540dbd22026bb2d24862bbc32af9460"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[212'u8, 80'u8, 176'u8, 133'u8, 132'u8, 119'u8, 233'u8, 131'u8, 195'u8, 118'u8, 54'u8, 94'u8, 129'u8, 206'u8, 47'u8, 107'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[231'u8, 31'u8, 192'u8, 94'u8, 136'u8, 120'u8, 228'u8, 222'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[114'u8, 23'u8, 239'u8, 220'u8, 169'u8, 188'u8, 213'u8, 179'u8, 223'u8, 129'u8, 189'u8, 50'u8, 158'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 18446744073709551615'u64, validator_index: 109465'u64, address: ExecutionAddress.fromHex("0x30376c1737df493e34318acb7efa0aadd3d78738"), amount: 419309'u64.Gwei),
          capella.Withdrawal(index: 3744271566165938073'u64, validator_index: 162930'u64, address: ExecutionAddress.fromHex("0x9a3eee4729cf5ef57a1c4aeb474636461991270a"), amount: 9043308530560640624'u64.Gwei),
          capella.Withdrawal(index: 10893292846301120513'u64, validator_index: 15952780188276928656'u64, address: ExecutionAddress.fromHex("0xfccc1279aa3dde74ea08b699fecb4481c777f259"), amount: 5614376920521492084'u64.Gwei),
          capella.Withdrawal(index: 18446744073709551615'u64, validator_index: 2895353066704396409'u64, address: ExecutionAddress.fromHex("0x7e8b34a029236dc0d15db19153165d1eccab05a8"), amount: 3749025806369957542'u64.Gwei),
        ]),
        blob_gas_used:    0,
        excess_blob_gas:  1597862542620394734'u64,
        deposit_requests: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD].init(@[
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x324b63f48d1a5e1b0858799c200e774326b0487e3037f048d20462065e42065d189b1419b018b06becdeb7ed46eacec6")),
            withdrawal_credentials: Eth2Digest.fromHex("0x98b06ec79f8c27a94d13de9774ef0e8756a08650654771aee335ac0c4f14a36b"),
            amount:                 5951406920150253456'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x3cffce51a48cb97b5ddc300c82cecad819bf8d7220e95785908969adc2fe81a4c54ca561b751f8f8afc987bc232b75c3fc590368b51433370bad030aadb7a9f7e5975aada8f6c8f8954fcde7892af4f957daf88b544594d1094ab10072e2efd0")),
            index:                  6209810282279082517'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0xd40cedb2ee345c1106a11b9df2b99b7bf6c87172052a084b7f51424b0eb5cff3b9de788124974d89ce20bcc41d12a3f0")),
            withdrawal_credentials: Eth2Digest.fromHex("0xa31f86305d23a833cbc2f0ab5bb3d7eec6418ca06e2bd16368cdfd849b43a592"),
            amount:                 6087805632659367228'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x7a4df2b27bded4e1cc2e20120e70f576e9991369d77dfad54186d3067416bfe1f7cb7a1021a9c0722370680367fe4c12e571902c2f4ce4c2754a4738c10ead67b1d9a1a82b2ecd4ce3b6567c87e0066c979664bf79025851cd9583c5ed2f7c2f")),
            index:                  4361690020859323832'u64),
        ]),
        withdrawal_requests: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD].init(@[
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x9c2b1570328c29ef47c715cd021aead97695741e"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x6d3da7dd6f61e0818830bf11df8c91af8be664041d8832ca48b0c90566963acaa54695da7fb9ae2904d1aa0d7de5dcbd"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0xf3fff390ae583278167deb91dba09b4ba089acaf"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0xaeaef2b0928efd727bab75c3859118681492d7aaa0ceb7cb0897e21d4689ce7a6a9306850b2dbd801cb3ec165bb97d68"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x9a89ea1df940046760d3a84e134ea525a05a91fd"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x7afe11eec6aa2da5eb2bb7f9c6f2329ef9b9c17cd2f2ea35fee5e4169bc4e26c73c30cbbde16cbe4ae2351266454c31f"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0xf77580ffa7329925db0934de5f3667b1a32effd1"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x3f5026c08a653bb8cc9f46a5cb1c35200c43efb6c44f729b48d12400828f5029fdc88f4672f1f9393d7d764ba3599bf1"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0xc61710d4969b77326cfe3ee23b65023c23e8789e"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0xb2952e0f7d6581c3032f95f4908bf76f6df8d7e866b7b67996254597ef73ce9a15dac375b78a3456d4f7f156af2b5ed5"))),
        ]),
        consolidation_requests: List[ConsolidationRequest, Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD].init(@[
          ]),
      ),
      (electra.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x8b3e7e8d447527b9d00693389928260e7ea9da6855efd99369182bd9c213988a"),
        fee_recipient:    ExecutionAddress.fromHex("0xb45716c9aeddeb030c0b94202fcb97bd75a039b6"),
        state_root:       Eth2Digest.fromHex("0x8114b285e5f3277c04a66e660fef3b86295d6ca859dfa216df3309c0a7242f2d"),
        receipts_root:    Eth2Digest.fromHex("0x2a3ff38541ef83faad176c3c98ceb5c55622dec83fbfc5a19bdb27646849e852"),
        logs_bloom:       BloomLogs.fromHex("0x384a9b3d38d343af68d00c229e79aa31f2059e17c655f5e48d31d2b59b769660e91c1e5f386e4f7dc83f2570029a6f2b3351623fcb4dadd6b5b7b26e27de19e248ebd970a9678b69403ea8e16fe88562959586fcfdee3c407fcf623c94891a2270ba1829bf2ab77fa32913bb11c8a4a69e9baa6544ad336253637626b16d4a98884e7ac7d6c1e697a9435b1e5403b5122eebddec9c03c8a6c8fed0d8877888371e133fb837d33f073375f7e1536abf622610734b9b0aced8a891f02d5b35734e58b0ead66c49ed9f898b8f27e9415275c5d15051ec00cb006f8aef702a7414aefacfa9742cd3d8d34be817e0c731696e20b973cf2da66799121c0c6d12bc835d"),
        prev_randao:      Eth2Digest.fromHex("0x3bd54c7151dae2ad524b4df0d4283e3641ba787fc76f54221dba3a2aa556a1bb"),
        block_number:     18446744073709551615'u64,
        gas_limit:        637978774023867007'u64,
        gas_used:         15110835166938431016'u64,
        timestamp:        18065456863038184935'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[235'u8, 229'u8, 162'u8, 249'u8, 154'u8, 135'u8]),
        base_fee_per_gas: UInt256.fromHex("0xbe93cc3dc2bb7e012db659df49e57653bf6ff21354c64eeb69c0002e9f933035"),
        block_hash:       Eth2Digest.fromHex("0x46cb3f590b2fbce372e67968a0d2ff4ce1b2c530fcc26b7a24ed6db054f52035"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[16'u8, 66'u8, 215'u8, 40'u8, 223'u8, 195'u8, 43'u8, 228'u8, 225'u8, 244'u8, 34'u8, 14'u8, 117'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[92'u8, 46'u8, 215'u8, 218'u8, 71'u8, 99'u8, 115'u8, 119'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[]),
        blob_gas_used:    1,
        excess_blob_gas:  1,
        deposit_requests: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD].init(@[
        ]),
        withdrawal_requests: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD].init(@[
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0xe4bed2d5de111ca1d0a77bf6006c09ced6c6cc89"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x814d7cd0b6d428414fa787584e1eb52a5f215b8f0e7792499365f465ac43f5696e8d18ab579568c348f6dde75c189301"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x95137ca91b36a9a753441d911bdf91677931615c"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x0e223fadbfa2985e293f13e083bbe22a9a208d0e9f37fd99d24be92b3e329d77f1d40d61b891e2bdfed12ca746eeec50"))),
        ]),
        consolidation_requests: List[ConsolidationRequest, Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD].init(@[
          ConsolidationRequest(
            source_address: ExecutionAddress.fromHex("0xbcd0cbd6a0bf406f2af8b28c0d7509f80bc020ae"),
            source_pubkey:  ValidatorPubKey(blob: hexToByteArray[48]("0xd51d34ca13ca3ae5c9f2821414457e0a0e19ac03057e84371954b0f20d4e834997d9592c9e5c3b548097a2497fa4b230")),
            target_pubkey:  ValidatorPubKey(blob: hexToByteArray[48]("0x097c5ccdf7e60c886c2fced51dedd5be62f20aed504898cb89e215d655bd5cc450a2219b805717497c978c1fabd7faa0")))
          ]),
      ),
      (electra.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xa4854e346d2e9a921cc6b3c4ce9fc739c99795cf10002924089f9886f8624d59"),
        fee_recipient:    ExecutionAddress.fromHex("0xa88781cf69a1eed63bcc3a32b6f9aba35d4f5b5e"),
        state_root:       Eth2Digest.fromHex("0xdc06d9210fd2738b0fa9df6d68e4ffbfef0dd7d7d8093fdbcd97ff845318cf6b"),
        receipts_root:    Eth2Digest.fromHex("0xfe1b70c143066edc444f9b49e778cf6db0060bd4e9122564350cf23061830439"),
        logs_bloom:       BloomLogs.fromHex("0x095a57c3f2d97aad8692cd09dfdd8388f1bf9ef98a1c3223ecfd0aed17d8c7c3ef593d7f09ba86500644deaa676df811da501d572f342e3f7ee7b9b081992f344f71fa50b3b9635d7375f67dbd85a0b1ade3d8d4778118df55b90c44f7dd1114f2ebcea5778b32701ef94af9b3713d1fe00275e09c7e918d7c529a37aa9de3464eb6364812ec486464ccbf7df2523369fdeb1b28955e35e8685c16f07fbe342edd1bc044021ed480bf4ceffefb13eaf4550c67ef8a5079f3f612f07fff60193eda6ac11d39f3056c41ea4355ef5ef7f311493c415cc8c42cb30a73dd58098262acebe6d901e4bae26b6e1eba693c7dc596ea27b0cdd4fee2f6450ca8b50b1a70"),
        prev_randao:      Eth2Digest.fromHex("0xc52844ad11072faa2222ffe9cbff77dcc7f681367d2aef5f1c3b206140064195"),
        block_number:     767785029239287422'u64,
        gas_limit:        15062566578072747104'u64,
        gas_used:         7648884410596067087'u64,
        timestamp:        4380084205540210041'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[217'u8, 40'u8, 125'u8, 94'u8, 156'u8, 71'u8, 79'u8, 66'u8, 117'u8, 228'u8, 173'u8, 189'u8, 115'u8, 41'u8, 153'u8, 226'u8, 130'u8, 21'u8, 108'u8, 194'u8, 206'u8, 218'u8, 141'u8]),
        base_fee_per_gas: UInt256.fromHex("0x436767990abff9288346859c6b85b8a972421619eab2253483385c8151cb2016"),
        block_hash:       Eth2Digest.fromHex("0xca4f05c33836d82aee8230ef660016b993bca4aaf9a7b6cad96c2a0193eb026c"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[156'u8, 143'u8, 203'u8, 250'u8, 238'u8, 137'u8, 34'u8, 245'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[64'u8, 44'u8, 165'u8, 9'u8, 1'u8, 211'u8, 27'u8, 108'u8, 166'u8, 61'u8, 119'u8, 11'u8, 222'u8, 85'u8, 48'u8, 185'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[165'u8, 95'u8, 221'u8, 213'u8, 229'u8, 134'u8, 185'u8, 221'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 373208'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0x1ef66a8127bdbf1302c13af1b2a3fde17f1e421e"), amount: 12972917955689502470'u64.Gwei),
          capella.Withdrawal(index: 7007268656739027478'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0xca30e17b5a7925b1a5afa06710d6cffb4681d2fb"), amount: 13141021224557402822'u64.Gwei),
          capella.Withdrawal(index: 10730268187610256048'u64, validator_index: 7483561449283560970'u64, address: ExecutionAddress.fromHex("0x84e755db228c9399912364a239227c467477e076"), amount: 16091384671148001130'u64.Gwei),
          capella.Withdrawal(index: 861292'u64, validator_index: 101133'u64, address: ExecutionAddress.fromHex("0x70e7126e6288dd8559b6bf8946b98fe02bc53e8f"), amount: 5439105246644982514'u64.Gwei),
        ]),
        blob_gas_used:    2533380168586417970'u64,
        excess_blob_gas:  307516487526704997'u64,
        deposit_requests: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD].init(@[
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x4dfd0237e85c7fa842fe25ed710e4b9394731e38a27f2adaf03f7c15c0478917d31d93b7acab73f6af454e86dd24b99c")),
            withdrawal_credentials: Eth2Digest.fromHex("0x6cacb6bd39183416e6bbef6f4725e4b1ddff84fe80f4630183f2cbed9a23e135"),
            amount:                 0.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0xe7c07da5cb5f8fda5223db042db39643418920beba7e66d1e3bcc3ba6e80170a6846caa6d67a544b3863f57eadae7d86d09d3767a20d1568b4796b32288156dda21a6ee036a47b51a806d2c27724e7ee4f974bf03116b85184a8f41c53f068f6")),
            index:                  0),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x7fe03a03b1e91c134ebbcf8d3f80cb282b2f8f06659e80681aeba55b08353fd4306f6ee71be7c1f3e64df0d3ca945a15")),
            withdrawal_credentials: Eth2Digest.fromHex("0x656c24211a240b215d2a7d97a5410fe7a182e34b255e11627d03c51fb9e5c3b1"),
            amount:                 14255636113874187022'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x8e0886f9bd55885f102852f38c980d2bd9304fab0fddc803f4233251e4c5ce891fbd53d8079dfccdb67dfd7f713fcab0c4f9e10a6cf5cdaeaf9195827b6579d36b8822e24631c1c9022d27f99cf414396f3c889e2e24d58d547d79c27291e724")),
            index:                  12470930277850569937'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x629474c4e5a9d1ffc7507e388d86eed83cf0762eb404ddb5860bf575ef4f6a7ff3dce8a63a09375e3a9a5a49fbc6fb72")),
            withdrawal_credentials: Eth2Digest.fromHex("0x48c7a56b506f4838f3dafa9ba67e43a3aa2b681faa6b573ea68acdf55679f15e"),
            amount:                 14112283334180796705'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0xc614759dcdc309a46d9f24ae6b2840625bc5ddecd802c2907f9141d9091966e3367d78b3963717877a6110d741f40b45486acd32ac0e7bf1b4c36e681411570a7d1156dda127c1c5e5c6011ff857222ea51086016c01346e6cd2c8764bc7e7f4")),
            index:                  9892892756897161299'u64),
        ]),
        withdrawal_requests: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD].init(@[
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x9892501906b7abf06fdb6893b8e1767884bc17f5"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x30099e0ee2adf0d51a0a96d10fd2fd5cf6f17cdb4b4ea88b5a0e205bd10d40319595e0403891aaa1bac82b980ef76f23"))),
        ]),
        consolidation_requests: List[ConsolidationRequest, Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD].init(@[
          ]),
      ),
      (electra.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x5e7b12465e0461e5dfa59a3254282378c55961b0e411023ce89d968bbdc33e9c"),
        fee_recipient:    ExecutionAddress.fromHex("0xbd1a1396ab49631cc933770944996b294da97d43"),
        state_root:       Eth2Digest.fromHex("0x74e6ccfb15da8afb94eebf28cb3ba3f9ce63e3354097f2f2527fe1cf978e76bf"),
        receipts_root:    Eth2Digest.fromHex("0x8e48bee56e149d1851cff0740ceab06767bd0e819261c5a2f75dbea382a110b6"),
        logs_bloom:       BloomLogs.fromHex("0x7894fbe58c624a153dbb160c516c9e82bd0cacf5f347f984efcca9450e9a20b50e058ed38e41c331df61114086f8a6b8a049467d7dafd812953aa593b2e9fbc056f0dba80973b2eaae8814b5e0804300eeea15613e59c8d34339f58e1b45599361497a3608c05140cf432e7983a30985aa0faf45dff56dce99eaa5ad3418722df17eaaa4e8df25ed1d9eedee1390e6440c4c37675182dcc07ff199d6dd015d3aa03194765e85fc0d4759d3c693fc2550e50835b88ba41d10fc33b58550d813abaa75bab39c0fbe419f1bde8fb82db9fcfb79894faeed84b2314f115a8fb9e276315ccbfb8e9650571add358f594ff2fb4ab9661afde76081bb2cfbfd2f26d212"),
        prev_randao:      Eth2Digest.fromHex("0xb9a9bce05e42cf3d2ffc2c2ea95164c9b215fc8e440dd2985ca24cff40e32780"),
        block_number:     14460352585391846826'u64,
        gas_limit:        2426408612341958329'u64,
        gas_used:         13656152006197676019'u64,
        timestamp:        6263571560389404595'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[177'u8, 36'u8, 79'u8, 26'u8, 164'u8, 59'u8, 182'u8, 88'u8, 223'u8, 22'u8, 79'u8, 197'u8, 109'u8, 53'u8, 53'u8, 134'u8, 244'u8, 84'u8, 146'u8, 158'u8, 234'u8, 252'u8, 188'u8, 175'u8, 69'u8, 51'u8, 118'u8, 101'u8, 242'u8, 0'u8, 51'u8, 103'u8]),
        base_fee_per_gas: UInt256.fromHex("0x997e6c8ffbd1ea95e875612109843c6cdfd0c6bcaffa1e06ba303b3012b3c371"),
        block_hash:       Eth2Digest.fromHex("0x9a7f83cf6a64e153fc3316244fabd972a49ebf5dfb173d7e611bf3447a175c41"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[137'u8, 103'u8, 164'u8, 112'u8, 136'u8, 91'u8, 170'u8, 241'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 12452742873210027116'u64, validator_index: 163643'u64, address: ExecutionAddress.fromHex("0x5d09dd69d2b2370e11b21d758bc82c2a73ee00d0"), amount: 12246034467900494037'u64.Gwei),
          capella.Withdrawal(index: 256915780184525584'u64, validator_index: 364410'u64, address: ExecutionAddress.fromHex("0x40a55ad4a156caf112e2abe789554520814e48a1"), amount: 297315'u64.Gwei),
        ]),
        blob_gas_used:    3541847679255581458'u64,
        excess_blob_gas:  1,
        deposit_requests: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD].init(@[
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x0040411f8a57799b620765d6125d09ab8aac3074bd7ad75c4c02c99e819e63ff37882940702644921ef7509d48e45c4c")),
            withdrawal_credentials: Eth2Digest.fromHex("0xf601917dad8bf2e472ad4da2affd60b710264fb1802aacbe796acbae3bc26930"),
            amount:                 3582020308334691622'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x811ffff27712770001d25199c5f1689ef102362da9a617fe7a9db13b50949c705defad17795f52d4db786e80ee3b963b402f5cbd4772bbca81893a104f091a2b11f025287250200fdcee4ad1fc20d24cee626d89c5d05360e9d19e94c8e129d2")),
            index:                  9118657603155344378'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0xeec8485a98937b5c18d52d02e8e52ef6a72ca2d0fccc367816789d49b9596e1814b63a3efbc4faf11349f360abbdb046")),
            withdrawal_credentials: Eth2Digest.fromHex("0x557778b1a01594a2fc0bc05835de388ff3c141bd3141820c286fe114ad14e80d"),
            amount:                 5881642850443225888'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x967057d2edd3b53ae9fb665fe668ab2319403b4f8e4620064b11f0933f9def18d952cae5f50395ffd1a8e8554604d95371b7643386df808a18c913e186a7a915e5a5c65908dd6668f2c0d02e404eb88d3499c096967e93b791d814429caae9a2")),
            index:                  7603599240231509693'u64),
        ]),
        withdrawal_requests: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD].init(@[
        ]),
        consolidation_requests: List[ConsolidationRequest, Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD].init(@[
          ]),
      ),
      (electra.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xa8f90a617f1f230506d200c6026bd60e38f599930ed04f90cdc320a6d45bb022"),
        fee_recipient:    ExecutionAddress.fromHex("0x3531157eaf2c185bd8720f3edfaf76829632f07d"),
        state_root:       Eth2Digest.fromHex("0xa16f8936e945ecd45a4ae107e46acd8530e438fa1bc8eb85aef62afaca1656da"),
        receipts_root:    Eth2Digest.fromHex("0x3e76522c8f3b7e8d8a63f4968ab15413b8bbd7af9782c4878b52213b0b3d13f8"),
        logs_bloom:       BloomLogs.fromHex("0xc13b59de763feaa39debf70d280364ec68eb578af8a90aba7e2cf3a6cee413a28836c674662a0283df8ff04964eb928de97a3883226950b584d773c9b4479d6d5bda6fd71951c0c846752ed688e13dccff947b7a6c81bfac198b6bf785bca7be28bcf9a208b983afe6e766b0536311c1c12b4d01c712cdaa167ecec5520395068b1c1f939d20962de1aba36454cdb36031fa0ba886a8ece71234654e8b081562452046a388ebcf3cfd975493833ff4e146d5e5ddb061d994461ab8b468cf1d6d491d78fd8923f9f6563e3fbfa72639de993701ff6214fd83cd3597e870dec1c1e788a4f01f881c48e57b07c5a217132658208d2221a86c7e9823159984d235b5"),
        prev_randao:      Eth2Digest.fromHex("0xbac4a9aa16b289584d13abe3c47a58dda713c4b479ee70e1ac7b3b698e8505af"),
        block_number:     4839752353493107669'u64,
        gas_limit:        4713453319947764960'u64,
        gas_used:         3470256075652600568'u64,
        timestamp:        13764471837770950237'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[60'u8, 109'u8, 153'u8, 55'u8, 17'u8, 196'u8, 17'u8, 96'u8, 202'u8, 173'u8, 16'u8, 189'u8, 165'u8, 107'u8, 68'u8, 230'u8, 238'u8, 62'u8, 199'u8, 211'u8, 244'u8, 83'u8, 88'u8]),
        base_fee_per_gas: UInt256.fromHex("0x3adad83f48e34c6220dce41ecc0b09f9bb1ae4bda4466935c70e7c6cd54e185e"),
        block_hash:       Eth2Digest.fromHex("0x9183524f908425608c1e3a80d7c4ac2c539903af4b3a2f1b22c3283281706aba"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 645596'u64, validator_index: 248698'u64, address: ExecutionAddress.fromHex("0x124e32ea8d0363647a58a5511b6de35bdd50236e"), amount: 18446744073709551615'u64.Gwei),
        ]),
        blob_gas_used:    3410596457491766161'u64,
        excess_blob_gas:  0,
        deposit_requests: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD].init(@[
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0xea1c8a68747bf78cf13fc0035612547fa9b98da285369c234822eea879ad1c86c5c7d5516db5ca374acc023a21ce0477")),
            withdrawal_credentials: Eth2Digest.fromHex("0x6cc96c66ac799953125c24b4311e703728b294ca302ec0dfe5e82fcbfe3636ea"),
            amount:                 10141350867210496320'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0xd6a92f4de599923ba4955c360b2cd54bd544e2b75947127fefa9ec08f5e53cf02bf398b63a0420226dd356fc5d50683eaead8a5aa8a6d4fdbe62296506c813e5e02a2513b6457c1ca408e1189fba32e80d74c48e389f62c7b0b0ff3c1881ec55")),
            index:                  14462442824619447645'u64),
        ]),
        withdrawal_requests: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD].init(@[
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0xf55f4b626328f2b7a725d8a3f8485072eebf7f6e"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x3eb1812d045ff1d2f7d96f919c41230db2993ed8194de6ba564fad54047e3b45fb925e5216cc47f69e184a4e2c45ce39"))),
        ]),
        consolidation_requests: List[ConsolidationRequest, Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD].init(@[
          ]),
      ),
      (electra.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xc914f63464f3f1588a32d3751900d415bbf1fe002c42068650f5c7c588b1935c"),
        fee_recipient:    ExecutionAddress.fromHex("0x61523b6add59cc65d3c5b75c6f749fa601e157de"),
        state_root:       Eth2Digest.fromHex("0xe84ecb995f6c7e753355c8d2e24694441c528b65ef9b1d8c6f4e9d98d409342b"),
        receipts_root:    Eth2Digest.fromHex("0x887bdafa340c24acb58f36a7e3825ce39fb7e0caaba3a9b63f78d2186cc6994a"),
        logs_bloom:       BloomLogs.fromHex("0x1fbd358ad7e32eefe4489b6c72bafcf6dbac109970e5c103e329279cede3619faf1309faf266ba155496c19565b31562f31539c98b6256919d8950bb6eca937401d91fa5b3032b4400ce6dd60a8c1c6cc94331b7e78d7a350ebb5d6e04a2594af981f167a89227c7c902dbb8eac3d7b54177d85214a6ef57b50da82b6420cf914fd63171f0b7dff9233bfaa2069774b142a136c5183ed4f57cde2590735b19ef549ff5bc910477b98344e7557ffc440b03d56842f356a6e223fd052c6272e24f43dc9e64055c097d81b56ecfd6087238602a743e09c383ad4eae6ef449570febdfebfefa347f06f480f319ff06365bbfae16b62a950143f9acc3663510356f0c"),
        prev_randao:      Eth2Digest.fromHex("0xc755584f86084ab2e62bd58f25dfe54538c0171e6447e7e1a51cf05db94377da"),
        block_number:     9276126375553452674'u64,
        gas_limit:        9007257403963034102'u64,
        gas_used:         12806310385580231715'u64,
        timestamp:        9957937708118639445'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[]),
        base_fee_per_gas: UInt256.fromHex("0xe2df33500d1162994934e9fa65fd5db641b0be2b61a6c302c7b9019f86042338"),
        block_hash:       Eth2Digest.fromHex("0xce58ef51926a6eb4cf2997c4ec771b54907737ae8fe9522fc316c97a1c7ee6d7"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 16986670237072862757'u64, validator_index: 701065'u64, address: ExecutionAddress.fromHex("0x50371592a27339f868b9ef63f6c02e8c1e72ce94"), amount: 3561319411833205205'u64.Gwei),
          capella.Withdrawal(index: 2402770018709110103'u64, validator_index: 798632'u64, address: ExecutionAddress.fromHex("0x9d42c6c10cbc0b04e3f2e74f63c777802d4ca064"), amount: 898967'u64.Gwei),
          capella.Withdrawal(index: 944680'u64, validator_index: 507423'u64, address: ExecutionAddress.fromHex("0x640d578aeed6b8a9acc83f13343f3139fe8f4a15"), amount: 941781'u64.Gwei),
        ]),
        blob_gas_used:    15366131400223670470'u64,
        excess_blob_gas:  13352270791962864689'u64,
        deposit_requests: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD].init(@[
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x1e9d9b4c3b9ade4b4835d9ca67aab333ec3019b775960c734627ced08ff62080f47879339cdec66a6e3c6c54adcf5004")),
            withdrawal_credentials: Eth2Digest.fromHex("0xfae4f9dfdeea6379f5623d452670c431331e5cff819bd1f3d1cb24f5f34135fd"),
            amount:                 18192096631954481393'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x0c8407a90cf206e5233d3c702e23dfeb2238ce281cf00764fdfb3d12708babd45d21767373a0c57231f20d2479cc0fcd88b58547c0281e76584f709b1afe4ef4bb0b65db3a3bf9f87e1e11fea88caf23b4ac9d9b84efdfae174628bdea84c7e0")),
            index:                  11885726942708777117'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x5ffc8c61c4ea561e6de463b54a9b09d9d467fb3db6149c40e5f0006c1840e605bd26b92414e61041c6c9f7527920d346")),
            withdrawal_credentials: Eth2Digest.fromHex("0x77e707557d73e53cc2ca694428e99b2acb9e56cfe0f55afa5e58772a533e9e61"),
            amount:                 699724654155768223'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x597938ce07c7c767bf0ac21bbdb56e9696db13044da930cf916b01648db8ec1ef4a989e483b79a381c2de2cd42a5a01ba96df21cbf71107330eb23e5de99797ddec2044c83576a7567238230d8fe19f421986761615c6ce1cb66502911c65e56")),
            index:                  2345813180163742962'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0xd8ac112850aa690da757eac4bd7726d222e04c48e22ded62e24880fa4419948cbf5a2325fe3e1bcee205f733a308a39b")),
            withdrawal_credentials: Eth2Digest.fromHex("0xb796c0757bcc940a422de5d3f8fc4aa130f7c9db954846330a23dc021bea4b61"),
            amount:                 15859650167034453942'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x2f470357ded569d4fe968b5da6619cbeb414271e71ec7abc8e0e6c7c962b1932934bef085f682bc6af358670bdaf80572dd4ee3fdf80711e60205868aad5859971a858f30eaeee2883bad62b5c4e6ada3ea38ae1ab516f294a16b18c099fa760")),
            index:                  3956355178667798015'u64),
        ]),
        withdrawal_requests: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD].init(@[
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x98410af351e5be94f9d37f7cc9f97a85e9bd0dad"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0xd96132438444f4582e21aaa4950d907a84d56f5edaf5d4262439210d6b6aae00ef67d15caa1e95040484b977ba677f31"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0xe640e25259ffe5aa8b481e98684b41a14f3d2192"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0xfb8bad5edefcf4a76157dd4df48c345b10966ebe21c5265519a3d166ee6f43b92bc67707a7bcc478c05cb5d5aaa5e217"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x6544a67710ed5b8466aea7bb74de9e275c7a7338"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0xae821baad66de4d33dc8a8ea9088ab97cce0be2f1be1243c3c640377fd57f3f7389087ace339f953d52372d198300f8c"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x48f380f0b267ceec6fbe39f80b7108991acf97b5"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x2c9a9040e72e095e347f8ba9ad33947a1ec5ffddaa2e86a112fd73c30af209625f1bf19eb7b4fcee28409707679781d1"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x04fb4574aa211ef818aa9c13135f20f4694b8ce3"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x8d381b3ee22253692bd5861ede4c0d62cb2f6c90df6afd180831ec183ac3f8bcccbbfb5fa1f3ee38d5c3871ca8e28ba3"))),
        ]),
        consolidation_requests: List[ConsolidationRequest, Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD].init(@[
          ConsolidationRequest(
            source_address: ExecutionAddress.fromHex("0x459b669c12e0acba7faa0ba7e6233644ee3d6b80"),
            source_pubkey:  ValidatorPubKey(blob: hexToByteArray[48]("0x6d00f156d7db5c9f2a0f1dd38917c5a0062f7ed54436f35e6e363e5db15ea60434482236614e41e37a25b0fcaf19ea5c")),
            target_pubkey:  ValidatorPubKey(blob: hexToByteArray[48]("0xc13b30ba7af6c7be66f9af3bf6c6b837a54eb67a88ca19b156285327da4ad7a24205356a862bb7805ccae30f78b2bcc9")))
          ]),
      ),
      (electra.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x086322b79160568c7d096747ef351338ddc93f252dab1df3ef65aaf24723d2c3"),
        fee_recipient:    ExecutionAddress.fromHex("0x03c6998b5a3ff1c98538c2333d279f2b1cc59f7f"),
        state_root:       Eth2Digest.fromHex("0x446d99a7e9fd2c327fbd445dbfb3b3e3a895cdfa6f208496dd09c0f84f7ac0fd"),
        receipts_root:    Eth2Digest.fromHex("0xf4c74d5c59c46f1d9f916b32d8a12939cc2a379bae83153137de76415f6e5afe"),
        logs_bloom:       BloomLogs.fromHex("0x40f87c3729ba599c3e9bb749c48148ee0d5563db71cf0daaad3af95c45622d7b2a64204157a92a93cf0ffbe0052fb79eef83ba8389fe9d9e7646874b0636960e4eee86eeca00ba70f65b2046620264b795852def9beebb671f841e19ce07934b7c2f66301cc3c7dfa2606067cdeb04a564b87e56ff3650c7c6bbbc96b2de5ccf8e314ae74a26347371c315062532a1f1a2fe0c417ed5d12b6f81c3440c0d8b19d0cf8a030be83ee7ada6046d75098b6ee66664ead786a65ef5cdcb33c4634aa07cd7490abc0ea9ce722423a0cba1aecb379552e89483de43dd321cdaa8a005ab7e8e2a958038ca12e2b08709348a7f6daf34c488add1a0a21aed0da0b64251f9"),
        prev_randao:      Eth2Digest.fromHex("0x2ff08bd0b22bae8c3627f61b8da627fc367b3a60f93dbe48de1ca6f25ada489b"),
        block_number:     10605470807350562909'u64,
        gas_limit:        587854351728657338'u64,
        gas_used:         8799032544585725320'u64,
        timestamp:        18028498231539883963'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[]),
        base_fee_per_gas: UInt256.fromHex("0xfbe348f0c77be2ddbd3ec038e3aad88107625dc6e96b1fb3bbfdba8c737a3d7e"),
        block_hash:       Eth2Digest.fromHex("0xc545e833aa2ee5d708e041f4dcb44bda654372b3f5f660c683d12230303da729"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[89'u8, 59'u8, 131'u8, 146'u8, 186'u8, 180'u8, 208'u8, 76'u8, 69'u8, 40'u8, 29'u8, 211'u8, 97'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[208'u8, 136'u8, 157'u8, 0'u8, 120'u8, 231'u8, 99'u8, 33'u8, 31'u8, 210'u8, 80'u8, 203'u8, 24'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 225873861246030158'u64, validator_index: 3132710425326779052'u64, address: ExecutionAddress.fromHex("0x4d2573288e7949201c806877449e441801ba62c5"), amount: 9096383177302198854'u64.Gwei),
          capella.Withdrawal(index: 2816791477401799195'u64, validator_index: 12199871733060832130'u64, address: ExecutionAddress.fromHex("0xd4e21e668d5e8b1c097cb250dc862bfd7f8a2b76"), amount: 7278220627858832735'u64.Gwei),
          capella.Withdrawal(index: 12003547154719720523'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0xe888b3288bfaf8f979c93699cbabef6c1f156f19"), amount: 18446744073709551615'u64.Gwei),
        ]),
        blob_gas_used:    0,
        excess_blob_gas:  1233408100755176706'u64,
        deposit_requests: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD].init(@[
        ]),
        withdrawal_requests: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD].init(@[
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x16c6ba72f97bd60af3008e747aa0045eace969dd"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x79b68340894f69a82de6d6ac26b6cffd1f84be9008f7cec5a8f740c5dcd73103e50366cb45ec0c2a0984b37597011784"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0xf950853d752ff1e8dfd3ffb9bdb504e851361060"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x9924a9bf1759d436f9dcc185cdb646d06af53ddf9e86351b69bda506eaaf4b47739a0737ebfcb7d734d33237eb77983c"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x7ef709dcc026c545a1707a4161948637f4c1afce"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0xfe1b2e2cd818d436f9cfd7ad7e9efb8e8940bff9ac2c5094793d26f9a50f76436e25b40d375d7b9d461ac7fac81887d3"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x1e6d99ec506e2b79322f77283f3e18dfc0561346"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x25931e58a52265a5a90f7004706cd736fdb762d50aff67039d5e0242039dfc49fd6670e6f4cf62639d7debe3efe5298b"))),
        ]),
        consolidation_requests: List[ConsolidationRequest, Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD].init(@[
          ]),
      ),
      (electra.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xcfba7f4aa4ff01d3d9de84dbe1761c79627a10c3188fb0a7c8adfa0d489e6441"),
        fee_recipient:    ExecutionAddress.fromHex("0x106b3bcaae4ff58dd837768be35c29c48571e4a4"),
        state_root:       Eth2Digest.fromHex("0xe6242399020361e70cb6b89701001fa8326251e6bae3b4ca1978eded8831d9a7"),
        receipts_root:    Eth2Digest.fromHex("0x3db0f9a05cc39be94414c3be28378d2b91ba3ff43ea2ea7e4e0a1874a0983f58"),
        logs_bloom:       BloomLogs.fromHex("0xd591169a3cc38e0837a76c4d7057f94c1ef08ad5af1778b1b06c3a0ec85201bfc659b18c49de831ce6b4a40f0d2800a9cc9001f74810c58473f9b973b720f84626cc9270b0428439b985043f5d9c3289ef8a794f5b8265e10e9fb9fa53a93887d270b8204f8f16cd968e295b0a06aa70e9f6f174733d251f3bfc644a7fb274b0138729f18c0e4382bd4bf0387870f633ed897a125ca854120c2885194f3180af4b62760db96da51f88ae1cd222f49b00fbbc1544eb0e98cea67e36368816f541723158d3691f3cf1509c65a51a8e68efb66c500dd6516ca1b02aeb4e0c13cf5bbead53672fb5a7a1863c8edfaf4eb9a4b4322a39d8643528bccf22493914fa01"),
        prev_randao:      Eth2Digest.fromHex("0x14fec0a1edb9c82dc9aa7fb7224791c51a3937e74e5da59646123867496460f2"),
        block_number:     6272046003849350913'u64,
        gas_limit:        15423951135645467684'u64,
        gas_used:         3743939155619454195'u64,
        timestamp:        8496536260448579184'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[152'u8]),
        base_fee_per_gas: UInt256.fromHex("0xd8b104041bdc4c76a9735e2b4b45f0f3612e8962f672aaf511f06a94b48562c8"),
        block_hash:       Eth2Digest.fromHex("0x8ca67fec04b7e3bc5a01f5bb265b93b4488b58ec2ac7f2c3ced030311de2762e"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[152'u8, 232'u8, 136'u8, 228'u8, 253'u8, 248'u8, 85'u8, 92'u8, 103'u8, 38'u8, 106'u8, 166'u8, 148'u8, 8'u8, 37'u8, 245'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[58'u8, 215'u8, 97'u8, 99'u8, 152'u8, 126'u8, 14'u8, 252'u8, 64'u8, 87'u8, 242'u8, 60'u8, 210'u8, 217'u8, 75'u8, 189'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 18405055677765556765'u64, validator_index: 13513833286292305941'u64, address: ExecutionAddress.fromHex("0xfe53af2bf3560b2157a683a545d4f898354f4d55"), amount: 911502'u64.Gwei),
        ]),
        blob_gas_used:    11215270247452431947'u64,
        excess_blob_gas:  0,
        deposit_requests: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD].init(@[
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x44142d2fd3abda9800ef805779e63c7ea88068f2b2509a92a2e05f61e0fc9ad1c2272e96db6ae6fdee235dff74917afe")),
            withdrawal_credentials: Eth2Digest.fromHex("0x65d4629f775514b46c0e413f9bf42f52cdf46f75a2a2b7b22e2a2a6b635adee4"),
            amount:                 18375333628189344873'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x436fa460d6fce0b4df72719d42d3d7e992585fb95c573868478c2ea343af6755c702fa84cd5bd6d237688d6905261c52f9d45ae52acdfe95b6de2e34127df773fb0d32d231f138dfdc3c3837f68ba77e7586f64aa5dc45c2eb0d44a61fcb29df")),
            index:                  11602205279250285026'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0xb5ca0fc53760118a8c10c994d885d409fb93f07196f7a8bad868d5b2275f925db9119903e180d1b76b4aebe2ec2bd1d7")),
            withdrawal_credentials: Eth2Digest.fromHex("0x7de076e071a5916c3c122a22fc9853b6c31712c7ddfe128216bd5d87784cc008"),
            amount:                 8755851176211479347'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x0b7a4a77b5554a3be5f9338c31158e9f0b0b5fc95e9ef176ca38183ceb3aaf214711af03ecf194091cbc99a11aa7a376d721b3c1e27e71447828326ee811a07f4680c5a73fb52106bfe9b66eadd40cf80f027f0db90e41c77c78552edaccf295")),
            index:                  659556622372086172'u64),
        ]),
        withdrawal_requests: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD].init(@[
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0xa80127ae927ef2fc72e527bee414d2a899e1050f"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x463d04b11a5f2b3a5ff5d93f7c20acb46b06d8a434d9dcbbcde024be06f50b6542ebca1a759d8cf8381e7142bce4bd1c"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x91e2ec291b66f267104a11157c46ef32fd40c22f"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0xc05bcf497d5e305552b041c7a239536c938fff8bc755fadd28fd907f070f7f4a5553660a3351739a0b1bec2e6ec3d2aa"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x1281069954affabc619e8092861136ada40cb869"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x781f234560ec5d2197a33908a66fcb156330141f51212a51a0f0117417b5370f3fd0266c9dd1bf2c66d47eaf98375327"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x56855acbe00c442f0d20d489deb80fc02b31a173"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x805d72db2998bbfaf07d13f5328db300ea7a2fa156d049bf072590d61dca40ae142de4a204e36768f6e546af62d7e1fb"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x722d597ea5a6f82a0f9b06bd8af0449d18f78795"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x1de64f16597d52214d1a5987abc026398d310712ad0db48d48e747e7783204579a886bbd9a58a47704d9874a83726a50"))),
        ]),
        consolidation_requests: List[ConsolidationRequest, Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD].init(@[
          ConsolidationRequest(
            source_address: ExecutionAddress.fromHex("0x70ce642845a24bd208442a6aeb263b5d9977926f"),
            source_pubkey:  ValidatorPubKey(blob: hexToByteArray[48]("0x581a1e6d7b11b2512426c8aacdc735470ba2b85e164a65062fabbf1341f6cd994ca0c8b2fa8640d679ad481abaa70555")),
            target_pubkey:  ValidatorPubKey(blob: hexToByteArray[48]("0x17d58eca3304640ac6da21ac5a629b32573cc99602971e7a751db3ec253e3e75810488fcd60c59dd43cc80ad9cbf66a1")))
          ]),
      ),
      (electra.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x063bc56b731eeeff8bf1c33d88523a04a14fa0c745eb3c750139842d88244982"),
        fee_recipient:    ExecutionAddress.fromHex("0x415b1cd5b42709a3724ab2f6f50a6dab7399d7ca"),
        state_root:       Eth2Digest.fromHex("0xf261abf37066b8dc5c868946346c98aae445adbb48e6dd05969fbb49267a276e"),
        receipts_root:    Eth2Digest.fromHex("0x5a337b7ee29d98e22b461f43b7a87e52d89fda2e7a3487ea92873be04a49ea68"),
        logs_bloom:       BloomLogs.fromHex("0x01817fd642526acdd8b57b4fc2fb58aba269095ce220ae5770004055f550918778021eae3abeffff1b3fa9fba50ff8d532fd8e2e67da7bdcca1cf9505179f19f595f5d9f09b98d5bc7d1ecb22527255e8e161ca2124c5fedbb59527f91a242671177e33a6fa377d585ebdbd6d9ff2bf80bec3695657441e35da43861f14b9a7e65ed475c323ece62d84aed7262cf3fd2b06ba03695e2e26e5e58fc5b8b99d519fda879587e3764930e3921aa15b2ee8691ea0e738030acb8832ca353d3bb63fbc0150c532b842cd053abeae8238c9ffe6f4b2b7210dc862c48843ae2a9088ecdb8c258592a0feb5215b8c9ad494ad896379d86e0ac89e6cd8765003ac5c95cce"),
        prev_randao:      Eth2Digest.fromHex("0xb28f434f3f40e40693b0c1726a018e2b3bc13c41608a2ca71aa5c8bf61829287"),
        block_number:     14597257287993827247'u64,
        gas_limit:        9090926713872599867'u64,
        gas_used:         17391976671717618186'u64,
        timestamp:        13439825139187707720'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[73'u8, 163'u8, 138'u8, 201'u8, 62'u8, 1'u8, 37'u8, 90'u8, 157'u8]),
        base_fee_per_gas: UInt256.fromHex("0x8a42339ef76757729ef6c4536b3b59255b18d7085d8ba786275b2076fc55b3c6"),
        block_hash:       Eth2Digest.fromHex("0xb3f6ec11b285a105833f5b68b67e8e23c85c28df2362a13a76db705f110fce8c"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 5477557954669138518'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0x4b840b26a19377c64b870be600aa336a40ae46ed"), amount: 42381'u64.Gwei),
          capella.Withdrawal(index: 0'u64, validator_index: 1'u64, address: ExecutionAddress.fromHex("0x3d22a723824a2944ea9accc8653002bf7d61a10a"), amount: 2799163561369818755'u64.Gwei),
        ]),
        blob_gas_used:    69111814634726666'u64,
        excess_blob_gas:  10785611890433610477'u64,
        deposit_requests: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD].init(@[
        ]),
        withdrawal_requests: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD].init(@[
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x027404a69d1a1a8b931d0deb6ef4c90cc23fe74e"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x144cd543ddf6cc88499595246d2373629467e69048b4c638824b8c4d82296fb635028f495c7516174670ed1c5b320462"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x748168ee6835196ae76808fe3232a422b40e42a7"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x5e024d736b5c4d340929745f59b7d681eeb151107f895a87d534491b5af13fbf7bed890a2f41dc8debacf2f65fce2c20"))),
        ]),
        consolidation_requests: List[ConsolidationRequest, Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD].init(@[
          ConsolidationRequest(
            source_address: ExecutionAddress.fromHex("0xc80ff3b9e9f68f8a64b9207600adfe37ba1fad50"),
            source_pubkey:  ValidatorPubKey(blob: hexToByteArray[48]("0x9495309c1e65aa3ba8097bf1bee00be1f067910a8abcc897f5752eab5962387973e394caf9c873ea71c958c3c08e1b4f")),
            target_pubkey:  ValidatorPubKey(blob: hexToByteArray[48]("0xf1a12eaa4fe32257839694fdf8fb17083d6c35fe20d045db01ffa1b45721021b68efc2a7f7f5360493bc1f0902ff121e")))
          ]),
      ),
      (electra.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xb31c41d39ef7e9a9b905cc93d82264415024d7daef48d886f1b3bc0fd6545edb"),
        fee_recipient:    ExecutionAddress.fromHex("0x5ad4b6c0d6b986e775f3a9ae2be73a330ba9f87c"),
        state_root:       Eth2Digest.fromHex("0x01dbc857a3d8994cf10cd1be3b2018be0e26ba54a5456e10a6e5729328a0b5f5"),
        receipts_root:    Eth2Digest.fromHex("0xa51e9cb9893bd7d73a8fd4e5267d80ddcb29d998814cfa9980dbae50ef101aff"),
        logs_bloom:       BloomLogs.fromHex("0xf1280db0ef6bb796e70dfef3b0bafa62690ef1e8f14a237856bae5dbe29dfd43ac789c53305ab5b0b7cc48ed53d1236ab9433a5352dac55b6e0a3ff90e9e815e2ce16fe5574c87f0066090c39b811996e2974da0bdb8bb59eb044bbb6bc2d7f8241093c7143a7c9892be85ea4284258ea2477f6a677d424efb6469724d641bbdc3f9254529b6af5cc5f5a77dad49c1a59ae37c19ffc69f6e331139b6ebac306ea09460dc0fc5791ef2cfb9e7bf29d662872e30b94384be90416df03bef5cf5a2339af4745f2f620fd1320d3fb79848692719cb8956b8efd427c9c0cc3ea6efb8f84feae0075ed10ec5c6243074e6004849712d8d1dd97ebb2948fcdf1d020c6e"),
        prev_randao:      Eth2Digest.fromHex("0xc8a27f0b7850de04e3d794b9e9d4f144c356f864401c3f802927faf4b88b47ac"),
        block_number:     10821099926525463598'u64,
        gas_limit:        7115919978619568727'u64,
        gas_used:         1,
        timestamp:        5900615379943209755'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[56'u8, 176'u8, 67'u8, 30'u8, 11'u8, 27'u8, 136'u8, 121'u8, 86'u8, 17'u8, 4'u8, 121'u8, 11'u8, 222'u8, 158'u8, 78'u8, 56'u8, 66'u8, 243'u8]),
        base_fee_per_gas: UInt256.fromHex("0xfbaacdba879288838ff725df19b7a31148ec5a24e7989441544d6dec1c980034"),
        block_hash:       Eth2Digest.fromHex("0x04616c0808df7a1bc177bc48cb6ed865125fbbac2fa3e3c36f33a5f1c48a23fd"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 143666'u64, validator_index: 849676'u64, address: ExecutionAddress.fromHex("0xbf06178f996afec7c9d3cb488e812f32aafe4242"), amount: 18446744073709551615'u64.Gwei),
          capella.Withdrawal(index: 560588584813483246'u64, validator_index: 18446744073709551615'u64, address: ExecutionAddress.fromHex("0x1a1b89bf52af0d4a8eff759986ffd93cf4464114"), amount: 13046900622089392610'u64.Gwei),
        ]),
        blob_gas_used:    1,
        excess_blob_gas:  10155937412879977460'u64,
        deposit_requests: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD].init(@[
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x5333b0180b311e552ce6b94225290f3e948b601845d628ae8137bee6e5fc8ef65d2eb2948cd564f48f40a39107d425a0")),
            withdrawal_credentials: Eth2Digest.fromHex("0x311c904177ac7dab28a516a2306e47550b373338232eb146993204120e838a1e"),
            amount:                 0.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0xf1dad35f740e178ef1aac4df7470becd0bb2d54767c04cda321ec2ff9e74fdd9ab1e42d65fcf2e1fbaa42f0f0de36e7d58f300de706ce634886c6883b36c517cdc411c236d984ed9568f39111d562360c1f61a066b30a0e7b724b4f5bc5d34b2")),
            index:                  5781210920531179973'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0xfd253bde6458c872a3052a365ed5fca973dad3a0bef826f46a14c866bda1bbbc1c54c8117c89ec6fb514cb358af293dc")),
            withdrawal_credentials: Eth2Digest.fromHex("0xd9471e69c21bdfefe367eebff0f5500573ded27a7793f9a1f9149f6997f750bf"),
            amount:                 439091423098684932'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0xddb1aa7c758a9513fd8ad0a0cd3332a9b9411d7a0795e08591f363b5b4887b4cd4e4d22c87ac9c62a5aed65e3325cb4451d9c37539c1a9d6d84e69f38ddb0b7fb27e6ed7d744b95f5dbaff6b17794fd627842c652884f46c293251bbc0c8970a")),
            index:                  16197400268122174810'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x08dbad1402daa1c3e58e1cac5bdaa36704c9d21df7772d734f4fec1f770140dd4779646794d47c4df0c55adc130b89ea")),
            withdrawal_credentials: Eth2Digest.fromHex("0x3969600fb0033db2f9bf9718367ffffdc6044f53dd397042d89c822887a72bc5"),
            amount:                 18281837285233220396'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x655e809ad38376a8d7fdd895a30d8a1ac52861864f67e1ce885cc40cbdf3ff27a8a6f8cb1b33f74254c5bfef90de22f6b1c724e888d284438995fab628ecdc5278319435192ed259b56ab6d2f18ad3ba53aa534e85fa802e15c1a1ec9fe3b7e1")),
            index:                  15032238460111462081'u64),
        ]),
        withdrawal_requests: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD].init(@[
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0xc8bcdf0144cd4eb45e62b4fa76b7d5963fa912ec"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x4569a134a3f6e0ac638b19e8d88c9010f7281449f78adcbad225d11d2358790b2454504ac56209ac54cf66d5df779bce"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x308d3b908ce2fb2ebd207120422994608d8c3354"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x3deec67ff0f69aeeeddf322043b694ed4ec79aa2cd2414797bb95da5691b2b9731d3fe3d3627684d022241f80504f3ad"))),
        ]),
        consolidation_requests: List[ConsolidationRequest, Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD].init(@[
          ConsolidationRequest(
            source_address: ExecutionAddress.fromHex("0xfa3b832100b4deb83db5776ebb5c920b88c5ee4f"),
            source_pubkey:  ValidatorPubKey(blob: hexToByteArray[48]("0xc414a06a2bfafdb6ccde87c98b99de8124cfedf66b86832cae0ada7005c4939608282a7b947d43b322918765f1cdb1fd")),
            target_pubkey:  ValidatorPubKey(blob: hexToByteArray[48]("0x0b4c6a47a37b9fa0633348712fc45033dbd7ab958c8aa8a2c99dbdb325917728586b4dab8846da152df1a51c8301fd9f")))
          ]),
      ),
      (electra.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0xf6cba3ced37c08da230babbf9d1e360661e5a21ac235fefa75cbe756f15809de"),
        fee_recipient:    ExecutionAddress.fromHex("0x0c080349793b7f43fb3ee9101889e7d32e02c01d"),
        state_root:       Eth2Digest.fromHex("0x6a33580fc482e9783d66bee9276f42b74a2cbc2b7434fc408a6ba9df77db0ceb"),
        receipts_root:    Eth2Digest.fromHex("0xd896daff74ffd6ffcc088adba01aea52af82d861b7ff649265a750e5995dcf31"),
        logs_bloom:       BloomLogs.fromHex("0xec00c3385b735b6a4088ed066bdb088e7826a2830fd13a1a1525c4590eb08baeba81bb511bbf2db2c0547c69c10b5c6c1bf5c8e5a7931584e6ed8ed7357431e1e2391fc0e61a060baf8984a6fd5c04c68fe0f28f94281d0db663b1b2fdaad9b51d3a12bb9fba255c923dea5ce45dd68ec2c5afc9fd13a0e24d234a3c8c5f255e7d62d48a8e01fb5c1eaf0c7a68a616ac935416fe3332943d78eb28a48a180e2bee26e85d786583ae0609a8b98e1045738f054aa12bef97593cd16d8d795314bfff33c51b397afa2299a4a64244817e5a07cdcd75eb4c4c06e8e943d8d1db8e65f17368ab6175c3e14daad0b99fd0f1050feebadf9db8fe8f1c19ed867f4df676"),
        prev_randao:      Eth2Digest.fromHex("0xdcd37bc148c25afa7e320009ce19567108745ef5ed57781f55df1d73b707e26e"),
        block_number:     13754339262807377549'u64,
        gas_limit:        5250261236890759949'u64,
        gas_used:         1335844244115849195'u64,
        timestamp:        16758901654456753273'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[28'u8, 8'u8, 171'u8, 122'u8, 126'u8, 38'u8, 142'u8, 246'u8, 162'u8, 197'u8, 241'u8, 216'u8, 158'u8, 184'u8, 73'u8, 191'u8, 208'u8, 5'u8, 79'u8, 231'u8, 254'u8, 55'u8, 126'u8, 97'u8, 184'u8, 78'u8, 36'u8, 80'u8, 160'u8, 124'u8, 188'u8, 176'u8]),
        base_fee_per_gas: UInt256.fromHex("0x0ea1185e0ac50d1e2cc0be7229c846528380def25f7d8860cf366e6edd793be0"),
        block_hash:       Eth2Digest.fromHex("0xb471874aa6e8987deee40902d59537fed8af3e9b6ae2f8b476ddb051629b3b09"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[231'u8, 215'u8, 225'u8, 83'u8, 163'u8, 187'u8, 111'u8, 141'u8, 246'u8, 57'u8, 238'u8, 163'u8, 25'u8, 91'u8, 114'u8, 111'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[93'u8, 42'u8, 101'u8, 80'u8, 160'u8, 252'u8, 158'u8, 121'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[164'u8, 98'u8, 105'u8, 179'u8, 25'u8, 33'u8, 130'u8, 239'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 5378768050415100863'u64, validator_index: 0'u64, address: ExecutionAddress.fromHex("0x3d84c03e4c18979ee8288bd58b24989580f0a590"), amount: 815393520574223128'u64.Gwei),
          capella.Withdrawal(index: 17328504288784263137'u64, validator_index: 305278'u64, address: ExecutionAddress.fromHex("0xa00491dfbee05f23fc7ddcfcb1b27b2855334e81"), amount: 7734460020873819187'u64.Gwei),
          capella.Withdrawal(index: 0'u64, validator_index: 444647'u64, address: ExecutionAddress.fromHex("0x0689ed39160f4b4c20138f300b3b2502e6d6ab5a"), amount: 18446744073709551615'u64.Gwei),
          capella.Withdrawal(index: 834083'u64, validator_index: 10715076713456342424'u64, address: ExecutionAddress.fromHex("0x07ee24f650e7254d10d61b832db7174128bf22b4"), amount: 17794546242151296198'u64.Gwei),
        ]),
        blob_gas_used:    7080212387270627767'u64,
        excess_blob_gas:  17322910515629142083'u64,
        deposit_requests: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD].init(@[
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0xf08f319d0ceaed0b05713852711ac610c213b902e2173d8db62f1eb6aa3a6beaca49c48e76bcc5a25ed6a16d949fc2cd")),
            withdrawal_credentials: Eth2Digest.fromHex("0x166df75e231abc5e67a30cbe8f8392df207b0a203784d5cfccc8d757472defb4"),
            amount:                 0.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0xaadc232ca2439def6d7ef995342870dd330c245f46e5cd42fcf1a86a491f65baf722d4d8cad5faf0c66920b17bbad2d92bee6db09afee46839beff07db973e8515da6c77741396a4c844400c7d5f2f9cb815a4fc14dc12e85dfa1e265c8f8e52")),
            index:                  11769346303267269586'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x4ea1b17de1819b452f77c0ec61ca191225cd3d21bd94ebaa8f63eaf87b2a7e131b45688d8187b5853e25193bee3f5586")),
            withdrawal_credentials: Eth2Digest.fromHex("0xabff3296e33aa3656c2911cc07ed003b5520db5ad937c60b3ba70423d25de9ce"),
            amount:                 13132016002583744347'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0xc544cafb21de7664dc3f6e49fb1d972bb9b0e84672889c29116cc08af20191c09d1078f70f5ebdfadfae76092cd5bc3328709703ec0aede57f8a339a2cea50d76f3b14b26dca2d6d66c5775190896040d91c38ebe45b642ed48a224c300f1353")),
            index:                  0),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x926949c6a561ac127c2d6e7fb2fac3d3df36abdb91aaf857f923cd43645bfb76bf75c4afae07aafe5f4c7bd8d2aff312")),
            withdrawal_credentials: Eth2Digest.fromHex("0xbd953da5243317a12f8088fbd1483795ed953b05f49e4c82b7b95a93c7fb3347"),
            amount:                 12812987719379600277'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0xac73e1dfb07bae2ee700bf7cd09a10a39595491047e708d4e47c7d7149f40853657ca564beda87b00e4bc164122c0973ccd9df366b274dafd8bd949881c5ad6fee9f0abcfad2677481f41ca4a5df978ae1f26d783609772706c9c3ef1c35a54f")),
            index:                  18434818685702059208'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x013f9a9161f2e1a9235ab5ffc2e8968cdfed7126341ab0e0f3ab176546a3e2cd3d0d9c8523542ebbbaea50b6f096af47")),
            withdrawal_credentials: Eth2Digest.fromHex("0x7be93c7783e230acb77ff4fa480299c5e295f7516325b73e4c4efd987d6a590d"),
            amount:                 0.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x97ea0a8e3f3e73fb11ded1814f4232e8bfb1e7b71bce608f3f181e5609bdaab3ffde52b1ff98d94c3d02ffefa6b3716cd83deda00888224f24716619f685c940da205910227b976bedf7f0cfc16262e2ec48dd837509326c97e329fe666846ab")),
            index:                  8630770799181013738'u64),
        ]),
        withdrawal_requests: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD].init(@[
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x4e4c648248758aaba856a20f8496700f036a9177"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x96902ac59a4940715d171f1d6ec3e03b0c1557fc0100abb930b6626917b9792aabd48ec1bc1e37737c582fe11c966658"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0xa99cc4727a81a0abfb662fe28748133420938dae"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x10f3cea6d52558a866988352bef57525f708aecb5fb392af8453e306cf7c5da68aea8a544d71db63dc1057317b00feb7"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0xe13404d88c1418f69c92ed12d256382a462ecf4e"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0xf8f8cffff4aa7bec351b9e084274b6e47c536671bd559c7fbf110985e684a58c0384ffc314c23c4441c0f17ce33bd767"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x6f9427252a6fa414a6501e0761cf92f0839f3bbe"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x4ca4f660800c2cfa68827299ddcbfddcf2cb01c51dcaf5af1abc5e8f05164846ca26f1c8c884a3e674a22dbfc0d9fa7b"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x14bce680ec1a632aac5f77cb4d5eca52f74bd1e6"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0xb4f363283d5276f12a6c2c98c58484c6a6e8e3c7f5b3adfc044d2de76365bef427f8b9ac1e321baa7a611447010f9e8d"))),
        ]),
        consolidation_requests: List[ConsolidationRequest, Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD].init(@[
          ]),
      ),
      (electra.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x62ce6a6d68578309c4730f96f98a809d4b4225fc3d37a285daf26288b10f9590"),
        fee_recipient:    ExecutionAddress.fromHex("0x8c892b06f1e9c877c310b6eccefb20fcf5e00227"),
        state_root:       Eth2Digest.fromHex("0x578f93b83206e3239c69f51cc8e59cd89087260cda9f0efc892aa2ffb2bf386e"),
        receipts_root:    Eth2Digest.fromHex("0xa4ac657af8e0dad66ec74f4f66b246fe0089485e2810071fa556c09ea585059f"),
        logs_bloom:       BloomLogs.fromHex("0x18d67e640f9ad3a24deb7e3f8cbe0ba8224cf9cb9e67b2fd6c774fac7aa3f4adca2befe8322962cf000cb89c3e352433cf1aade51ceac9fe69966a8a89f7985030a301eb690e7eb20b5ac3b315930ee5397b6d65b03a1131b94e7f3505ef030877e460e9195b742e943716d9875a3e2e9998236d3565d622216af1721b658a12fe7d82a62619b4f2d042f146305ff1ad1bf394437340735eac9e962b3fe67597793d1151ec87fcb5f0056837c5813c75c4a0f94d91da71299b3780f250ee31eb9f106e3c443f0ba05213da05177238909fd9e60de9484e091b91dead82debc020929d1f14e79b610af3d15bf9c3757e62bb32a69523c1bd576e5c5d4bc2ef0a6"),
        prev_randao:      Eth2Digest.fromHex("0x552627eb969604e7d4ed1e631b74b2410dea7f4dbd49511bda390e3b9da8bf60"),
        block_number:     7763671958353664038'u64,
        gas_limit:        3930616259240751958'u64,
        gas_used:         7960068863134244743'u64,
        timestamp:        18446744073709551615'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[227'u8, 111'u8, 127'u8, 243'u8, 191'u8, 237'u8, 88'u8, 146'u8, 146'u8, 236'u8, 162'u8, 237'u8, 164'u8, 177'u8, 249'u8, 52'u8, 1'u8, 26'u8, 187'u8, 208'u8, 244'u8, 234'u8, 113'u8, 199'u8, 30'u8, 209'u8, 197'u8, 63'u8, 126'u8, 104'u8, 143'u8, 30'u8]),
        base_fee_per_gas: UInt256.fromHex("0x6bcd9684e1bc8f4fc5d089e0bf5fed35a8bf3039808d030bb9eb1ff7147180b5"),
        block_hash:       Eth2Digest.fromHex("0x9e2505de9f245873565b553e7215abff698bdfcee1dbd93e40eb295dd84e7f45"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[140'u8, 134'u8, 173'u8, 70'u8, 168'u8, 181'u8, 221'u8, 210'u8, 25'u8, 142'u8, 168'u8, 139'u8, 77'u8, 134'u8, 203'u8, 219'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 0'u64, validator_index: 780337'u64, address: ExecutionAddress.fromHex("0xf0ab5949e96d8befa8090fe5612d9c45beea0c8f"), amount: 2246589958612652012'u64.Gwei),
        ]),
        blob_gas_used:    0,
        excess_blob_gas:  9638659159857567769'u64,
        deposit_requests: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD].init(@[
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x0d7bd99094b190c06d115f727bab3974676f30feda394294d2fd7250443e3514868fca6c749b42bf6cf70c9fbea48d53")),
            withdrawal_credentials: Eth2Digest.fromHex("0x983b0d33e8325a806a21d0ac9bb262e565ca7e094d578876a89501a8985413d9"),
            amount:                 6392806474408369626'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0xac560bee8d8dd4dad94f2bd5b480e7799f7a8445adf3e0070747f8b5724d442453fbba2f332cc69af3a450dce80249b6b7afe19340f4fc5dc54a5c0e56cd4c484c94c61480bc56c75eef44e55c1288bd58739b8354caa93da5d2502bb38546df")),
            index:                  7086745948630243467'u64),
        ]),
        withdrawal_requests: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD].init(@[
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x91810ed86a3244c89274f94fd510532cf12d7074"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0xbb480d96367f62ab5790cbfdeeac6344e21774681edd0afe64c50b48f4d07795e584468821788948c7d8c151733ad01f"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0xe16b15a5256815cf6d338498a5cb0e8ec0d5bfec"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x79b49178606e2a5cda067c04b982d445df7b41d09d4361e5498b7a454d0e8a37a6975da56c3bd20694a3fcb467f7ff59"))),
        ]),
        consolidation_requests: List[ConsolidationRequest, Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD].init(@[
          ]),
      ),
      (electra.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x4f8251c361a23171de8648d1e96c91fea2cc5a691dcd884e3a957dc8f6a8802a"),
        fee_recipient:    ExecutionAddress.fromHex("0x7da9175abaf6e4e400e0ee516fd3ab07dd659f2a"),
        state_root:       Eth2Digest.fromHex("0x1bd3a5da4c266dd396b8209288e68be066176ebe64cd4c17c4c6cdccaf03577e"),
        receipts_root:    Eth2Digest.fromHex("0x16133c4fe31f0487e700514160acf9257458a6ee716be8043cb6c532f84ef614"),
        logs_bloom:       BloomLogs.fromHex("0x5ca3807e674d69536b33337d798deaeb9fa6c7cbab7aef1473e6a6614f6f2c74ef85ee3632612b9c1e78d2a63e0b2f58d48d71e8d62e38510bc2f307680497cb965153b43392b8aa2dcd91a766356eab3ff1b4a6c4b037d61df1a8a4c6d3fa0e3c57a299a1c0a7382052ac25c412f2d2356c302e326fa0cfb570354e31e2f8046b80e2690ba69ec7c284c2df8ad23d16764cbc0ba28516f3c31aa89da3e3286106dcecc835b3007a17f33c4962efc3c9b0f5bff14c783e414ba60d35b79ab33ccd0151c34a94efc461d0df0a994085373f33275a4cd6839603632409b670072a4554f1c9342c03cd403a6feb67b23d3a075707ca89b77bad64e24a6ab79446ad"),
        prev_randao:      Eth2Digest.fromHex("0x6353ec5b94b9112f25e66de48b532ff5610c63f34c50a02fdf64af6c9d0ef2f4"),
        block_number:     16866969889068542818'u64,
        gas_limit:        5116920640663397560'u64,
        gas_used:         13292402101416991817'u64,
        timestamp:        1,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[136'u8, 133'u8, 189'u8, 60'u8, 229'u8, 217'u8, 70'u8, 145'u8, 136'u8, 97'u8, 175'u8, 23'u8, 183'u8, 73'u8]),
        base_fee_per_gas: UInt256.fromHex("0xe1307a28a2868b4d934aefdde7bbd09b0644b5c422d2c680770775cb44623512"),
        block_hash:       Eth2Digest.fromHex("0x11e23850b143b8b4dd8394ee1f2cebf073068502d04dde00000925cf23ff55cc"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[]),
        blob_gas_used:    4954178403284176013'u64,
        excess_blob_gas:  1,
        deposit_requests: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD].init(@[
        ]),
        withdrawal_requests: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD].init(@[
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x08396e3d726ff055f903e2b4e7b743fd8c128f4b"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x01c1c045960d8121bc8ab57c4728dfb3c07289818df71893c002352eca51c54f03db8840f608607bea01bd7b0f02284d"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0xc7fefcefc468685bc9b8cdd3c4e1ae643952b254"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x816cae90cab4ca290dfaf9f32b7ad508bd82095ec815cd55b9399eee91208d30f79e548951bfdddc60b7e7560f2b9e1b"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x7eef42203641e2f5c21779289b6c48d24d578887"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x738dfea8a133b5fd384bd6242fa58f1119bcfed0cfca93899c95f1670d1460b905134cc91eabb429d2147b5f147d5d1f"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x032d5223828ee1c8943fdacfbcd25ce4bb2eacfd"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0xf42315c025ae7ef0e8a04175441e9617b0e315a9e7c8fc5f0a0bba4efc9775fea3a8af9b40c4aa37633718ccb5b3260d"))),
        ]),
        consolidation_requests: List[ConsolidationRequest, Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD].init(@[
          ConsolidationRequest(
            source_address: ExecutionAddress.fromHex("0x548760f25ecda293ef4950d60520003770b31964"),
            source_pubkey:  ValidatorPubKey(blob: hexToByteArray[48]("0x1e384047c673119fbed6c635e11f4db74edddd17cc6e51634f5eea100a21a07012fc9b89d2c7677c282bab0d1136cead")),
            target_pubkey:  ValidatorPubKey(blob: hexToByteArray[48]("0x9454bddf457231bf55c91db6a018a0501e97e31d0cb2e7fa180910b75aa1a98e80739885ba4a878df2ef7ac3f2db9fad")))
          ]),
      ),
      (electra.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x0c67b44b492590ffb9e6d2a63c84714821be7526ce1c337c06276e33a62b7b93"),
        fee_recipient:    ExecutionAddress.fromHex("0x1d16dbe66ead2ba8afb8594acaf8d536be08dac3"),
        state_root:       Eth2Digest.fromHex("0xeeb40e334aff8512435b5908a8dd3c06993cadca8bc44e9a6c28c6003162c6a9"),
        receipts_root:    Eth2Digest.fromHex("0xefa5b7de19da2333bfb7bfa814a306f904fef2ff4f8b1154314649a56fea3c8d"),
        logs_bloom:       BloomLogs.fromHex("0x4ebbaff6a56343a6bc0170aca2e2ba303f3e3f972c88539ef84e402740e3c9e21c6951d461baf56eec14c06ca0e95f4921079d0d82e9dd46e73f3fa76417246217ff9c5425f19b0f8b2a735ee522c1bc377a2b079099430d0f9316164f5930456245534bbe138d0a19ee58bb13a0d724723a6fa50e39b8a7ad5804f92ab43c24782e27dbb32789408cdd716af9a0b0cb1e2f3aee0bcb5aa4088c0cf1528fad466f3d71d906649becf25f405f619dead731e0831efb522b5faee7a39ca28128effc79977816d50ae23745ab96b80dc7f548aa5d43b0d5c331fdc1ce080a4d63e19942ecb4df8f56397b2ef67d017f2d2de9296e1fd8036ed8592f5a89553c4642"),
        prev_randao:      Eth2Digest.fromHex("0x5d3c3ac25330e1cd3a516003315ed24bd2dc6cd31d389639cce4b6ae4a3ac8cf"),
        block_number:     10891095348111649307'u64,
        gas_limit:        13670668340379820434'u64,
        gas_used:         1482104080767186829'u64,
        timestamp:        6602476120092784163'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[223'u8, 228'u8, 253'u8, 3'u8, 38'u8, 218'u8, 253'u8, 87'u8, 206'u8, 243'u8, 168'u8, 113'u8]),
        base_fee_per_gas: UInt256.fromHex("0x972a01f27d586035ce5fb233118e52652ebbf89f6d39558a41b27c8840c849b1"),
        block_hash:       Eth2Digest.fromHex("0x9280fa96a569e7c25b2dfc12a141d3edd24acf2fbfa19ee72e5a1fd5dba25a11"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[116'u8, 179'u8, 195'u8, 80'u8, 193'u8, 73'u8, 187'u8, 64'u8, 41'u8, 251'u8, 55'u8, 90'u8, 161'u8, 30'u8, 221'u8, 210'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 820354'u64, validator_index: 626992'u64, address: ExecutionAddress.fromHex("0x4abb3f9a694bf6b27be97e24290ca6826b23c5d0"), amount: 100271'u64.Gwei),
        ]),
        blob_gas_used:    0,
        excess_blob_gas:  4396492484488695305'u64,
        deposit_requests: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD].init(@[
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x9aa3ec3541db18dc4f7bd8e3111a3f00c0d7c5c096a4cf312e3c91a10ca1a91802c4b7b8bbd657dd30af4f3c365a70ba")),
            withdrawal_credentials: Eth2Digest.fromHex("0xf26e0fb84321ae08d027c81a3e8b113263c01ba0b5e8b258089e496854c4571f"),
            amount:                 14325001783554754582'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0xe3654532d224f33eba82bb7f487098c687c180592f8d6406af9d13e8019f417f4bac5ab12c4da72d85f90af2ba18ae4f1f27984033ee63687635db7a69375b38b48168575926def4ba0cd2322a3d970436ed788627fbb4889bba989114da9b82")),
            index:                  0),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x5960755c394a07ae7c11ab0260a033eb22b0a0f957be785a513878d0ef04cd3b46af090fd6e2bbd930cc345f81f209e9")),
            withdrawal_credentials: Eth2Digest.fromHex("0xa86195129950eb6a8df3190107c2b84e8ad8fdff7b0720d84c42fab9de51e38a"),
            amount:                 279514025671376926'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x121632563dca7d7a560e5b243d7f27dc7dc72319f1486f67cb41751c5f5a42bd9f8efdd14e3f811e03c84e3ba36295a0cb2313bb9792cfc7d80a1669f0adc30934440adbd665ef96b3c30a2762cbaf932e6eb1b4a1c93063ec7f0b6f6aa2a9db")),
            index:                  10368232928814555152'u64),
        ]),
        withdrawal_requests: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD].init(@[
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x7bee235a632b5f79831f376843209740d409b9f8"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x8f40af9186eb70dea2f3105785a930511368e60d2235055c34a0be1a591c5b580eed67542c89a0f8a024c4a6bd1f9bb7"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0x72fdf4c5a62970c6d6c9ee395eec4dfd6fcca4de"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x540a810f4e9ad62bca1d677e9135d519100012f6f12a8f5105623762ba5de3782cb3baaf63c4a32cf03a036127d6d009"))),
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0xd3a0f8518063d55c61423dce1bfcd2abd9a27a62"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x82bec5cd588df021e98087c703b995075ee1cfde2257eebed5e27f53a3a16903479fa2e6864ab3c3c397cd25b6ba3d4f"))),
        ]),
        consolidation_requests: List[ConsolidationRequest, Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD].init(@[
          ]),
      ),
      (electra.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x7a9d6ab34c0314959d5bdceb0bd80f142e59e5e2addedcd178612303897e7a8a"),
        fee_recipient:    ExecutionAddress.fromHex("0x3425bc529b4791f5fdb7dd365501199b2f81e578"),
        state_root:       Eth2Digest.fromHex("0x4eb1a9a3c4b9392325a14f3f8efbc0b3cc3bfc2d7e9992377abd84af6c556db5"),
        receipts_root:    Eth2Digest.fromHex("0x094e9114d3487925f6818140978e4db64d8306083a8e5c987657e21c3a1995bd"),
        logs_bloom:       BloomLogs.fromHex("0x0815701b4689d0bb7f80fb1485ad3255a66b890725a1d2d66b4fc66678e2d08784c21ef583401493d5dda1549eda32303b7d102edc72b9fe1d696ab459294a88db0d7263abdf982ddf59ce008b8ac734565de79c269dfc18a36709ca91a3cd50516725e9fa9d98302fa0322254382aab0cdf1f95f2397579f7219bd7ab096ef1f00d7b1131b0055bff65ae9954cb22959adbc40983840ae3b85358fd205bdf6ac6bcf723047ffc53a094a06c2039935b6ef579efc618bf4127a6e4e531f6d97c17789be639691ef87fa5540cf732a184a0e09d5c60866ecd0be0a04bc94317712c395d84c2cec90f43f4807048bf1a93e3e6520a1a7c59092e2e391abf9d2e68"),
        prev_randao:      Eth2Digest.fromHex("0x349eec90244f3d812002732cd833952969b27a463def04291051137344c89c41"),
        block_number:     5715688900321967041'u64,
        gas_limit:        17172684770312311722'u64,
        gas_used:         9286597649062725614'u64,
        timestamp:        195835912833125491'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[34'u8, 35'u8, 209'u8, 45'u8, 117'u8]),
        base_fee_per_gas: UInt256.fromHex("0x7b5b4e48b3daadecb9724a74d426a86ffb5c5f8abd43469b4e3fe2a728b5a645"),
        block_hash:       Eth2Digest.fromHex("0xc71c294b5562af30b9e2b03e76cec0cc6d8b50694219404aaed2ace8f756a22e"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[178'u8, 142'u8, 115'u8, 217'u8, 56'u8, 74'u8, 150'u8, 16'u8, 244'u8, 148'u8, 19'u8, 33'u8, 89'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[195'u8, 248'u8, 42'u8, 129'u8, 151'u8, 119'u8, 232'u8, 235'u8, 245'u8, 240'u8, 113'u8, 157'u8, 235'u8, 158'u8, 160'u8, 222'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[16'u8, 27'u8, 72'u8, 107'u8, 18'u8, 210'u8, 127'u8, 78'u8])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 5186085670428433087'u64, validator_index: 156817'u64, address: ExecutionAddress.fromHex("0xf8d93a548c4b243e66f4f73b29da342a0fab04de"), amount: 18446744073709551615'u64.Gwei),
          capella.Withdrawal(index: 9475052657186699106'u64, validator_index: 759532'u64, address: ExecutionAddress.fromHex("0x97559fac3168c6ee81b0f0b0b88563080ca24769"), amount: 4852567582077527137'u64.Gwei),
        ]),
        blob_gas_used:    11199168226748373856'u64,
        excess_blob_gas:  13194543368024635634'u64,
        deposit_requests: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD].init(@[
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0xe4476f7d26f357eeb0a2c31eca0febf37a9bbd8bb28810101b3d62832fbc63ecf6ae6019bbea00bbf1b786ccd4e5143e")),
            withdrawal_credentials: Eth2Digest.fromHex("0xc9b68e2b8e85dc344cb56a8f2b1930ebad58094a8724e64d7de0b7d39178abb1"),
            amount:                 6807629444642690487'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x742db20aaebafe1bde890ff9a00901d9b8e2ff5e1f27ec96d0adcd4d058fc4b7dc8545931f686c71180035d90eb61c107f96b6f401b75afaa4f4824bc9085c8bf7618f86e64e04d0b0779e54dfc6b9188c4dce82a70e383298403025ef634e6c")),
            index:                  8242431675098722712'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x9cbfe60e6b7fd6ca80f047492eee67fe83391b71ae1d70e2e6e7143c096e4059897f3033cf01a266209b974f1accf9d1")),
            withdrawal_credentials: Eth2Digest.fromHex("0xdcfd039ba7148cc07212f227be45fdc329a499b8b0ab074dda9c6fa0f4534066"),
            amount:                 17558068707432308727'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x8e274ccbdef898449a07a296386e5983ec423f7ddee02bb9d480ec99dca4f5074b8f6cf469758a45586f031e2ae0a5448aa133531cddf88e9bd2b9fae191fdc817c1989124f1866753fbc833f79fb78f89677df12bc6d288693e5362f2a972bd")),
            index:                  15922103202526011942'u64),
        ]),
        withdrawal_requests: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD].init(@[
          WithdrawalRequest(
            source_address:   ExecutionAddress.fromHex("0xe368e59ddc49ffac6818f01b4be692a517b6838e"),
            validator_pubkey: ValidatorPubKey(blob: hexToByteArray[48]("0x9c7a489a7498cada308db339f80aafeeff5e38ef7dc5803344a725b3b7f23d6d6162a33798a69660417b8fffb51c3d50")))
        ]),
        consolidation_requests: List[ConsolidationRequest, Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD].init(@[
          ConsolidationRequest(
            source_address: ExecutionAddress.fromHex("0x45c3398e59b885ccf52ef5d36ab2acc3c3f9d584"),
            source_pubkey:  ValidatorPubKey(blob: hexToByteArray[48]("0x47faa2f4d2bc6e1b2c8366db1e4300fb6fb099f26c9e0cd53b87b22f4fd038751b8fef08f6c1e636116c95874bab5bb1")),
            target_pubkey:  ValidatorPubKey(blob: hexToByteArray[48]("0x632e3e022a91046f0a6769abfd159b998321363c79d77b7bc139359fafb4cce331322599fc05fd8c5b1d6aef94e810ed")))
          ]),
      ),
      (electra.ExecutionPayload)(
        parent_hash:      Eth2Digest.fromHex("0x806a868f0f31e8f519fa6339ad18c414dba17feb03aaf6ca3775b152bac64f3b"),
        fee_recipient:    ExecutionAddress.fromHex("0xa2bcc8b793c4a5d4e0f68251d2f22e1ff4366d2c"),
        state_root:       Eth2Digest.fromHex("0x6979ac9545f31eaf7ed8bd227cd7cbd1017492b892bcc118f7417ea87d50d412"),
        receipts_root:    Eth2Digest.fromHex("0xca0ac1828fae211c9d0fd7ab763460d89f9da0669d082c68b9fdca3ca1b59123"),
        logs_bloom:       BloomLogs.fromHex("0x0656423dc7b375cee4f5c3bedc500eaff2da91d0dd5f4e695933c92a2a6af7441200a41177bcae7912839f993a733aa2bb82976f08180a901e63c588a26dc9ccc58f477eccbb08aa932d512bfc765a57527acd04c585af23f48f389420890d06877d8a0f523cb90be10dbc73cb5b11e808f5c6c90c6fc3a9434dab462f2977eacf79146b35ee2372aae8a6fe3628cbe21a8988fd9546b25581b6d998462f9af7f653d3a4702a4a63b9f26cc7d2f72e18a3918fa9b65ed81d23ac0a64dd8f3f878f745fcb4de9ad144ae9565288d7bf90e6d356f49cc242d000e988fe76e0196f0c5b24bdf9dc501222e54f64861e0d45dda2bdf09e5fb290a1ec6dce39b02883"),
        prev_randao:      Eth2Digest.fromHex("0xc986211f6550cb787e89140d8856531ec309f652e2a871e2715c1dd055448074"),
        block_number:     7781035717593646205'u64,
        gas_limit:        9088183223170031827'u64,
        gas_used:         0,
        timestamp:        1844848381084178223'u64,
        extra_data:       List[byte, MAX_EXTRA_DATA_BYTES].init(@[]),
        base_fee_per_gas: UInt256.fromHex("0xaac988479abbe95e03cc214e7b99795c4ec117bfe4da06e4624e94b262b015e2"),
        block_hash:       Eth2Digest.fromHex("0x14137d373f6e6110b3fe3c1d743a4f84547ad3d59d0b42598b794ff601e97e38"),
        transactions:     List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(@[List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[10'u8, 28'u8, 79'u8, 238'u8, 85'u8, 206'u8, 161'u8, 222'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[144'u8, 222'u8, 190'u8, 14'u8, 247'u8, 119'u8, 95'u8, 48'u8, 238'u8, 50'u8, 180'u8, 12'u8, 216'u8]), List[byte, Limit MAX_BYTES_PER_TRANSACTION].init(@[])]),
        withdrawals:      List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(@[
          capella.Withdrawal(index: 428032'u64, validator_index: 18218455002493563835'u64, address: ExecutionAddress.fromHex("0x389fe5e57a13de364b852d7e2cebc2add2cb7510"), amount: 726634'u64.Gwei),
          capella.Withdrawal(index: 18446744073709551615'u64, validator_index: 0'u64, address: ExecutionAddress.fromHex("0xc6a0db1d09160cec69bda14b444c46745e09c96b"), amount: 742028'u64.Gwei),
          capella.Withdrawal(index: 858390'u64, validator_index: 326055'u64, address: ExecutionAddress.fromHex("0x6a861508a89443c763d5daf15dab44a8a45147fc"), amount: 597242'u64.Gwei),
          capella.Withdrawal(index: 18446744073709551615'u64, validator_index: 17239721441660215355'u64, address: ExecutionAddress.fromHex("0x1450447dc71e28e312c7de7034523cd322eabc98"), amount: 18446744073709551615'u64.Gwei),
        ]),
        blob_gas_used:    6943026604784588438'u64,
        excess_blob_gas:  4081254329996628499'u64,
        deposit_requests: List[DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD].init(@[
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0xdb77124f3289375b57590aa624baa5feabd0cb05d9b849ddf7fb6c6a19ae6e0e9b2b5f0b5619f8114d2e84f86387b8b1")),
            withdrawal_credentials: Eth2Digest.fromHex("0xda71d922d0c2f43e0e743d15acf61fbbc235cd7e5a6b5d3ddf0a8f99c09e5423"),
            amount:                 8900470305881875693'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x0359d1b9bb630af7adedef569b58902f861eabd6832fdac38f4ea9fcee0687d5b32beb1762707bb7f197cc7cb7e56a2c5071f0c20647fe133bc807f8656d55ba454adc7c0c82e1d91b6ee2015c659595a29b20c75fdc9eb09c1dd181ca30cde3")),
            index:                  7027910908460072698'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x766195f078501722f6c2250140a793ca7c7e4eedf04a08d7a9046790347feba8b43a07824c279c3382e30dac18e24dc9")),
            withdrawal_credentials: Eth2Digest.fromHex("0x8033ec1a06aba2965b7e5a44c3195aadf60c733e54cd737c3f08183ba15fc91c"),
            amount:                 18016967842448743237'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0xfe46ea45efda7361cfbc8a5436dac3d2906176f219f38e477106a7a1bcb7efa726097a058553f0df0336bc982fcc7ff0ec99a085032d853f0a865639581bf40c06d463a6341f40a0bb5a149e1052ee9cbb60948cb9e673d12dc26979b7c75150")),
            index:                  2199989485519321583'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x3da140a6919e15bbce6592e20deb726c7f49490de1d785f2c6dccacf042a73b3baaf7a8a78b2b845bb91dd94bb4516e1")),
            withdrawal_credentials: Eth2Digest.fromHex("0xd7ca318f49e1acc9dd1b42088b59d7321cbf61ab08deb200b507569a84b45a6d"),
            amount:                 0.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0xdb1d2894d5f853b0bf89dc64d977608ac2774d8c5f4f59566f4ee3a723caf13b4eb66aca7495dfced5068057516b1ba6106e2af198bb5a0a78ecc47cace8b6e0b570b13b23d58827f756f8947d12187c4f804b49924f9beaa669f5d8690513b0")),
            index:                  2386861599472159894'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x551918d44e257d9a00f2e9307eb6735d5da6dcb6b372a0c80d35b167afca47f6087e0fb2fbd8d3846977bb1975b431b5")),
            withdrawal_credentials: Eth2Digest.fromHex("0x23d544fec453c12e55f24488f48870115d07946ba266621aa03997f8340ba0c9"),
            amount:                 15504548595993808618'u64.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x8be2d5ec33930f835ba523c8db1d5c47e7719a8844a2339f9a7497df2687efe009dbee6429accd5794272609b3f75ba25c959c7daa30e87f0eada1268363de1afd86656162f95a5b7a76eebae76c8cb3619045fd0050224b77ff1567e590a42f")),
            index:                  17558896845903288827'u64),
          DepositRequest(
            pubkey:                 ValidatorPubKey(blob: hexToByteArray[48]("0x920b41013a660d49b8ec1651d7ed869b0812cab03ff409e32b29beb8d8d74744d5d2375e40afa7da019408552026017a")),
            withdrawal_credentials: Eth2Digest.fromHex("0xb8f6d6891169e1fa957873ae437ac92f650dbf32f0ce5dbede96926ccf755d52"),
            amount:                 0.Gwei,
            signature:              ValidatorSig(blob: hexToByteArray[96]("0x232d34989ba30727e4ae0aa874a4bfc3934d61d0295d8f1c5f8416523f5cd05a3181a03543ff7318c4f4b9207d006267dde451177612bd888f69b43ebea83a4289cd6615526160d7ecf2a09842d4c2e90ae9f207a440a348ed8ef31e0cf1fe8b")),
            index:                  4403524705240661292'u64),
        ]),
        withdrawal_requests: List[WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD].init(@[
        ]),
        consolidation_requests: List[ConsolidationRequest, Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD].init(@[
          ConsolidationRequest(
            source_address: ExecutionAddress.fromHex("0xaa3e4b371bd5d3c907eae23ce4c4f6b5dfe0cb65"),
            source_pubkey:  ValidatorPubKey(blob: hexToByteArray[48]("0x5bfc2cffb681249ff93734c176a8bac7cb207859a77658019f7fadf0a49f8f5b2496c7fcb2a270ea99f9a80f15b95ac1")),
            target_pubkey:  ValidatorPubKey(blob: hexToByteArray[48]("0x495170003efda9e294e95cd4d80c903b4fe6c48846b1c8fcbca71b21837e6ca8ffecd0f224aead3e1088ae755a882ae5")))
          ]),
      )]

    for executionPayload in executionPayloads:
      check:
        executionPayload == asConsensusType(
          asEngineExecutionPayload(executionPayload))