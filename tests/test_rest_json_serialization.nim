# beacon_chain
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  unittest2,
  ../beacon_chain/spec/eth2_apis/eth2_rest_serialization

from std/strutils import endsWith, startsWith

const denebSignedContents = """
{
  "signed_block": {
    "message": {
      "slot": "1",
      "proposer_index": "78",
      "parent_root": "0xc45ed64e18affc40b6bd457da94edddded48e19d7c0a408872a0338291109d69",
      "state_root": "0xb389964bf50be75a47ad3184a88bd1a81c82debd0bfc8ad3026f32918aa2b678",
      "body": {
        "randao_reveal": "0x99b4d30c266a917d0a1d4dcaa184623da4e857c1b4f6af037f60b0d9c025aad5683c7ef186c9e92349f170130644c160125eee68f63874987666900e9910fe8ae22a253be446b95db72fcea232fc38b13055f954e7ea4dd089469c6b35d2f03f",
        "eth1_data": {
          "deposit_root": "0xd70a234731285c6804c2a4f56711ddb8c82c99740f207854891028af34e27e5e",
          "deposit_count": "0",
          "block_hash": "0x0e2dd0573112a2e7c3b47fcd350bd2e7fad74190cf400a59a4fe9be577f6e09a"
        },
        "graffiti": "0x4e696d6275732f7632332e31302e302d3764313032652d73746174656f667573",
        "proposer_slashings": [],
        "attester_slashings": [],
        "attestations": [],
        "deposits": [],
        "voluntary_exits": [],
        "sync_aggregate": {
          "sync_committee_bits": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
          "sync_committee_signature": "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        },
        "execution_payload": {
          "parent_hash": "0x0e2dd0573112a2e7c3b47fcd350bd2e7fad74190cf400a59a4fe9be577f6e09a",
          "fee_recipient": "0x0000000000000000000000000000000000000000",
          "state_root": "0x98eab6d31b718e561b6287b52aa0a671eea7507582f1676546396898d2d47909",
          "receipts_root": "0x7aca796fcc5d37e5c8dd6705e01b315fa28619159a1347cd14aabef1d52ff035",
          "logs_bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
          "prev_randao": "0x0e2dd0573112a2e7c3b47fcd350bd2e7fad74190cf400a59a4fe9be577f6e09a",
          "block_number": "1",
          "gas_limit": "30000000",
          "gas_used": "840000",
          "timestamp": "1698104353",
          "extra_data": "0xd983010d05846765746889676f312e32302e3130856c696e7578",
          "base_fee_per_gas": "875000000",
          "block_hash": "0x9488776c029345f7e3071666777857a566144b954cc39eb99843dc5427329b79",
          "transactions": [
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c080a03b358450d692c56faf7b980c92fcfba88c559aa39af99208a9f00b423acc20b0a0468cabd58fd69be69ff312acd1e833927770bace40722cad1e9d488f22b66f9c",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c080a0702629786f30a4261c75ed288e72e0bdb6cf3d319c6202eba861e591ca1c0c5da0632579257c0dd0157b584cc520691b37deb87699f389dbc4d9664337a0216ba9",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c080a059206a69bbf90b0be091afdbc4e8cda8a3d4320a4622290a5248629dc7cdfbbfa01abbb96bee39092974064a1ad468e4c9afe358a75bfcb1aa97e33ca7aef3b6e6",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c001a07a24d6001d13f0eec4d6945884e1c98bbce6e509aa15b7ac2e278452d232921ca0131d6a5d7cfea460c2409e93653fe40097c6ebfddfac3b8cf4f0148f29100513",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c001a0cd5cd45d25ef127fce9d9bfe22bd8f3a7b5cb7221ea8be58d391cf8d9ec8d8f3a045f2acc16c0aa77e9ceadec9b2bee55cb055dbcfcfefdc8e55cf3d44104c54c5",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c080a0a5d70c326eea7f50f30b0c53957b013312e2f61980248ce2faced348c914a053a047b3d1b1fff0c636be6f0afa84068249b2fa9b07e620ee8d0c9155514b2dd1c9",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c001a02ca4d129cb28926d2b828a7d55c38398e5dee053163a9c84f55b15a6ac9928cda01f2ddf1f7677df0fff8472192b4af65616bc4437e939dcc0b85a34310161b638",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c080a0cbc3b7af0bd38c3144e435e2e4320e8e12083f530eed3cfb3b38547420081650a07d08a31fd494a5fd77df4b28664021ce7fe55222235091d2b3c9f9494e98dd18",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c001a0edd8f7f423972a6cdc2ff9e1183f7a378b72666ae4eb1f7beb823570ea05ba8ba05e6e4d265672d35150bf8b4466ca370a6f552f66f00f730004776aef27d29448",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c001a0c3d2f210c42963f43e2c4ab922fb4b60b31f5772dd5cd51a04fd247b29c6aceda078e95f10084f4220834b6b9920685bbc6c0a1c03fc3945ffcb2f1c3c45908add",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c001a0414d20fd87b2cc3cd5578c16f63f7401771491c82b7f5236f77511fffdf37877a06d79d20c574be24b501aa1243f7ea0db0241d204a58c446ad2dc2edd0068eb04",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c001a0a4325fef7a1f8fd67db36d0fbabce01833adc86c0ab60bd5fff5371837f54d1da0663684a3bdc5a09fed86071baf934edf2985fa7f8e86625f75df810e7718e377",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c001a0e2b35cc96ebc8b829084a905b671ba7a685dbf9e80fb615f394e54e0bbae7136a03dbd0fd6f6a135907454b025a0db0b5bde2315cdcbeef0bb5582e066fe604ec9",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c001a0ffa39fac1e37413438cf2ffc7757aff009986d43fd54579dcc5e268c6271c19aa02fcc2b6f8bba9b52df57fa7a10d2f9db6327540a26d6b0647a793c0969345e7a",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c080a085468d61846280340e4a525b5c59567e47b1e56d5cc05bb9bad32c031b4743d0a01e0a59da0f6fce7fb72bae04919fecb8f1da65bdbb09d78ab52ad68c39367616",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c080a0e67e3f807df24367389a49f381a3da1245f6922e2d2dcb718db69d292b708032a05da40991323fb916b96be1fd698a2a82184e602317d1a37d2a14578b1ce45714",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c080a07f69331c1bcadc48ea531b4450527799b8e8d787360e30ab10dbd44dcc0e26b3a01d0bff9937c25eb5d5d5a2e7567e57483dbb2adfd7d25c9738e76751241b39a7",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c001a0b68303608457dd14592c8f2bbadf2be0293a0dcca18f3d40fe160d696d5268b3a0224d8632e1bf68dfa0de590db44ec140f71ea23681a874d16b85bc920b16a88d",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c001a01d669d7e9f13d59581986f9beb6ab713027344d593a67d591057316b085ebc85a07efb1f4d925e4ee1517b7878a02721c564e50d538fef95093064f9b407630f87",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c080a0249eee695f8747b231080a21e258853ade0cb19c8df4499bf75ceca1f6a25c99a07675eba7ee8800989973bc02766cb6d55ff8b9c4db05abb5ca48af42af314e5b",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c080a09c0405f697d5c00b59d3038418f4e511ad97d61810fc34815f336057e6f0bc6fa07ce86996838412ab0cbc38df5abfacaf43634f19e016589a38da6b92a9894975",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c080a06665d395ed5644d42db090fedb01a780c9db3be38c05e59b3643e049a1d91ab7a02dbe3f4991dfef1a18fe7b0f35baa5094d9c65f4acb3d1b4a5dd3a1d0a4f1557",
            "0x02f86b0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c080a050f8ed2d6a8203c38b26c68cfb14ace783fc4c1b430b78716c460804d50bd9619fd3ea81bbc032c41c3044f2fc5af507d0e8c5db9e120dd502c58a89ea25e373",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c001a04a40d062c4b5264bf0d676d076df85f24e3324a4183ddb0cf30be5582d49b20ba017b1adc11bf51d49c0c607213f08a1069f362e948fc074e1b773424598d774d6",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c001a0ac2c6671fe12e0fd59352c66eed2d60c61e6d97244332988b12b6c6a349f3e55a02d44af153ab2ffa799f4ec03c2177f68c5329540f619db36ea01148834ca4657",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c001a09c7e6fdabf2761746c6722c37750be186c2fc0609f47c97dbdae8280efe0f11da0537e2f8eaa958f5309edc85bceb14be65f87ccb9fb8658b5ffe82f9635d82317",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c080a0d4226152b464b050a7b5895f59dd18a5de77583ebd8b4f4631edac68cc5c2423a001330ad7552fd87047f3d0bea09437d532072a7deac3bae38db3866bb64516b0",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c080a0f8b11f229a1e41afe4e3701d4232505bb078b1a246ace0c88ff36f74994369d7a06f61cc9f29e7bc26b4ba4aa3999fb242f26a020b03f8a07e420dfc0fdd79265a",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c080a0dc833462e0deeda30d8b2aa5535b47d7edf9f27f8464a11a6b769e8dfd92aeb4a077225b4c5d679d67568330872b5655ff83d00bd933a116fcd1b7ac18815b12d0",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c080a052e410cc346d4d62044a0a08d1e3abbf9540cb49c67d9214fef11da411164f4ba0608ea170b1866e71c04a6ffe9f6455c901ae84d5f1c99a918d75aa1b0219bbd2",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c080a02adaa9b7c7655e20ee7524c6a6a232d448fef92ee916fff929486e8042448a54a038d4a09bdcd2b162529a30d0f25a6c8c43b119e97f3f4f367f2b70073cd17f36",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c001a0be55e714a8325aa08c50541f3a161dc41b3564b6f8969139d91b2ce4b698c874a06c715c986b9791e443d07c87d7c4e2bd255945316f3b218379d7d03b2d55ae45",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c080a00bef40a5ff05529d9ba778d863212d796ee961142b110a4f7f2596b070a543cfa03018a840307759cbb07601a3f67f28fdbd771968a04314794af051b738eb86e5",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c001a090091b17606193063439c7856849c53ec9eef795f769044d4388832044a26843a0315c1fc1185ae8f76aa284966288f5993ff2bf3dbde9852fb96748f713cd4551",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c001a04346018d335183d4a50ad8f65427db300dde0aaa46d6a63a78290fd3dd4e00e6a0740075872df331f79765007307424fe47377063535587e77c71482d4a79f7098",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c080a0f83505c2f2416ed193b42bbdca2d500cdaaacaf069949b5762f4c06dbcaa56f8a06dad5d8e30f9c26fb856e36047ed624f72cc8b6af7d15b8b0ed1abe8c1c9d9ac",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c001a0f1d100bfe1f755a777950fc1359ce34e4052cbac78e5d6dab2e56a53abec3da3a070543fc4be8c05d0b36ddc1199cb0c8e3e42cc2403c32e96f6296c5edc209869",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c080a0b0197617790cc75ba0404fe0de1ec906d42b7c50aad71aa69233fb67b871a2f7a04a7024859e0f53de69d3483a10a1145d2bef117c5dc20c99707118fabf8cc2a3",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c001a028c9b913712fbfae85cfd8cf599571b55a2d9e82f76c7234ce86799c9df482daa04bf773848792f29e80a55a004ceae7d7ddfc66e1d002ec0ea18e0e1104d47bd1",
            "0x02f86c0780843b9aca008506fc23ac008307a12094cccccccccccccccccccccccccccccccccccccccc0180c080a0b0aeafd16d1a8cc85486aa6b656ea91f561b20b073b1b6cb872fc42a3170c25ca0308e031d5cbe46b884786c663971f6d17427bdf7df2209cd34e9fb6d2c5f6726"
          ],
          "withdrawals": [
            {
              "index": "0",
              "validator_index": "0",
              "address": "0x0000000000000000000000000000000000000000",
              "amount": "1000000"
            },
            {
              "index": "1",
              "validator_index": "1",
              "address": "0x0100000000000000000000000000000000000000",
              "amount": "2000000"
            },
            {
              "index": "2",
              "validator_index": "2",
              "address": "0x0200000000000000000000000000000000000000",
              "amount": "3000000"
            },
            {
              "index": "3",
              "validator_index": "3",
              "address": "0x0300000000000000000000000000000000000000",
              "amount": "4000000"
            },
            {
              "index": "4",
              "validator_index": "4",
              "address": "0x0400000000000000000000000000000000000000",
              "amount": "5000000"
            },
            {
              "index": "5",
              "validator_index": "5",
              "address": "0x0500000000000000000000000000000000000000",
              "amount": "6000000"
            },
            {
              "index": "6",
              "validator_index": "6",
              "address": "0x0600000000000000000000000000000000000000",
              "amount": "7000000"
            },
            {
              "index": "7",
              "validator_index": "7",
              "address": "0x0700000000000000000000000000000000000000",
              "amount": "8000000"
            },
            {
              "index": "8",
              "validator_index": "8",
              "address": "0x0800000000000000000000000000000000000000",
              "amount": "9000000"
            },
            {
              "index": "9",
              "validator_index": "9",
              "address": "0x0900000000000000000000000000000000000000",
              "amount": "10000000"
            },
            {
              "index": "10",
              "validator_index": "10",
              "address": "0x0a00000000000000000000000000000000000000",
              "amount": "11000000"
            },
            {
              "index": "11",
              "validator_index": "11",
              "address": "0x0b00000000000000000000000000000000000000",
              "amount": "12000000"
            },
            {
              "index": "12",
              "validator_index": "12",
              "address": "0x0c00000000000000000000000000000000000000",
              "amount": "13000000"
            },
            {
              "index": "13",
              "validator_index": "13",
              "address": "0x0d00000000000000000000000000000000000000",
              "amount": "14000000"
            },
            {
              "index": "14",
              "validator_index": "14",
              "address": "0x0e00000000000000000000000000000000000000",
              "amount": "15000000"
            },
            {
              "index": "15",
              "validator_index": "15",
              "address": "0x0f00000000000000000000000000000000000000",
              "amount": "16000000"
            }
          ],
          "blob_gas_used": "0",
          "excess_blob_gas": "0"
        },
        "bls_to_execution_changes": [],
        "blob_kzg_commitments": []
      }
    },
    "signature": "0x8e2cd6cf4457825818eb380f1ea74f2fc99665041194ab5bcbdbf96f2e22bad4376d2a94f69d762c999ffd500e2525ab0561b01a79158456c83cf5bf0f2104e26f7b0d22f41dcc8f49a0e1cc29bb09aee1c548903fa04bdfcd20603c400d948d"
  },
  "kzg_proofs": [],
  "blobs": []
}
"""

# Can't be in same namespace as some other KZG-related fromHex overloads due to
# https://github.com/nim-lang/Nim/issues/22861
from stew/byteutils import hexToByteArray
func fromHex(T: typedesc[KzgCommitment], s: string): T {.
     raises: [ValueError].} =
  var res: T
  hexToByteArray(s, res)
  res

suite "REST JSON encoding and decoding":
  test "DenebSignedBlockContents decoding":
    check: hash_tree_root(RestJson.decode(
      denebSignedContents, DenebSignedBlockContents, requireAllFields = true,
      allowUnknownFields = true)) == Eth2Digest.fromHex(
        "0xe02803d15690a13e5d04c2b269ed8628394b502716bca3b14837b289292e8e80")

  test "RestPublishedSignedBlockContents decoding":
    check: hash_tree_root(RestJson.decode(
      denebSignedContents, RestPublishedSignedBlockContents,
      requireAllFields = true, allowUnknownFields = true).denebData) ==
        Eth2Digest.fromHex(
          "0xe02803d15690a13e5d04c2b269ed8628394b502716bca3b14837b289292e8e80")

  test "KzgCommitment":
    let
      zeroString =
        "\"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\""
      randString =
        "\"0xe2822fdd03685968091c79b1f81d17ed646196c920baecf927a6abbe45cd2d930a692e85ff5d96ebe36d99a57c74d5cb\""
      zeroKzgCommitment = KzgCommitment.fromHex(
        "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
      randKzgCommitment = KzgCommitment.fromHex(
        "0xe2822fdd03685968091c79b1f81d17ed646196c920baecf927a6abbe45cd2d930a692e85ff5d96ebe36d99a57c74d5cb")

    check:
      RestJson.decode(
        zeroString, KzgCommitment, requireAllFields = true,
          allowUnknownFields = true) == zeroKzgCommitment
      RestJson.decode(
        zeroString, KzgCommitment, requireAllFields = true,
          allowUnknownFields = true) != randKzgCommitment
      RestJson.decode(
        randString, KzgCommitment, requireAllFields = true,
          allowUnknownFields = true) != zeroKzgCommitment
      RestJson.decode(
        randString, KzgCommitment, requireAllFields = true,
          allowUnknownFields = true) == randKzgCommitment

      RestJson.encode(zeroKzgCommitment) == zeroString
      RestJson.encode(zeroKzgCommitment) != randString
      RestJson.encode(randKzgCommitment) != zeroString
      RestJson.encode(randKzgCommitment) == randString

  test "KzgProof":
    let
      zeroString =
        "\"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\""
      randString =
        "\"0xe2822fdd03685968091c79b1f81d17ed646196c920baecf927a6abbe45cd2d930a692e85ff5d96ebe36d99a57c74d5cb\""
      zeroKzgProof = KzgProof.fromHex(
        "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
      randKzgProof = KzgProof.fromHex(
        "0xe2822fdd03685968091c79b1f81d17ed646196c920baecf927a6abbe45cd2d930a692e85ff5d96ebe36d99a57c74d5cb")

    check:
      RestJson.decode(
        zeroString, KzgProof, requireAllFields = true,
          allowUnknownFields = true) == zeroKzgProof
      RestJson.decode(
        zeroString, KzgProof, requireAllFields = true,
          allowUnknownFields = true) != randKzgProof
      RestJson.decode(
        randString, KzgProof, requireAllFields = true,
          allowUnknownFields = true) != zeroKzgProof
      RestJson.decode(
        randString, KzgProof, requireAllFields = true,
          allowUnknownFields = true) == randKzgProof

      RestJson.encode(zeroKzgProof) == zeroString
      RestJson.encode(zeroKzgProof) != randString
      RestJson.encode(randKzgProof) != zeroString
      RestJson.encode(randKzgProof) == randString

  test "Blob":
    let
      zeroBlob = new Blob
      nonzeroBlob = new Blob
      blobLen = distinctBase(nonzeroBlob[]).lenu64

    for i in 0 ..< blobLen:
      nonzeroBlob[i] = 17.byte

    let
      zeroString = newClone(RestJson.encode(zeroBlob[]))
      nonzeroString = newClone(RestJson.encode(nonzeroBlob[]))

    let
      zeroBlobRoundTrip =
        newClone(RestJson.decode(
          zeroString[], Blob, requireAllFields = true, allowUnknownFields = true))
      nonzeroBlobRoundTrip =
        newClone(RestJson.decode(
          nonzeroString[], Blob, requireAllFields = true,
          allowUnknownFields = true))

    check:
      zeroString[].startsWith "\"0x0000000000000000000000000000000000000000000000000"
      nonzeroString[].startsWith "\"0x111111111111111111111111111111111111111111111111"
      zeroString[].endsWith "0000000000000000000000000000000000000000000000\""
      nonzeroString[].endsWith "1111111111111111111111111111111111111111111111\""
      zeroString[].lenu64 == 2*blobLen + 4   # quotation marks and 0x prefix
      nonzeroString[].lenu64 == 2*blobLen + 4   # quotation marks and 0x prefix
      zeroBlob[] == zeroBlobRoundTrip[]
      nonzeroBlob[] == nonzeroBlobRoundTrip[]
      zeroBlob[] != nonzeroBlob[]
