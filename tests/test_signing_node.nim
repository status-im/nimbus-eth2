# nimbus_signing_node
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/algorithm,
  presto, unittest2, chronicles, stew/[results, byteutils, io2],
  chronos/asyncproc,
  chronos/unittest2/asynctests,
  ../beacon_chain/spec/[signatures, crypto],
  ../beacon_chain/spec/eth2_apis/rest_remote_signer_calls,
  ../beacon_chain/filepath,
  ../beacon_chain/validators/validator_pool

from os import getEnv, osErrorMsg

{.used.}

const
  TestDirectoryName = "test-signing-node"
  TestDirectoryNameVerifyingWeb3Signer = "test-signing-node-verifying-web3signer"
  ValidatorKeystore1 = "{\"crypto\":{\"kdf\":{\"function\":\"pbkdf2\",\"params\":{\"dklen\":32,\"c\":1,\"prf\":\"hmac-sha256\",\"salt\":\"040f3f4b9dfc4bdeb37de870cbaa83582f981f358e370f271c2945f2e6430aab\"},\"message\":\"\"},\"checksum\":{\"function\":\"sha256\",\"params\":{},\"message\":\"8b98b30b4e144dbbcc724e502ffecc67c33651aa49600e745e41f959e12abf37\"},\"cipher\":{\"function\":\"aes-128-ctr\",\"params\":{\"iv\":\"04f91a7eb3d6430a598255ea83621e78\"},\"message\":\"5c652e6cdd1215eb9203281e2446abc4d3e1bd50cb822583ce5c74570e9cab18\"}},\"pubkey\":\"99a8df087e253a874c3ca31e0d1115500a671ed8714800d503e99c2c887331a968a7fa7f0290c3a0698675eee138b407\",\"path\":\"m/12381/3600/161/0/0\",\"uuid\":\"81bec933-d928-4e7e-83da-54bbe37a4715\",\"version\":4}"
  ValidatorKeystore2 = "{\"crypto\":{\"kdf\":{\"function\":\"pbkdf2\",\"params\":{\"dklen\":32,\"c\":1,\"prf\":\"hmac-sha256\",\"salt\":\"040f3f4b9dfc4bdeb37de870cbaa83582f981f358e370f271c2945f2e6430aab\"},\"message\":\"\"},\"checksum\":{\"function\":\"sha256\",\"params\":{},\"message\":\"2ecda276340c04cb92ce003db9cface0727905f0ba1aa9c60b101f478fca9a5e\"},\"cipher\":{\"function\":\"aes-128-ctr\",\"params\":{\"iv\":\"9d9d73af0031fd19e6833983557b2e30\"},\"message\":\"16d5f87e0675c95cb1e4fc209eea738d45c19b3c0f14088c9e140c573bce0253\"}},\"pubkey\":\"aa19751eb240a04a17b8720e2334acf1d78182ab496e77c51b3bb9e887d50295a478d499abcf6434efbc1aa4c4c4f352\",\"path\":\"m/12381/3600/232/0/0\",\"uuid\":\"291e837b-d8ff-494c-8c7b-7e6bab23b8bf\",\"version\":4}"
  ValidatorKeystore3 = "{\"crypto\":{\"kdf\":{\"function\":\"pbkdf2\",\"params\":{\"dklen\":32,\"c\":1,\"prf\":\"hmac-sha256\",\"salt\":\"040f3f4b9dfc4bdeb37de870cbaa83582f981f358e370f271c2945f2e6430aab\"},\"message\":\"\"},\"checksum\":{\"function\":\"sha256\",\"params\":{},\"message\":\"a8c2333e787d65415a02d607c0ec774b654e5a67066e4bc379e2f3b7cf4c826a\"},\"cipher\":{\"function\":\"aes-128-ctr\",\"params\":{\"iv\":\"161171cb21c1c6ec20b15798f545fffc\"},\"message\":\"8ecb326d14dece099d4ba4800a5326324ccf3a8df38fd4aa37af02e8f0617da0\"}},\"pubkey\":\"acf31f9b1ecf65dbb198e380599b6c81fc1a1f5db4457482cc697d81b1fdfb6e49cf8eff4980477f6e32749eef61dc4d\",\"path\":\"m/12381/3600/36/0/0\",\"uuid\":\"420578fd-6832-4e79-a3db-ac0662ace13c\",\"version\":4}"
  ValidatorKeystore4 = "{\"crypto\":{\"kdf\":{\"function\":\"pbkdf2\",\"params\":{\"dklen\":32,\"c\":1,\"prf\":\"hmac-sha256\",\"salt\":\"040f3f4b9dfc4bdeb37de870cbaa83582f981f358e370f271c2945f2e6430aab\"},\"message\":\"\"},\"checksum\":{\"function\":\"sha256\",\"params\":{},\"message\":\"ca3ab990616d81e77e89b14eb6f613c1f13056ef2d062259259d54c7a85d63c9\"},\"cipher\":{\"function\":\"aes-128-ctr\",\"params\":{\"iv\":\"d0096f545dcdb366ef3f86e609fc008e\"},\"message\":\"be2f4f3edde8ade888eb4b0211a00b0528ddc4fa68bb0e67c992a05518cd9d96\"}},\"pubkey\":\"a73469094bf134f32a4e91fce07101290c85ffb259f277c97308310ffd0ef1aa3bd90eea1a8217d060b727b7a0154c34\",\"path\":\"m/12381/3600/119/0/0\",\"uuid\":\"2e07f033-c1b6-4d5f-b448-d18caab93adc\",\"version\":4}"

  KeystorePassword =
    "1331CE70907C1F64745D47447CE378EEA6A95DB271CDA7E54D9D7AB52EE0E0A2"
  ValidatorPrivateKey1 =
    "0x151c2858787a50476b5107f64977bfaed5b925e9db38b2f5a6ed39c77159d7a6"
  ValidatorPrivateKey2 =
    "0x44e711335ab6981a92a8711cd68399b4d14da7105368fc26cd59520f69dd8e83"
  ValidatorPrivateKey3 =
    "0x47264627bb3d80ceab5d4de081418927837ce777434af2609c1106d0b5327cb5"
  ValidatorPubKey1 =
    "0x99a8df087e253a874c3ca31e0d1115500a671ed8714800d503e99c2c887331a968a7fa7f0290c3a0698675eee138b407"
  ValidatorPubKey2 =
    "0xaa19751eb240a04a17b8720e2334acf1d78182ab496e77c51b3bb9e887d50295a478d499abcf6434efbc1aa4c4c4f352"
  ValidatorPubKey3 =
    "0xacf31f9b1ecf65dbb198e380599b6c81fc1a1f5db4457482cc697d81b1fdfb6e49cf8eff4980477f6e32749eef61dc4d"
  ValidatorPubKey4 =
    "0xa73469094bf134f32a4e91fce07101290c85ffb259f277c97308310ffd0ef1aa3bd90eea1a8217d060b727b7a0154c34"
  GenesisValidatorsRoot = Eth2Digest.fromHex(
    "043db0d9a83813551ee2f33450d23797757d430911a9320530ad8a0eabc43efb")
  GenesisForkVersion = Version(hexToByteArray[4]("00001020"))
  SomeOtherRoot = Eth2Digest.fromHex(
    "ccccccaaaaaaffffffeeeeee50d23797757d430911a9320530ad8a0eabc43efb")
  SigningFork = Fork(
    previous_version: Version(hexToByteArray[4]("00001020")),
    current_version: Version(hexToByteArray[4]("00001020")),
    epoch: Epoch(0'u64)
  )
  SomeSignature =
    "0xb3baa751d0a9132cfe93e4e3d5ff9075111100e3789dca219ade5a24d27e19d16b3353149da1833e9b691bb38634e8dc04469be7032132906c927d7e1a49b414730612877bc6b2810c8f202daf793d1ab0d6b5cb21d52f9e52e883859887a5d9"

  SigningExpectedFeeRecipient = "0x000095e79eac4d76aab57cb2c1f091d553b36ca0"
  SigningOtherFeeRecipient =    "0x000096e79eac4d76aab57cb2c1f091d553b36ca0"

  AgAttestation = "{\"data\":{\"aggregation_bits\":\"0x01\",\"signature\":\"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505\",\"data\":{\"slot\":\"1\",\"index\":\"1\",\"beacon_block_root\":\"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2\",\"source\":{\"epoch\":\"1\",\"root\":\"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2\"},\"target\":{\"epoch\":\"1\",\"root\":\"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2\"}}}}"

  Phase0Block = "{\"version\":\"phase0\",\"data\":{\"slot\":\"1\",\"proposer_index\":\"1\",\"parent_root\":\"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2\",\"state_root\":\"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2\",\"body\":{\"randao_reveal\":\"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505\",\"eth1_data\":{\"deposit_root\":\"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2\",\"deposit_count\":\"1\",\"block_hash\":\"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2\"},\"graffiti\":\"\",\"proposer_slashings\":[],\"attester_slashings\":[],\"attestations\":[],\"deposits\":[],\"voluntary_exits\":[]}}}"
  AltairBlock = "{\"version\":\"altair\",\"data\":{\"slot\":\"5297696\",\"proposer_index\":\"153094\",\"parent_root\":\"0xe6106533af9be918120ead7440a8006c7f123cc3cb7daf1f11d951864abea014\",\"state_root\":\"0xf86196d34500ca25d1f4e7431d4d52f6f85540bcaf97dd0d2ad9ecdb3eebcdf0\",\"body\":{\"randao_reveal\":\"0xa7efee3d5ddceb60810b23e3b5d39734696418f41dfd13a0851c7be7a72acbdceaa61e1db27513801917d72519d1c1040ccfed829faf06abe06d9964949554bf4369134b66de715ea49eb4fecf3e2b7e646f1764a1993e31e53dbc6557929c12\",\"eth1_data\":{\"deposit_root\":\"0x8ec87d7219a3c873fff3bfe206b4f923d1b471ce4ff9d6d6ecc162ef07825e14\",\"deposit_count\":\"259476\",\"block_hash\":\"0x877b6f8332c7397251ff3f0c5cecec105ff7d4cb78251b47f91fd15a86a565ab\"},\"graffiti\":\"\",\"proposer_slashings\":[],\"attester_slashings\":[],\"attestations\":[],\"deposits\":[],\"voluntary_exits\":[],\"sync_aggregate\":{\"sync_committee_bits\":\"0x733dfda7f5ffde5ade73367fcbf7fffeef7fe43777ffdffab9dbad6f7eed5fff9bfec4affdefbfaddf35bf5efbff9ffff9dfd7dbf97fbfcdfaddfeffbf95f75f\",\"sync_committee_signature\":\"0x81fdf76e797f81b0116a1c1ae5200b613c8041115223cd89e8bd5477aab13de6097a9ebf42b130c59527bbb4c96811b809353a17c717549f82d4bd336068ef0b99b1feebd4d2432a69fa77fac12b78f1fcc9d7b59edbeb381adf10b15bc4a520\"}}}}"
  BellatrixBlock = "{\"version\":\"bellatrix\",\"data\":{\"slot\":\"5297696\",\"proposer_index\":\"153094\",\"parent_root\":\"0xe6106533af9be918120ead7440a8006c7f123cc3cb7daf1f11d951864abea014\",\"state_root\":\"0xf86196d34500ca25d1f4e7431d4d52f6f85540bcaf97dd0d2ad9ecdb3eebcdf0\",\"body\":{\"randao_reveal\":\"0xa7efee3d5ddceb60810b23e3b5d39734696418f41dfd13a0851c7be7a72acbdceaa61e1db27513801917d72519d1c1040ccfed829faf06abe06d9964949554bf4369134b66de715ea49eb4fecf3e2b7e646f1764a1993e31e53dbc6557929c12\",\"eth1_data\":{\"deposit_root\":\"0x8ec87d7219a3c873fff3bfe206b4f923d1b471ce4ff9d6d6ecc162ef07825e14\",\"deposit_count\":\"259476\",\"block_hash\":\"0x877b6f8332c7397251ff3f0c5cecec105ff7d4cb78251b47f91fd15a86a565ab\"},\"graffiti\":\"\",\"proposer_slashings\":[],\"attester_slashings\":[],\"attestations\":[],\"deposits\":[],\"voluntary_exits\":[],\"sync_aggregate\":{\"sync_committee_bits\":\"0x733dfda7f5ffde5ade73367fcbf7fffeef7fe43777ffdffab9dbad6f7eed5fff9bfec4affdefbfaddf35bf5efbff9ffff9dfd7dbf97fbfcdfaddfeffbf95f75f\",\"sync_committee_signature\":\"0x81fdf76e797f81b0116a1c1ae5200b613c8041115223cd89e8bd5477aab13de6097a9ebf42b130c59527bbb4c96811b809353a17c717549f82d4bd336068ef0b99b1feebd4d2432a69fa77fac12b78f1fcc9d7b59edbeb381adf10b15bc4a520\"},\"execution_payload\":{\"parent_hash\":\"0x14c2242a8cfbce559e84c391f5f16d10d7719751b8558873012dc88ae5a193e8\",\"fee_recipient\":\"$1\",\"state_root\":\"0xdf8d96b2c292736d39e72e25802c2744d34d3d3c616de5b362425cab01f72fa5\",\"receipts_root\":\"0x4938a2bf640846d213b156a1a853548b369cd02917fa63d8766ab665d7930bac\",\"logs_bloom\":\"0x298610600038408c201080013832408850a00bc8f801920121840030a015310010e2a0e0108628110552062811441c84802f43825c4fc82140b036c58025a28800054c80a44025c052090a0f2c209a0400058040019ea0008e589084078048050880930113a2894082e0112408b088382402a851621042212aa40018a408d07e178c68691486411aa9a2809043b000a04c040000065a030028018540b04b1820271d00821b00c29059095022322c10a530060223240416140190056608200063c82248274ba8f0098e402041cd9f451031481a1010b8220824833520490221071898802d206348449116812280014a10a2d1c210100a30010802490f0a221849\",\"prev_randao\":\"0xc061711e135cd40531ec3ee29d17d3824c0e5f80d07f721e792ab83240aa0ab5\",\"block_number\":\"8737497\",\"gas_limit\":\"30000000\",\"gas_used\":\"16367052\",\"timestamp\":\"1680080352\",\"extra_data\":\"0xd883010b05846765746888676f312e32302e32856c696e7578\",\"base_fee_per_gas\":\"231613172261\",\"block_hash\":\"0x5aa9fd22a9238925adb2b038fd6eafc77adabf554051db5bc16ae5168a52eff6\",\"transactions\":[],\"withdrawals\":[]}}}}"
  CapellaBlock = "{\"version\":\"capella\",\"data\":{\"slot\":\"5297696\",\"proposer_index\":\"153094\",\"parent_root\":\"0xe6106533af9be918120ead7440a8006c7f123cc3cb7daf1f11d951864abea014\",\"state_root\":\"0xf86196d34500ca25d1f4e7431d4d52f6f85540bcaf97dd0d2ad9ecdb3eebcdf0\",\"body\":{\"randao_reveal\":\"0xa7efee3d5ddceb60810b23e3b5d39734696418f41dfd13a0851c7be7a72acbdceaa61e1db27513801917d72519d1c1040ccfed829faf06abe06d9964949554bf4369134b66de715ea49eb4fecf3e2b7e646f1764a1993e31e53dbc6557929c12\",\"eth1_data\":{\"deposit_root\":\"0x8ec87d7219a3c873fff3bfe206b4f923d1b471ce4ff9d6d6ecc162ef07825e14\",\"deposit_count\":\"259476\",\"block_hash\":\"0x877b6f8332c7397251ff3f0c5cecec105ff7d4cb78251b47f91fd15a86a565ab\"},\"graffiti\":\"\",\"proposer_slashings\":[],\"attester_slashings\":[],\"attestations\":[],\"deposits\":[],\"voluntary_exits\":[],\"sync_aggregate\":{\"sync_committee_bits\":\"0x733dfda7f5ffde5ade73367fcbf7fffeef7fe43777ffdffab9dbad6f7eed5fff9bfec4affdefbfaddf35bf5efbff9ffff9dfd7dbf97fbfcdfaddfeffbf95f75f\",\"sync_committee_signature\":\"0x81fdf76e797f81b0116a1c1ae5200b613c8041115223cd89e8bd5477aab13de6097a9ebf42b130c59527bbb4c96811b809353a17c717549f82d4bd336068ef0b99b1feebd4d2432a69fa77fac12b78f1fcc9d7b59edbeb381adf10b15bc4a520\"},\"execution_payload\":{\"parent_hash\":\"0x14c2242a8cfbce559e84c391f5f16d10d7719751b8558873012dc88ae5a193e8\",\"fee_recipient\":\"$1\",\"state_root\":\"0xdf8d96b2c292736d39e72e25802c2744d34d3d3c616de5b362425cab01f72fa5\",\"receipts_root\":\"0x4938a2bf640846d213b156a1a853548b369cd02917fa63d8766ab665d7930bac\",\"logs_bloom\":\"0x298610600038408c201080013832408850a00bc8f801920121840030a015310010e2a0e0108628110552062811441c84802f43825c4fc82140b036c58025a28800054c80a44025c052090a0f2c209a0400058040019ea0008e589084078048050880930113a2894082e0112408b088382402a851621042212aa40018a408d07e178c68691486411aa9a2809043b000a04c040000065a030028018540b04b1820271d00821b00c29059095022322c10a530060223240416140190056608200063c82248274ba8f0098e402041cd9f451031481a1010b8220824833520490221071898802d206348449116812280014a10a2d1c210100a30010802490f0a221849\",\"prev_randao\":\"0xc061711e135cd40531ec3ee29d17d3824c0e5f80d07f721e792ab83240aa0ab5\",\"block_number\":\"8737497\",\"gas_limit\":\"30000000\",\"gas_used\":\"16367052\",\"timestamp\":\"1680080352\",\"extra_data\":\"0xd883010b05846765746888676f312e32302e32856c696e7578\",\"base_fee_per_gas\":\"231613172261\",\"block_hash\":\"0x5aa9fd22a9238925adb2b038fd6eafc77adabf554051db5bc16ae5168a52eff6\",\"transactions\":[],\"withdrawals\":[]},\"bls_to_execution_changes\":[]}}}"
  DenebBlockContents = "{\"version\":\"deneb\",\"data\":{\"block\":{\"slot\":\"5297696\",\"proposer_index\":\"153094\",\"parent_root\":\"0xe6106533af9be918120ead7440a8006c7f123cc3cb7daf1f11d951864abea014\",\"state_root\":\"0xf86196d34500ca25d1f4e7431d4d52f6f85540bcaf97dd0d2ad9ecdb3eebcdf0\",\"body\":{\"randao_reveal\":\"0xa7efee3d5ddceb60810b23e3b5d39734696418f41dfd13a0851c7be7a72acbdceaa61e1db27513801917d72519d1c1040ccfed829faf06abe06d9964949554bf4369134b66de715ea49eb4fecf3e2b7e646f1764a1993e31e53dbc6557929c12\",\"eth1_data\":{\"deposit_root\":\"0x8ec87d7219a3c873fff3bfe206b4f923d1b471ce4ff9d6d6ecc162ef07825e14\",\"deposit_count\":\"259476\",\"block_hash\":\"0x877b6f8332c7397251ff3f0c5cecec105ff7d4cb78251b47f91fd15a86a565ab\"},\"graffiti\":\"\",\"proposer_slashings\":[],\"attester_slashings\":[],\"attestations\":[],\"deposits\":[],\"voluntary_exits\":[],\"sync_aggregate\":{\"sync_committee_bits\":\"0x733dfda7f5ffde5ade73367fcbf7fffeef7fe43777ffdffab9dbad6f7eed5fff9bfec4affdefbfaddf35bf5efbff9ffff9dfd7dbf97fbfcdfaddfeffbf95f75f\",\"sync_committee_signature\":\"0x81fdf76e797f81b0116a1c1ae5200b613c8041115223cd89e8bd5477aab13de6097a9ebf42b130c59527bbb4c96811b809353a17c717549f82d4bd336068ef0b99b1feebd4d2432a69fa77fac12b78f1fcc9d7b59edbeb381adf10b15bc4a520\"},\"execution_payload\":{\"parent_hash\":\"0x14c2242a8cfbce559e84c391f5f16d10d7719751b8558873012dc88ae5a193e8\",\"fee_recipient\":\"$1\",\"state_root\":\"0xdf8d96b2c292736d39e72e25802c2744d34d3d3c616de5b362425cab01f72fa5\",\"receipts_root\":\"0x4938a2bf640846d213b156a1a853548b369cd02917fa63d8766ab665d7930bac\",\"logs_bloom\":\"0x298610600038408c201080013832408850a00bc8f801920121840030a015310010e2a0e0108628110552062811441c84802f43825c4fc82140b036c58025a28800054c80a44025c052090a0f2c209a0400058040019ea0008e589084078048050880930113a2894082e0112408b088382402a851621042212aa40018a408d07e178c68691486411aa9a2809043b000a04c040000065a030028018540b04b1820271d00821b00c29059095022322c10a530060223240416140190056608200063c82248274ba8f0098e402041cd9f451031481a1010b8220824833520490221071898802d206348449116812280014a10a2d1c210100a30010802490f0a221849\",\"prev_randao\":\"0xc061711e135cd40531ec3ee29d17d3824c0e5f80d07f721e792ab83240aa0ab5\",\"block_number\":\"8737497\",\"gas_limit\":\"30000000\",\"gas_used\":\"16367052\",\"timestamp\":\"1680080352\",\"extra_data\":\"0xd883010b05846765746888676f312e32302e32856c696e7578\",\"base_fee_per_gas\":\"231613172261\",\"block_hash\":\"0x5aa9fd22a9238925adb2b038fd6eafc77adabf554051db5bc16ae5168a52eff6\",\"transactions\":[],\"withdrawals\":[],\"blob_gas_used\":\"2316131761\",\"excess_blob_gas\":\"231613172261\"},\"bls_to_execution_changes\":[],\"blob_kzg_commitments\":[]}},\"kzg_proofs\":[],\"blobs\":[]}}"

  SigningNodeAddress = "127.0.0.1"
  defaultSigningNodePort = 35333

  SigningRequestTimeoutSeconds = 1

type
  SigningProcess = object
    process: AsyncProcessRef
    reader: Future[seq[byte]]

proc getNodePort(basePort: int, rt: RemoteSignerType): int =
  # Individual port numbers derived by adding to configurable base port
  case rt
  of RemoteSignerType.Web3Signer:
    basePort
  of RemoteSignerType.VerifyingWeb3Signer:
    basePort + 1

func init(T: type ForkedBeaconBlock, contents: ProduceBlockResponseV2): T =
  case contents.kind
  of ConsensusFork.Phase0:
    return ForkedBeaconBlock.init(contents.phase0Data)
  of ConsensusFork.Altair:
    return ForkedBeaconBlock.init(contents.altairData)
  of ConsensusFork.Bellatrix:
    return ForkedBeaconBlock.init(contents.bellatrixData)
  of ConsensusFork.Capella:
    return ForkedBeaconBlock.init(contents.capellaData)
  of ConsensusFork.Deneb:
    return ForkedBeaconBlock.init(contents.denebData.`block`)

proc getBlock(fork: ConsensusFork,
              feeRecipient = SigningExpectedFeeRecipient): ForkedBeaconBlock =
  let
    blckData =
      case fork
      of ConsensusFork.Phase0:    Phase0Block
      of ConsensusFork.Altair:    AltairBlock
      of ConsensusFork.Bellatrix: BellatrixBlock % [feeRecipient]
      of ConsensusFork.Capella:   CapellaBlock % [feeRecipient]
      of ConsensusFork.Deneb:     DenebBlockContents % [feeRecipient]
    contentType = ContentTypeData(
      mediaType: MediaType.init("application/json"))


  let b = decodeBytes(ProduceBlockResponseV2,
                      blckData.toOpenArrayByte(0, len(blckData) - 1),
                      Opt.some(contentType),
                      $fork).tryGet()
  ForkedBeaconBlock.init(b)

proc init(t: typedesc[Web3SignerForkedBeaconBlock],
          forked: ForkedBeaconBlock): Web3SignerForkedBeaconBlock =
  case forked.kind
  of ConsensusFork.Phase0, ConsensusFork.Altair:
    raiseAssert "supports Bellatrix and later forks"
  of ConsensusFork.Bellatrix:
    Web3SignerForkedBeaconBlock(
      kind: ConsensusFork.Bellatrix,
      data: forked.bellatrixData.toBeaconBlockHeader)
  of ConsensusFork.Capella:
    Web3SignerForkedBeaconBlock(
      kind: ConsensusFork.Capella,
      data: forked.capellaData.toBeaconBlockHeader)
  of ConsensusFork.Deneb:
    Web3SignerForkedBeaconBlock(
      kind: ConsensusFork.Deneb,
      data: forked.denebData.toBeaconBlockHeader)

proc createKeystore(dataDir, pubkey,
                    store, password: string): Result[void, string] =
  let
    validatorsDir = dataDir & DirSep & "validators"
    keystoreDir = validatorsDir & DirSep & pubkey
    keystoreFile = keystoreDir & DirSep & "keystore.json"
    secretsDir = dataDir & DirSep & "secrets"
    secretFile = secretsDir & DirSep & pubkey

  if not(isDir(dataDir)):
    let res = secureCreatePath(dataDir)
    if res.isErr(): return err(ioErrorMsg(res.error))
  if not(isDir(validatorsDir)):
    let res = secureCreatePath(validatorsDir)
    if res.isErr(): return err(ioErrorMsg(res.error))
  if not(isDir(secretsDir)):
    let res = secureCreatePath(secretsDir)
    if res.isErr(): return err(ioErrorMsg(res.error))
  if not(isDir(keystoreDir)):
    let res = secureCreatePath(keystoreDir)
    if res.isErr(): return err(ioErrorMsg(res.error))

  block:
    let res = secureWriteFile(keystoreFile,
                              store.toOpenArrayByte(0, len(store) - 1))
    if res.isErr(): return err(ioErrorMsg(res.error))
  block:
    let res = secureWriteFile(secretFile,
                              password.toOpenArrayByte(0, len(password) - 1))
    if res.isErr(): return err(ioErrorMsg(res.error))

  ok()

proc removeKeystore(dataDir, pubkey: string) =
  let
    validatorsDir = dataDir & DirSep & "validators"
    keystoreDir = validatorsDir & DirSep & pubkey
    keystoreFile = keystoreDir & DirSep & "keystore.json"
    secretsDir = dataDir & DirSep & "secrets"
    secretFile = secretsDir & DirSep & pubkey

  discard removeFile(secretFile)
  discard removeFile(keystoreFile)
  discard removeDir(keystoreDir)
  discard removeDir(validatorsDir)
  discard removeDir(secretsDir)

proc createDataDir(pathName: string): Result[void, string] =
  ? createKeystore(pathName, ValidatorPubKey1, ValidatorKeystore1,
                   KeystorePassword)
  ? createKeystore(pathName, ValidatorPubKey2, ValidatorKeystore2,
                   KeystorePassword)
  ? createKeystore(pathName, ValidatorPubKey3, ValidatorKeystore3,
                   KeystorePassword)
  ok()

proc getTestDir(rt: RemoteSignerType): string =
  case rt
  of RemoteSignerType.Web3Signer:
    TestDirectoryName
  of RemoteSignerType.VerifyingWeb3Signer:
    TestDirectoryNameVerifyingWeb3Signer

proc createTestDir(rt: RemoteSignerType): Result[void, string] =
  let
    pathName = getTestDir(rt)
    signingDir = pathName & DirSep & "signing-node"
  if not(isDir(pathName)):
    let res = secureCreatePath(pathName)
    if res.isErr(): return err(ioErrorMsg(res.error))
  createDataDir(signingDir)

proc createAdditionalKeystore(rt: RemoteSignerType): Result[void, string] =
  let signingDir = getTestDir(rt) & DirSep & "signing-node"
  createKeystore(signingDir, ValidatorPubKey4, ValidatorKeystore4,
                 KeystorePassword)

proc removeTestDir(rt: RemoteSignerType) =
  let
    pathName = getTestDir(rt)
    signingDir = pathName & DirSep & "signing-node"
  # signing-node cleanup
  removeKeystore(signingDir, ValidatorPubKey1)
  removeKeystore(signingDir, ValidatorPubKey2)
  removeKeystore(signingDir, ValidatorPubKey3)
  removeKeystore(signingDir, ValidatorPubKey4)
  discard removeDir(signingDir)
  discard removeDir(pathName)

proc getPrivateKey(data: string): Result[ValidatorPrivKey, string] =
  var key: blscurve.SecretKey
  if fromHex(key, data):
    ok(ValidatorPrivKey(key))
  else:
    err("Unable to initialize private key")

proc getLocalKeystoreData(data: string): Result[KeystoreData, string] =
  let privateKey =
    block:
      var key: blscurve.SecretKey
      if not(fromHex(key, data)):
        return err("Unable to initialize private key")
      ValidatorPrivKey(key)

  ok KeystoreData(
    kind: KeystoreKind.Local,
    privateKey: privateKey,
    version: uint64(4),
    pubkey: privateKey.toPubKey().toPubKey())

proc getRemoteKeystoreData(data: string, basePort: int,
                           rt: RemoteSignerType): Result[KeystoreData, string] =
  let
    publicKey = ValidatorPubKey.fromHex(data).valueOr:
      return err("Invalid public key")

    info = RemoteSignerInfo(
      url: HttpHostUri(parseUri("http://" & SigningNodeAddress & ":" &
                                $getNodePort(basePort, rt))),
      pubkey: publicKey
    )

  ok case rt
    of RemoteSignerType.Web3Signer:
      KeystoreData(
        kind: KeystoreKind.Remote,
        remoteType: RemoteSignerType.Web3Signer,
        version: uint64(4),
        pubkey: publicKey,
        remotes: @[info])
    of RemoteSignerType.VerifyingWeb3Signer:
      KeystoreData(
        kind: KeystoreKind.Remote,
        remoteType: RemoteSignerType.VerifyingWeb3Signer,
        provenBlockProperties: @[
          ProvenProperty(
            path: ".execution_payload.fee_recipient",
            denebIndex: some GeneralizedIndex(801),
            capellaIndex: some GeneralizedIndex(401),
            bellatrixIndex: some GeneralizedIndex(401)
          )
        ],
        version: uint64(4),
        pubkey: publicKey,
        remotes: @[info])

proc spawnSigningNodeProcess(
    basePort: int, rt: RemoteSignerType): Future[SigningProcess] {.async.} =
  let arguments =
    case rt
    of RemoteSignerType.Web3Signer:
      @[
        "--non-interactive=true",
        "--log-level=DEBUG",
        "--data-dir=" & getTestDir(rt) & "/signing-node",
        "--bind-address=" & SigningNodeAddress,
        "--bind-port=" & $getNodePort(basePort, rt),
        "--request-timeout=" & $SigningRequestTimeoutSeconds
          # we make so low `timeout` to test connection pool.
      ]
    of RemoteSignerType.VerifyingWeb3Signer:
      @[
        "--non-interactive=true",
        "--log-level=DEBUG",
        "--data-dir=" & getTestDir(rt) & "/signing-node",
        "--bind-address=" & SigningNodeAddress,
        "--bind-port=" & $getNodePort(basePort, rt),
        "--expected-fee-recipient=" & $SigningExpectedFeeRecipient,
        "--request-timeout=" & $SigningRequestTimeoutSeconds
          # we make so low `timeout` to test connection pool.
      ]

  let res =
    await startProcess("build/nimbus_signing_node",
                       arguments = arguments,
                       options = {AsyncProcessOption.StdErrToStdOut},
                       stdoutHandle = AsyncProcess.Pipe)
  SigningProcess(
    process: res, reader: res.stdoutStream.read()
  )

proc shutdownSigningNodeProcess(sp: SigningProcess) {.async.} =
  let resultCode =
    block:
      var rescode: Opt[int]
      for i in 1 .. 10:
        if sp.process.running().get(true):
          let res = sp.process.kill()
          if res.isErr():
            echo "Unable to kill `nimbus_signing_node` process [",
                 sp.process.pid(), "], reason = ",
                 "[", int(res.error), "] ", osErrorMsg(res.error)
        else:
          let res = sp.process.peekExitCode()
          if res.isErr():
            echo "Unable to peek exit code for `nimbus_signing_node` process [",
                 sp.process.pid(), "], reason =",
                 "[", int(res.error), "] ", osErrorMsg(res.error)
          else:
            rescode = Opt.some(res.get())
          break

        try:
          let res = await sp.process.waitForExit().wait(1.seconds)
          rescode = Opt.some(res)
          break
        except AsyncTimeoutError:
          echo "Timeout exceeded while waiting for `nimbus_signing_node` ",
               "process [", sp.process.pid(), "]"
      rescode

  if resultCode.isSome():
    await allFutures(sp.reader)
    let data = sp.reader.read()
    echo ""
    echo "===== `nimbus_signing_node` process [", sp.process.pid(),
         "] exited with [", resultCode.get(), "] ====="
    echo bytesToString(data)
  else:
    echo ""
    echo "Unable to terminate `nimbus_signing_node` process [",
         sp.process.pid(), "]"

let
  basePortStr =
    os.getEnv("NIMBUS_TEST_SIGNING_NODE_BASE_PORT", $defaultSigningNodePort)
  basePort =
    try:
      let val = parseInt(basePortStr)
      if val < 0 or val > (uint16.high.int - RemoteSignerType.high.ord):
        fatal "Invalid base port arg", basePort = basePortStr
        quit 1
      val
    except ValueError as exc:
      fatal "Invalid base port arg", basePort = basePortStr, exc = exc.msg
      quit 1

block:
  let res = createTestDir(RemoteSignerType.Web3Signer)
  doAssert(res.isOk())
  let process = waitFor(spawnSigningNodeProcess(
                        basePort, RemoteSignerType.Web3Signer))

  suite "Nimbus remote signer/signing test (web3signer)":
    setup:
      let pool1 = newClone(default(ValidatorPool))
      let
        validator1 = pool1[].addValidator(
          getLocalKeystoreData(ValidatorPrivateKey1).get(),
          default(Eth1Address), 300_000_000'u64
        )
        validator2 = pool1[].addValidator(
          getLocalKeystoreData(ValidatorPrivateKey2).get(),
          default(Eth1Address), 300_000_000'u64
        )
        validator3 = pool1[].addValidator(
          getLocalKeystoreData(ValidatorPrivateKey3).get(),
          default(Eth1Address), 300_000_000'u64
        )

      validator1.index = Opt.some(ValidatorIndex(100))
      validator2.index = Opt.some(ValidatorIndex(101))
      validator3.index = Opt.some(ValidatorIndex(102))

      let pool2 = newClone(default(ValidatorPool))
      let validator4 = pool2[].addValidator(
        getRemoteKeystoreData(ValidatorPubKey1, basePort,
                              RemoteSignerType.Web3Signer).get(),
        default(Eth1Address), 300_000_000'u64
      )
      let validator5 = pool2[].addValidator(
        getRemoteKeystoreData(ValidatorPubKey2, basePort,
                              RemoteSignerType.Web3Signer).get(),
        default(Eth1Address), 300_000_000'u64
      )
      let validator6 = pool2[].addValidator(
        getRemoteKeystoreData(ValidatorPubKey3, basePort,
                              RemoteSignerType.Web3Signer).get(),
        default(Eth1Address), 300_000_000'u64
      )

      validator4.index = Opt.some(ValidatorIndex(100))
      validator5.index = Opt.some(ValidatorIndex(101))
      validator6.index = Opt.some(ValidatorIndex(102))

    asyncTest "Waiting for signing node (/upcheck) test":
      let
        remoteUrl = "http://" & SigningNodeAddress & ":" &
                    $getNodePort(basePort, RemoteSignerType.Web3Signer)
        prestoFlags = {RestClientFlag.CommaSeparatedArray}
        rclient = RestClientRef.new(remoteUrl, prestoFlags, {})

      check rclient.isOk()
      let client = rclient.get()

      var attempts = 0
      while attempts < 3:
        let loopBreak =
          try:
            let response = await client.getUpcheck()
            check:
              response.status == 200
              response.data.status == "OK"
            true
          except CatchableError:
            inc(attempts)
            false
        if loopBreak:
          break
        await sleepAsync(500.milliseconds)

      await client.closeWait()

    asyncTest "Public keys enumeration (/api/v1/eth2/publicKeys) test":
      let
        remoteUrl = "http://" & SigningNodeAddress & ":" &
                    $getNodePort(basePort, RemoteSignerType.Web3Signer)
        prestoFlags = {RestClientFlag.CommaSeparatedArray}
        rclient = RestClientRef.new(remoteUrl, prestoFlags, {})

      check rclient.isOk()
      let client = rclient.get()

      try:
        let response = await client.getKeys()
        check:
          response.status == 200
          len(response.data) == 3
        let
          received = sorted([
            "0x" & response.data[0].toHex(),
            "0x" & response.data[1].toHex(),
            "0x" & response.data[2].toHex()
          ])
          expected = sorted([
            ValidatorPubKey1,
            ValidatorPubKey2,
            ValidatorPubKey3
          ])
        check received == expected
      finally:
        await client.closeWait()

    asyncTest "Signing aggregation slot (getSlotSignature())":
      let
        sres1 =
          await validator1.getSlotSignature(SigningFork,
            GenesisValidatorsRoot, Slot(10))
        sres2 =
          await validator2.getSlotSignature(SigningFork,
            GenesisValidatorsRoot, Slot(100))
        sres3 =
          await validator3.getSlotSignature(SigningFork,
            GenesisValidatorsRoot, Slot(1000))
        rres1 =
          await validator4.getSlotSignature(SigningFork,
            GenesisValidatorsRoot, Slot(10))
        rres2 =
          await validator5.getSlotSignature(SigningFork,
            GenesisValidatorsRoot, Slot(100))
        rres3 =
          await validator6.getSlotSignature(SigningFork,
            GenesisValidatorsRoot, Slot(1000))
      check:
        sres1.isOk()
        sres2.isOk()
        sres3.isOk()
        rres1.isOk()
        rres2.isOk()
        rres3.isOk()
        sres1.get() == rres1.get()
        sres2.get() == rres2.get()
        sres3.get() == rres3.get()

    asyncTest "Signing randao reveal (getEpochSignature())":
      let
        sres1 =
          await validator1.getEpochSignature(SigningFork,
            GenesisValidatorsRoot, Epoch(10))
        sres2 =
          await validator2.getEpochSignature(SigningFork,
            GenesisValidatorsRoot, Epoch(100))
        sres3 =
          await validator3.getEpochSignature(SigningFork,
            GenesisValidatorsRoot, Epoch(1000))
        rres1 =
          await validator4.getEpochSignature(SigningFork,
            GenesisValidatorsRoot, Epoch(10))
        rres2 =
          await validator5.getEpochSignature(SigningFork,
            GenesisValidatorsRoot, Epoch(100))
        rres3 =
          await validator6.getEpochSignature(SigningFork,
            GenesisValidatorsRoot, Epoch(1000))
      check:
        sres1.isOk()
        sres2.isOk()
        sres3.isOk()
        rres1.isOk()
        rres2.isOk()
        rres3.isOk()
        sres1.get() == rres1.get()
        sres2.get() == rres2.get()
        sres3.get() == rres3.get()

    asyncTest "Signing SC message (getSyncCommitteeMessage())":
      let
        sres1 =
          await validator1.getSyncCommitteeMessage(SigningFork,
            GenesisValidatorsRoot, Slot(10), SomeOtherRoot)
        sres2 =
          await validator2.getSyncCommitteeMessage(SigningFork,
            GenesisValidatorsRoot, Slot(100), SomeOtherRoot)
        sres3 =
          await validator3.getSyncCommitteeMessage(SigningFork,
            GenesisValidatorsRoot, Slot(1000), SomeOtherRoot)
        rres1 =
          await validator4.getSyncCommitteeMessage(SigningFork,
            GenesisValidatorsRoot, Slot(10), SomeOtherRoot)
        rres2 =
          await validator5.getSyncCommitteeMessage(SigningFork,
            GenesisValidatorsRoot, Slot(100), SomeOtherRoot)
        rres3 =
          await validator6.getSyncCommitteeMessage(SigningFork,
            GenesisValidatorsRoot, Slot(1000), SomeOtherRoot)
      check:
        sres1.isOk()
        sres2.isOk()
        sres3.isOk()
        rres1.isOk()
        rres2.isOk()
        rres3.isOk()
        sres1.get() == rres1.get()
        sres2.get() == rres2.get()
        sres3.get() == rres3.get()

    asyncTest "Signing SC selection proof " &
              "(getSyncCommitteeSelectionProof())":
      let
        sres1 =
          await validator1.getSyncCommitteeSelectionProof(SigningFork,
            GenesisValidatorsRoot, Slot(10), SyncSubcommitteeIndex(1))
        sres2 =
          await validator2.getSyncCommitteeSelectionProof(SigningFork,
            GenesisValidatorsRoot, Slot(100), SyncSubcommitteeIndex(2))
        sres3 =
          await validator3.getSyncCommitteeSelectionProof(SigningFork,
            GenesisValidatorsRoot, Slot(1000), SyncSubcommitteeIndex(3))
        rres1 =
          await validator4.getSyncCommitteeSelectionProof(SigningFork,
            GenesisValidatorsRoot, Slot(10), SyncSubcommitteeIndex(1))
        rres2 =
          await validator5.getSyncCommitteeSelectionProof(SigningFork,
            GenesisValidatorsRoot, Slot(100), SyncSubcommitteeIndex(2))
        rres3 =
          await validator6.getSyncCommitteeSelectionProof(SigningFork,
            GenesisValidatorsRoot, Slot(1000), SyncSubcommitteeIndex(3))

      check:
        sres1.isOk()
        sres2.isOk()
        sres3.isOk()
        rres1.isOk()
        rres2.isOk()
        rres3.isOk()
        sres1.get() == rres1.get()
        sres2.get() == rres2.get()
        sres3.get() == rres3.get()

    asyncTest "Signing SC contribution and proof " &
              "(getContributionAndProofSignature())":
      let
        conProof = default(ContributionAndProof)
        sres1 =
          await validator1.getContributionAndProofSignature(SigningFork,
            GenesisValidatorsRoot, conProof)
        sres2 =
          await validator2.getContributionAndProofSignature(SigningFork,
            GenesisValidatorsRoot, conProof)
        sres3 =
          await validator3.getContributionAndProofSignature(SigningFork,
            GenesisValidatorsRoot, conProof)
        rres1 =
          await validator4.getContributionAndProofSignature(SigningFork,
            GenesisValidatorsRoot, conProof)
        rres2 =
          await validator5.getContributionAndProofSignature(SigningFork,
            GenesisValidatorsRoot, conProof)
        rres3 =
          await validator6.getContributionAndProofSignature(SigningFork,
            GenesisValidatorsRoot, conProof)

      check:
        sres1.isOk()
        sres2.isOk()
        sres3.isOk()
        rres1.isOk()
        rres2.isOk()
        rres3.isOk()
        sres1.get() == rres1.get()
        sres2.get() == rres2.get()
        sres3.get() == rres3.get()

    asyncTest "Signing attestation (getAttestationSignature())":
      let
        adata = default(AttestationData)
        sres1 =
          await validator1.getAttestationSignature(SigningFork,
            GenesisValidatorsRoot, adata)
        sres2 =
          await validator2.getAttestationSignature(SigningFork,
            GenesisValidatorsRoot, adata)
        sres3 =
          await validator3.getAttestationSignature(SigningFork,
            GenesisValidatorsRoot, adata)
        rres1 =
          await validator4.getAttestationSignature(SigningFork,
            GenesisValidatorsRoot, adata)
        rres2 =
          await validator5.getAttestationSignature(SigningFork,
            GenesisValidatorsRoot, adata)
        rres3 =
          await validator6.getAttestationSignature(SigningFork,
            GenesisValidatorsRoot, adata)

      check:
        sres1.isOk()
        sres2.isOk()
        sres3.isOk()
        rres1.isOk()
        rres2.isOk()
        rres3.isOk()
        sres1.get() == rres1.get()
        sres2.get() == rres2.get()
        sres3.get() == rres3.get()

    asyncTest "Signing aggregate and proof (getAggregateAndProofSignature())":
      let
        contentType = ContentTypeData(
          mediaType: MediaType.init("application/json"))
        agAttestation = decodeBytes(
          GetAggregatedAttestationResponse,
          AgAttestation.toOpenArrayByte(0, len(AgAttestation) - 1),
          Opt.some(contentType)).tryGet().data
        agProof = AggregateAndProof(
          aggregator_index: 1'u64,
          aggregate: agAttestation,
          selection_proof: ValidatorSig.fromHex(SomeSignature).get())
        sres1 =
          await validator1.getAggregateAndProofSignature(SigningFork,
            GenesisValidatorsRoot, agProof)
        sres2 =
          await validator2.getAggregateAndProofSignature(SigningFork,
            GenesisValidatorsRoot, agProof)
        sres3 =
          await validator3.getAggregateAndProofSignature(SigningFork,
            GenesisValidatorsRoot, agProof)
        rres1 =
          await validator4.getAggregateAndProofSignature(SigningFork,
            GenesisValidatorsRoot, agProof)
        rres2 =
          await validator5.getAggregateAndProofSignature(SigningFork,
            GenesisValidatorsRoot, agProof)
        rres3 =
          await validator6.getAggregateAndProofSignature(SigningFork,
            GenesisValidatorsRoot, agProof)

      check:
        sres1.isOk()
        sres2.isOk()
        sres3.isOk()
        rres1.isOk()
        rres2.isOk()
        rres3.isOk()
        sres1.get() == rres1.get()
        sres2.get() == rres2.get()
        sres3.get() == rres3.get()

    asyncTest "Signing validator registration (getBuilderSignature())":
      let
        vdata = default(ValidatorRegistrationV1)
        sres1 = await validator1.getBuilderSignature(SigningFork, vdata)
        sres2 = await validator2.getBuilderSignature(SigningFork, vdata)
        sres3 = await validator3.getBuilderSignature(SigningFork, vdata)
        rres1 = await validator4.getBuilderSignature(SigningFork, vdata)
        rres2 = await validator5.getBuilderSignature(SigningFork, vdata)
        rres3 = await validator6.getBuilderSignature(SigningFork, vdata)

      check:
        sres1.isOk()
        sres2.isOk()
        sres3.isOk()
        rres1.isOk()
        rres2.isOk()
        rres3.isOk()
        sres1.get() == rres1.get()
        sres2.get() == rres2.get()
        sres3.get() == rres3.get()

    asyncTest "Signing voluntary exit (getValidatorExitSignature())":
      let
        voluntaryExit = default(VoluntaryExit)
        sres1 =
          await validator1.getValidatorExitSignature(SigningFork,
            GenesisValidatorsRoot, voluntaryExit)
        sres2 =
          await validator2.getValidatorExitSignature(SigningFork,
            GenesisValidatorsRoot, voluntaryExit)
        sres3 =
          await validator3.getValidatorExitSignature(SigningFork,
            GenesisValidatorsRoot, voluntaryExit)
        rres1 =
          await validator4.getValidatorExitSignature(SigningFork,
            GenesisValidatorsRoot, voluntaryExit)
        rres2 =
          await validator5.getValidatorExitSignature(SigningFork,
            GenesisValidatorsRoot, voluntaryExit)
        rres3 =
          await validator6.getValidatorExitSignature(SigningFork,
            GenesisValidatorsRoot, voluntaryExit)

      check:
        sres1.isOk()
        sres2.isOk()
        sres3.isOk()
        rres1.isOk()
        rres2.isOk()
        rres3.isOk()
        sres1.get() == rres1.get()
        sres2.get() == rres2.get()
        sres3.get() == rres3.get()

    asyncTest "Signing deposit message (getDepositMessageSignature())":
      let
        depositMessage = default(DepositMessage)
        sres1 =
          await validator1.getDepositMessageSignature(GenesisForkVersion,
            depositMessage)
        sres2 =
          await validator2.getDepositMessageSignature(GenesisForkVersion,
            depositMessage)
        sres3 =
          await validator3.getDepositMessageSignature(GenesisForkVersion,
            depositMessage)
        rres1 =
          await validator4.getDepositMessageSignature(GenesisForkVersion,
            depositMessage)
        rres2 =
          await validator5.getDepositMessageSignature(GenesisForkVersion,
            depositMessage)
        rres3 =
          await validator6.getDepositMessageSignature(GenesisForkVersion,
            depositMessage)

      check:
        sres1.isOk()
        sres2.isOk()
        sres3.isOk()
        rres1.isOk()
        rres2.isOk()
        rres3.isOk()
        sres1.get() == rres1.get()
        sres2.get() == rres2.get()
        sres3.get() == rres3.get()

    asyncTest "Signing BeaconBlock (getBlockSignature(bellatrix))":
      let
        forked = getBlock(ConsensusFork.Bellatrix)
        blockRoot = withBlck(forked): hash_tree_root(forkyBlck)

        sres1 =
          await validator1.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot, forked)
        sres2 =
          await validator2.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot, forked)
        sres3 =
          await validator3.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot, forked)
        rres1 =
          await validator4.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot, forked)
        rres2 =
          await validator5.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot, forked)
        rres3 =
          await validator6.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot, forked)

      check:
        sres1.isOk()
        sres2.isOk()
        sres3.isOk()
        rres1.isOk()
        rres2.isOk()
        rres3.isOk()
        sres1.get() == rres1.get()
        sres2.get() == rres2.get()
        sres3.get() == rres3.get()

    asyncTest "Signing BeaconBlock (getBlockSignature(capella))":
      let
        forked = getBlock(ConsensusFork.Capella)
        blockRoot = withBlck(forked): hash_tree_root(forkyBlck)

        sres1 =
          await validator1.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot, forked)
        sres2 =
          await validator2.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot, forked)
        sres3 =
          await validator3.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot, forked)
        rres1 =
          await validator4.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot, forked)
        rres2 =
          await validator5.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot, forked)
        rres3 =
          await validator6.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot, forked)

      check:
        sres1.isOk()
        sres2.isOk()
        sres3.isOk()
        rres1.isOk()
        rres2.isOk()
        rres3.isOk()
        sres1.get() == rres1.get()
        sres2.get() == rres2.get()
        sres3.get() == rres3.get()

    asyncTest "Signing BeaconBlock (getBlockSignature(deneb))":
      let
        forked = getBlock(ConsensusFork.Deneb)
        blockRoot = withBlck(forked): hash_tree_root(forkyBlck)

        sres1 =
          await validator1.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot, forked)
        sres2 =
          await validator2.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot, forked)
        sres3 =
          await validator3.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot, forked)
        rres1 =
          await validator4.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot, forked)
        rres2 =
          await validator5.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot, forked)
        rres3 =
          await validator6.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot, forked)

      check:
        sres1.isOk()
        sres2.isOk()
        sres3.isOk()
        rres1.isOk()
        rres2.isOk()
        rres3.isOk()
        sres1.get() == rres1.get()
        sres2.get() == rres2.get()
        sres3.get() == rres3.get()

    asyncTest "Connection timeout test":
      let
        request = Web3SignerRequest.init(SigningFork, GenesisValidatorsRoot,
                                         Epoch(10))
        deadline = newFuture[void]()
        (client, info) = validator4.clients[0]

      deadline.complete()
      let res = await client.signData(info.pubkey, deadline, 1, request)
      check:
        res.isErr()
        res.error.kind == Web3SignerErrorKind.TimeoutError

    asyncTest "Public keys reload (/reload) test":
      let
        res = createAdditionalKeystore(RemoteSignerType.Web3Signer)
        remoteUrl = "http://" & SigningNodeAddress & ":" &
                    $getNodePort(basePort, RemoteSignerType.Web3Signer)
        prestoFlags = {RestClientFlag.CommaSeparatedArray}
        rclient = RestClientRef.new(remoteUrl, prestoFlags, {})

      check:
        res.isOk()
        rclient.isOk()

      let client = rclient.get()
      check res.isOk()
      try:
        block:
          let response = await client.reload()
          check response.status == 200
        block:
          let response = await client.getKeys()
          check:
            response.status == 200
            len(response.data) == 4
          let
            received = sorted([
              "0x" & response.data[0].toHex(),
              "0x" & response.data[1].toHex(),
              "0x" & response.data[2].toHex(),
              "0x" & response.data[3].toHex()
            ])
            expected = sorted([
              ValidatorPubKey1,
              ValidatorPubKey2,
              ValidatorPubKey3,
              ValidatorPubKey4
            ])
          check received == expected
      finally:
        await client.closeWait()

  waitFor(shutdownSigningNodeProcess(process))
  removeTestDir(RemoteSignerType.Web3Signer)

block:
  let res = createTestDir(RemoteSignerType.VerifyingWeb3Signer)
  doAssert(res.isOk())
  let process = waitFor(spawnSigningNodeProcess(
                        basePort, RemoteSignerType.VerifyingWeb3Signer))

  suite "Nimbus remote signer/signing test (verifying-web3signer)":
    setup:
      let pool1 = newClone(default(ValidatorPool))
      let
        validator1 = pool1[].addValidator(
          getLocalKeystoreData(ValidatorPrivateKey1).get(),
          default(Eth1Address), 300_000_000'u64
        )
        validator2 = pool1[].addValidator(
          getLocalKeystoreData(ValidatorPrivateKey2).get(),
          default(Eth1Address), 300_000_000'u64
        )
        validator3 = pool1[].addValidator(
          getLocalKeystoreData(ValidatorPrivateKey3).get(),
          default(Eth1Address), 300_000_000'u64
        )

      validator1.index = Opt.some(ValidatorIndex(100))
      validator2.index = Opt.some(ValidatorIndex(101))
      validator3.index = Opt.some(ValidatorIndex(102))

      let pool2 = newClone(default(ValidatorPool))
      let validator4 = pool2[].addValidator(
        getRemoteKeystoreData(ValidatorPubKey1, basePort,
                              RemoteSignerType.VerifyingWeb3Signer).get(),
        default(Eth1Address), 300_000_000'u64
      )
      let validator5 = pool2[].addValidator(
        getRemoteKeystoreData(ValidatorPubKey2, basePort,
                              RemoteSignerType.VerifyingWeb3Signer).get(),
        default(Eth1Address), 300_000_000'u64
      )
      let validator6 = pool2[].addValidator(
        getRemoteKeystoreData(ValidatorPubKey3, basePort,
                              RemoteSignerType.VerifyingWeb3Signer).get(),
        default(Eth1Address), 300_000_000'u64
      )

      validator4.index = Opt.some(ValidatorIndex(100))
      validator5.index = Opt.some(ValidatorIndex(101))
      validator6.index = Opt.some(ValidatorIndex(102))

    asyncTest "Waiting for signing node (/upcheck) test":
      let
        remoteUrl = "http://" & SigningNodeAddress & ":" &
                    $getNodePort(basePort, RemoteSignerType.VerifyingWeb3Signer)
        prestoFlags = {RestClientFlag.CommaSeparatedArray}
        rclient = RestClientRef.new(remoteUrl, prestoFlags, {})

      check rclient.isOk()
      let client = rclient.get()

      var attempts = 0
      while attempts < 3:
        let loopBreak =
          try:
            let response = await client.getUpcheck()
            check:
              response.status == 200
              response.data.status == "OK"
            true
          except CatchableError:
            inc(attempts)
            false
        if loopBreak:
          break
        await sleepAsync(500.milliseconds)

      await client.closeWait()

    asyncTest "Signing BeaconBlock (getBlockSignature(bellatrix))":
      let
        fork = ConsensusFork.Bellatrix
        forked1 = getBlock(fork)
        blockRoot1 = withBlck(forked1): hash_tree_root(forkyBlck)
        forked2 = getBlock(fork, SigningOtherFeeRecipient)
        blockRoot2 = withBlck(forked2): hash_tree_root(forkyBlck)
        request1 = Web3SignerRequest.init(SigningFork, GenesisValidatorsRoot,
          Web3SignerForkedBeaconBlock.init(forked1))
        request2 = Web3SignerRequest.init(SigningFork, GenesisValidatorsRoot,
          Web3SignerForkedBeaconBlock.init(forked1), @[])
        remoteUrl = "http://" & SigningNodeAddress & ":" &
                    $getNodePort(basePort, RemoteSignerType.VerifyingWeb3Signer)
        prestoFlags = {RestClientFlag.CommaSeparatedArray}
        rclient = RestClientRef.new(remoteUrl, prestoFlags, {})
        publicKey1 = ValidatorPubKey.fromHex(ValidatorPubKey1).get()
        publicKey2 = ValidatorPubKey.fromHex(ValidatorPubKey2).get()
        publicKey3 = ValidatorPubKey.fromHex(ValidatorPubKey3).get()

      check rclient.isOk()

      let
        client = rclient.get()
        sres1 =
          await validator1.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot1, forked1)
        sres2 =
          await validator2.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot1, forked1)
        sres3 =
          await validator3.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot1, forked1)
        rres1 =
          await validator4.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot1, forked1)
        rres2 =
          await validator5.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot1, forked1)
        rres3 =
          await validator6.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot1, forked1)
        bres1 =
          await validator4.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot2, forked2)
        bres2 =
          await validator5.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot2, forked2)
        bres3 =
          await validator6.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot2, forked2)

      check:
        # Local requests
        sres1.isOk()
        sres2.isOk()
        sres3.isOk()
        # Remote requests with proper Merkle proof of proper FeeRecipent field
        rres1.isOk()
        rres2.isOk()
        rres3.isOk()
        # Signature comparison
        sres1.get() == rres1.get()
        sres2.get() == rres2.get()
        sres3.get() == rres3.get()
        # Remote requests with changed FeeRecipient field
        bres1.isErr()
        bres2.isErr()
        bres3.isErr()

      try:
        let
          # `proofs` array is not present.
          response1 = await client.signDataPlain(publicKey1, request1)
          response2 = await client.signDataPlain(publicKey2, request1)
          response3 = await client.signDataPlain(publicKey3, request1)
          # `proofs` array is empty.
          response4 = await client.signDataPlain(publicKey1, request2)
          response5 = await client.signDataPlain(publicKey2, request2)
          response6 = await client.signDataPlain(publicKey3, request2)
        check:
          response1.status == 400
          response2.status == 400
          response3.status == 400
          response4.status == 400
          response5.status == 400
          response6.status == 400
      finally:
        await client.closeWait()

    asyncTest "Signing BeaconBlock (getBlockSignature(capella))":
      let
        fork = ConsensusFork.Capella
        forked1 = getBlock(fork)
        blockRoot1 = withBlck(forked1): hash_tree_root(forkyBlck)
        forked2 = getBlock(fork, SigningOtherFeeRecipient)
        blockRoot2 = withBlck(forked2): hash_tree_root(forkyBlck)
        request1 = Web3SignerRequest.init(SigningFork, GenesisValidatorsRoot,
          Web3SignerForkedBeaconBlock.init(forked1))
        request2 = Web3SignerRequest.init(SigningFork, GenesisValidatorsRoot,
          Web3SignerForkedBeaconBlock.init(forked1), @[])
        remoteUrl = "http://" & SigningNodeAddress & ":" &
                    $getNodePort(basePort, RemoteSignerType.VerifyingWeb3Signer)
        prestoFlags = {RestClientFlag.CommaSeparatedArray}
        rclient = RestClientRef.new(remoteUrl, prestoFlags, {})
        publicKey1 = ValidatorPubKey.fromHex(ValidatorPubKey1).get()
        publicKey2 = ValidatorPubKey.fromHex(ValidatorPubKey2).get()
        publicKey3 = ValidatorPubKey.fromHex(ValidatorPubKey3).get()

      check rclient.isOk()

      let
        client = rclient.get()
        sres1 =
          await validator1.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot1, forked1)
        sres2 =
          await validator2.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot1, forked1)
        sres3 =
          await validator3.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot1, forked1)
        rres1 =
          await validator4.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot1, forked1)
        rres2 =
          await validator5.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot1, forked1)
        rres3 =
          await validator6.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot1, forked1)
        bres1 =
          await validator4.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot2, forked2)
        bres2 =
          await validator5.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot2, forked2)
        bres3 =
          await validator6.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot2, forked2)

      check:
        # Local requests
        sres1.isOk()
        sres2.isOk()
        sres3.isOk()
        # Remote requests with proper Merkle proof of proper FeeRecipent field
        rres1.isOk()
        rres2.isOk()
        rres3.isOk()
        # Signature comparison
        sres1.get() == rres1.get()
        sres2.get() == rres2.get()
        sres3.get() == rres3.get()
        # Remote requests with changed FeeRecipient field
        bres1.isErr()
        bres2.isErr()
        bres3.isErr()

      try:
        let
          # `proofs` array is not present.
          response1 = await client.signDataPlain(publicKey1, request1)
          response2 = await client.signDataPlain(publicKey2, request1)
          response3 = await client.signDataPlain(publicKey3, request1)
          # `proofs` array is empty.
          response4 = await client.signDataPlain(publicKey1, request2)
          response5 = await client.signDataPlain(publicKey2, request2)
          response6 = await client.signDataPlain(publicKey3, request2)
        check:
          response1.status == 400
          response2.status == 400
          response3.status == 400
          response4.status == 400
          response5.status == 400
          response6.status == 400
      finally:
        await client.closeWait()

    asyncTest "Signing BeaconBlock (getBlockSignature(deneb))":
      let
        fork = ConsensusFork.Deneb
        forked1 = getBlock(fork)
        blockRoot1 = withBlck(forked1): hash_tree_root(forkyBlck)
        forked2 = getBlock(fork, SigningOtherFeeRecipient)
        blockRoot2 = withBlck(forked2): hash_tree_root(forkyBlck)
        request1 = Web3SignerRequest.init(SigningFork, GenesisValidatorsRoot,
          Web3SignerForkedBeaconBlock.init(forked1))
        request2 = Web3SignerRequest.init(SigningFork, GenesisValidatorsRoot,
          Web3SignerForkedBeaconBlock.init(forked1), @[])
        remoteUrl = "http://" & SigningNodeAddress & ":" &
                    $getNodePort(basePort, RemoteSignerType.VerifyingWeb3Signer)
        prestoFlags = {RestClientFlag.CommaSeparatedArray}
        rclient = RestClientRef.new(remoteUrl, prestoFlags, {})
        publicKey1 = ValidatorPubKey.fromHex(ValidatorPubKey1).get()
        publicKey2 = ValidatorPubKey.fromHex(ValidatorPubKey2).get()
        publicKey3 = ValidatorPubKey.fromHex(ValidatorPubKey3).get()

      check rclient.isOk()

      let
        client = rclient.get()
        sres1 =
          await validator1.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot1, forked1)
        sres2 =
          await validator2.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot1, forked1)
        sres3 =
          await validator3.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot1, forked1)
        rres1 =
          await validator4.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot1, forked1)
        rres2 =
          await validator5.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot1, forked1)
        rres3 =
          await validator6.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot1, forked1)
        bres1 =
          await validator4.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot2, forked2)
        bres2 =
          await validator5.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot2, forked2)
        bres3 =
          await validator6.getBlockSignature(SigningFork, GenesisValidatorsRoot,
            Slot(1), blockRoot2, forked2)

      check:
        # Local requests
        sres1.isOk()
        sres2.isOk()
        sres3.isOk()
        # Remote requests with proper Merkle proof of proper FeeRecipent field
        rres1.isOk()
        rres2.isOk()
        rres3.isOk()
        # Signature comparison
        sres1.get() == rres1.get()
        sres2.get() == rres2.get()
        sres3.get() == rres3.get()
        # Remote requests with changed FeeRecipient field
        bres1.isErr()
        bres2.isErr()
        bres3.isErr()

      try:
        let
          # `proofs` array is not present.
          response1 = await client.signDataPlain(publicKey1, request1)
          response2 = await client.signDataPlain(publicKey2, request1)
          response3 = await client.signDataPlain(publicKey3, request1)
          # `proofs` array is empty.
          response4 = await client.signDataPlain(publicKey1, request2)
          response5 = await client.signDataPlain(publicKey2, request2)
          response6 = await client.signDataPlain(publicKey3, request2)
        check:
          response1.status == 400
          response2.status == 400
          response3.status == 400
          response4.status == 400
          response5.status == 400
          response6.status == 400
      finally:
        await client.closeWait()

  waitFor(shutdownSigningNodeProcess(process))
  removeTestDir(RemoteSignerType.VerifyingWeb3Signer)
