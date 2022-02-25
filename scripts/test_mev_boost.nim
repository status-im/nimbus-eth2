# Monitor traffic: socat -v TCP-LISTEN:19550,fork TCP-CONNECT:127.0.0.1:18550

import
  unittest2,
  chronos, web3/[builder_api, builder_api_types, engine_api_types, ethtypes],
  ../beacon_chain/eth1/eth1_monitor,
  ../beacon_chain/spec/[digest, presets],
  ./testutil

suite "mev-boost RPC":
  setup:
    let web3Provider = (waitFor Web3DataProvider.new(
      default(Eth1Address), "http://127.0.0.1:18550")).get.web3.provider

  test "builder_ProposeBlindedBlockV1":
    let proposedBlindedBlockResp =
      waitFor web3Provider.builder_proposeBlindedBlockV1(default(SignedBlindedBeaconBlock))

  test "builder_getPayloadHeaderV1":
    let getPayloadHeaderResp =
      waitFor web3Provider.builder_getPayloadHeaderV1(default(PayloadID))
