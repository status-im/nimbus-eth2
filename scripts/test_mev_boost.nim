import
  unittest2,
  chronos, presto/client, web3/ethtypes,
  ../beacon_chain/spec/mev/rest_bellatrix_mev_calls,
  ../tests/testutil

from ../beacon_chain/beacon_chain_db import DepositContractSnapshot
from ../beacon_chain/eth1/eth1_monitor import
  Eth1Monitor, Web3DataProvider, asEth2Digest, ensureDataProvider,
  forkchoiceUpdated, getBlockByNumber, init, new
from ../beacon_chain/networking/network_metadata import Eth1Network
from ../beacon_chain/spec/helpers import compute_signing_root
from ../tests/testdbutil import makeTestDB

suite "MEV tests":
  setup:
    const
      feeRecipient =
        Eth1Address.fromHex("0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b")
      web3Url = "http://127.0.0.1:8551"
      restUrl = "http://127.0.0.1:28545"

    let
      db = makeTestDB(64)
      eth1Monitor = Eth1Monitor.init(
        defaultRuntimeConfig, db, nil, @[web3Url],
        none(DepositContractSnapshot), none(Eth1Network), false, none(seq[byte]))
      web3Provider = (waitFor Web3DataProvider.new(
        default(Eth1Address), web3Url, some(@[0xcdu8, 0xcau8, 0xe4u8, 0xecu8, 0x6au8, 0x3du8, 0x0bu8, 0x4bu8, 0x97u8, 0x00u8, 0x21u8, 0x21u8, 0xb0u8, 0x5bu8, 0x22u8, 0xe2u8, 0xd6u8, 0xd5u8, 0x7fu8, 0xaau8, 0x51u8, 0x53u8, 0x84u8, 0x5fu8, 0xe0u8, 0x4fu8, 0x06u8, 0xb5u8, 0xf3u8, 0xadu8, 0xc4u8, 0x0bu8]))).get
      restClient = RestClientRef.new(restUrl).get
      privKey = ValidatorPrivKey.init(
        "0x066e3bdc0415530e5c7fed6382d5c822c192b620203cf669903e1810a8c67d06")
      pubKey = privKey.toPubKey.toPubKey

  test "forkchoiceUpdated, getHeader, and submitBlindedBlock":
    waitFor eth1Monitor.ensureDataProvider()
    let
      existingBlock = waitFor web3Provider.getBlockByNumber(0)
      payloadId = waitFor eth1Monitor.forkchoiceUpdated(
        existingBlock.hash.asEth2Digest,
        existingBlock.hash.asEth2Digest,
        existingBlock.timestamp.uint64 + 12,
        default(Eth2Digest).data,  # Random
        feeRecipient)
      blindedHeader = waitFor restClient.getHeader(
        1.Slot, existingBlock.hash.asEth2Digest, pubKey)

    # construct block
    var blck: SignedBlindedBeaconBlock
    blck.message.body.execution_payload_header = blindedHeader.data.data.message.header

    # sign block
    let domain: Eth2Domain = [
      byte 0x00, 0x00, 0x00, 0x00, 0x8a, 0x02, 0x3a, 0x9e, 0x4a, 0xff, 0xbb, 0x25, 0x5a, 0x6b, 0x48, 0xae, 0x85, 0xcc, 0x4a, 0x7d, 0x1a, 0x1b, 0x9e, 0x8e, 0x68, 0x09, 0xfe, 0x9e, 0x48, 0x53, 0x5c, 0x01]
    blck.signature = blsSign(
      privKey,
      compute_signing_root(hash_tree_root(blck.message), domain).data).
        toValidatorSig

    let signedBuilderBid = waitFor restClient.submitBlindedBlock(blck)
