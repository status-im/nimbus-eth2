# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/macros,
  chronos, presto/client, web3/ethtypes,
  ../beacon_chain/spec/mev/rest_bellatrix_mev_calls

from ../beacon_chain/eth1/eth1_monitor import
  DepositContractSnapshot, Eth1Monitor, Web3DataProvider, asEth2Digest,
  ensureDataProvider, forkchoiceUpdated, getBlockByNumber, init, new
from ../beacon_chain/networking/network_metadata import Eth1Network
from ../beacon_chain/spec/datatypes/bellatrix import SignedBeaconBlock
from ../beacon_chain/spec/helpers import compute_domain, compute_signing_root
from ../tests/testdbutil import makeTestDB

const
  feeRecipient =
    Eth1Address.fromHex("0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b")
  web3Url = "http://127.0.0.1:8551"
  restUrl = "http://127.0.0.1:28545"

proc main() {.async.} =
  let
    db = makeTestDB(64)
    elMonitor = Eth1Monitor.init(
      defaultRuntimeConfig, db, nil, @[web3Url],
      none(DepositContractSnapshot), none(Eth1Network), false, none(seq[byte]))
    web3Provider = (await Web3DataProvider.new(
      default(Eth1Address), web3Url, some(@[0xcdu8, 0xcau8, 0xe4u8, 0xecu8, 0x6au8, 0x3du8, 0x0bu8, 0x4bu8, 0x97u8, 0x00u8, 0x21u8, 0x21u8, 0xb0u8, 0x5bu8, 0x22u8, 0xe2u8, 0xd6u8, 0xd5u8, 0x7fu8, 0xaau8, 0x51u8, 0x53u8, 0x84u8, 0x5fu8, 0xe0u8, 0x4fu8, 0x06u8, 0xb5u8, 0xf3u8, 0xadu8, 0xc4u8, 0x0bu8]))).get
    restClient = RestClientRef.new(restUrl).get
    privKey = ValidatorPrivKey.init(
      "0x066e3bdc0415530e5c7fed6382d5c822c192b620203cf669903e1810a8c67d06")
    pubKey = privKey.toPubKey.toPubKey

  await elMonitor.ensureDataProvider()
  let
    existingBlock = await web3Provider.getBlockByNumber(0)
    payloadId = await elMonitor.forkchoiceUpdated(
      existingBlock.hash.asEth2Digest,
      existingBlock.hash.asEth2Digest,
      existingBlock.timestamp.uint64 + 12,
      ZERO_HASH.data,  # Random
      feeRecipient)
    blindedHeader = await restClient.getHeader(
      1.Slot, existingBlock.hash.asEth2Digest, pubKey)

  var blck: SignedBlindedBeaconBlock
  blck.message.body.execution_payload_header =
    blindedHeader.data.data.message.header

  # Can't be const:
  # https://github.com/nim-lang/Nim/issues/15952
  # https://github.com/nim-lang/Nim/issues/19969
  let mergeMockDomain = compute_domain(
    DOMAIN_BEACON_PROPOSER, defaultRuntimeConfig.BELLATRIX_FORK_VERSION)

  blck.signature = blsSign(
    privKey, compute_signing_root(
      hash_tree_root(blck.message), mergeMockDomain).data).toValidatorSig

  let submitBlindedBlockResponse =
    await restClient.submitBlindedBlock(blck)
  doAssert submitBlindedBlockResponse.status == 200
  doAssert submitBlindedBlockResponse.data.data is ExecutionPayload

  macro copyExecutionPayloadFields(a, b: untyped) =
    result = newStmtList()
    for name, value in fieldPairs(blck.message.body.execution_payload_header):
      if name != "transactions_root":
        result.add newAssignment(
          newDotExpr(a, ident(name)), newDotExpr(b, ident(name)))

  var fullBlck: bellatrix.SignedBeaconBlock
  fullBlck.signature = blck.signature
  copyExecutionPayloadFields(
    fullBlck.message.body.execution_payload,
    blck.message.body.execution_payload_header)
  fullBlck.message.body.execution_payload.transactions =
    submitBlindedBlockResponse.data.data.transactions

  doAssert hash_tree_root(fullBlck.message.body.execution_payload) ==
    hash_tree_root(blck.message.body.execution_payload_header)

  echo fullBlck.message.body.execution_payload
  echo submitBlindedBlockResponse.data.data

waitFor main()
