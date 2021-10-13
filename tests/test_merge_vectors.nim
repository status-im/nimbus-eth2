{.used.}

# https://notes.ethereum.org/@9AeMAlpyQYaAAyuj47BzRw/rkwW3ceVY
# Monitor traffic: socat -v TCP-LISTEN:9545,fork TCP-CONNECT:127.0.0.1:8545

import
  unittest2,
  chronos, web3/[engine_api_types, ethtypes],
  ../beacon_chain/eth1/eth1_monitor,
  ../beacon_chain/spec/[digest, presets],
  ./testutil

suite "Merge test vectors":
  let web3Provider = (waitFor Web3DataProvider.new(
    default(Eth1Address), "ws://127.0.0.1:8546")).get

  test "preparePayload, getPayload, executePayload, and forkchoiceUpdated":
    let
      existingBlock = waitFor web3Provider.getBlockByNumber(5)
      payloadId = waitFor web3Provider.preparePayload(
        existingBlock.hash.asEth2Digest,
        existingBlock.timestamp.uint64 + 12,
        default(Eth2Digest).data,  # Random
        Eth1Address.fromHex("0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"))  # Fee recipient
      payload =         waitFor web3Provider.getPayload(
        Quantity(payloadId.payloadId))
      payloadStatus =   waitFor web3Provider.executePayload(payload)
      fcupdatedStatus = waitFor web3Provider.forkchoiceUpdated(
        payload.blockHash.asEth2Digest, payload.blockHash.asEth2Digest)

      payloadId2 = waitFor web3Provider.preparePayload(
        payload.blockHash.asEth2Digest,
        existingBlock.timestamp.uint64 + 24,
        default(Eth2Digest).data,  # Random
        Eth1Address.fromHex("0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"))  # Fee recipient
      payload2 =         waitFor web3Provider.getPayload(
        Quantity(payloadId2.payloadId))
      payloadStatus2 =   waitFor web3Provider.executePayload(payload2)
      fcupdatedStatus2 = waitFor web3Provider.forkchoiceUpdated(
        payload2.blockHash.asEth2Digest, payload2.blockHash.asEth2Digest)

    check: payloadStatus.status == "VALID"

  test "getPayload unknown payload":
    try:
      let res = waitFor web3Provider.getPayload(Quantity(100000))
      doAssert false
    except ValueError as e:
      # expected outcome
      echo e.msg
