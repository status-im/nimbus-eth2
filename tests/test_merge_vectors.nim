{.used.}

# https://notes.ethereum.org/@9AeMAlpyQYaAAyuj47BzRw/rkwW3ceVY
# Monitor traffic: socat -v TCP-LISTEN:9550,fork TCP-CONNECT:127.0.0.1:8550

import
  unittest2,
  chronos, web3/[engine_api_types, ethtypes],
  ../beacon_chain/eth1/eth1_monitor,
  ../beacon_chain/spec/[digest, presets],
  ./testutil

suite "Merge test vectors":
  setup:
    let web3Provider = (waitFor Web3DataProvider.new(
      default(Eth1Address), "http://127.0.0.1:8550")).get

  test "getPayload, executePayload, and forkchoiceUpdated":
    const feeRecipient =
      Eth1Address.fromHex("0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b")
    let
      existingBlock = waitFor web3Provider.getBlockByNumber(0)
      payloadId = waitFor web3Provider.forkchoiceUpdated(
        existingBlock.hash.asEth2Digest,
        existingBlock.hash.asEth2Digest,
        existingBlock.timestamp.uint64 + 12,
        default(Eth2Digest).data,  # Random
        feeRecipient)
      payload =         waitFor web3Provider.getPayload(
        array[8, byte] (payloadId.payloadId.get))
      payloadStatus =   waitFor web3Provider.executePayload(payload)
      fcupdatedStatus = waitFor web3Provider.forkchoiceUpdated(
        payload.blockHash.asEth2Digest,
        payload.blockHash.asEth2Digest,
        existingBlock.timestamp.uint64 + 24,
        default(Eth2Digest).data,  # Random
        feeRecipient)

      payload2 =         waitFor web3Provider.getPayload(
        array[8, byte] (fcupdatedStatus.payloadId.get))
      payloadStatus2 =   waitFor web3Provider.executePayload(payload2)
      fcupdatedStatus2 = waitFor web3Provider.forkchoiceUpdated(
        payload2.blockHash.asEth2Digest,
        payload2.blockHash.asEth2Digest,
        existingBlock.timestamp.uint64 + 36,
        default(Eth2Digest).data,  # Random
        feeRecipient)

    check:
      payloadStatus.status == PayloadExecutionStatus.valid
      fcupdatedStatus.status == ForkchoiceUpdatedStatus.success
      payloadStatus2.status == PayloadExecutionStatus.valid
      fcupdatedStatus2.status == ForkchoiceUpdatedStatus.success
