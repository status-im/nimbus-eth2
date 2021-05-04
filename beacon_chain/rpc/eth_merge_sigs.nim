## This module contains signatures for the Ethereum merge RPCs.
## The signatures are not imported directly, but read and processed with parseStmt,
## then a procedure body is generated to marshal native Nim parameters to json and visa versa.

import json, options, stint, ethtypes

# https://hackmd.io/@n0ble/ethereum_consensus_upgrade_mainnet_perspective
# https://notes.ethereum.org/@n0ble/rayonism-the-merge-spec
# https://github.com/gballet/go-ethereum/blob/catalyst-for-rayonism/eth/catalyst/api.go
# https://github.com/gballet/go-ethereum/blob/catalyst-for-rayonism/eth/catalyst/api_test.go
proc consensus_assembleBlock(blockParams: BlockParams): ExecutionPayloadRPC
proc consensus_newBlock(executableData: ExecutionPayloadRPC): BoolReturnValidRPC
proc consensus_finalizeBlock(blockHash: Eth2Digest): BoolReturnValidRPC
proc consensus_setHead(newHead: string): BoolReturnSuccessRPC
