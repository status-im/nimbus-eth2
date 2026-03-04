# beacon_chain
# Copyright (c) 2024-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  kzg4844/[kzg_abi, kzg],
  ../spec/datatypes/[bellatrix, capella, deneb, electra, fulu, gloas],
  ../spec/[eth2_ssz_serialization, state_transition_block],
  web3/[engine_api, engine_api_types]

from std/sequtils import mapIt

func asEth2Digest*(x: Hash32|Bytes32): Eth2Digest =
  Eth2Digest(data: array[32, byte](x))

template asBlockHash*(x: Eth2Digest): Hash32 =
  Hash32(x.data)

func asConsensusWithdrawal*(w: WithdrawalV1): capella.Withdrawal =
  capella.Withdrawal(
    index: w.index.uint64,
    validator_index: w.validatorIndex.uint64,
    address: w.address,
    amount: Gwei w.amount)

func asEngineWithdrawal*(w: capella.Withdrawal): WithdrawalV1 =
  WithdrawalV1(
    index: Quantity(w.index),
    validatorIndex: Quantity(w.validator_index),
    address: w.address,
    amount: Quantity(w.amount))

func asConsensusType*(rpcExecutionPayload: ExecutionPayloadV1):
    bellatrix.ExecutionPayload =
  template getTransaction(tt: TypedTransaction): bellatrix.Transaction =
    bellatrix.Transaction.init(tt.distinctBase)

  bellatrix.ExecutionPayload(
    parent_hash: rpcExecutionPayload.parentHash.asEth2Digest,
    feeRecipient: rpcExecutionPayload.feeRecipient,
    state_root: rpcExecutionPayload.stateRoot.asEth2Digest,
    receipts_root: rpcExecutionPayload.receiptsRoot.asEth2Digest,
    logs_bloom: BloomLogs(data: rpcExecutionPayload.logsBloom.distinctBase),
    prev_randao: rpcExecutionPayload.prevRandao.asEth2Digest,
    block_number: rpcExecutionPayload.blockNumber.uint64,
    gas_limit: rpcExecutionPayload.gasLimit.uint64,
    gas_used: rpcExecutionPayload.gasUsed.uint64,
    timestamp: rpcExecutionPayload.timestamp.uint64,
    extra_data: List[byte, MAX_EXTRA_DATA_BYTES].init(rpcExecutionPayload.extraData.data),
    base_fee_per_gas: rpcExecutionPayload.baseFeePerGas,
    block_hash: rpcExecutionPayload.blockHash.asEth2Digest,
    transactions: List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(
      mapIt(rpcExecutionPayload.transactions, it.getTransaction)))

template maybeDeref*[T](o: Opt[T]): T = o.get
template maybeDeref*[V](v: V): V = v

func asConsensusType*(rpcExecutionPayload: ExecutionPayloadV1OrV2|ExecutionPayloadV2):
    capella.ExecutionPayload =
  template getTransaction(tt: TypedTransaction): bellatrix.Transaction =
    bellatrix.Transaction.init(tt.distinctBase)

  capella.ExecutionPayload(
    parent_hash: rpcExecutionPayload.parentHash.asEth2Digest,
    feeRecipient: rpcExecutionPayload.feeRecipient,
    state_root: rpcExecutionPayload.stateRoot.asEth2Digest,
    receipts_root: rpcExecutionPayload.receiptsRoot.asEth2Digest,
    logs_bloom: BloomLogs(data: rpcExecutionPayload.logsBloom.distinctBase),
    prev_randao: rpcExecutionPayload.prevRandao.asEth2Digest,
    block_number: rpcExecutionPayload.blockNumber.uint64,
    gas_limit: rpcExecutionPayload.gasLimit.uint64,
    gas_used: rpcExecutionPayload.gasUsed.uint64,
    timestamp: rpcExecutionPayload.timestamp.uint64,
    extra_data: List[byte, MAX_EXTRA_DATA_BYTES].init(rpcExecutionPayload.extraData.data),
    base_fee_per_gas: rpcExecutionPayload.baseFeePerGas,
    block_hash: rpcExecutionPayload.blockHash.asEth2Digest,
    transactions: List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(
      mapIt(rpcExecutionPayload.transactions, it.getTransaction)),
    withdrawals: List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(
      mapIt(maybeDeref rpcExecutionPayload.withdrawals, it.asConsensusWithdrawal)))

func asConsensusType*(
    rpcExecutionPayload: ExecutionPayloadV3 | ExecutionPayloadV4):
    deneb.ExecutionPayload =
  template getTransaction(tt: TypedTransaction): bellatrix.Transaction =
    bellatrix.Transaction.init(tt.distinctBase)

  deneb.ExecutionPayload(
    parent_hash: rpcExecutionPayload.parentHash.asEth2Digest,
    feeRecipient: rpcExecutionPayload.feeRecipient,
    state_root: rpcExecutionPayload.stateRoot.asEth2Digest,
    receipts_root: rpcExecutionPayload.receiptsRoot.asEth2Digest,
    logs_bloom: BloomLogs(data: rpcExecutionPayload.logsBloom.distinctBase),
    prev_randao: rpcExecutionPayload.prevRandao.asEth2Digest,
    block_number: rpcExecutionPayload.blockNumber.uint64,
    gas_limit: rpcExecutionPayload.gasLimit.uint64,
    gas_used: rpcExecutionPayload.gasUsed.uint64,
    timestamp: rpcExecutionPayload.timestamp.uint64,
    extra_data: List[byte, MAX_EXTRA_DATA_BYTES].init(rpcExecutionPayload.extraData.data),
    base_fee_per_gas: rpcExecutionPayload.baseFeePerGas,
    block_hash: rpcExecutionPayload.blockHash.asEth2Digest,
    transactions: List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(
      mapIt(rpcExecutionPayload.transactions, it.getTransaction)),
    withdrawals: List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(
      mapIt(rpcExecutionPayload.withdrawals, it.asConsensusWithdrawal)),
    blob_gas_used: rpcExecutionPayload.blobGasUsed.uint64,
    excess_blob_gas: rpcExecutionPayload.excessBlobGas.uint64)

func asConsensusType*(
    payload: engine_api.GetPayloadV4Response):
    electra.ExecutionPayloadForSigning =
  electra.ExecutionPayloadForSigning(
    executionPayload: payload.executionPayload.asConsensusType(),
    blockValue: payload.blockValue,
    # TODO
    # The `mapIt` calls below are necessary only because we use different distinct
    # types for KZG commitments and Blobs in the `web3` and the `deneb` spec types.
    # Both are defined as `array[N, byte]` under the hood.
    blobsBundle: deneb.BlobsBundle(
      commitments: KzgCommitments.init(
        payload.blobsBundle.commitments.mapIt(
          kzg_abi.KzgCommitment(bytes: it.data))),
      proofs: deneb.KzgProofs.init(
        payload.blobsBundle.proofs.mapIt(
          kzg_abi.KzgProof(bytes: it.data))),
      blobs: Blobs.init(
        payload.blobsBundle.blobs.mapIt(it.data))),
    executionRequests: payload.executionRequests)

func asConsensusType*(
    payload: GetPayloadV5Response): fulu.ExecutionPayloadForSigning =
  fulu.ExecutionPayloadForSigning(
    executionPayload: payload.executionPayload.asConsensusType,
    blockValue: payload.blockValue,
    # TODO
    # The `mapIt` calls below are necessary only because we use different distinct
    # types for KZG commitments and Blobs in the `web3` and the `deneb` spec types.
    # Both are defined as `array[N, byte]` under the hood.
    blobsBundle: fulu.BlobsBundle(
      commitments: KzgCommitments.init(
        payload.blobsBundle.commitments.mapIt(
          kzg_abi.KzgCommitment(bytes: it.data))),
      proofs: fulu.KzgProofs.init(
        payload.blobsBundle.proofs.mapIt(
          kzg_abi.KzgProof(bytes: it.data))),
      blobs: Blobs.init(
        payload.blobsBundle.blobs.mapIt(it.data))),
    executionRequests: payload.executionRequests)

func asConsensusTypeGloas*(
    payload: GetPayloadV5Response): gloas.ExecutionPayloadForSigning =
  gloas.ExecutionPayloadForSigning(
    executionPayload: payload.executionPayload.asConsensusType,
    blockValue: payload.blockValue,
    # TODO
    # The `mapIt` calls below are necessary only because we use different distinct
    # types for KZG commitments and Blobs in the `web3` and the `deneb` spec types.
    # Both are defined as `array[N, byte]` under the hood.
    blobsBundle: fulu.BlobsBundle(
      commitments: KzgCommitments.init(
        payload.blobsBundle.commitments.mapIt(
          kzg_abi.KzgCommitment(bytes: it.data))),
      proofs: fulu.KzgProofs.init(
        payload.blobsBundle.proofs.mapIt(
          kzg_abi.KzgProof(bytes: it.data))),
      blobs: Blobs.init(
        payload.blobsBundle.blobs.mapIt(it.data))),
    executionRequests: payload.executionRequests)

func asEngineExecutionPayload*(executionPayload: bellatrix.ExecutionPayload):
    ExecutionPayloadV1 =
  template getTypedTransaction(tt: bellatrix.Transaction): TypedTransaction =
    TypedTransaction(tt.distinctBase)

  engine_api.ExecutionPayloadV1(
    parentHash: executionPayload.parent_hash.asBlockHash,
    feeRecipient: executionPayload.fee_recipient,
    stateRoot: executionPayload.state_root.asBlockHash,
    receiptsRoot: executionPayload.receipts_root.asBlockHash,
    logsBloom:
      FixedBytes[BYTES_PER_LOGS_BLOOM](executionPayload.logs_bloom.data),
    prevRandao: executionPayload.prev_randao.data.to(Bytes32),
    blockNumber: Quantity(executionPayload.block_number),
    gasLimit: Quantity(executionPayload.gas_limit),
    gasUsed: Quantity(executionPayload.gas_used),
    timestamp: Quantity(executionPayload.timestamp),
    extraData: DynamicBytes[0, MAX_EXTRA_DATA_BYTES](executionPayload.extra_data),
    baseFeePerGas: executionPayload.base_fee_per_gas,
    blockHash: executionPayload.block_hash.asBlockHash,
    transactions: mapIt(executionPayload.transactions, it.getTypedTransaction))

template toEngineWithdrawal*(w: capella.Withdrawal): WithdrawalV1 =
  WithdrawalV1(
    index: Quantity(w.index),
    validatorIndex: Quantity(w.validator_index),
    address: w.address,
    amount: Quantity(w.amount))

func asEngineExecutionPayload*(executionPayload: capella.ExecutionPayload):
    ExecutionPayloadV2 =
  template getTypedTransaction(tt: bellatrix.Transaction): TypedTransaction =
    TypedTransaction(tt.distinctBase)
  engine_api.ExecutionPayloadV2(
    parentHash: executionPayload.parent_hash.asBlockHash,
    feeRecipient: executionPayload.fee_recipient,
    stateRoot: executionPayload.state_root.asBlockHash,
    receiptsRoot: executionPayload.receipts_root.asBlockHash,
    logsBloom:
      FixedBytes[BYTES_PER_LOGS_BLOOM](executionPayload.logs_bloom.data),
    prevRandao: executionPayload.prev_randao.data.to(Bytes32),
    blockNumber: Quantity(executionPayload.block_number),
    gasLimit: Quantity(executionPayload.gas_limit),
    gasUsed: Quantity(executionPayload.gas_used),
    timestamp: Quantity(executionPayload.timestamp),
    extraData: DynamicBytes[0, MAX_EXTRA_DATA_BYTES](executionPayload.extra_data),
    baseFeePerGas: executionPayload.base_fee_per_gas,
    blockHash: executionPayload.block_hash.asBlockHash,
    transactions: mapIt(executionPayload.transactions, it.getTypedTransaction),
    withdrawals: mapIt(executionPayload.withdrawals, it.toEngineWithdrawal))

func asEngineExecutionPayload*(executionPayload: deneb.ExecutionPayload):
    ExecutionPayloadV3 =
  template getTypedTransaction(tt: bellatrix.Transaction): TypedTransaction =
    TypedTransaction(tt.distinctBase)

  engine_api.ExecutionPayloadV3(
    parentHash: executionPayload.parent_hash.asBlockHash,
    feeRecipient: executionPayload.fee_recipient,
    stateRoot: executionPayload.state_root.asBlockHash,
    receiptsRoot: executionPayload.receipts_root.asBlockHash,
    logsBloom:
      FixedBytes[BYTES_PER_LOGS_BLOOM](executionPayload.logs_bloom.data),
    prevRandao: executionPayload.prev_randao.data.to(Bytes32),
    blockNumber: Quantity(executionPayload.block_number),
    gasLimit: Quantity(executionPayload.gas_limit),
    gasUsed: Quantity(executionPayload.gas_used),
    timestamp: Quantity(executionPayload.timestamp),
    extraData: DynamicBytes[0, MAX_EXTRA_DATA_BYTES](executionPayload.extra_data),
    baseFeePerGas: executionPayload.base_fee_per_gas,
    blockHash: executionPayload.block_hash.asBlockHash,
    transactions: mapIt(executionPayload.transactions, it.getTypedTransaction),
    withdrawals: mapIt(executionPayload.withdrawals, it.asEngineWithdrawal),
    blobGasUsed: Quantity(executionPayload.blob_gas_used),
    excessBlobGas: Quantity(executionPayload.excess_blob_gas))

func asEngineExecutionPayloadV4*(executionPayload: deneb.ExecutionPayload):
    ExecutionPayloadV4 =
  template getTypedTransaction(tt: bellatrix.Transaction): TypedTransaction =
    TypedTransaction(tt.distinctBase)

  engine_api.ExecutionPayloadV4(
    parentHash: executionPayload.parent_hash.asBlockHash,
    feeRecipient: executionPayload.fee_recipient,
    stateRoot: executionPayload.state_root.asBlockHash,
    receiptsRoot: executionPayload.receipts_root.asBlockHash,
    logsBloom:
      FixedBytes[BYTES_PER_LOGS_BLOOM](executionPayload.logs_bloom.data),
    prevRandao: executionPayload.prev_randao.data.to(Bytes32),
    blockNumber: Quantity(executionPayload.block_number),
    gasLimit: Quantity(executionPayload.gas_limit),
    gasUsed: Quantity(executionPayload.gas_used),
    timestamp: Quantity(executionPayload.timestamp),
    extraData: DynamicBytes[0, MAX_EXTRA_DATA_BYTES](executionPayload.extra_data),
    baseFeePerGas: executionPayload.base_fee_per_gas,
    blockHash: executionPayload.block_hash.asBlockHash,
    transactions: mapIt(executionPayload.transactions, it.getTypedTransaction),
    withdrawals: mapIt(executionPayload.withdrawals, it.asEngineWithdrawal),
    blobGasUsed: Quantity(executionPayload.blob_gas_used),
    excessBlobGas: Quantity(executionPayload.excess_blob_gas),
    blockAccessList: @[],  # TODO: stub
    slotNumber: Quantity(0)) # TODO: stub

proc asEngineVersionedHashes*(
    blob_kzg_commitments: KzgCommitments
): seq[VersionedHash] =
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-alpha.1/specs/deneb/beacon-chain.md#process_execution_payload

  mapIt(blob_kzg_commitments, kzg_commitment_to_versioned_hash(it))

proc asEngineExecutionRequests*(
    execution_requests: electra.ExecutionRequests
): seq[seq[byte]] =
  # https://github.com/ethereum/execution-apis/blob/7c9772f95c2472ccfc6f6128dc2e1b568284a2da/src/engine/prague.md#request
  # "Each list element is a `requests` byte array as defined by
  # EIP-7685. The first byte of each element is the `request_type`
  # and the remaining bytes are the `request_data`. Elements of
  # the list MUST be ordered by `request_type` in ascending order.
  # Elements with empty `request_data` MUST be excluded from the
  # list."

  var requests: seq[seq[byte]]
  for request_type, request_data in [
    SSZ.encode(execution_requests.deposits),
    SSZ.encode(execution_requests.withdrawals),
    SSZ.encode(execution_requests.consolidations),
  ]:
    if request_data.len > 0:
      requests.add @[request_type.byte] & request_data
  requests
