# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  kzg4844/[kzg_abi, kzg],
  ../spec/datatypes/[bellatrix, capella, deneb, electra],
  web3/[engine_api, engine_api_types]

from std/sequtils import mapIt

type
  BellatrixExecutionPayloadWithValue* = object
    executionPayload*: ExecutionPayloadV1
    blockValue*: UInt256

func asEth2Digest*(x: BlockHash): Eth2Digest =
  Eth2Digest(data: array[32, byte](x))

template asBlockHash*(x: Eth2Digest): BlockHash =
  BlockHash(x.data)

func asConsensusWithdrawal*(w: WithdrawalV1): capella.Withdrawal =
  capella.Withdrawal(
    index: w.index.uint64,
    validator_index: w.validatorIndex.uint64,
    address: ExecutionAddress(data: w.address.distinctBase),
    amount: Gwei w.amount)

func asEngineWithdrawal(w: capella.Withdrawal): WithdrawalV1 =
  WithdrawalV1(
    index: Quantity(w.index),
    validatorIndex: Quantity(w.validator_index),
    address: Address(w.address.data),
    amount: Quantity(w.amount))

func asConsensusType*(rpcExecutionPayload: ExecutionPayloadV1):
    bellatrix.ExecutionPayload =
  template getTransaction(tt: TypedTransaction): bellatrix.Transaction =
    bellatrix.Transaction.init(tt.distinctBase)

  bellatrix.ExecutionPayload(
    parent_hash: rpcExecutionPayload.parentHash.asEth2Digest,
    feeRecipient:
      ExecutionAddress(data: rpcExecutionPayload.feeRecipient.distinctBase),
    state_root: rpcExecutionPayload.stateRoot.asEth2Digest,
    receipts_root: rpcExecutionPayload.receiptsRoot.asEth2Digest,
    logs_bloom: BloomLogs(data: rpcExecutionPayload.logsBloom.distinctBase),
    prev_randao: rpcExecutionPayload.prevRandao.asEth2Digest,
    block_number: rpcExecutionPayload.blockNumber.uint64,
    gas_limit: rpcExecutionPayload.gasLimit.uint64,
    gas_used: rpcExecutionPayload.gasUsed.uint64,
    timestamp: rpcExecutionPayload.timestamp.uint64,
    extra_data: List[byte, MAX_EXTRA_DATA_BYTES].init(rpcExecutionPayload.extraData.bytes),
    base_fee_per_gas: rpcExecutionPayload.baseFeePerGas,
    block_hash: rpcExecutionPayload.blockHash.asEth2Digest,
    transactions: List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(
      mapIt(rpcExecutionPayload.transactions, it.getTransaction)))

func asConsensusType*(payloadWithValue: BellatrixExecutionPayloadWithValue):
    bellatrix.ExecutionPayloadForSigning =
  bellatrix.ExecutionPayloadForSigning(
    executionPayload: payloadWithValue.executionPayload.asConsensusType,
    blockValue: payloadWithValue.blockValue)

template maybeDeref*[T](o: Opt[T]): T = o.get
template maybeDeref*[V](v: V): V = v

func asConsensusType*(rpcExecutionPayload: ExecutionPayloadV1OrV2|ExecutionPayloadV2):
    capella.ExecutionPayload =
  template getTransaction(tt: TypedTransaction): bellatrix.Transaction =
    bellatrix.Transaction.init(tt.distinctBase)

  capella.ExecutionPayload(
    parent_hash: rpcExecutionPayload.parentHash.asEth2Digest,
    feeRecipient:
      ExecutionAddress(data: rpcExecutionPayload.feeRecipient.distinctBase),
    state_root: rpcExecutionPayload.stateRoot.asEth2Digest,
    receipts_root: rpcExecutionPayload.receiptsRoot.asEth2Digest,
    logs_bloom: BloomLogs(data: rpcExecutionPayload.logsBloom.distinctBase),
    prev_randao: rpcExecutionPayload.prevRandao.asEth2Digest,
    block_number: rpcExecutionPayload.blockNumber.uint64,
    gas_limit: rpcExecutionPayload.gasLimit.uint64,
    gas_used: rpcExecutionPayload.gasUsed.uint64,
    timestamp: rpcExecutionPayload.timestamp.uint64,
    extra_data: List[byte, MAX_EXTRA_DATA_BYTES].init(rpcExecutionPayload.extraData.bytes),
    base_fee_per_gas: rpcExecutionPayload.baseFeePerGas,
    block_hash: rpcExecutionPayload.blockHash.asEth2Digest,
    transactions: List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(
      mapIt(rpcExecutionPayload.transactions, it.getTransaction)),
    withdrawals: List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(
      mapIt(maybeDeref rpcExecutionPayload.withdrawals, it.asConsensusWithdrawal)))

func asConsensusType*(payloadWithValue: engine_api.GetPayloadV2Response):
    capella.ExecutionPayloadForSigning =
  capella.ExecutionPayloadForSigning(
    executionPayload: payloadWithValue.executionPayload.asConsensusType,
    blockValue: payloadWithValue.blockValue)

func asConsensusType*(rpcExecutionPayload: ExecutionPayloadV3):
    deneb.ExecutionPayload =
  template getTransaction(tt: TypedTransaction): bellatrix.Transaction =
    bellatrix.Transaction.init(tt.distinctBase)

  deneb.ExecutionPayload(
    parent_hash: rpcExecutionPayload.parentHash.asEth2Digest,
    feeRecipient:
      ExecutionAddress(data: rpcExecutionPayload.feeRecipient.distinctBase),
    state_root: rpcExecutionPayload.stateRoot.asEth2Digest,
    receipts_root: rpcExecutionPayload.receiptsRoot.asEth2Digest,
    logs_bloom: BloomLogs(data: rpcExecutionPayload.logsBloom.distinctBase),
    prev_randao: rpcExecutionPayload.prevRandao.asEth2Digest,
    block_number: rpcExecutionPayload.blockNumber.uint64,
    gas_limit: rpcExecutionPayload.gasLimit.uint64,
    gas_used: rpcExecutionPayload.gasUsed.uint64,
    timestamp: rpcExecutionPayload.timestamp.uint64,
    extra_data: List[byte, MAX_EXTRA_DATA_BYTES].init(rpcExecutionPayload.extraData.bytes),
    base_fee_per_gas: rpcExecutionPayload.baseFeePerGas,
    block_hash: rpcExecutionPayload.blockHash.asEth2Digest,
    transactions: List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(
      mapIt(rpcExecutionPayload.transactions, it.getTransaction)),
    withdrawals: List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(
      mapIt(rpcExecutionPayload.withdrawals, it.asConsensusWithdrawal)),
    blob_gas_used: rpcExecutionPayload.blobGasUsed.uint64,
    excess_blob_gas: rpcExecutionPayload.excessBlobGas.uint64)

func asConsensusType*(payload: engine_api.GetPayloadV3Response):
    deneb.ExecutionPayloadForSigning =
  deneb.ExecutionPayloadForSigning(
    executionPayload: payload.executionPayload.asConsensusType,
    blockValue: payload.blockValue,
    # TODO
    # The `mapIt` calls below are necessary only because we use different distinct
    # types for KZG commitments and Blobs in the `web3` and the `deneb` spec types.
    # Both are defined as `array[N, byte]` under the hood.
    blobsBundle: deneb.BlobsBundle(
      commitments: KzgCommitments.init(
        payload.blobsBundle.commitments.mapIt(
          kzg_abi.KzgCommitment(bytes: it.bytes))),
      proofs: KzgProofs.init(
        payload.blobsBundle.proofs.mapIt(
          kzg_abi.KzgProof(bytes: it.bytes))),
      blobs: Blobs.init(
        payload.blobsBundle.blobs.mapIt(it.bytes))))

func asConsensusType*(rpcExecutionPayload: ExecutionPayloadV4):
    electra.ExecutionPayload =
  template getTransaction(tt: TypedTransaction): bellatrix.Transaction =
    bellatrix.Transaction.init(tt.distinctBase)

  template getDepositRequest(
      dr: DepositRequestV1): electra.DepositRequest =
    electra.DepositRequest(
      pubkey: ValidatorPubKey(blob: dr.pubkey.distinctBase),
      withdrawal_credentials: dr.withdrawalCredentials.asEth2Digest,
      amount: dr.amount.Gwei,
      signature: ValidatorSig(blob: dr.signature.distinctBase),
      index: dr.index.uint64)

  template getWithdrawalRequest(
      wr: WithdrawalRequestV1): electra.WithdrawalRequest =
    electra.WithdrawalRequest(
      source_address: ExecutionAddress(data: wr.sourceAddress.distinctBase),
      validator_pubkey: ValidatorPubKey(blob: wr.validatorPubkey.distinctBase),
      amount: wr.amount.Gwei)

  template getConsolidationRequest(
      cr: ConsolidationRequestV1): electra.ConsolidationRequest =
    electra.ConsolidationRequest(
      source_address: ExecutionAddress(data: cr.sourceAddress.distinctBase),
      source_pubkey: ValidatorPubKey(blob: cr.sourcePubkey.distinctBase),
      target_pubkey: ValidatorPubKey(blob: cr.targetPubkey.distinctBase))

  electra.ExecutionPayload(
    parent_hash: rpcExecutionPayload.parentHash.asEth2Digest,
    feeRecipient:
      ExecutionAddress(data: rpcExecutionPayload.feeRecipient.distinctBase),
    state_root: rpcExecutionPayload.stateRoot.asEth2Digest,
    receipts_root: rpcExecutionPayload.receiptsRoot.asEth2Digest,
    logs_bloom: BloomLogs(data: rpcExecutionPayload.logsBloom.distinctBase),
    prev_randao: rpcExecutionPayload.prevRandao.asEth2Digest,
    block_number: rpcExecutionPayload.blockNumber.uint64,
    gas_limit: rpcExecutionPayload.gasLimit.uint64,
    gas_used: rpcExecutionPayload.gasUsed.uint64,
    timestamp: rpcExecutionPayload.timestamp.uint64,
    extra_data: List[byte, MAX_EXTRA_DATA_BYTES].init(
      rpcExecutionPayload.extraData.bytes),
    base_fee_per_gas: rpcExecutionPayload.baseFeePerGas,
    block_hash: rpcExecutionPayload.blockHash.asEth2Digest,
    transactions: List[bellatrix.Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(
      mapIt(rpcExecutionPayload.transactions, it.getTransaction)),
    withdrawals: List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(
      mapIt(rpcExecutionPayload.withdrawals, it.asConsensusWithdrawal)),
    blob_gas_used: rpcExecutionPayload.blobGasUsed.uint64,
    excess_blob_gas: rpcExecutionPayload.excessBlobGas.uint64)

func asConsensusType*(payload: engine_api.GetPayloadV4Response):
    electra.ExecutionPayloadForSigning =
  electra.ExecutionPayloadForSigning(
    executionPayload: payload.executionPayload.asConsensusType,
    blockValue: payload.blockValue,
    # TODO
    # The `mapIt` calls below are necessary only because we use different distinct
    # types for KZG commitments and Blobs in the `web3` and the `deneb` spec types.
    # Both are defined as `array[N, byte]` under the hood.
    blobsBundle: deneb.BlobsBundle(
      commitments: KzgCommitments.init(
        payload.blobsBundle.commitments.mapIt(
          kzg_abi.KzgCommitment(bytes: it.bytes))),
      proofs: KzgProofs.init(
        payload.blobsBundle.proofs.mapIt(
          kzg_abi.KzgProof(bytes: it.bytes))),
      blobs: Blobs.init(
        payload.blobsBundle.blobs.mapIt(it.bytes))))

func asEngineExecutionPayload*(
    # `SomeBeaconBlockBody`: https://github.com/nim-lang/Nim/issues/18095
    blockBody: bellatrix.BeaconBlockBody | bellatrix.TrustedBeaconBlockBody
): ExecutionPayloadV1 =
  template executionPayload(): untyped = blockBody.execution_payload

  template getTypedTransaction(tt: bellatrix.Transaction): TypedTransaction =
    TypedTransaction(tt.distinctBase)

  engine_api.ExecutionPayloadV1(
    parentHash: executionPayload.parent_hash.asBlockHash,
    feeRecipient: Address(executionPayload.fee_recipient.data),
    stateRoot: executionPayload.state_root.asBlockHash,
    receiptsRoot: executionPayload.receipts_root.asBlockHash,
    logsBloom:
      FixedBytes[BYTES_PER_LOGS_BLOOM](executionPayload.logs_bloom.data),
    prevRandao: executionPayload.prev_randao.asBlockHash,
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
    address: Address(w.address.data),
    amount: Quantity(w.amount))

func asEngineExecutionPayload*(
    # `SomeBeaconBlockBody`: https://github.com/nim-lang/Nim/issues/18095
    blockBody: capella.BeaconBlockBody | capella.TrustedBeaconBlockBody
): ExecutionPayloadV2 =
  template executionPayload(): untyped = blockBody.execution_payload

  template getTypedTransaction(tt: bellatrix.Transaction): TypedTransaction =
    TypedTransaction(tt.distinctBase)
  engine_api.ExecutionPayloadV2(
    parentHash: executionPayload.parent_hash.asBlockHash,
    feeRecipient: Address(executionPayload.fee_recipient.data),
    stateRoot: executionPayload.state_root.asBlockHash,
    receiptsRoot: executionPayload.receipts_root.asBlockHash,
    logsBloom:
      FixedBytes[BYTES_PER_LOGS_BLOOM](executionPayload.logs_bloom.data),
    prevRandao: executionPayload.prev_randao.asBlockHash,
    blockNumber: Quantity(executionPayload.block_number),
    gasLimit: Quantity(executionPayload.gas_limit),
    gasUsed: Quantity(executionPayload.gas_used),
    timestamp: Quantity(executionPayload.timestamp),
    extraData: DynamicBytes[0, MAX_EXTRA_DATA_BYTES](executionPayload.extra_data),
    baseFeePerGas: executionPayload.base_fee_per_gas,
    blockHash: executionPayload.block_hash.asBlockHash,
    transactions: mapIt(executionPayload.transactions, it.getTypedTransaction),
    withdrawals: mapIt(executionPayload.withdrawals, it.toEngineWithdrawal))

func asEngineExecutionPayload*(
    # `SomeBeaconBlockBody`: https://github.com/nim-lang/Nim/issues/18095
    blockBody: deneb.BeaconBlockBody | deneb.TrustedBeaconBlockBody
): ExecutionPayloadV3 =
  template executionPayload(): untyped = blockBody.execution_payload

  template getTypedTransaction(tt: bellatrix.Transaction): TypedTransaction =
    TypedTransaction(tt.distinctBase)

  engine_api.ExecutionPayloadV3(
    parentHash: executionPayload.parent_hash.asBlockHash,
    feeRecipient: Address(executionPayload.fee_recipient.data),
    stateRoot: executionPayload.state_root.asBlockHash,
    receiptsRoot: executionPayload.receipts_root.asBlockHash,
    logsBloom:
      FixedBytes[BYTES_PER_LOGS_BLOOM](executionPayload.logs_bloom.data),
    prevRandao: executionPayload.prev_randao.asBlockHash,
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

func asEngineExecutionPayload*(
    # `SomeBeaconBlockBody`: https://github.com/nim-lang/Nim/issues/18095
    blockBody: electra.BeaconBlockBody | electra.TrustedBeaconBlockBody
): ExecutionPayloadV4 =
  template executionPayload(): untyped = blockBody.execution_payload

  template getTypedTransaction(tt: bellatrix.Transaction): TypedTransaction =
    TypedTransaction(tt.distinctBase)

  template getDepositRequest(
      dr: electra.DepositRequest): DepositRequestV1 =
    DepositRequestV1(
      pubkey: FixedBytes[RawPubKeySize](dr.pubkey.blob),
      withdrawalCredentials: FixedBytes[32](dr.withdrawal_credentials.data),
      amount: dr.amount.Quantity,
      signature: FixedBytes[RawSigSize](dr.signature.blob),
      index: dr.index.Quantity)

  template getWithdrawalRequest(
      wr: electra.WithdrawalRequest): WithdrawalRequestV1 =
    WithdrawalRequestV1(
      sourceAddress: Address(wr.source_address.data),
      validatorPubkey: FixedBytes[RawPubKeySize](wr.validator_pubkey.blob),
      amount: wr.amount.Quantity)

  template getConsolidationRequest(
      cr: electra.ConsolidationRequest): ConsolidationRequestV1 =
    ConsolidationRequestV1(
      sourceAddress: Address(cr.source_address.data),
      sourcePubkey: FixedBytes[RawPubKeySize](cr.source_pubkey.blob),
      targetPubkey: FixedBytes[RawPubKeySize](cr.target_pubkey.blob))

  engine_api.ExecutionPayloadV4(
    parentHash: executionPayload.parent_hash.asBlockHash,
    feeRecipient: Address(executionPayload.fee_recipient.data),
    stateRoot: executionPayload.state_root.asBlockHash,
    receiptsRoot: executionPayload.receipts_root.asBlockHash,
    logsBloom:
      FixedBytes[BYTES_PER_LOGS_BLOOM](executionPayload.logs_bloom.data),
    prevRandao: executionPayload.prev_randao.asBlockHash,
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
    depositRequests:
      mapIt(blockBody.execution_requests.deposits, it.getDepositRequest),
    withdrawalRequests: mapIt(
      blockBody.execution_requests.withdrawals, it.getWithdrawalRequest),
    consolidationRequests: mapIt(
      blockBody.execution_requests.consolidations, it.getConsolidationRequest))
