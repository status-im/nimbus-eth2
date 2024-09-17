# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  ../spec/datatypes/[bellatrix, capella, deneb, electra],
  web3/[engine_api, engine_api_types, eth_api_types]

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
  template getTransaction(
      tt: engine_api_types.Transaction): electra.Eip6404Transaction =
    electra.Eip6404Transaction(
      payload: Eip6404TransactionPayload(
        `type`:
          if tt.payload.`type`.isSome:
            Opt.some(tt.payload.`type`.get.uint64.uint8)
          else:
            Opt.none(uint8),
        chain_id:
          if tt.payload.chainId.isSome:
            Opt.some(tt.payload.chainId.get.uint64)
          else:
            Opt.none(uint64),
        nonce:
          if tt.payload.nonce.isSome:
            Opt.some(tt.payload.nonce.get.uint64)
          else:
            Opt.none(uint64),
        max_fees_per_gas:
          if tt.payload.maxFeesPerGas.isSome:
            Opt.some(Eip6404FeesPerGas(
              regular:
                if tt.payload.maxFeesPerGas.get.regular.isSome:
                  Opt.some(tt.payload.maxFeesPerGas.get.regular.get)
                else:
                  Opt.none(Uint256),
              blob:
                if tt.payload.maxFeesPerGas.get.blob.isSome:
                  Opt.some(tt.payload.maxFeesPerGas.get.blob.get)
                else:
                  Opt.none(Uint256)))
          else:
            Opt.none(Eip6404FeesPerGas),
        gas:
          if tt.payload.gas.isSome:
            Opt.some(tt.payload.gas.get.uint64)
          else:
            Opt.none(uint64),
        to:
          if tt.payload.to.isSome:
            Opt.some(ExecutionAddress(data: tt.payload.to.get.distinctBase))
          else:
            Opt.none(ExecutionAddress),
        value:
          if tt.payload.value.isSome:
            Opt.some(tt.payload.value.get)
          else:
            Opt.none(UInt256),
        input:
          if tt.payload.input.isSome:
            Opt.some(List[byte, Limit MAX_CALLDATA_SIZE].init(
              tt.payload.input.get))
          else:
            Opt.none(List[byte, Limit MAX_CALLDATA_SIZE]),
        access_list:
          if tt.payload.accessList.isSome:
            Opt.some(List[Eip6404AccessTuple, Limit MAX_ACCESS_LIST_SIZE].init(
              tt.payload.accessList.get.mapIt(
                Eip6404AccessTuple(
                  address: ExecutionAddress(data: distinctBase(it.address)),
                  storage_keys:
                    List[Eth2Digest, Limit MAX_ACCESS_LIST_STORAGE_KEYS]
                      .init(it.storage_keys.mapIt(
                        Eth2Digest(data: distinctBase(it))))))))
          else:
            Opt.none(List[Eip6404AccessTuple, Limit MAX_ACCESS_LIST_SIZE]),
        max_priority_fees_per_gas:
          if tt.payload.maxPriorityFeesPerGas.isSome:
            Opt.some(Eip6404FeesPerGas(
              regular:
                if tt.payload.maxPriorityFeesPerGas.get.regular.isSome:
                  Opt.some(tt.payload.maxPriorityFeesPerGas.get.regular.get)
                else:
                  Opt.none(Uint256),
              blob:
                if tt.payload.maxPriorityFeesPerGas.get.blob.isSome:
                  Opt.some(tt.payload.maxPriorityFeesPerGas.get.blob.get)
                else:
                  Opt.none(Uint256)))
          else:
            Opt.none(Eip6404FeesPerGas),
        blob_versioned_hashes:
          if tt.payload.blobVersionedHashes.isSome:
            Opt.some(
              List[stable.VersionedHash, Limit MAX_BLOB_COMMITMENTS_PER_BLOCK]
                .init(tt.payload.blobVersionedHashes.get.mapIt(
                  stable.VersionedHash(it))))
          else:
            Opt.none(
              List[stable.VersionedHash,
                Limit MAX_BLOB_COMMITMENTS_PER_BLOCK])),
      `from`: Eip6404ExecutionSignature(
        address:
          if tt.`from`.address.isSome:
            Opt.some(ExecutionAddress(
              data: distinctBase(tt.`from`.address.get)))
          else:
            Opt.none(ExecutionAddress),
        secp256k1_signature:
          if tt.`from`.secp256k1Signature.isSome:
            Opt.some(array[65, byte](tt.`from`.secp256k1Signature.get))
          else:
            Opt.none(array[65, byte])))

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
    transactions: List[Eip6404Transaction, MAX_TRANSACTIONS_PER_PAYLOAD].init(
      mapIt(rpcExecutionPayload.transactions, it.getTransaction)),
    withdrawals: List[capella.Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD].init(
      mapIt(rpcExecutionPayload.withdrawals, it.asConsensusWithdrawal)),
    blob_gas_used: rpcExecutionPayload.blobGasUsed.uint64,
    excess_blob_gas: rpcExecutionPayload.excessBlobGas.uint64,
    deposit_requests:
      List[electra.DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD].init(
        mapIt(rpcExecutionPayload.depositRequests, it.getDepositRequest)),
    withdrawal_requests: List[electra.WithdrawalRequest,
      MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD].init(
        mapIt(rpcExecutionPayload.withdrawalRequests,
          it.getWithdrawalRequest)),
    consolidation_requests: List[electra.ConsolidationRequest,
      Limit MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD].init(
        mapIt(rpcExecutionPayload.consolidationRequests,
          it.getConsolidationRequest)))

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

func asEngineExecutionPayload*(executionPayload: bellatrix.ExecutionPayload):
    ExecutionPayloadV1 =
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

func asEngineExecutionPayload*(executionPayload: capella.ExecutionPayload):
    ExecutionPayloadV2 =
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

func asEngineExecutionPayload*(executionPayload: deneb.ExecutionPayload):
    ExecutionPayloadV3 =
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

func asEngineExecutionPayload*(executionPayload: electra.ExecutionPayload):
    ExecutionPayloadV4 =
  template getTypedTransaction(
      tt: electra.Eip6404Transaction): engine_api_types.Transaction =
    engine_api_types.Transaction(
      payload: engine_api_types.TransactionPayload(
        `type`:
          if tt.payload.`type`.isSome:
            Opt.some(tt.payload.`type`.get.Quantity)
          else:
            Opt.none(Quantity),
        chainId:
          if tt.payload.chain_id.isSome:
            Opt.some(tt.payload.chain_id.get.Quantity)
          else:
            Opt.none(Quantity),
        nonce:
          if tt.payload.nonce.isSome:
            Opt.some(tt.payload.nonce.get.Quantity)
          else:
            Opt.none(Quantity),
        maxFeesPerGas:
          if tt.payload.max_fees_per_gas.isSome:
            Opt.some(engine_api_types.FeesPerGas(
              regular:
                if tt.payload.max_fees_per_gas.get.regular.isSome:
                  Opt.some(tt.payload.max_fees_per_gas.get.regular.get)
                else:
                  Opt.none(UInt256),
              blob:
                if tt.payload.max_fees_per_gas.get.blob.isSome:
                  Opt.some(tt.payload.max_fees_per_gas.get.blob.get)
                else:
                  Opt.none(UInt256)))
          else:
            Opt.none(engine_api_types.FeesPerGas),
        gas:
          if tt.payload.gas.isSome:
            Opt.some(tt.payload.gas.get.Quantity)
          else:
            Opt.none(Quantity),
        to:
          if tt.payload.to.isSome:
            Opt.some(Address(tt.payload.to.get.data))
          else:
            Opt.none(Address),
        value:
          if tt.payload.value.isSome:
            Opt.some(tt.payload.value.get)
          else:
            Opt.none(UInt256),
        input:
          if tt.payload.input.isSome:
            Opt.some(distinctBase(tt.payload.input.get))
          else:
            Opt.none(seq[byte]),
        accessList:
          if tt.payload.access_list.isSome:
            Opt.some(distinctBase(tt.payload.access_list.get).mapIt(
              AccessTuple(
                address: Address(it.address.data),
                storage_keys: distinctBase(it.storage_keys)
                  .mapIt(FixedBytes[32](it.data)))))
          else:
            Opt.none(seq[AccessTuple]),
        maxPriorityFeesPerGas:
          if tt.payload.max_priority_fees_per_gas.isSome:
            Opt.some(engine_api_types.FeesPerGas(
              regular:
                if tt.payload.max_priority_fees_per_gas.get.regular.isSome:
                  Opt.some(
                    tt.payload.max_priority_fees_per_gas.get.regular.get)
                else:
                  Opt.none(UInt256),
              blob:
                if tt.payload.max_priority_fees_per_gas.get.blob.isSome:
                  Opt.some(
                    tt.payload.max_priority_fees_per_gas.get.blob.get)
                else:
                  Opt.none(UInt256)))
          else:
            Opt.none(engine_api_types.FeesPerGas),
        blobVersionedHashes:
          if tt.payload.blob_versioned_hashes.isSome:
            Opt.some(distinctBase(tt.payload.blob_versioned_hashes.get)
              .mapIt(FixedBytes[32](it)))
          else:
            Opt.none(seq[FixedBytes[32]])),
      `from`: engine_api_types.ExecutionSignature(
        address:
          if tt.`from`.address.isSome:
            Opt.some(Address(tt.`from`.address.get.data))
          else:
            Opt.none(Address),
        secp256k1Signature:
          if tt.`from`.secp256k1_signature.isSome:
            Opt.some(FixedBytes[65](tt.`from`.secp256k1_signature.get))
          else:
            Opt.none(FixedBytes[65])))

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
    depositRequests: mapIt(
      executionPayload.deposit_requests, it.getDepositRequest),
    withdrawalRequests: mapIt(
      executionPayload.withdrawal_requests, it.getWithdrawalRequest),
    consolidationRequests: mapIt(
      executionPayload.consolidation_requests, it.getConsolidationRequest))
