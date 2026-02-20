# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

## Types and constants for EIP-8025: Execution Payloads with Multiple Execution Proofs

import ssz_serialization, ../crypto, ../digest

from eth/common/hashes import VersionedHash

from ./constants import DomainType
from ./base import AttnetBits, ValidatorIndex
from ./altair import SyncnetBits
from ./deneb import ExecutionPayloadHeader, ExecutionPayload
from ./electra import ExecutionRequests

export crypto, ssz_serialization

const
  # https://github.com/ethereum/consensus-specs/blob/2938e1ad74cea54f1a24508a85704d5bd87837ad/specs/_features/eip8025/beacon-chain.md#constants
  MAX_PROOF_SIZE = 307_200
  DOMAIN_EXECUTION_PROOF* = DomainType([byte 0x0D, 0x00, 0x00, 0x00])

type
  # https://github.com/ethereum/consensus-specs/blob/2938e1ad74cea54f1a24508a85704d5bd87837ad/specs/_features/eip8025/beacon-chain.md#types
  ProofType* = uint8

  # https://github.com/ethereum/consensus-specs/blob/2938e1ad74cea54f1a24508a85704d5bd87837ad/specs/_features/eip8025/beacon-chain.md#containers
  PublicInput* = object
    new_payload_request_root*: Eth2Digest

  ExecutionProof* = object
    proof_data*: ByteList[MAX_PROOF_SIZE]
    proof_type*: ProofType
    public_input*: PublicInput

  SignedExecutionProof* = object
    message*: ExecutionProof
    validator_index*: uint64
      # ValidatorIndex is uint32 and not used in serialization. TODO create new distinct type here
    signature*: ValidatorSig

  # debugEIP8025Comment("not an SSZ type, this if for el manager, move it somewhere else?")
  # https://github.com/ethereum/consensus-specs/blob/2938e1ad74cea54f1a24508a85704d5bd87837ad/specs/_features/eip8025/beacon-chain.md#new-newpayloadrequestheader
  NewPayloadRequestHeader* = object
    execution_payload_header*: ExecutionPayloadHeader
      # should this be ExecutionPayloadV3? No, these should get transformed later for Engine API
    versioned_hashes*: seq[VersionedHash]
    parent_beacon_block_root*: Eth2Digest
    execution_requests*: ExecutionRequests
      # should this be just seq[seq[byte]]. Not SSZ types..No, these should get transformed later for Engine API

  # debugEIP8025Comment("Not a new type, we just didn't introduce it before at el manager")
  NewPayloadRequest* = object
    execution_payload: ExecutionPayload
      # should this be ExecutionPayloadV3? No, these should get transformed later for Engine API
    versioned_hashes: seq[VersionedHash]
    parent_beacon_block_root: Eth2Digest
    execution_requests: ExecutionRequests
      # should this be just seq[seq[byte]]. Not SSZ types.. No, these should get transformed later for Engine API

  # EIP8025 p2p-interface part
  # https://github.com/ethereum/consensus-specs/blob/2938e1ad74cea54f1a24508a85704d5bd87837ad/specs/_features/eip8025/p2p-interface.md#metadata
  MetaData* = object
    seq_number*: uint64
    attnets*: AttnetBits
    syncnets*: SyncnetBits
    custody_group_count*: uint64
    execution_proof_aware*: bool

  # callback type for execution proofs verification
  VerifyPayload* =
    proc(execution_payload: NewPayloadRequestHeader): bool {.gcsafe, raises: [].}
