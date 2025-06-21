# beacon_chain
# Copyright (c) 2022-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Types specific to Fulu (i.e. known to have changed across hard forks) - see
# `base` for types and guidelines common across forks

# TODO Careful, not nil analysis is broken / incomplete and the semantics will
#      likely change in future versions of the language:
#      https://github.com/nim-lang/RFCs/issues/250
{.experimental: "notnil".}

import
  std/[sequtils, typetraits],
  "."/[phase0, base, electra],
  chronicles,
  json_serialization,
  ssz_serialization/[merkleization, proofs],
  ssz_serialization/types as sszTypes,
  ../digest,
  kzg4844/[kzg, kzg_abi]

from std/strutils import join
from stew/bitops2 import log2trunc
from stew/byteutils import to0xHex
from ./altair import
  EpochParticipationFlags, InactivityScores, SyncAggregate, SyncCommittee,
  TrustedSyncAggregate, SyncnetBits, num_active_participants
from ./bellatrix import BloomLogs, ExecutionAddress, Transaction
from ./capella import
  ExecutionBranch, HistoricalSummary, SignedBLSToExecutionChange,
  SignedBLSToExecutionChangeList, Withdrawal, EXECUTION_PAYLOAD_GINDEX
from ./deneb import Blobs, BlobsBundle, KzgCommitments, KzgProofs
from ./constants import DomainType

export json_serialization, base

const
  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.2/specs/_features/eip7805/beacon-chain.md#domain-types
  DOMAIN_INCLUSION_LIST_COMMITTEE* = DomainType([byte 0x0c, 0x00, 0x00, 0x00])
  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.2/specs/_features/eip7805/beacon-chain.md#preset
  INCLUSION_LIST_COMMITTEE_SIZE* = 16'u64

type
  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.2/specs/_features/eip7805/beacon-chain.md#inclusionlist
  InclusionList* = object
    slot*: Slot
    validator_index*: ValidatorIndex
    inclusion_list_committee_root: Eth2Digest
    transactions: List[Transaction, MAX_TRANSACTIONS_PER_PAYLOAD]

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.2/specs/_features/eip7805/beacon-chain.md#signedinclusionlist
  SignedInclusionList* = object
    message*: InclusionList
    signature*: ValidatorSig
