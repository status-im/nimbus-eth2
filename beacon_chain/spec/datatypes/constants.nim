# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import chronos/timer

type
  Slot* = distinct uint64
  Epoch* = distinct uint64
  SyncCommitteePeriod* = distinct uint64

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/beacon-chain.md#custom-types
  WithdrawalIndex* = uint64

  DomainType* = distinct array[4, byte]

const
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/p2p-interface.md#constants
  NODE_ID_BITS* = 256

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/p2p-interface.md#configuration
  EPOCHS_PER_SUBNET_SUBSCRIPTION* = 256'u64
  SUBNETS_PER_NODE* = 2'u64
  ATTESTATION_SUBNET_COUNT*: uint64 = 64
  ATTESTATION_SUBNET_EXTRA_BITS* = 0'u64
  ATTESTATION_SUBNET_PREFIX_BITS* = 6'u64 ## \
    ## int(ceillog2(ATTESTATION_SUBNET_COUNT) + ATTESTATION_SUBNET_EXTRA_BITS)

static: doAssert 1 shl (ATTESTATION_SUBNET_PREFIX_BITS - ATTESTATION_SUBNET_EXTRA_BITS) ==
  ATTESTATION_SUBNET_COUNT

const
  # 2^64 - 1 in spec
  FAR_FUTURE_SLOT* = Slot(not 0'u64)
  FAR_FUTURE_EPOCH* = Epoch(not 0'u64)
  FAR_FUTURE_PERIOD* = SyncCommitteePeriod(not 0'u64)

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#domain-types
  DOMAIN_BEACON_PROPOSER* = DomainType([byte 0x00, 0x00, 0x00, 0x00])
  DOMAIN_BEACON_ATTESTER* = DomainType([byte 0x01, 0x00, 0x00, 0x00])
  DOMAIN_RANDAO* = DomainType([byte 0x02, 0x00, 0x00, 0x00])
  DOMAIN_DEPOSIT* = DomainType([byte 0x03, 0x00, 0x00, 0x00])
  DOMAIN_VOLUNTARY_EXIT* = DomainType([byte 0x04, 0x00, 0x00, 0x00])
  DOMAIN_SELECTION_PROOF* = DomainType([byte 0x05, 0x00, 0x00, 0x00])
  DOMAIN_AGGREGATE_AND_PROOF* = DomainType([byte 0x06, 0x00, 0x00, 0x00])
  DOMAIN_APPLICATION_MASK* = DomainType([byte 0x00, 0x00, 0x00, 0x01])

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/beacon-chain.md#domain-types
  DOMAIN_SYNC_COMMITTEE* = DomainType([byte 0x07, 0x00, 0x00, 0x00])
  DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF* = DomainType([byte 0x08, 0x00, 0x00, 0x00])
  DOMAIN_CONTRIBUTION_AND_PROOF* = DomainType([byte 0x09, 0x00, 0x00, 0x00])

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/beacon-chain.md#domain-types
  DOMAIN_BLS_TO_EXECUTION_CHANGE* = DomainType([byte 0x0a, 0x00, 0x00, 0x00])

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/fork-choice.md#configuration
  PROPOSER_SCORE_BOOST*: uint64 = 40
  REORG_HEAD_WEIGHT_THRESHOLD*: uint64 = 20
  REORG_PARENT_WEIGHT_THRESHOLD*: uint64 = 160
  REORG_MAX_EPOCHS_SINCE_FINALIZATION* = Epoch(2)

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/p2p-interface.md#configuration
  BLOB_SIDECAR_SUBNET_COUNT*: uint64 = 6

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.1/specs/phase0/p2p-interface.md#configuration
  MAX_REQUEST_BLOCKS* = 1024'u64
  RESP_TIMEOUT* = 10'u64
  ATTESTATION_PROPAGATION_SLOT_RANGE*: uint64 = 32
  MAXIMUM_GOSSIP_CLOCK_DISPARITY* = 500.millis

  # https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/bellatrix/p2p-interface.md#configuration
  GOSSIP_MAX_SIZE* = 10'u64 * 1024 * 1024 # bytes
  MAX_CHUNK_SIZE* = 10'u64 * 1024 * 1024 # bytes

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.4/specs/deneb/p2p-interface.md#configuration
  MAX_REQUEST_BLOCKS_DENEB*: uint64 = 128 # TODO Make use of in request code
