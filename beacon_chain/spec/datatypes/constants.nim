# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

type
  Slot* = distinct uint64
  Epoch* = distinct uint64
  SyncCommitteePeriod* = distinct uint64

  # https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.5/specs/capella/beacon-chain.md#custom-types
  WithdrawalIndex* = uint64

  DomainType* = distinct array[4, byte]

const
  # 2^64 - 1 in spec
  FAR_FUTURE_SLOT* = Slot(not 0'u64)
  FAR_FUTURE_EPOCH* = Epoch(not 0'u64)
  FAR_FUTURE_PERIOD* = SyncCommitteePeriod(not 0'u64)

  # https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.5/specs/phase0/beacon-chain.md#domain-types
  DOMAIN_BEACON_PROPOSER* = DomainType([byte 0x00, 0x00, 0x00, 0x00])
  DOMAIN_BEACON_ATTESTER* = DomainType([byte 0x01, 0x00, 0x00, 0x00])
  DOMAIN_RANDAO* = DomainType([byte 0x02, 0x00, 0x00, 0x00])
  DOMAIN_DEPOSIT* = DomainType([byte 0x03, 0x00, 0x00, 0x00])
  DOMAIN_VOLUNTARY_EXIT* = DomainType([byte 0x04, 0x00, 0x00, 0x00])
  DOMAIN_SELECTION_PROOF* = DomainType([byte 0x05, 0x00, 0x00, 0x00])
  DOMAIN_AGGREGATE_AND_PROOF* = DomainType([byte 0x06, 0x00, 0x00, 0x00])
  DOMAIN_APPLICATION_MASK* = DomainType([byte 0x00, 0x00, 0x00, 0x01])

  # https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.3/specs/altair/beacon-chain.md#domain-types
  DOMAIN_SYNC_COMMITTEE* = DomainType([byte 0x07, 0x00, 0x00, 0x00])
  DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF* = DomainType([byte 0x08, 0x00, 0x00, 0x00])
  DOMAIN_CONTRIBUTION_AND_PROOF* = DomainType([byte 0x09, 0x00, 0x00, 0x00])

  # https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.2/specs/capella/beacon-chain.md#domain-types
  DOMAIN_BLS_TO_EXECUTION_CHANGE* = DomainType([byte 0x0a, 0x00, 0x00, 0x00])

  # https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.5/specs/bellatrix/beacon-chain.md#transition-settings
  TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH* = FAR_FUTURE_EPOCH

  # https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.5/specs/phase0/fork-choice.md#configuration
  PROPOSER_SCORE_BOOST*: uint64 = 40

  # https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.5/specs/phase0/validator.md#misc
  ATTESTATION_SUBNET_COUNT*: uint64 = 64
