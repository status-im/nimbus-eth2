# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  "."/[helpers, forks],
  "."/datatypes/base,
  std/typetraits

type

  # https://github.com/ethereum/consensus-specs/blob/1508f51b80df5488a515bfedf486f98435200e02/specs/_features/eipxxxx/beacon-chain.md#payloadattestationdata
  PayloadAttestationData* = object
    beaconBlockRoot*: Eth2Digest
    slot*: Slot
    payload_Status*: uint8

  # https://github.com/ethereum/consensus-specs/blob/1508f51b80df5488a515bfedf486f98435200e02/specs/_features/eipxxxx/beacon-chain.md#payloadattestation
  PayloadAttestation* = object
    aggregation_bits*: ElectraCommitteeValidatorsBits
    data*: PayloadAttestationData
    signature*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/1508f51b80df5488a515bfedf486f98435200e02/specs/_features/eipxxxx/beacon-chain.md#payloadattestationmessage
  PayloadAttestationMessage* = object
    validatorIndex: ValidatorIndex
    data: PayloadAttestationData
    signature: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/1508f51b80df5488a515bfedf486f98435200e02/specs/_features/eipxxxx/beacon-chain.md#indexedpayloadattestation
  IndexedPayloadAttestation* = object
    attestingIndices: List[ValidatorIndex, Limit PTC_SIZE]
    data: PayloadAttestationData
    signature: ValidatorSig


