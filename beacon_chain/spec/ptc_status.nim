# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

type
  PTCStatus* = distinct uint64

# PTCStatus represents a single payload status. These values represent the
# possible votes that the Payload Timeliness Committee(PTC) can cast
# in ePBS when attesting for an execution payload.
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.5/specs/_features/eip7732/beacon-chain.md#payload-status
const
  PAYLOAD_ABSENT* = PTCStatus(0)
  PAYLOAD_PRESENT* = PTCStatus(1)
  PAYLOAD_WITHHELD* = PTCStatus(2)
  PAYLOAD_INVALID_STATUS* = PTCStatus(3)