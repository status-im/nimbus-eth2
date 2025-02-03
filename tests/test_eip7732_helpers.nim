# beacon_chain
# Copyright (c) 2022-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  std/[sequtils, sets, random],
  unittest2,
  stew/bitseqs,
  ../beacon_chain/spec/[forks, signatures, state_transition, validator,
    beaconstate, eth2_merkleization],
  ../beacon_chain/spec/[helpers, eip7732_helpers],
  ../beacon_chain/spec/datatypes/fulu,
    # Test utilities
  ./testutil, ./testdbutil, ./testblockutil, ./consensus_spec/fixtures_utils

suite "EIP-7732 Unit Tests":

  test "bit_floor calculations":
    check:
      bit_floor(0'u64) == 0'u64
      bit_floor(1'u64) == 1'u64
      bit_floor(2'u64) == 2'u64
      bit_floor(3'u64) == 2'u64
      bit_floor(4'u64) == 4'u64
      bit_floor(5'u64) == 4'u64
      bit_floor(6'u64) == 4'u64
      bit_floor(7'u64) == 4'u64
      bit_floor(9'u64) == 8'u64

  test "remove_flag operations":
    let flags = ParticipationFlags(0b111)
    check:
      remove_flag(flags, TimelyFlag(0)) == ParticipationFlags(0b110)
      remove_flag(flags, TimelyFlag(1)) == ParticipationFlags(0b101)
      remove_flag(flags, TimelyFlag(2)) == ParticipationFlags(0b011)
