# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  unittest2,
  ../beacon_chain/spec/[helpers, eip7594_helpers]

suite "EIP-7594 Sampling Tests":
  test "EIP7594: Extended Sample Count":
    proc testExtendedSampleCount() =
      let samplesPerSlot = 16
      const tests = [
        (0, 16),
        (1, 20),
        (2, 24),
        (3, 27),
        (4, 29),
        (5, 32),
        (6, 35),
        (7, 37),
        (8, 40),
        (9, 42),
        (10, 44),
        (11, 47),
        (12, 49),
        (13, 51),
        (14, 53),
        (15, 55),
        (16, 57),
        (17, 59),
        (18, 61),
        (19, 63),
        (20, 65)
      ]

      for (allowed_failures, extendedSampleCount) in tests:
        check: get_extended_sample_count(samplesPerSlot, allowed_failures) == extendedSampleCount
    testExtendedSampleCount()