# beacon_chain
# Copyright (c) 2021-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  testutils/fuzzing, faststreams/inputs, serialization/testing/tracing,
  ../../beacon_chain/spec/datatypes/base

export
  ssz, base, fuzzing

template sszFuzzingTest*(T: type) =
  test:
    block:
      let input = unsafeMemoryInput(payload)
      let decoded = try: input.readValue(SSZ, T)
                    except SSZError: break

      if input.len.get > 0:
        # Some unconsumed input remained, this is not a valid test case
        break

      let reEncoded = SSZ.encode(decoded)

      when T isnot SignedBeaconBlock:
        let hash = hash_tree_root(decoded)

      if payload != reEncoded:
        when hasSerializationTracing:
          # Run deserialization again to produce a seriazation trace
          # (this is useful for comparing with the initial deserialization)
          discard SSZ.decode(reEncoded, T)

        echo "Payload with len = ", payload.len
        echo payload
        echo "Re-encoided payload with len = ", reEncoded.len
        echo reEncoded

        when T isnot SignedBeaconBlock:
          echo "HTR: ", hash

        echo repr(decoded)

        doAssert false
