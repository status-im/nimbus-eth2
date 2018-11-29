# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Uncategorized helper functions from the spec

import ./datatypes, ./digest, sequtils, math

func shuffle*[T](values: seq[T], seed: Eth2Digest): seq[T] =
  ## Returns the shuffled ``values`` with seed as entropy.
  ## TODO: this calls out for tests, but I odn't particularly trust spec
  ## right now.

  let values_count = values.len

  const
    # Entropy is consumed from the seed in 3-byte (24 bit) chunks.
    rand_bytes = 3
    # The highest possible result of the RNG.
    rand_max = 2^(rand_bytes * 8) - 1

  # The range of the RNG places an upper-bound on the size of the list that
  # may be shuffled. It is a logic error to supply an oversized list.
  assert values_count < rand_max

  result = values
  var
    source = seed
    index = 0
  while index < values_count - 1:
    # Re-hash the `source` to obtain a new pattern of bytes.
    source = eth2hash source.data

    # Iterate through the `source` bytes in 3-byte chunks.
    for pos in countup(0, 29, 3):
      let remaining = values_count - index
      if remaining == 1:
        break

      # Read 3-bytes of `source` as a 24-bit big-endian integer.
      let sample_from_source =
        source.data[pos].Uint24 shl 16 or
        source.data[pos+1].Uint24 shl 8 or
        source.data[pos+2].Uint24

      # Sample values greater than or equal to `sample_max` will cause
      # modulo bias when mapped into the `remaining` range.
      let sample_max = rand_max - rand_max mod remaining

      # Perform a swap if the consumed entropy will not cause modulo bias.
      if sample_from_source < sample_max:
        # Select a replacement index for the current index.
        let replacement_position = sample_from_source mod remaining + index
        swap result[index], result[replacement_position]
        inc index

func split*[T](lst: openArray[T], N: Positive): seq[seq[T]] =
  ## split lst in N pieces, with each piece having `len(lst) div N` or
  ## `len(lst) div N + 1` pieces
  # TODO: implement as an iterator
  result = newSeq[seq[T]](N)
  for i in 0 ..< N:
    result[i] = lst[lst.len * i div N ..< lst.len * (i+1) div N] # TODO: avoid alloc via toOpenArray

func get_new_recent_block_hashes*(old_block_hashes: seq[Eth2Digest],
                                  parent_slot, current_slot: int64,
                                  parent_hash: Eth2Digest
                                  ): seq[Eth2Digest] =

  # Should throw for `current_slot - CYCLE_LENGTH * 2 - 1` according to spec comment
  let d = current_slot - parent_slot
  result = old_block_hashes[d .. ^1]
  for _ in 0 ..< min(d, old_block_hashes.len):
    result.add parent_hash

func ceil_div8*(v: int): int = (v + 7) div 8
