# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Temporary dumping ground for extra types and helpers that could make it into
# the spec potentially
#
# The `skipXXXValidation` flags are used to skip over certain checks that are
# normally done when an untrusted block arrives from the network. The
# primary use case for this flag is when a proposer must propose a new
# block - in order to do so, it needs to update the state as if the block
# was valid, before it can sign it. Also useful for some testing, fuzzing with
# improved coverage, and to avoid unnecessary validation when replaying trusted
# (previously validated) blocks.

type
  UpdateFlag* = enum
    skipMerkleValidation ##\
    ## When processing deposits, skip verifying the Merkle proof trees of each
    ## deposit. This is a holdover from both interop issues with the malformed
    ## proofs and, more currently, nim-beacon-chain's creation of proofs which
    ## are inconsistent with the current specification. Furthermore several of
    ## the mocking interfaces deliberately do not create Merkle proofs. Whilst
    ## this seems less than entirely justifiable, for now enable keeping those
    ## in place while minimizing the tech debt they create. One, in principle,
    ## should be able to remove this flag entirely. It is not intrinsically an
    ## expensive operation to perform.
    skipBlsValidation ##\
    ## Skip verification of BLS signatures in block processing.
    ## Predominantly intended for use in testing, e.g. to allow extra coverage.
    ## Also useful to avoid unnecessary work when replaying known, good blocks.
    skipStateRootValidation ##\
    ## Skip verification of block state root.
    skipBlockParentRootValidation ##\
    ## Skip verification that the block's parent root matches the previous block header.

  UpdateFlags* = set[UpdateFlag]
