# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Temporary dumping ground for extra types and helpers that could make it into
# the spec potentially

# TOdO

type
  UpdateFlag* = enum
    skipValidation ##\
    ## The `skipValidation` flag is used to skip over certain checks that are
    ## normally done when an untrusted block arrives from the network. The
    ## primary use case for this flag is when a proposer must propose a new
    ## block - in order to do so, it needs to update the state as if the block
    ## was valid, before it can sign it.
    nextSlot ##\
    ## Perform the operation as if the next slot was being processed - this is
    ## useful when using the state to verify data that will go in the next slot,
    ## for example when proposing
    ## TODO need to be careful here, easy to assume that slot number change is
    ##      enough, vs advancing the state - however, making a full state copy
    ##      is expensive also :/
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

  UpdateFlags* = set[UpdateFlag]
