# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

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
    skipBlsValidation ##\
    ## Skip verification of BLS signatures in block processing.
    ## Predominantly intended for use in testing, e.g. to allow extra coverage.
    ## Also useful to avoid unnecessary work when replaying known, good blocks.
    skipStateRootValidation ##\
    ## Skip verification of block state root.
    strictVerification ##\
    ## Strictly assert on unexpected conditions to aid debugging.
    ## Should not be used in production, as additional asserts are reachable.
    slotProcessed ##\
    ## Allow blocks to be applied to states with the same slot number as the
    ## block which is what happens when `process_block` is called separately
    skipLastStateRootCalculation ##\
    ## When process_slots() is being called as part of a state_transition(),
    ## the hash_tree_root() from the block will fill in the state.root so it
    ## should skip calculating that last state root.
    experimental ##\
    ## Whether to enable extra features in development.
    enableTestFeatures ##\
    ## Whether to enable extra features for testing.

  UpdateFlags* = set[UpdateFlag]
