# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  std/strformat, std/tables, std/options,
  # Status libraries
  stew/result, nimcrypto/[sha2, utils],
  # Internals
  ../../beacon_chain/spec/[datatypes, digest],
  ../../beacon_chain/fork_choice/[fork_choice, fork_choice_types]

export result, datatypes, digest, fork_choice, fork_choice_types, tables, options

func fakeHash*(index: int): Eth2Digest =
  ## Create fake hashes
  sha256.digest(cast[array[sizeof(int), byte]](index))

# The fork choice tests are quite complex.
# For flexibility in block arrival, timers, operations sequencing, ...
# we create a small interpreter that will trigger events in proper order
# before fork choice.

type
  OpKind* = enum
    FindHead
    InvalidFindHead
    ProcessBlock
    ProcessAttestation
    Prune

  Operation* = object
    # variant specific fields
    case kind*: OpKind
    of FindHead, InvalidFindHead:
      justified_epoch*: Epoch
      justified_root*: Eth2Digest
      finalized_epoch*: Epoch
      justified_state_balances*: seq[Gwei]
      expected_head*: Eth2Digest
    of ProcessBlock:
      slot*: Slot
      root*: Eth2Digest
      parent_root*: Eth2Digest
      blk_justified_epoch*: Epoch
      blk_finalized_epoch*: Epoch
    of ProcessAttestation:
      validator_index*: ValidatorIndex
      block_root*: Eth2Digest
      target_epoch*: Epoch
    of Prune: # ProtoArray specific
      finalized_root*: Eth2Digest
      prune_threshold*: int
      expected_len*: int

func apply(ctx: var ForkChoice, id: int, op: Operation) =
  ## Apply the specified operation to a ForkChoice context
  ## ``id`` is additional debugging info. It is the
  ## operation index.

  case op.kind
  of FindHead, InvalidFindHead:
    let r = ctx.find_head(
      op.justified_epoch,
      op.justified_root,
      op.finalized_epoch,
      op.justified_state_balances
    )
    if op.kind == FindHead:
      doAssert r.isOk(), &"find_head (op #{id}) returned an error: {r.error}"
      doAssert r.get() == op.expected_head, &"find_head (op #{id}) returned an incorrect result: {r.get()} (expected: {op.expected_head})"
      debugEcho "    Successfully found head: ", op.expected_head
    else:
      doAssert r.isErr(), "find_head was unexpectedly successful"
      debugEcho "    Successfully detected an invalid head"
  of ProcessBlock:
    let r = ctx.process_block(
      slot = op.slot,
      block_root = op.root,
      parent_root = op.parent_root,
      state_root = default(Eth2Digest),
      justified_epoch = op.blk_justified_epoch,
      finalized_epoch = op.blk_finalized_epoch
    )
    doAssert r.isOk(), &"process_block (op #{id}) returned an error: {r.error}"
    debugEcho "    Processed block 0x", op.root, " with parent 0x", op.parent_root, " and justified epoch ", op.blk_justified_epoch
  of ProcessAttestation:
    let r = ctx.process_attestation(
      validator_index = op.validator_index,
      block_root = op.block_root,
      target_epoch = op.target_epoch
    )
    doAssert r.isOk(), &"process_attestation (op #{id}) returned an error: {r.error}"
    debugEcho "    Processed attestation for validator ", op.validator_index, " targeting ", op.block_root, " at epoch ", op.target_epoch
  of Prune:
    ctx.proto_array.prune_threshold = op.prune_threshold
    let r = ctx.maybe_prune(op.finalized_root)
    doAssert r.isOk(), &"prune (op #{id}) returned an error: {r.error}"
    doAssert ctx.proto_array.nodes.len == op.expected_len,
      &"prune (op #{id}): the resulting length ({ctx.proto_array.nodes.len}) was not expected ({op.expected_len})"
    debugEcho "    Maybe_pruned block preceding finalized block 0x", op.finalized_root

func run*(ctx: var ForkChoice, ops: seq[Operation]) =
  ## Apply a sequence of fork-choice operations on a store
  for i, op in ops:
    ctx.apply(i, op)
