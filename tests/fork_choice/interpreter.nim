# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  std/[options, strformat, tables],
  # Status libraries
  stew/[results, endians2],
  # Internals
  ../../beacon_chain/spec/datatypes/base,
  ../../beacon_chain/spec/helpers,
  ../../beacon_chain/fork_choice/[fork_choice, fork_choice_types]

export results, base, helpers, fork_choice, fork_choice_types, tables, options

func fakeHash*(index: SomeInteger): Eth2Digest =
  ## Create fake hashes
  ## Those are just the value serialized in big-endian
  ## We add 16x16 to avoid having a zero hash as those are special cased
  ## We store them in the first 8 bytes
  ## as those are the ones used in hash tables Table[Eth2Digest, T]
  result.data[0 ..< 8] = (16*16+index).uint64.toBytesBE()

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
      checkpoints*: FinalityCheckpoints
      justified_state_balances*: seq[Gwei]
      expected_head*: Eth2Digest
    of ProcessBlock:
      bid*: BlockId
      parent_root*: Eth2Digest
      blk_checkpoints*: FinalityCheckpoints
    of ProcessAttestation:
      validator_index*: ValidatorIndex
      block_root*: Eth2Digest
      target_epoch*: Epoch
    of Prune: # ProtoArray specific
      prune_checkpoints*: FinalityCheckpoints
      expected_len*: int

func apply(ctx: var ForkChoiceBackend, id: int, op: Operation) =
  ## Apply the specified operation to a ForkChoice context
  ## ``id`` is additional debugging info. It is the
  ## operation index.
  # debugEcho "    ========================================================================================="
  case op.kind
  of FindHead, InvalidFindHead:
    let r = ctx.find_head(
      GENESIS_EPOCH,
      op.checkpoints,
      op.justified_state_balances,
      # Don't use proposer boosting
      ZERO_HASH)
    if op.kind == FindHead:
      doAssert r.isOk(), &"find_head (op #{id}) returned an error: {r.error}"
      doAssert r.get() == op.expected_head, &"find_head (op #{id}) returned an incorrect result: {r.get()} (expected: {op.expected_head}, from justified checkpoint: {op.checkpoints.justified}, finalized checkpoint: {op.checkpoints.finalized})"
      debugEcho &"    Found expected head: 0x{op.expected_head} from justified checkpoint {op.checkpoints.justified}, finalized checkpoint {op.checkpoints.justified}"
    else:
      doAssert r.isErr(), &"invalid_find_head (op #{id}) was unexpectedly successful, head {op.expected_head} from justified checkpoint {op.checkpoints.justified}, finalized checkpoint {op.checkpoints.finalized}"
      debugEcho &"    Detected an expected invalid head from justified checkpoint {op.checkpoints.justified}, finalized checkpoint {op.checkpoints.finalized}"
  of ProcessBlock:
    let r = ctx.process_block(
      bid = op.bid,
      parent_root = op.parent_root,
      checkpoints = op.blk_checkpoints)
    doAssert r.isOk(), &"process_block (op #{id}) returned an error: {r.error}"
    debugEcho "    Processed block      0x", op.bid.root, " with parent 0x", op.parent_root, " and justified checkpoint ", op.blk_checkpoints.justified
  of ProcessAttestation:
    ctx.process_attestation(
      validator_index = op.validator_index,
      block_root = op.block_root,
      target_epoch = op.target_epoch)
    debugEcho "    Processed att target 0x", op.block_root, " from validator ", op.validator_index, " for epoch ", op.target_epoch
  of Prune:
    let r = ctx.prune(op.prune_checkpoints)
    doAssert r.isOk(), &"prune (op #{id}) returned an error: {r.error}"
    doAssert ctx.proto_array.nodes.len == op.expected_len,
      &"prune (op #{id}): the resulting length ({ctx.proto_array.nodes.len}) was not expected ({op.expected_len})"
    debugEcho "    Maybe_pruned block preceding finalized block 0x", op.prune_checkpoints.finalized.root

func run*(ctx: var ForkChoiceBackend, ops: seq[Operation]) =
  ## Apply a sequence of fork-choice operations on a store
  for i, op in ops:
    ctx.apply(i, op)
