# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  unittest2,
  ../beacon_chain/spec/datatypes/base,
  ".."/beacon_chain/fork_choice/[fork_choice_types, fork_choice]

suite "Vote Processing - Slot Tracking":
  test "Gloas: Votes update based on slot":
    var backend = ForkChoiceBackend()
    backend.votes = newSeq[VoteTracker](10)

    var cfg = defaultRuntimeConfig
    cfg.GLOAS_FORK_EPOCH = Epoch(0)

    let
      validator_idx = ValidatorIndex(5)
      block_root1 = Eth2Digest.fromHex("0x4444444444444444444444444444444444444444444444444444444444444444")
    backend.process_attestation(
      validator_idx, block_root1, Epoch(3), Slot(100), false, cfg)

    check:
      backend.votes[5].next_slot == Slot(100)
      backend.votes[5].next_root == block_root1
      backend.votes[5].payload_present == false

    # Try to update with older slot - should NOT update
    let block_root2 = Eth2Digest.fromHex("0x5555555555555555555555555555555555555555555555555555555555555555")
    backend.process_attestation(
      validator_idx, block_root2, Epoch(3), Slot(99), true, cfg)

    check:
      backend.votes[5].next_slot == Slot(100)
      backend.votes[5].next_root == block_root1

    # Update with newer slot - should update
    let block_root3 = Eth2Digest.fromHex("0x6666666666666666666666666666666666666666666666666666666666666666")
    backend.process_attestation(
      validator_idx, block_root3, Epoch(3), Slot(101), true, cfg)

    check:
      backend.votes[5].next_slot == Slot(101)
      backend.votes[5].next_root == block_root3
      backend.votes[5].payload_present == true

  test "Gloas: payload_present flag tracks EMPTY vs FULL preference":
    # When attesting to a block from a previous slot, validators signal
    # whether they prefer building on EMPTY or FULL branch.
    var backend = ForkChoiceBackend()
    backend.votes = newSeq[VoteTracker](10)

    var cfg = defaultRuntimeConfig
    cfg.GLOAS_FORK_EPOCH = Epoch(0)

    let validator_idx = ValidatorIndex(3)

    # Vote preferring EMPTY branch (attestation.data.index = 0)
    backend.process_attestation(
      validator_idx,
      Eth2Digest.fromHex("0x7777777777777777777777777777777777777777777777777777777777777777"),
      Epoch(5), Slot(150), false, cfg)

    check:
      backend.votes[3].payload_present == false

    # Later vote preferring FULL branch (attestation.data.index = 1)
    backend.process_attestation(
      validator_idx,
      Eth2Digest.fromHex("0x8888888888888888888888888888888888888888888888888888888888888888"),
      Epoch(5), Slot(151), true, cfg)

    check:
      backend.votes[3].payload_present == true

  suite "PTC Voting - Payload Timeliness":
    test "is_payload_timely: False when payload not locally available":
      var backend = ForkChoiceBackend()
      let block_root = Eth2Digest.fromHex(
        "0x4444444444444444444444444444444444444444444444444444444444444444")

      backend.ptc_vote[block_root] = newSeq[bool](PTC_SIZE)
      for i in 0..<300:
        backend.ptc_vote[block_root][i] = true

      # Don't mark as locally available
      # (on_execution_payload was not called)
      check:
        not backend.is_payload_timely(block_root)

    test "is_payload_timely: False with exactly 256 votes (boundary)":
      var backend = ForkChoiceBackend()
      let block_root = Eth2Digest.fromHex(
        "0x7777777777777777777777777777777777777777777777777777777777777777")

      # Exactly 256 votes (at threshold, not above)
      backend.ptc_vote[block_root] = newSeq[bool](PTC_SIZE)
      for i in 0..<256:
        backend.ptc_vote[block_root][i] = true

      backend.execution_payload_states[block_root] = Eth2Digest.fromHex(
        "0x8888888888888888888888888888888888888888888888888888888888888888")

      check:
        not backend.is_payload_timely(block_root)

    test "is_payload_timely: True with 257 votes (just above threshold)":
      var backend = ForkChoiceBackend()
      let block_root = Eth2Digest.fromHex(
        "0x9999999999999999999999999999999999999999999999999999999999999999")

      # 257 votes (just above threshold)
      backend.ptc_vote[block_root] = newSeq[bool](PTC_SIZE)
      for i in 0..<257:
        backend.ptc_vote[block_root][i] = true

      backend.execution_payload_states[block_root] = Eth2Digest.fromHex(
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
      check:
        backend.is_payload_timely(block_root)

    test "is_payload_timely: Both conditions must be met":
      var backend = ForkChoiceBackend()

      # Case 1: Votes YES, Local NO → FALSE
      let root1 = Eth2Digest.fromHex(
        "0x1111111111111111111111111111111111111111111111111111111111111111")
      backend.ptc_vote[root1] = newSeq[bool](PTC_SIZE)
      for i in 0..<300:
        backend.ptc_vote[root1][i] = true
      # Don't add to execution_payload_states
      check:
        not backend.is_payload_timely(root1)

      # Case 2: Votes NO, Local YES → FALSE
      let root2 = Eth2Digest.fromHex(
        "0x2222222222222222222222222222222222222222222222222222222222222222")
      backend.ptc_vote[root2] = newSeq[bool](PTC_SIZE)
      for i in 0..<100:
        backend.ptc_vote[root2][i] = true
      backend.execution_payload_states[root2] = Eth2Digest.fromHex(
        "0x3333333333333333333333333333333333333333333333333333333333333333")
      check:
        not backend.is_payload_timely(root2)

      # Case 3: Votes YES, Local YES → TRUE
      let root3 = Eth2Digest.fromHex(
        "0x4444444444444444444444444444444444444444444444444444444444444444")
      backend.ptc_vote[root3] = newSeq[bool](PTC_SIZE)
      for i in 0..<300:
        backend.ptc_vote[root3][i] = true
      backend.execution_payload_states[root3] = Eth2Digest.fromHex(
        "0x5555555555555555555555555555555555555555555555555555555555555555")
      check:
        backend.is_payload_timely(root3)
