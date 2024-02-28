# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  chronicles,
  ../../beacon_chain/spec/forks,
  ../../beacon_chain/spec/state_transition,
  ../../beacon_chain/validators/rewards,
  ./consensus_spec/os_ops,
  ./testutil

from std/sequtils import toSeq
from std/strutils import toLowerAscii
from ../../beacon_chain/spec/presets import
  const_preset, defaultRuntimeConfig
from ./consensus_spec/fixtures_utils import
  SSZ, SszTestsDir, hash_tree_root, parseTest, readSszBytes, toSszType

proc runTest(consensusFork: static ConsensusFork,
             testDir: static[string], suiteName, path: string) =
  test "Block rewards test -" & preset():
    echo ""
    echo "path = ", path

    when consensusFork == ConsensusFork.Phase0:
      skip()
    else:
      let
        testPath = testDir / path
        preState = newClone(parseTest(testPath / "pre.ssz_snappy",
                     SSZ, consensusFork.BeaconState))
        postState = testPath / "post.ssz_snappy"
        blockPath = testPath / "blocks_0.ssz_snappy"

      if not(fileExists(blockPath)) or not(fileExists(postState)):
        discard
      else:
        var
          fhPreState = ForkedHashedBeaconState.new(preState[])
          cache = StateCache()
          info = ForkedEpochInfo()

        let
          blck = parseTest(testPath/"blocks_0.ssz_snappy",
                           SSZ, consensusFork.SignedBeaconBlock)
          forkedBlock = ForkedBeaconBlock.init(blck.message)
          consensusBlockValue = collectBlockRewards(fhPreState[], forkedBlock)

        let (proposerIndex, preStateBalance, blockValue, stateSlot, blckSlot) =
          withStateAndBlck(fhPreState[], forkedBlock):
            (forkyBlck.proposer_index,
             forkyState.data.balances.item(forkyBlck.proposer_index),
             consensusBlockValue.get(),
             forkyState.data.slot,
             forkyBlck.slot)

        info "Perform state_transition with block",
             blck = shortLog(forkedBlock),
             block_consensus_value = blockValue,
             proposer_index = proposerIndex,
             validator_balance = preStateBalance,
             state_slot = stateSlot,
             expected_balance = preStateBalance + blockValue

        block:
          let res =
            process_slots(defaultRuntimeConfig, fhPreState[],
                          blckSlot, cache, info, flags = {})
          if res.isErr():
            # Ignore failed states.
            info "State advance failed", reason = $res.error
            return

        let advanceBalance =
          withState(fhPreState[]):
            forkyState.data.balances.item(proposerIndex)

        block:
          let res =
            state_transition_block(defaultRuntimeConfig, fhPreState[], blck,
                                   cache, flags = {}, noRollback)
          if res.isErr():
            # Ignore failed states.
            info "State transition failed", reason = $res.error
            return

        let balance =
          withState(fhPreState[]):
            forkyState.data.balances.item(proposerIndex)

        info "State transition succesfull",
             actual_validator_balance = balance,
             snapshot0_balance = preStateBalance,
             snapshot1_balance = advanceBalance,
             calculated_value0 = preStateBalance + blockValue,
             calculated_value1 = advanceBalance + blockValue

template runForkBlockTests(consensusFork: static ConsensusFork) =
  const
    forkHumanName = $consensusFork
    forkDirName = forkHumanName.toLowerAscii()
    FinalityDir =
      SszTestsDir/const_preset/forkDirName/"finality"/"finality"/"pyspec_tests"
    RandomDir =
      SszTestsDir/const_preset/forkDirName/"random"/"random"/"pyspec_tests"
    SanityBlocksDir =
      SszTestsDir/const_preset/forkDirName/"sanity"/"blocks"/"pyspec_tests"

  suite "Consensus block value calculation - " & forkHumanName &
          " - Sanity -" & preset():
    for kind, path in walkDir(SanityBlocksDir, relative = true,
                              checkDir = true):
      consensusFork.runTest(SanityBlocksDir, suiteName, path)

  suite "Consensus block value calculation - " & forkHumanName &
          " - Finality -" & preset():
    for kind, path in walkDir(FinalityDir, relative = true,
                              checkDir = true):
      consensusFork.runTest(FinalityDir, suiteName, path)

  suite "Consensus block value calculation - " & forkHumanName &
          " - Random -" & preset():
    for kind, path in walkDir(RandomDir, relative = true,
                              checkDir = true):
      consensusFork.runTest(RandomDir, suiteName, path)


withAll(ConsensusFork):
  runForkBlockTests(consensusFork)
