# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  unittest2,
  ../beacon_chain/conf

template reject(val: string) =
  expect CatchableError:
    echo Checkpoint.parseCmdArg(val)

suite "Configuration parsing":
  suite "weak-subjectivity-checkpoint":
    test "Correct values":
      let
        c1 = Checkpoint.parseCmdArg("0x3c1e98bf132530c669723f58aa3d395be0d0bfaa653152eecb04605e203bfeb5:31714")
        c2 = Checkpoint.parseCmdArg("3c1e98bf132530c669723f58aa3d395be0d0bfaa653152eecb04605e203bfeb5:31714")
     
      check:
        c1.epoch == 31714
        c1.root == Eth2Digest.fromHex("3c1e98bf132530c669723f58aa3d395be0d0bfaa653152eecb04605e203bfeb5")
        c1 == c2

      #[
      let
        c3 = Checkpoint.parseCmdArg("3c1e98bf132530c669723f58aa3d395be0d0bfaa653152eecb04605e203bfeb5:0")
        c4 = Checkpoint.parseCmdArg("3c1e98bf132530c669723f58aa3d395be0d0bfaa653152eecb04605e203bfeb5:1")

      check:
        c3.epoch == 0
        c4.epoch == 1
      ]#

    test "missing separator":
      reject ""
      reject "3c1e98bf132530c669723f58aa3d395be0d0bfaa653152eecb04605e203bfeb5"
      reject "0x3c1e98bf132530c669723f58aa3d395be0d0bfaa653152eecb04605e203bfeb5"
      reject "3c1e98bf132530c669723f58aa3d395be0d0bfaa653152eecb04605e203bfeb531714"

    test "missing root":
      reject ":31714"

    test "shorter root":
      reject "3c1e98bf132530c669723f58aa3d395be0d0bfaa653152eecb04605e203bfe:31714"
      reject "3c1e98bf132530c669723f58aa3d395be0d0bfaa653152eecb04605e203bfeb:31714"

    test "longer root":
      reject "3c1e98bf132530c669723f58aa3d395be0d0bfaa653152eecb04605e203bfeb50:31714"
      reject "3c1e98bf132530c669723f58aa3d395be0d0bfaa653152eecb04605e203bfeb500:31714"
      
    test "invalid characters in root":
      reject "1x3c1e98bf132530c669723f58aa3d395be0d0bfaa653152eecb04605e203bfeb5:31714"
      reject "3g1e98bf132530c669723f58aa3d395be0d0bfaa653152eecb04605e203bfeb5:31714"

    test "missing epoch":
      reject "3c1e98bf132530c669723f58aa3d395be0d0bfaa653152eecb04605e203bfeb500:"
      
    test "non-number epoch":
      reject "3c1e98bf132530c669723f58aa3d395be0d0bfaa653152eecb04605e203bfeb500:123c"
      reject "3c1e98bf132530c669723f58aa3d395be0d0bfaa653152eecb04605e203bfeb500:а"

    test "negative epoch":
      reject "3c1e98bf132530c669723f58aa3d395be0d0bfaa653152eecb04605e203bfeb500:-1000"
