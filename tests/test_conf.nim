# beacon_chain
# Copyright (c) 2022-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  unittest2,
  chronos,
  ../beacon_chain/conf,
  ../beacon_chain/spec/presets

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

suite "Runtime network configuration":
  test "defaults preserve compiled networking values":
    let (cfg, unknowns) = readRuntimeConfig(
      "PRESET_BASE: " & const_preset & "\n",
      "runtime-config-defaults")

    check:
      unknowns.len == 0
      cfg.MAX_REQUEST_BLOCKS == MAX_REQUEST_BLOCKS
      cfg.EPOCHS_PER_SUBNET_SUBSCRIPTION ==
        EPOCHS_PER_SUBNET_SUBSCRIPTION
      cfg.SUBNETS_PER_NODE == SUBNETS_PER_NODE
      cfg.gossipClockDisparityDuration ==
        MAXIMUM_GOSSIP_CLOCK_DISPARITY

  test "custom networking values":
    let
      base = "PRESET_BASE: " & const_preset & "\n"
      (cfg, unknowns) = readRuntimeConfig(
        base &
        "TERMINAL_BLOCK_HASH: \"ignored legacy value\"\n" &
        "MAX_REQUEST_BLOCKS: 256\n" &
        "EPOCHS_PER_SUBNET_SUBSCRIPTION: 64\n" &
        "MAXIMUM_GOSSIP_CLOCK_DISPARITY: 1000\n" &
        "SUBNETS_PER_NODE: 1\n",
        "runtime-config-custom")

    check:
      unknowns.len == 0
      cfg.TERMINAL_BLOCK_HASH ==
        defaultRuntimeConfig.TERMINAL_BLOCK_HASH
      cfg.MAX_REQUEST_BLOCKS == 256
      cfg.EPOCHS_PER_SUBNET_SUBSCRIPTION == 64
      cfg.SUBNETS_PER_NODE == 1
      cfg.MAXIMUM_GOSSIP_CLOCK_DISPARITY == 1000
      cfg.gossipClockDisparityDuration == milliseconds(1000)

  test "networking guardrails reject invalid values":
    let base = "PRESET_BASE: " & const_preset & "\n"

    let
      (zeroRequestCfg, zeroRequestUnknowns) = readRuntimeConfig(
        base & "MAX_REQUEST_BLOCKS: 0\n",
        "runtime-config-max-request-zero")
      (maxRequestCfg, maxRequestUnknowns) = readRuntimeConfig(
        base &
        "MAX_REQUEST_BLOCKS: " & $(high(uint64)) & "\n",
        "runtime-config-max-request-max")

    check:
      zeroRequestUnknowns.len == 0
      zeroRequestCfg.MAX_REQUEST_BLOCKS == 0
      maxRequestUnknowns.len == 0
      maxRequestCfg.MAX_REQUEST_BLOCKS == high(uint64)

    expect PresetFileError:
      discard readRuntimeConfig(
        base & "EPOCHS_PER_SUBNET_SUBSCRIPTION: 0\n",
        "runtime-config-epochs-zero")

    expect PresetFileError:
      discard readRuntimeConfig(
        base & "SUBNETS_PER_NODE: 0\n",
        "runtime-config-subnets-zero")

    expect PresetFileError:
      discard readRuntimeConfig(
        base &
        "SUBNETS_PER_NODE: " & $(ATTESTATION_SUBNET_COUNT + 1) & "\n",
        "runtime-config-subnets-too-large")

    expect PresetFileError:
      discard readRuntimeConfig(
        base &
        "MAXIMUM_GOSSIP_CLOCK_DISPARITY: " & $(high(uint64)) & "\n",
        "runtime-config-gossip-disparity-too-large")
