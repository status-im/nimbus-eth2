# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  confutils/defs

# Nimbus Bench - Scenario configuration
# --------------------------------------------------

type
  StartupCommand* = enum
    noCommand
    cmdFullStateTransition
    cmdSlotProcessing
    cmdBlockProcessing
    cmdEpochProcessing

  BlockProcessingCat* = enum
    catBlockHeader
    catRANDAO
    catEth1Data
    catProposerSlashings
    catAttesterSlashings
    catAttestations
    catDeposits
    catVoluntaryExits

  ScenarioConf* = object
    scenarioDir* {.
      desc: "The directory of your benchmark scenario"
      name: "scenario-dir"
      abbr: "d"
      required .}: InputDir
    preState* {.
      desc: "The name of your pre-state (without .ssz)"
      name: "pre"
      abbr: "p"
      defaultValue: "pre".}: string
    blocksPrefix* {.
      desc: "The prefix of your blocks file, for exemple \"blocks_\" for blocks in the form \"blocks_XX.ssz\""
      name: "blocks-prefix"
      abbr: "b"
      defaultValue: "blocks_".}: string
    blocksQty* {.
      desc: "The number of blocks to process for this transition. Blocks should start at 0."
      name: "block-quantity"
      abbr: "q"
      defaultValue: 1.}: int
    skipBLS*{.
      desc: "Skip BLS public keys and signature verification"
      name: "skip-bls"
      defaultValue: true.}: bool
    case cmd*{.
      command
      defaultValue: noCommand }: StartupCommand
    of noCommand:
      discard
    of cmdFullStateTransition:
      discard
    of cmdSlotProcessing:
      numSlots* {.
        desc: "The number of slots the pre-state will be advanced by"
        name: "num-slots"
        abbr: "s"
        defaultValue: 1.}: uint64
    of cmdBlockProcessing:
      case blockProcessingCat* {.
        desc: "block transitions"
        name: "process-blocks"
        implicitlySelectable
        required .}: BlockProcessingCat
      of catBlockHeader:
        discard
      of catRANDAO:
        discard
      of catEth1Data:
        discard
      of catProposerSlashings:
        discard
      of catAttesterSlashings:
        discard
      of catAttestations:
        discard
      of catDeposits:
        discard
      of catVoluntaryExits:
        discard
    of cmdEpochProcessing:
      discard
