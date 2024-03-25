# beacon_chain
# Copyright (c) 2020-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  confutils, json_serialization,
  snappy,
  ../beacon_chain/spec/eth2_apis/eth2_rest_serialization,
  ../beacon_chain/spec/[eth2_ssz_serialization, state_transition]

from std/os import splitFile
from std/stats import RunningStat
from std/strutils import cmpIgnoreCase
from stew/byteutils import toHex
from stew/io2 import readAllBytes
from ../beacon_chain/networking/network_metadata import getRuntimeConfig
from ../research/simutils import printTimers, withTimer, withTimerRet

type
  Cmd* = enum
    hash_tree_root = "Compute hash tree root of SSZ object"
    pretty = "Pretty-print SSZ object"
    transition = "Run state transition function"
    slots = "Apply empty slots"

  NcliConf* = object
    eth2Network* {.
      desc: "The Eth2 network preset to use"
      name: "network" }: Option[string]

    printTimes* {.
      defaultValue: false # false to avoid polluting minimal output
      name: "print-times"
      desc: "Print timing information".}: bool

    # TODO confutils argument pragma doesn't seem to do much; also, the cases
    # are largely equivalent, but this helps create command line usage text
    case cmd* {.command}: Cmd
    of hash_tree_root:
      htrKind* {.
        argument
        desc: "kind of SSZ object: attester_slashing, attestation, signed_block, block, block_body, block_header, deposit, deposit_data, eth1_data, state, proposer_slashing, or voluntary_exit"}: string

      htrFile* {.
        argument
        desc: "filename of SSZ or JSON-encoded object of which to compute hash tree root"}: string

    of pretty:
      prettyKind* {.
        argument
        desc: "kind of SSZ object: attester_slashing, attestation, signed_block, block, block_body, block_header, deposit, deposit_data, eth1_data, state, proposer_slashing, or voluntary_exit"}: string

      prettyFile* {.
        argument
        desc: "filename of SSZ or JSON-encoded object to pretty-print"}: string

    of transition:
      preState* {.
        argument
        desc: "State to which to apply specified block"}: string

      blck* {.
        argument
        desc: "Block to apply to preState"}: string

      postState* {.
        argument
        desc: "Filename of state resulting from applying blck to preState"}: string

      verifyStateRoot* {.
        argument
        desc: "Verify state root (default true)"
        defaultValue: true}: bool

    of slots:
      preState2* {.
        argument
        desc: "State to which to apply specified block"}: string

      slot* {.
        argument
        desc: "Block to apply to preState"}: uint64

      postState2* {.
        argument
        desc: "Filename of state resulting from applying blck to preState"}: string

template saveSSZFile(filename: string, value: ForkedHashedBeaconState) =
  try:
    case value.kind:
    of ConsensusFork.Phase0:    SSZ.saveFile(filename, value.phase0Data.data)
    of ConsensusFork.Altair:    SSZ.saveFile(filename, value.altairData.data)
    of ConsensusFork.Bellatrix: SSZ.saveFile(filename, value.bellatrixData.data)
    of ConsensusFork.Capella:   SSZ.saveFile(filename, value.capellaData.data)
    of ConsensusFork.Deneb:     SSZ.saveFile(filename, value.denebData.data)
  except IOError:
    raiseAssert "error saving SSZ file"

proc loadFile(filename: string, bytes: openArray[byte], T: type): T =
  let
    ext = splitFile(filename).ext

  try:
    if cmpIgnoreCase(ext, ".ssz") == 0:
      SSZ.decode(bytes, T)
    elif cmpIgnoreCase(ext, ".ssz_snappy") == 0:
      SSZ.decode(snappy.decode(bytes), T)
    elif cmpIgnoreCase(ext, ".json") == 0:
      # JSON.loadFile(file, t)
      echo "TODO needs porting to RestJson"
      quit 1
    else:
      echo "Unknown file type: ", ext
      quit 1
  except CatchableError:
    echo "failed to load SSZ file"
    quit 1

proc doTransition(conf: NcliConf) =
  type
    Timers = enum
      tLoadState = "Load state from file"
      tTransition = "Apply slot"
      tSaveState = "Save state to file"
  var timers: array[Timers, RunningStat]

  let
    cfg = getRuntimeConfig(conf.eth2Network)
    stateY = withTimerRet(timers[tLoadState]):
      try:
        newClone(readSszForkedHashedBeaconState(
          cfg, readAllBytes(conf.preState).tryGet()))
      except CatchableError:
        raiseAssert "error reading hashed beacon state"
    blckX =
      try:
        readSszForkedSignedBeaconBlock(
          cfg, readAllBytes(conf.blck).tryGet())
      except CatchableError:
        raiseAssert "error reading signed beacon block"
    flags = if not conf.verifyStateRoot: {skipStateRootValidation} else: {}

  var
    cache = StateCache()
    info = ForkedEpochInfo()
  let res = withTimerRet(timers[tTransition]): withBlck(blckX):
    state_transition(
      cfg, stateY[], forkyBlck, cache, info, flags, noRollback)
  if res.isErr():
    error "State transition failed", error = res.error()
    quit 1
  else:
    withTimer(timers[tSaveState]):
      saveSSZFile(conf.postState, stateY[])

  if conf.printTimes:
    printTimers(false, timers)

proc doSlots(conf: NcliConf) =
  type
    Timers = enum
      tLoadState = "Load state from file"
      tApplySlot = "Apply slot"
      tApplyEpochSlot = "Apply epoch slot"
      tSaveState = "Save state to file"

  var timers: array[Timers, RunningStat]
  let
    cfg = getRuntimeConfig(conf.eth2Network)
    stateY = withTimerRet(timers[tLoadState]):
      try:
        newClone(readSszForkedHashedBeaconState(
          cfg, readAllBytes(conf.preState2).tryGet()))
      except CatchableError:
        raiseAssert "error reading hashed beacon state"
  var
    cache = StateCache()
    info = ForkedEpochInfo()
  for i in 0'u64..<conf.slot:
    let isEpoch = (getStateField(stateY[], slot) + 1).is_epoch
    withTimer(timers[if isEpoch: tApplyEpochSlot else: tApplySlot]):
      process_slots(
        cfg, stateY[], getStateField(stateY[], slot) + 1,
        cache, info, {}).expect("should be able to advance slot")

  withTimer(timers[tSaveState]):
    saveSSZFile(conf.postState2, stateY[])

  if conf.printTimes:
    printTimers(false, timers)

proc doSSZ(conf: NcliConf) =
  type Timers = enum
    tLoad = "Load file"
    tCompute = "Compute"
  var timers: array[Timers, RunningStat]

  let (kind, file) =
    case conf.cmd:
    of hash_tree_root: (conf.htrKind, conf.htrFile)
    of pretty: (conf.prettyKind, conf.prettyFile)
    else:
      raiseAssert "doSSZ() only implements hashTreeRoot and pretty commands"
  let bytes = readAllBytes(file).expect("file exists")

  template printit(t: untyped) {.dirty.} =

    let v = withTimerRet(timers[tLoad]):
      newClone(loadFile(file, bytes, t))

    case conf.cmd:
    of hash_tree_root:
      let root = withTimerRet(timers[tCompute]):
        when t is ForkySignedBeaconBlock:
          hash_tree_root(v[].message)
        else:
          hash_tree_root(v[])

      echo root.data.toHex()
    of pretty:
      echo RestJson.encode(v[], pretty = true)
    else:
      raiseAssert "doSSZ() only implements hashTreeRoot and pretty commands"

    if conf.printTimes:
      printTimers(false, timers)

  case kind
  of "attester_slashing": printit(AttesterSlashing)
  of "attestation": printit(Attestation)
  of "phase0_signed_block": printit(phase0.SignedBeaconBlock)
  of "altair_signed_block": printit(altair.SignedBeaconBlock)
  of "bellatrix_signed_block": printit(bellatrix.SignedBeaconBlock)
  of "capella_signed_block": printit(capella.SignedBeaconBlock)
  of "deneb_signed_block": printit(deneb.SignedBeaconBlock)
  of "phase0_block": printit(phase0.BeaconBlock)
  of "altair_block": printit(altair.BeaconBlock)
  of "bellatrix_block": printit(bellatrix.BeaconBlock)
  of "capella_block": printit(capella.BeaconBlock)
  of "deneb_block": printit(deneb.BeaconBlock)
  of "phase0_block_body": printit(phase0.BeaconBlockBody)
  of "altair_block_body": printit(altair.BeaconBlockBody)
  of "bellatrix_block_body": printit(bellatrix.BeaconBlockBody)
  of "capella_block_body": printit(capella.BeaconBlockBody)
  of "deneb_block_body": printit(deneb.BeaconBlockBody)
  of "block_header": printit(BeaconBlockHeader)
  of "deposit": printit(Deposit)
  of "deposit_data": printit(DepositData)
  of "eth1_data": printit(Eth1Data)
  of "phase0_state": printit(phase0.BeaconState)
  of "altair_state": printit(altair.BeaconState)
  of "bellatrix_state": printit(bellatrix.BeaconState)
  of "capella_state": printit(capella.BeaconState)
  of "deneb_state": printit(deneb.BeaconState)
  of "proposer_slashing": printit(ProposerSlashing)
  of "voluntary_exit": printit(VoluntaryExit)

when isMainModule:
  let
    conf = NcliConf.load()

  case conf.cmd:
  of hash_tree_root: doSSZ(conf)
  of pretty: doSSZ(conf)
  of transition: doTransition(conf)
  of slots: doSlots(conf)
