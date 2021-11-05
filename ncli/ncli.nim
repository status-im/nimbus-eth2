import
  std/[os, strutils, stats],
  confutils, chronicles, json_serialization,
  stew/byteutils,
  ../research/simutils,
  ../beacon_chain/spec/datatypes/[phase0],
  ../beacon_chain/spec/[
    eth2_ssz_serialization, forks, helpers, state_transition],
  ../beacon_chain/networking/network_metadata

type
  Cmd* = enum
    hashTreeRoot = "Compute hash tree root of SSZ object"
    pretty = "Pretty-print SSZ object"
    transition = "Run state transition function"
    slots = "Apply empty slots"

  NcliConf* = object

    eth2Network* {.
      desc: "The Eth2 network preset to use"
      name: "network" }: Option[string]

    # TODO confutils argument pragma doesn't seem to do much; also, the cases
    # are largely equivalent, but this helps create command line usage text
    case cmd* {.command}: Cmd
    of hashTreeRoot:
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
  case value.kind:
  of BeaconStateFork.Phase0: SSZ.saveFile(filename, value.phase0Data.data)
  of BeaconStateFork.Altair: SSZ.saveFile(filename, value.altairData.data)
  of BeaconStateFork.Merge:  SSZ.saveFile(filename, value.mergeData.data)

proc doTransition(conf: NcliConf) =
  let
    stateY = (ref ForkedHashedBeaconState)(
      phase0Data: phase0.HashedBeaconState(
        data: SSZ.loadFile(conf.preState, phase0.BeaconState)),
      kind: BeaconStateFork.Phase0
    )
    blckX = SSZ.loadFile(conf.blck, phase0.SignedBeaconBlock)
    flags = if not conf.verifyStateRoot: {skipStateRootValidation} else: {}

  setStateRoot(stateY[], hash_tree_root(stateY[].phase0Data.data))

  var
    cache = StateCache()
    info = ForkedEpochInfo()
  if not state_transition(getRuntimeConfig(conf.eth2Network),
                          stateY[], blckX, cache, info, flags, noRollback):
    error "State transition failed"
    quit 1
  else:
    saveSSZFile(conf.postState, stateY[])

proc doSlots(conf: NcliConf) =
  type
    Timers = enum
      tLoadState = "Load state from file"
      tApplySlot = "Apply slot"
      tApplyEpochSlot = "Apply epoch slot"
      tSaveState = "Save state to file"

  var timers: array[Timers, RunningStat]
  let
    stateY = withTimerRet(timers[tLoadState]): (ref ForkedHashedBeaconState)(
      phase0Data: phase0.HashedBeaconState(
        data: SSZ.loadFile(conf.preState2, phase0.BeaconState)),
      kind: BeaconStateFork.Phase0
    )

  setStateRoot(stateY[], hash_tree_root(stateY[].phase0Data.data))

  var
    cache = StateCache()
    info = ForkedEpochInfo()
  for i in 0'u64..<conf.slot:
    let isEpoch = (getStateField(stateY[], slot) + 1).isEpoch
    withTimer(timers[if isEpoch: tApplyEpochSlot else: tApplySlot]):
      doAssert process_slots(
        defaultRuntimeConfig, stateY[], getStateField(stateY[], slot) + 1,
        cache, info, {})

  withTimer(timers[tSaveState]):
    saveSSZFile(conf.postState, stateY[])

  printTimers(false, timers)

proc doSSZ(conf: NcliConf) =
  let (kind, file) =
    case conf.cmd:
    of hashTreeRoot: (conf.htrKind, conf.htrFile)
    of pretty: (conf.prettyKind, conf.prettyFile)
    else:
      raiseAssert "doSSZ() only implements hashTreeRoot and pretty commands"

  template printit(t: untyped) {.dirty.} =
    let v = newClone(
      if cmpIgnoreCase(ext, ".ssz") == 0:
        SSZ.loadFile(file, t)
      elif cmpIgnoreCase(ext, ".json") == 0:
        # JSON.loadFile(file, t)
        echo "TODO needs porting to RestJson"
        quit 1
      else:
        echo "Unknown file type: ", ext
        quit 1
    )

    case conf.cmd:
    of hashTreeRoot:
      when t is phase0.SignedBeaconBlock:
        echo hash_tree_root(v.message).data.toHex()
      else:
        echo hash_tree_root(v[]).data.toHex()
    of pretty:
      echo JSON.encode(v[], pretty = true)
    else:
      raiseAssert "doSSZ() only implements hashTreeRoot and pretty commands"

  let ext = splitFile(file).ext

  case kind
  of "attester_slashing": printit(AttesterSlashing)
  of "attestation": printit(Attestation)
  of "signed_block": printit(phase0.SignedBeaconBlock)
  of "block": printit(phase0.BeaconBlock)
  of "block_body": printit(phase0.BeaconBlockBody)
  of "block_header": printit(BeaconBlockHeader)
  of "deposit": printit(Deposit)
  of "deposit_data": printit(DepositData)
  of "eth1_data": printit(Eth1Data)
  of "state": printit(phase0.BeaconState)
  of "proposer_slashing": printit(ProposerSlashing)
  of "voluntary_exit": printit(VoluntaryExit)

when isMainModule:
  let conf = NcliConf.load()

  case conf.cmd:
  of hashTreeRoot: doSSZ(conf)
  of pretty: doSSZ(conf)
  of transition: doTransition(conf)
  of slots: doSlots(conf)
