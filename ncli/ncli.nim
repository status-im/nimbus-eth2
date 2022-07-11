import
  std/[os, strutils, stats],
  confutils, chronicles, json_serialization,
  stew/[byteutils, io2],
  snappy,
  ../research/simutils,
  ../beacon_chain/spec/eth2_apis/eth2_rest_serialization,
  ../beacon_chain/spec/datatypes/[phase0, altair, bellatrix],
  ../beacon_chain/spec/[
    eth2_ssz_serialization, forks, helpers, state_transition, signatures],
  ../beacon_chain/networking/network_metadata,
  ../beacon_chain/conf/eth2_types_confutils_defs,
  ../beacon_chain/eth1/deposit_contract_abi

type
  Cmd* = enum
    hashTreeRoot = "Compute hash tree root of SSZ object"
    pretty = "Pretty-print SSZ object"
    transition = "Run state transition function"
    slots = "Apply empty slots"
    verifyDeposit = "Verify deposit"

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
        desc: "kind of SSZ object: attester_slashing, attestation, signed_block, block, block_body, block_header, deposit, deposit_data, eth1_data, state, proposer_slashing, or voluntary_exit" .}: string

      htrFile* {.
        argument
        desc: "filename of SSZ or JSON-encoded object of which to compute hash tree root" .}: string

    of pretty:
      prettyKind* {.
        argument
        desc: "kind of SSZ object: attester_slashing, attestation, signed_block, block, block_body, block_header, deposit, deposit_data, eth1_data, state, proposer_slashing, or voluntary_exit" .}: string

      prettyFile* {.
        argument
        desc: "filename of SSZ or JSON-encoded object to pretty-print" .}: string

    of transition:
      preState* {.
        argument
        desc: "State to which to apply specified block" .}: string

      blck* {.
        argument
        desc: "Block to apply to preState" .}: string

      postState* {.
        argument
        desc: "Filename of state resulting from applying blck to preState"}: string

      verifyStateRoot* {.
        argument
        desc: "Verify state root (default true)"
        defaultValue: true .}: bool

    of slots:
      preState2* {.
        argument
        desc: "State to which to apply specified block" .}: string

      slot* {.
        argument
        desc: "Block to apply to preState" .}: uint64

      postState2* {.
        argument
        desc: "Filename of state resulting from applying blck to preState" .}: string

    of verifyDeposit:
      pubkey* {.
        desc: "The validator's public BLS signing key" .}: Option[ValidatorPubKey]

      withdrawalCredentials* {.
        desc: "The validator's withdrawal credentials (The prefixed 32 bytes form mandated by the spec)"
        name: "withdrawal-credentials" .}: Option[Eth2Digest]

      amount* {.
        defaultValue: 32000000000
        desc: "The deposit amount in gwei" .}: Gwei

      signature* {.
        desc: "The deposit signature" .}: Option[ValidatorSig]

      depositData* {.
        argument
        desc: "Deposit event data from the official deposit contract in ABI form (hex-encoded)" .}: Option[string]

template saveSSZFile(filename: string, value: ForkedHashedBeaconState) =
  case value.kind:
  of BeaconStateFork.Phase0:    SSZ.saveFile(filename, value.phase0Data.data)
  of BeaconStateFork.Altair:    SSZ.saveFile(filename, value.altairData.data)
  of BeaconStateFork.Bellatrix: SSZ.saveFile(filename, value.bellatrixData.data)

proc loadFile(filename: string, T: type): T =
  let
    ext = splitFile(filename).ext
    bytes = readAllBytes(filename).expect("file exists")
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

proc doTransition(conf: NcliConf) =
  let
    cfg = getRuntimeConfig(conf.eth2Network)
    stateY = newClone(readSszForkedHashedBeaconState(
      cfg, readAllBytes(conf.preState).tryGet()))
    blckX = readSszForkedSignedBeaconBlock(
      cfg, readAllBytes(conf.blck).tryGet())
    flags = if not conf.verifyStateRoot: {skipStateRootValidation} else: {}

  var
    cache = StateCache()
    info = ForkedEpochInfo()
  let res = withBlck(blckX):
    state_transition(
      cfg, stateY[], blck, cache, info, flags, noRollback)
  if res.isErr():
    error "State transition failed", error = res.error()
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
    cfg = getRuntimeConfig(conf.eth2Network)
    stateY = withTimerRet(timers[tLoadState]):
      newClone(readSszForkedHashedBeaconState(
        cfg, readAllBytes(conf.preState2).tryGet()))
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

  printTimers(false, timers)

proc doSSZ(conf: NcliConf) =
  let (kind, file) =
    case conf.cmd:
    of hashTreeRoot: (conf.htrKind, conf.htrFile)
    of pretty: (conf.prettyKind, conf.prettyFile)
    else:
      raiseAssert "doSSZ() only implements hashTreeRoot and pretty commands"

  template printit(t: untyped) {.dirty.} =
    let v = newClone(loadFile(file, t))

    case conf.cmd:
    of hashTreeRoot:
      when t is ForkySignedBeaconBlock:
        echo hash_tree_root(v.message).data.toHex()
      else:
        echo hash_tree_root(v[]).data.toHex()
    of pretty:
      echo RestJson.encode(v[], pretty = true)
    else:
      raiseAssert "doSSZ() only implements hashTreeRoot and pretty commands"

  case kind
  of "attester_slashing": printit(AttesterSlashing)
  of "attestation": printit(Attestation)
  of "phase0_signed_block": printit(phase0.SignedBeaconBlock)
  of "altair_signed_block": printit(altair.SignedBeaconBlock)
  of "bellatrix_signed_block": printit(bellatrix.SignedBeaconBlock)
  of "phase0_block": printit(phase0.BeaconBlock)
  of "altair_block": printit(altair.BeaconBlock)
  of "bellatrix_block": printit(bellatrix.BeaconBlock)
  of "phase0_block_body": printit(phase0.BeaconBlockBody)
  of "altair_block_body": printit(altair.BeaconBlockBody)
  of "bellatrix_block_body": printit(bellatrix.BeaconBlockBody)
  of "block_header": printit(BeaconBlockHeader)
  of "deposit": printit(Deposit)
  of "deposit_data": printit(DepositData)
  of "eth1_data": printit(Eth1Data)
  of "phase0_state": printit(phase0.BeaconState)
  of "altiar_state": printit(altair.BeaconState)
  of "bellatrix_state": printit(bellatrix.BeaconState)
  of "proposer_slashing": printit(ProposerSlashing)
  of "voluntary_exit": printit(VoluntaryExit)

template init[N: static int](T: type DynamicBytes[N, N]): T =
  T newSeq[byte](N)

proc doVerifyDeposit(conf: NcliConf) =
  let cfg = getRuntimeConfig(conf.eth2Network)

  let deposit = if conf.depositData.isSome:
    let eventBytes = conf.depositData.get.substr(10)
    var
      pubkey = init deposit_contract_abi.PubKeyBytes
      withdrawalCredentials = init WithdrawalCredentialsBytes
      amount = init Int64LeBytes
      signature = init SignatureBytes
      index = init Int64LeBytes

    echo eventBytes

    try:
      var offset = 0
      offset += decode(eventBytes, offset, pubkey)
      offset += decode(eventBytes, offset, withdrawalCredentials)
      offset += decode(eventBytes, offset, amount)
      offset += decode(eventBytes, offset, signature)
    except CatchableError as err:
      echo "Invalid deposit event: ", err.msg
      quit 1

    DepositData(
      pubkey: ValidatorPubKey.init(pubkey.toArray),
      withdrawal_credentials: Eth2Digest(data: withdrawalCredentials.toArray),
      amount: bytes_to_uint64(amount.toArray),
      signature: ValidatorSig.init(signature.toArray))
  else:
    var missingParams: seq[string]

    if conf.pubkey.isNone: missingParams.add "pubkey"
    if conf.withdrawalCredentials.isNone: missingParams.add "withdrawal-credentials"
    if conf.signature.isNone: missingParams.add "singature"

    if missingParams.len > 0:
      echo "Please supply the hex-encoded deposit data as an argument or provide all of the following parameters:"
      for param in missingParams:
        echo "  --", param
      quit 1

    DepositData(
      pubkey: conf.pubkey.get,
      withdrawal_credentials: conf.withdrawalCredentials.get,
      amount: conf.amount,
      signature: conf.signature.get)

  let status = if verify_deposit_signature(cfg, deposit): "valid"
               else: "invalid"

  echo "The deposit is ", status

when isMainModule:
  let
    conf = NcliConf.load()

  case conf.cmd:
  of hashTreeRoot: doSSZ(conf)
  of pretty: doSSZ(conf)
  of transition: doTransition(conf)
  of slots: doSlots(conf)
  of verifyDeposit: doVerifyDeposit(conf)
