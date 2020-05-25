# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  os, strutils, json, times,

  # Nimble packages
  stew/shims/[tables, macros],
  chronos, confutils, metrics, json_rpc/[rpcclient, jsonmarshal],
  blscurve, json_serialization/std/[options, sets, net],

  # Local modules
  spec/[datatypes, digest, crypto, helpers, network],
  conf, time,
  eth2_network, eth2_discovery, validator_pool, beacon_node_types,
  nimbus_binary_common,
  version, ssz, ssz/dynamic_navigator,
  sync_manager,
  spec/eth2_apis/validator_callsigs_types,
  eth2_json_rpc_serialization

template sourceDir: string = currentSourcePath.rsplit(DirSep, 1)[0]

## Generate client convenience marshalling wrappers from forward declarations
createRpcSigs(RpcClient, sourceDir & DirSep & "spec" & DirSep & "eth2_apis" & DirSep & "validator_callsigs.nim")

type
  ValidatorClient = ref object
    config: ValidatorClientConf
    client: RpcHttpClient
    beaconClock: BeaconClock
    attachedValidators: ValidatorPool
    validatorDutiesForEpoch: Table[Slot, ValidatorPubKey]

proc onSlotStart(vc: ValidatorClient, lastSlot, scheduledSlot: Slot) {.gcsafe, async.} =

  let
    # The slot we should be at, according to the clock
    beaconTime = vc.beaconClock.now()
    wallSlot = beaconTime.toSlot()

  let
    slot = wallSlot.slot # afterGenesis == true!
    nextSlot = slot + 1

  try:
    # TODO think about handling attestations in addition to block proposals - is waitFor OK...?

    # at the start of each epoch - request all validators which should propose
    # during this epoch and match that against the validators in this VC instance
    if scheduledSlot.isEpoch:
      let validatorDutiesForEpoch = waitFor vc.client.get_v1_validator_duties_proposer(scheduledSlot.compute_epoch_at_slot)
      # update the duties (block proposals) this VC client should do during this epoch
      vc.validatorDutiesForEpoch.clear()
      for curr in validatorDutiesForEpoch:
        if vc.attachedValidators.validators.contains curr.public_key:
          vc.validatorDutiesForEpoch.add(curr.slot, curr.public_key)
    # check if we have a validator which needs to propose on this slot
    if vc.validatorDutiesForEpoch.contains slot:
      let pubkey = vc.validatorDutiesForEpoch[slot]
      let validator = vc.attachedValidators.validators[pubkey]

      # TODO get these from the BN and store them in the ValidatorClient
      let fork = Fork()
      let genesis_validators_root = Eth2Digest()


      let randao_reveal = validator.genRandaoReveal(fork, genesis_validators_root, slot)

      var newBlock = SignedBeaconBlock(
          message: waitFor vc.client.get_v1_validator_blocks(slot, Eth2Digest(), randao_reveal)
        )

      let blockRoot = hash_tree_root(newBlock.message)
      newBlock.signature = waitFor validator.signBlockProposal(fork, genesis_validators_root, slot, blockRoot)

      discard waitFor vc.client.post_v1_beacon_blocks(newBlock)

  except CatchableError as err:
    echo err.msg

  let
    nextSlotStart = saturate(vc.beaconClock.fromNow(nextSlot))

  # it's much easier to wake up on every slot compared to scheduling the start of each
  # epoch and only the precise slots when the VC should sign/propose/attest with a key
  addTimer(nextSlotStart) do (p: pointer):
    asyncCheck vc.onSlotStart(slot, nextSlot)

programMain:
  let
    clientIdVC = "Nimbus validator client v" & fullVersionStr
    banner = clientIdVC & "\p" & copyrights & "\p\p" & nimBanner
    config = ValidatorClientConf.load(version = banner, copyrightBanner = banner)

  sleep(config.delayStart * 1000)

  setupMainProc(config.logLevel)

  # TODO figure out how to re-enable this without the VCs continuing
  # to run when `make eth2_network_simulation` is killed with CTRL+C
  #ctrlCHandling: discard

  case config.cmd
  of VCNoCommand:
    debug "Launching validator client",
          version = fullVersionStr,
          cmdParams = commandLineParams(),
          config

    # TODO: the genesis time should be obtained through calls to the beacon node
    # this applies also for genesis_validators_root... and the fork!
    var genesisState = config.getStateFromSnapshot()

    var vc = ValidatorClient(
      config: config,
      client: newRpcHttpClient(),
      beaconClock: BeaconClock.init(genesisState[]),
      attachedValidators: ValidatorPool.init()
    )
    vc.validatorDutiesForEpoch.init()

    for curr in vc.config.validatorKeys:
      vc.attachedValidators.addLocalValidator(curr.toPubKey, curr)

    waitFor vc.client.connect("localhost", Port(config.rpcPort)) # TODO: use config.rpcAddress
    echo "connected to beacon node running on port ", config.rpcPort

    let
      curSlot = vc.beaconClock.now().slotOrZero()
      nextSlot = curSlot + 1 # No earlier than GENESIS_SLOT + 1
      fromNow = saturate(vc.beaconClock.fromNow(nextSlot))

    info "Scheduling first slot action",
      beaconTime = shortLog(vc.beaconClock.now()),
      nextSlot = shortLog(nextSlot),
      fromNow = shortLog(fromNow),
      cat = "scheduling"

    addTimer(fromNow) do (p: pointer) {.gcsafe.}:
      asyncCheck vc.onSlotStart(curSlot, nextSlot)

    runForever()
