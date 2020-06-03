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
  chronicles,
  blscurve, json_serialization/std/[options, sets, net],

  # Local modules
  spec/[datatypes, digest, crypto, helpers, network],
  conf, time,
  eth2_network, eth2_discovery, validator_pool, beacon_node_types,
  nimbus_binary_common,
  version, ssz/merkleization,
  sync_manager,
  spec/eth2_apis/validator_callsigs_types,
  eth2_json_rpc_serialization

template sourceDir: string = currentSourcePath.rsplit(DirSep, 1)[0]

## Generate client convenience marshalling wrappers from forward declarations
createRpcSigs(RpcClient, sourceDir / "spec" / "eth2_apis" / "validator_callsigs.nim")

type
  ValidatorClient = ref object
    config: ValidatorClientConf
    client: RpcHttpClient
    beaconClock: BeaconClock
    attachedValidators: ValidatorPool
    fork: Fork
    proposalsForEpoch: Table[Slot, ValidatorPubKey]
    attestationsForEpoch: Table[Slot, AttesterDuties]
    beaconGenesis: BeaconGenesisTuple

# TODO remove this and move to real logging once done experimenting
# it's much easier to distinguish such output from the one with timestamps
proc port_logged(vc: ValidatorClient, msg: string) =
  echo "== ", vc.config.rpcPort, " ", msg

proc getValidatorDutiesForEpoch(vc: ValidatorClient, epoch: Epoch) {.gcsafe, async.} =
  vc.port_logged "await 1"
  let proposals = await vc.client.get_v1_validator_duties_proposer(epoch)
  vc.port_logged "await 2"
  # update the block proposal duties this VC should do during this epoch
  vc.proposalsForEpoch.clear()
  for curr in proposals:
    if vc.attachedValidators.validators.contains curr.public_key:
      vc.proposalsForEpoch.add(curr.slot, curr.public_key)

  # couldn't use mapIt in ANY shape or form so reverting to raw loops - sorry Sean Parent :|
  var validatorPubkeys: seq[ValidatorPubKey]
  for key in vc.attachedValidators.validators.keys:
    validatorPubkeys.add key
  # update the attestation duties this VC should do during this epoch
  let attestations = await vc.client.post_v1_validator_duties_attester(epoch, validatorPubkeys)
  vc.attestationsForEpoch.clear()
  for a in attestations:
    vc.attestationsForEpoch.add(a.slot, a)

  # for now we will get the fork each time we update the validator duties for each epoch
  vc.fork = await vc.client.get_v1_beacon_states_fork("head")

proc onSlotStart(vc: ValidatorClient, lastSlot, scheduledSlot: Slot) {.gcsafe, async.} =
  vc.port_logged "WAKE UP! slot " & $scheduledSlot

  let
    # The slot we should be at, according to the clock
    beaconTime = vc.beaconClock.now()
    wallSlot = beaconTime.toSlot()

  let
    slot = wallSlot.slot # afterGenesis == true!
    nextSlot = slot + 1

  try:
    # at the start of each epoch - request all validator duties for the current epoch
    # TODO perhaps call this not on the first slot of each Epoch but perhaps 1 slot earlier
    # because there are a few back-and-forth requests which could take up time for attesting...
    if scheduledSlot.isEpoch:
      await getValidatorDutiesForEpoch(vc, scheduledSlot.compute_epoch_at_slot)

    # check if we have a validator which needs to propose on this slot
    if vc.proposalsForEpoch.contains slot:
      let public_key = vc.proposalsForEpoch[slot]
      let validator = vc.attachedValidators.validators[public_key]

      let randao_reveal = validator.genRandaoReveal(
        vc.fork, vc.beaconGenesis.genesis_validators_root, slot)

      vc.port_logged "await 3"

      var newBlock = SignedBeaconBlock(
          message: await vc.client.get_v1_validator_blocks(slot, Eth2Digest(), randao_reveal)
        )

      vc.port_logged "await 4"

      let blockRoot = hash_tree_root(newBlock.message)
      newBlock.signature = await validator.signBlockProposal(
        vc.fork, vc.beaconGenesis.genesis_validators_root, slot, blockRoot)

      vc.port_logged "about to await for the last time!"

      discard await vc.client.post_v1_beacon_blocks(newBlock)

      vc.port_logged "did we do it?"

    # check if we have a validator which needs to propose on this slot
    if vc.attestationsForEpoch.contains slot:
      let a = vc.attestationsForEpoch[slot]
      let validator = vc.attachedValidators.validators[a.public_key]

      discard validator

      vc.port_logged("attestation: " & $a.committee_index.int64 & " " & $a.validator_committee_index)

  except CatchableError as err:
    error "Caught an unexpected error", err = err.msg

  let
    nextSlotStart = saturate(vc.beaconClock.fromNow(nextSlot))

  # it's much easier to wake up on every slot compared to scheduling the start of each
  # epoch and only the precise slots when the VC should sign/propose/attest with a key
  addTimer(nextSlotStart) do (p: pointer):
    asyncCheck vc.onSlotStart(slot, nextSlot)

programMain:
  let config = makeBannerAndConfig("Nimbus validator client v" & fullVersionStr, ValidatorClientConf)

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

    var vc = ValidatorClient(
      config: config,
      client: newRpcHttpClient(),
      attachedValidators: ValidatorPool.init()
    )
    vc.proposalsForEpoch.init()
    vc.attestationsForEpoch.init()

    # load all the validators from the data dir into memory
    for curr in vc.config.validatorKeys:
      vc.attachedValidators.addLocalValidator(curr.toPubKey, curr)

    # TODO perhaps we should handle the case if the BN is down and try to connect to it
    # untill success, and also later on disconnets we should continue trying to reconnect
    waitFor vc.client.connect("localhost", Port(config.rpcPort)) # TODO: use config.rpcAddress
    info "Connected to beacon node", port = config.rpcPort

    # init the beacon clock
    vc.beaconGenesis = waitFor vc.client.get_v1_beacon_genesis()
    vc.beaconClock = BeaconClock.init(vc.beaconGenesis.genesis_time)

    let
      curSlot = vc.beaconClock.now().slotOrZero()
      nextSlot = curSlot + 1 # No earlier than GENESIS_SLOT + 1
      fromNow = saturate(vc.beaconClock.fromNow(nextSlot))

    # onSlotStart() requests the validator duties only on the start of each epoch
    # so we should request the duties here when the VC binary boots up in order
    # to handle the case when in the middle of an epoch. Also for the genesis slot.
    waitFor vc.getValidatorDutiesForEpoch(curSlot.compute_epoch_at_slot)

    info "Scheduling first slot action",
      beaconTime = shortLog(vc.beaconClock.now()),
      nextSlot = shortLog(nextSlot),
      fromNow = shortLog(fromNow),
      cat = "scheduling"

    addTimer(fromNow) do (p: pointer) {.gcsafe.}:
      asyncCheck vc.onSlotStart(curSlot, nextSlot)

    runForever()
