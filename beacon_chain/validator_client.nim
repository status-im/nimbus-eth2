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
  sync_manager, keystore_management,
  spec/eth2_apis/callsigs_types,
  eth2_json_rpc_serialization

logScope: topics = "vc"

template sourceDir: string = currentSourcePath.rsplit(DirSep, 1)[0]

## Generate client convenience marshalling wrappers from forward declarations
createRpcSigs(RpcClient, sourceDir / "spec" / "eth2_apis" / "validator_callsigs.nim")
createRpcSigs(RpcClient, sourceDir / "spec" / "eth2_apis" / "beacon_callsigs.nim")

type
  ValidatorClient = ref object
    config: ValidatorClientConf
    client: RpcHttpClient
    beaconClock: BeaconClock
    attachedValidators: ValidatorPool
    fork: Fork
    proposalsForEpoch: Table[Slot, ValidatorPubKey]
    attestationsForEpoch: Table[Slot, seq[AttesterDuties]]
    beaconGenesis: BeaconGenesisTuple

proc connectToBN(vc: ValidatorClient) {.gcsafe, async.} =
  while true:
    try:
      await vc.client.connect($vc.config.rpcAddress, Port(vc.config.rpcPort))
      info "Connected to BN",
        port = vc.config.rpcPort,
        address = vc.config.rpcAddress
      return
    except CatchableError as err:
      error "Could not connect to the BN - retrying!", err = err.msg
      await sleepAsync(chronos.seconds(1)) # 1 second before retrying

template attemptUntilSuccess(vc: ValidatorClient, body: untyped) =
  while true:
    try:
      body
      break
    except CatchableError as err:
      error "Caught an unexpected error", err = err.msg
      waitFor vc.connectToBN()

proc getValidatorDutiesForEpoch(vc: ValidatorClient, epoch: Epoch) {.gcsafe, async.} =
  let proposals = await vc.client.get_v1_validator_duties_proposer(epoch)
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
  let attestations = await vc.client.post_v1_validator_duties_attester(
    epoch, validatorPubkeys)
  vc.attestationsForEpoch.clear()
  for a in attestations:
    if vc.attestationsForEpoch.hasKeyOrPut(a.slot, @[a]):
      vc.attestationsForEpoch[a.slot].add(a)

  # for now we will get the fork each time we update the validator duties for each epoch
  vc.fork = await vc.client.get_v1_beacon_states_fork("head")

proc onSlotStart(vc: ValidatorClient, lastSlot, scheduledSlot: Slot) {.gcsafe, async.} =

  let
    # The slot we should be at, according to the clock
    beaconTime = vc.beaconClock.now()
    wallSlot = beaconTime.toSlot()

  let
    slot = wallSlot.slot # afterGenesis == true!
    nextSlot = slot + 1

  info "Slot start",
    lastSlot = shortLog(lastSlot),
    scheduledSlot = shortLog(scheduledSlot),
    beaconTime = shortLog(beaconTime),
    portBN = vc.config.rpcPort,
    cat = "scheduling"

  try:
    # at the start of each epoch - request all validator duties
    # TODO perhaps call this not on the first slot of each Epoch but perhaps
    # 1 slot earlier because there are a few back-and-forth requests which
    # could take up time for attesting... Perhaps this should be called more
    # than once per epoch because of forks & other events...
    if slot.isEpoch:
      await getValidatorDutiesForEpoch(vc, slot.compute_epoch_at_slot)

    # check if we have a validator which needs to propose on this slot
    if vc.proposalsForEpoch.contains slot:
      let public_key = vc.proposalsForEpoch[slot]
      let validator = vc.attachedValidators.validators[public_key]

      let randao_reveal = validator.genRandaoReveal(
        vc.fork, vc.beaconGenesis.genesis_validators_root, slot)

      var newBlock = SignedBeaconBlock(
          message: await vc.client.get_v1_validator_blocks(slot, Eth2Digest(), randao_reveal)
        )

      let blockRoot = hash_tree_root(newBlock.message)
      newBlock.signature = await validator.signBlockProposal(
        vc.fork, vc.beaconGenesis.genesis_validators_root, slot, blockRoot)

      discard await vc.client.post_v1_beacon_blocks(newBlock)

    # https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/validator.md#attesting
    # A validator should create and broadcast the attestation to the associated
    # attestation subnet when either (a) the validator has received a valid
    # block from the expected block proposer for the assigned slot or
    # (b) one-third of the slot has transpired (`SECONDS_PER_SLOT / 3` seconds
    # after the start of slot) -- whichever comes first.
    discard await vc.beaconClock.sleepToSlotOffset(
      seconds(int64(SECONDS_PER_SLOT)) div 3, slot, "Waiting to send attestations")

    # check if we have validators which need to attest on this slot
    if vc.attestationsForEpoch.contains slot:
      for a in vc.attestationsForEpoch[slot]:
        let validator = vc.attachedValidators.validators[a.public_key]

        let ad = await vc.client.get_v1_validator_attestation_data(slot, a.committee_index)

        # TODO I don't like these (u)int64-to-int conversions...
        let attestation = await validator.produceAndSignAttestation(
          ad, a.committee_length.int, a.validator_committee_index.int,
          vc.fork, vc.beaconGenesis.genesis_validators_root)

        discard await vc.client.post_v1_beacon_pool_attestations(attestation)

  except CatchableError as err:
    error "Caught an unexpected error", err = err.msg, slot = shortLog(slot)
    await vc.connectToBN()

  let
    nextSlotStart = saturate(vc.beaconClock.fromNow(nextSlot))

  info "Slot end",
    slot = shortLog(slot),
    nextSlot = shortLog(nextSlot),
    portBN = vc.config.rpcPort,
    cat = "scheduling"

  when declared(GC_fullCollect):
    # The slots in the validator client work as frames in a game: we want to make
    # sure that we're ready for the next one and don't get stuck in lengthy
    # garbage collection tasks when time is of essence in the middle of a slot -
    # while this does not guarantee that we'll never collect during a slot, it
    # makes sure that all the scratch space we used during slot tasks (logging,
    # temporary buffers etc) gets recycled for the next slot that is likely to
    # need similar amounts of memory.
    GC_fullCollect()

  addTimer(nextSlotStart) do (p: pointer):
    asyncCheck vc.onSlotStart(slot, nextSlot)

programMain:
  let config = makeBannerAndConfig("Nimbus validator client v" & fullVersionStr, ValidatorClientConf)

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

    waitFor vc.connectToBN()

    vc.attemptUntilSuccess:
      # init the beacon clock
      vc.beaconGenesis = waitFor vc.client.get_v1_beacon_genesis()
      vc.beaconClock = BeaconClock.init(vc.beaconGenesis.genesis_time)

    let
      curSlot = vc.beaconClock.now().slotOrZero()
      nextSlot = curSlot + 1 # No earlier than GENESIS_SLOT + 1
      fromNow = saturate(vc.beaconClock.fromNow(nextSlot))

    vc.attemptUntilSuccess:
      waitFor vc.getValidatorDutiesForEpoch(curSlot.compute_epoch_at_slot)

    info "Scheduling first slot action",
      beaconTime = shortLog(vc.beaconClock.now()),
      nextSlot = shortLog(nextSlot),
      fromNow = shortLog(fromNow),
      cat = "scheduling"

    addTimer(fromNow) do (p: pointer) {.gcsafe.}:
      asyncCheck vc.onSlotStart(curSlot, nextSlot)

    runForever()
