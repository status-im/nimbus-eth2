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
  conf, time, version,
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
    graffitiBytes: GraffitiBytes
    client: RpcHttpClient
    beaconClock: BeaconClock
    attachedValidators: ValidatorPool
    fork: Fork
    proposalsForCurrentEpoch: Table[Slot, ValidatorPubKey]
    attestationsForEpoch: Table[Epoch, Table[Slot, seq[AttesterDuties]]]
    beaconGenesis: BeaconGenesisTuple

template attemptUntilSuccess(vc: ValidatorClient, body: untyped) =
  while true:
    try:
      body
      break
    except CatchableError as err:
      warn "Caught an unexpected error", err = err.msg
    waitFor sleepAsync(chronos.seconds(1)) # 1 second before retrying

proc getValidatorDutiesForEpoch(vc: ValidatorClient, epoch: Epoch) {.gcsafe, async.} =
  info "Getting validator duties for epoch", epoch = epoch

  let proposals = await vc.client.get_v1_validator_duties_proposer(epoch)
  # update the block proposal duties this VC should do during this epoch
  vc.proposalsForCurrentEpoch.clear()
  for curr in proposals:
    if vc.attachedValidators.validators.contains curr.public_key:
      vc.proposalsForCurrentEpoch.add(curr.slot, curr.public_key)

  # couldn't use mapIt in ANY shape or form so reverting to raw loops - sorry Sean Parent :|
  var validatorPubkeys: seq[ValidatorPubKey]
  for key in vc.attachedValidators.validators.keys:
    validatorPubkeys.add key

  proc getAttesterDutiesForEpoch(epoch: Epoch) {.gcsafe, async.} =
    # make sure there's an entry
    if not vc.attestationsForEpoch.contains epoch:
      vc.attestationsForEpoch.add(epoch, Table[Slot, seq[AttesterDuties]]())
    let attestations = await vc.client.post_v1_validator_duties_attester(
      epoch, validatorPubkeys)
    for a in attestations:
      if vc.attestationsForEpoch[epoch].hasKeyOrPut(a.slot, @[a]):
        vc.attestationsForEpoch[epoch][a.slot].add(a)

  # clear both for the current epoch and the next because a change of
  # fork could invalidate the attester duties even the current epoch
  vc.attestationsForEpoch.clear()
  await getAttesterDutiesForEpoch(epoch)
  # obtain the attestation duties this VC should do during the next epoch
  # TODO currently we aren't making use of this but perhaps we should
  await getAttesterDutiesForEpoch(epoch + 1)

  # for now we will get the fork each time we update the validator duties for each epoch
  # TODO should poll occasionally `/v1/config/fork_schedule`
  vc.fork = await vc.client.get_v1_beacon_states_fork("head")

  var numAttestationsForEpoch = 0
  for _, dutiesForSlot in vc.attestationsForEpoch[epoch]:
    numAttestationsForEpoch += dutiesForSlot.len

  info "Got validator duties for epoch",
    num_proposals = vc.proposalsForCurrentEpoch.len,
    num_attestations = numAttestationsForEpoch

proc onSlotStart(vc: ValidatorClient, lastSlot, scheduledSlot: Slot) {.gcsafe, async.} =

  let
    # The slot we should be at, according to the clock
    beaconTime = vc.beaconClock.now()
    wallSlot = beaconTime.toSlot()

  let
    slot = wallSlot.slot # afterGenesis == true!
    nextSlot = slot + 1
    epoch = slot.compute_epoch_at_slot

  info "Slot start",
    lastSlot = shortLog(lastSlot),
    scheduledSlot = shortLog(scheduledSlot),
    beaconTime = shortLog(beaconTime),
    portBN = vc.config.rpcPort

  try:
    # at the start of each epoch - request all validator duties
    # TODO perhaps call this not on the first slot of each Epoch but perhaps
    # 1 slot earlier because there are a few back-and-forth requests which
    # could take up time for attesting... Perhaps this should be called more
    # than once per epoch because of forks & other events...
    if slot.isEpoch:
      await getValidatorDutiesForEpoch(vc, epoch)

    # check if we have a validator which needs to propose on this slot
    if vc.proposalsForCurrentEpoch.contains slot:
      let public_key = vc.proposalsForCurrentEpoch[slot]
      let validator = vc.attachedValidators.validators[public_key]

      info "Proposing block", slot = slot, public_key = public_key

      let randao_reveal = validator.genRandaoReveal(
        vc.fork, vc.beaconGenesis.genesis_validators_root, slot)

      var newBlock = SignedBeaconBlock(
          message: await vc.client.get_v1_validator_block(slot, vc.graffitiBytes, randao_reveal)
        )

      newBlock.root = hash_tree_root(newBlock.message)
      newBlock.signature = await validator.signBlockProposal(
        vc.fork, vc.beaconGenesis.genesis_validators_root, slot, newBlock.root)

      discard await vc.client.post_v1_validator_block(newBlock)

    # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#attesting
    # A validator should create and broadcast the attestation to the associated
    # attestation subnet when either (a) the validator has received a valid
    # block from the expected block proposer for the assigned slot or
    # (b) one-third of the slot has transpired (`SECONDS_PER_SLOT / 3` seconds
    # after the start of slot) -- whichever comes first.
    discard await vc.beaconClock.sleepToSlotOffset(
      seconds(int64(SECONDS_PER_SLOT)) div 3, slot, "Waiting to send attestations")

    # check if we have validators which need to attest on this slot
    if vc.attestationsForEpoch.contains(epoch) and
        vc.attestationsForEpoch[epoch].contains slot:
      for a in vc.attestationsForEpoch[epoch][slot]:
        info "Attesting", slot = slot, public_key = a.public_key

        let validator = vc.attachedValidators.validators[a.public_key]
        let ad = await vc.client.get_v1_validator_attestation(slot, a.committee_index)

        # TODO I don't like these (u)int64-to-int conversions...
        let attestation = await validator.produceAndSignAttestation(
          ad, a.committee_length.int, a.validator_committee_index.int,
          vc.fork, vc.beaconGenesis.genesis_validators_root)

        discard await vc.client.post_v1_beacon_pool_attestations(attestation)

  except CatchableError as err:
    warn "Caught an unexpected error", err = err.msg, slot = shortLog(slot)

  let
    nextSlotStart = saturate(vc.beaconClock.fromNow(nextSlot))

  info "Slot end",
    slot = shortLog(slot),
    nextSlot = shortLog(nextSlot),
    portBN = vc.config.rpcPort

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

  setupLogging(config.logLevel, config.logFile)

  case config.cmd
  of VCNoCommand:
    debug "Launching validator client",
          version = fullVersionStr,
          cmdParams = commandLineParams(),
          config

    var vc = ValidatorClient(
      config: config,
      client: newRpcHttpClient(),
      graffitiBytes: if config.graffiti.isSome: config.graffiti.get.GraffitiBytes
                     else: defaultGraffitiBytes())

    # load all the validators from the data dir into memory
    for curr in vc.config.validatorKeys:
      vc.attachedValidators.addLocalValidator(curr.toPubKey.initPubKey, curr)

    waitFor vc.client.connect($vc.config.rpcAddress, Port(vc.config.rpcPort))
    info "Connected to BN",
      port = vc.config.rpcPort,
      address = vc.config.rpcAddress

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
      fromNow = shortLog(fromNow)

    addTimer(fromNow) do (p: pointer) {.gcsafe.}:
      asyncCheck vc.onSlotStart(curSlot, nextSlot)

    runForever()
