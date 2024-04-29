# beacon_chain
# Copyright (c) 2022-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# `wss_sim` loads a state and a set of validator keys, then simulates a
# beacon chain running with the given validators producing blocks
# and attesting when they're supposed to.

import
  std/[strformat, sequtils, tables],
  chronicles,
  confutils,
  stew/io2,
  ../tests/testblockutil,
  ../beacon_chain/el/el_manager,
  ../beacon_chain/networking/network_metadata,
  ../beacon_chain/[beacon_clock, sszdump],
  ../beacon_chain/spec/eth2_apis/eth2_rest_serialization,
  ../beacon_chain/spec/datatypes/[phase0, altair, bellatrix],
  ../beacon_chain/spec/[
    beaconstate, crypto, engine_authentication, forks, helpers,
    signatures, state_transition],
  ../beacon_chain/validators/[keystore_management, validator_pool]

from ../beacon_chain/gossip_processing/block_processor import
  newExecutionPayload

template findIt*(s: openArray, predicate: untyped): int =
  var res = -1
  for i, it {.inject.} in s:
    if predicate:
      res = i
      break
  res

func findValidator(validators: seq[Validator], pubkey: ValidatorPubKey):
    Opt[ValidatorIndex] =
  let idx = validators.findIt(it.pubkey == pubkey)
  if idx == -1:
    Opt.none ValidatorIndex
  else:
    Opt.some idx.ValidatorIndex

from ../beacon_chain/spec/datatypes/capella import SignedBeaconBlock
from ../beacon_chain/spec/datatypes/deneb import SignedBeaconBlock

cli do(validatorsDir: string, secretsDir: string,
       startState: string, startBlock: string,
       network: string, elUrl: string, jwtSecret: string,
       suggestedFeeRecipient: string, graffiti = "insecura"):
  let
    metadata = getMetadataForNetwork(network)
    cfg = metadata.cfg
    state = block:
      let data = readAllBytes(startState)
      if data.isErr:
        fatal "failed to read hashed beacon state", err = $data.error
        quit QuitFailure
      try:
        newClone(readSszForkedHashedBeaconState(cfg, data.get))
      except SerializationError as exc:
        fatal "failed to parse hashed beacon state", err = exc.msg
        quit QuitFailure
    blck = block:
      let data = readAllBytes(startBlock)
      if data.isErr:
        fatal "failed to read signed beacon block", err = $data.error
        quit QuitFailure
      try:
        newClone(readSszForkedSignedBeaconBlock(cfg, data.get))
      except SerializationError as exc:
        fatal "failed to parse signed beacon block", err = exc.msg
        quit QuitFailure
    engineApiUrl = block:
      let
        jwtSecretFile =
          try:
            InputFile.parseCmdArg(jwtSecret)
          except ValueError as exc:
            fatal "failed to read JWT secret file", err = exc.msg
            quit QuitFailure
        jwtSecret = loadJwtSecretFile(jwtSecretFile)
      if jwtSecret.isErr:
        fatal "failed to parse JWT secret file", err = jwtSecret.error
        quit QuitFailure
      let finalUrl = EngineApiUrlConfigValue(url: elUrl)
        .toFinalUrl(Opt.some jwtSecret.get)
      if finalUrl.isErr:
        fatal "failed to read EL URL", err = finalUrl.error
        quit QuitFailure
      finalUrl.get
    elManager = ELManager.new(
      cfg,
      metadata.depositContractBlock,
      metadata.depositContractBlockHash,
      db = nil,
      @[engineApiUrl],
      metadata.eth1Network)
    feeRecipient =
      try:
        Address.fromHex(suggestedFeeRecipient)
      except ValueError as exc:
        fatal "failed to parse suggested fee recipient", err = exc.msg
        quit QuitFailure
    graffitiValue =
      try:
        GraffitiBytes.init(graffiti)
      except ValueError as exc:
        fatal "failed to parse graffiti", err = exc.msg
        quit QuitFailure

  # Sync EL to initial state. Note that to construct the new branch, the EL
  # should not have advanced to a later block via `engine_forkchoiceUpdated`.
  # The EL may otherwise refuse to produce new heads
  elManager.start(syncChain = false)
  withBlck(blck[]):
    when consensusFork >= ConsensusFork.Bellatrix:
      if forkyBlck.message.is_execution_block:
        template payload(): auto = forkyBlck.message.body.execution_payload
        if not payload.block_hash.isZero:
          notice "Syncing EL", elUrl, jwtSecret
          while true:
            waitFor noCancel sleepAsync(chronos.seconds(2))
            (waitFor noCancel elManager
                .newExecutionPayload(forkyBlck.message)).isOkOr:
              continue

            let (status, _) = waitFor noCancel elManager.forkchoiceUpdated(
              headBlockHash = payload.block_hash,
              safeBlockHash = payload.block_hash,
              finalizedBlockHash = ZERO_HASH,
              payloadAttributes = none(consensusFork.PayloadAttributes))
            if status != PayloadExecutionStatus.valid:
              continue

            notice "EL synced", elUrl, jwtSecret
            break

  var
    clock = BeaconClock.init(getStateField(state[], genesis_time)).valueOr:
      error "Invalid genesis time in state"
      quit 1
    validators: Table[ValidatorIndex, ValidatorPrivKey]
    validatorKeys: Table[ValidatorPubKey, ValidatorPrivKey]

  for item in listLoadableKeystores(validatorsDir, secretsDir, true,
                                    {KeystoreKind.Local}, nil):
    let
      pubkey = item.privateKey.toPubKey().toPubKey()
      idx = findValidator(getStateField(state[], validators).toSeq, pubkey)
    if idx.isSome():
      notice "Loaded validator", pubkey
      validators[idx.get()] = item.privateKey
      validatorKeys[pubkey] = item.privateKey
    else:
      warn "Unknown validator", pubkey

  var
    blockRoot = withState(state[]): forkyState.latest_block_root
    cache: StateCache
    info: ForkedEpochInfo
    aggregates: seq[phase0.Attestation]
    syncAggregate = SyncAggregate.init()

  let
    genesis_validators_root = getStateField(state[], genesis_validators_root)

  block:
    let
      active = withState(state[]):
        get_active_validator_indices_len(
          forkyState.data, forkyState.data.slot.epoch)

    notice "Let's play",
      validators = validators.len(),
      active

  while true:
    # Move to slot
    let
      slot = getStateField(state[], slot) + 1
    process_slots(cfg, state[], slot, cache, info, {}).expect("works")

    if start_beacon_time(slot) > clock.now():
      notice "Ran out of time",
        epoch = slot.epoch
      break

    var exited: seq[ValidatorIndex]
    for k, v in validators:
      if getStateField(state[], validators).asSeq[k].exit_epoch != FAR_FUTURE_EPOCH:
        exited.add k
    for k in exited:
      warn "Validator exited", k

      validatorKeys.del(getStateField(state[], validators).asSeq[k].pubkey)
      validators.del(k)

    if slot.epoch != (slot - 1).epoch:
      let
        active = withState(state[]):
          get_active_validator_indices_len(forkyState.data, slot.epoch)
        balance = block:
          var b: Gwei
          for k, _ in validators:
            if is_active_validator(getStateField(state[], validators).asSeq[k], slot.epoch):
              b += getStateField(state[], balances).asSeq[k]
          b
        validators = block:
          var b: int
          for k, _ in validators:
            if is_active_validator(getStateField(state[], validators).asSeq[k], slot.epoch):
              b += 1
          b
        avgBalance = balance.int64 div validators.int64

      notice "Processing epoch",
        epoch = slot.epoch,
        active,
        epochsSinceFinality =
          slot.epoch - getStateField(state[], finalized_checkpoint).epoch,
        balance,
        validators,
        avgBalance

      if slot.epoch mod 32 == 0:
        withState(state[]): dump(".", forkyState)

    let
      fork = getStateField(state[], fork)
      proposer = get_beacon_proposer_index(state[], cache, slot).get()

    if proposer in validators:
      let
        blockAggregates = aggregates.filterIt(
          it.data.slot + MIN_ATTESTATION_INCLUSION_DELAY <= slot and
          slot <= it.data.slot + SLOTS_PER_EPOCH)
        randao_reveal = get_epoch_signature(
          fork, genesis_validators_root, slot.epoch,
          # should never fall back to default value
          validators.getOrDefault(
            proposer, default(ValidatorPrivKey))).toValidatorSig()
      withState(state[]):
        let
          payload =
            when consensusFork >= ConsensusFork.Bellatrix:
              let
                executionHead =
                  forkyState.data.latest_execution_payload_header.block_hash
                withdrawals =
                  when consensusFork >= ConsensusFork.Capella:
                    get_expected_withdrawals(forkyState.data)
                  else:
                    newSeq[Withdrawal]()

              var pl: consensusFork.ExecutionPayloadForSigning
              while true:
                pl = (waitFor noCancel elManager.getPayload(
                    consensusFork.ExecutionPayloadForSigning,
                    consensusHead = forkyState.latest_block_root,
                    headBlock = executionHead,
                    safeBlock = executionHead,
                    finalizedBlock = ZERO_HASH,
                    timestamp = compute_timestamp_at_slot(
                      forkyState.data, forkyState.data.slot),
                    randomData = get_randao_mix(
                      forkyState.data, get_current_epoch(forkyState.data)),
                    suggestedFeeRecipient = feeRecipient,
                    withdrawals = withdrawals)).valueOr:
                  waitFor noCancel sleepAsync(chronos.seconds(2))
                  continue
                break
              pl
            else:
              default(bellatrix.ExecutionPayloadForSigning)
          message = makeBeaconBlock(
            cfg,
            state[],
            proposer,
            randao_reveal,
            forkyState.data.eth1_data,
            graffitiValue,
            when typeof(payload).kind == ConsensusFork.Electra:
              block:
                debugRaiseAssert "wss_sim electra aggregates"
                default(seq[electra.Attestation])
            else:
              blockAggregates,
            @[],
            BeaconBlockValidatorChanges(),
            syncAggregate,
            payload,
            noRollback,
            cache).get()

        blockRoot = message.forky(consensusFork).hash_tree_root()
        let
          proposerPrivkey =
            try:
              validators[proposer]
            except KeyError as exc:
              raiseAssert "Proposer key not available: " & exc.msg
          signedBlock = consensusFork.SignedBeaconBlock(
            message: message.forky(consensusFork),
            root: blockRoot,
            signature: get_block_signature(
              fork, genesis_validators_root, slot, blockRoot,
              proposerPrivkey).toValidatorSig())

        dump(".", signedBlock)
        when consensusFork >= ConsensusFork.Deneb:
          let blobs = signedBlock.create_blob_sidecars(
            payload.blobsBundle.proofs, payload.blobsBundle.blobs)
          for blob in blobs:
            dump(".", blob)

        notice "Block proposed", message, blockRoot

        when consensusFork >= ConsensusFork.Bellatrix:
          while true:
            let status = waitFor noCancel elManager
              .newExecutionPayload(signedBlock.message)
            if status.isNone:
              waitFor noCancel sleepAsync(chronos.seconds(2))
              continue
            doAssert status.get in [
              PayloadExecutionStatus.valid,
              PayloadExecutionStatus.accepted,
              PayloadExecutionStatus.syncing]
            break

      aggregates.setLen(0)

    syncAggregate = SyncAggregate.init()

    withState(state[]):
      let committees_per_slot = get_committee_count_per_slot(
        forkyState.data, slot.epoch, cache)
      for committee_index in get_committee_indices(committees_per_slot):
        let committee = get_beacon_committee(
          forkyState.data, slot, committee_index, cache)

        var
          attestation = phase0.Attestation(
            data: makeAttestationData(
              forkyState.data, slot, committee_index, blockRoot),
            aggregation_bits: CommitteeValidatorsBits.init(committee.len))
          agg: AggregateSignature

        for index_in_committee, validator_index in committee:
          if validator_index notin validators:
            continue

          let
            signature = get_attestation_signature(
              fork, genesis_validators_root, attestation.data,
              validators.getOrDefault(validator_index, default(ValidatorPrivKey)))
          if attestation.aggregation_bits.isZeros:
            agg = AggregateSignature.init(signature)
          else:
            agg.aggregate(signature)
          attestation.aggregation_bits.setBit(index_in_committee)

        if not attestation.aggregation_bits.isZeros:
          attestation.signature = agg.finish().toValidatorSig()

          if aggregates.len == 128:
            aggregates.delete(0)

          aggregates.add(attestation)

      when consensusFork >= ConsensusFork.Altair:
        let
          nextSlot = slot + 1
          pubkeys =
            if slot.sync_committee_period == nextSlot.sync_committee_period:
              forkyState.data.current_sync_committee.pubkeys
            else:
              forkyState.data.next_sync_committee.pubkeys

        var
          agg: AggregateSignature
          inited = false

        for i, pubkey in pubkeys:
          validatorKeys.withValue(pubkey, privkey):
            let sig = get_sync_committee_message_signature(
              fork, genesis_validators_root, slot, blockRoot, privkey[])

            if inited:
              agg.aggregate(sig)
            else:
              agg = AggregateSignature.init(sig)
              inited = true
            syncAggregate.sync_committee_bits.setBit(i)

        if inited:
          syncAggregate.sync_committee_signature = finish(agg).toValidatorSig()