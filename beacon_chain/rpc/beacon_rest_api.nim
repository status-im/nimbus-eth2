# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
import
  std/[typetraits, sequtils, strutils, deques, sets, options],
  stew/[results, base10],
  chronicles,
  nimcrypto/utils as ncrutils,
  ../beacon_node_common, ../networking/eth2_network,
  ../consensus_object_pools/[blockchain_dag, exit_pool],
  ../gossip_processing/gossip_validation,
  ../validators/validator_duties,
  ../spec/[crypto, digest, validator, datatypes, network],
  ../ssz/merkleization,
  ./eth2_json_rest_serialization, ./rest_utils

logScope: topics = "rest_beaconapi"

type
  ValidatorTuple = tuple
    index: ValidatorIndex
    balance: string
    status: string
    validator: Validator

  ValidatorBalanceTuple = tuple
    index: ValidatorIndex
    balance: string

  BeaconStatesCommitteesTuple* = tuple
    index: CommitteeIndex
    slot: Slot
    validators: seq[ValidatorIndex]

  FailureTuple* = tuple
    index: uint64
    message: string

proc validateFilter(filters: seq[ValidatorFilter]): Result[ValidatorFilter,
                                                           cstring] =
  var res: ValidatorFilter
  for item in filters:
    if res * item != {}:
      return err("Validator status must be unique")
    res.incl(item)

  if res == {}:
    res = {ValidatorFilterKind.PendingInitialized,
           ValidatorFilterKind.PendingQueued,
           ValidatorFilterKind.ActiveOngoing,
           ValidatorFilterKind.ActiveExiting,
           ValidatorFilterKind.ActiveSlashed,
           ValidatorFilterKind.ExitedUnslashed,
           ValidatorFilterKind.ExitedSlashed,
           ValidatorFilterKind.WithdrawalPossible,
           ValidatorFilterKind.WithdrawalDone}
  ok(res)

proc getStatus(validator: Validator,
               current_epoch: Epoch): Result[ValidatorFilterKind, cstring] =
  if validator.activation_epoch > current_epoch:
    # pending
    if validator.activation_eligibility_epoch == FAR_FUTURE_EPOCH:
      ok(ValidatorFilterKind.PendingInitialized)
    else:
      # validator.activation_eligibility_epoch < FAR_FUTURE_EPOCH:
      ok(ValidatorFilterKind.PendingQueued)
  elif (validator.activation_epoch <= current_epoch) and
       (current_epoch < validator.exit_epoch):
    # active
    if validator.exit_epoch == FAR_FUTURE_EPOCH:
      ok(ValidatorFilterKind.ActiveOngoing)
    elif not validator.slashed:
      # validator.exit_epoch < FAR_FUTURE_EPOCH
      ok(ValidatorFilterKind.ActiveExiting)
    else:
      # validator.exit_epoch < FAR_FUTURE_EPOCH and validator.slashed:
      ok(ValidatorFilterKind.ActiveSlashed)
  elif (validator.exit_epoch <= current_epoch) and
       (current_epoch < validator.withdrawable_epoch):
    # exited
    if not validator.slashed:
      ok(ValidatorFilterKind.ExitedUnslashed)
    else:
      # validator.slashed
      ok(ValidatorFilterKind.ExitedSlashed)
  elif validator.withdrawable_epoch <= current_epoch:
    # withdrawal
    if validator.effective_balance != 0:
      ok(ValidatorFilterKind.WithdrawalPossible)
    else:
      # validator.effective_balance == 0
      ok(ValidatorFilterKind.WithdrawalDone)
  else:
    err("Invalid validator status")

proc toString*(kind: ValidatorFilterKind): string =
  case kind
  of ValidatorFilterKind.PendingInitialized:
    "pending_initialized"
  of ValidatorFilterKind.PendingQueued:
    "pending_queued"
  of ValidatorFilterKind.ActiveOngoing:
    "active_ongoing"
  of ValidatorFilterKind.ActiveExiting:
    "active_exiting"
  of ValidatorFilterKind.ActiveSlashed:
    "active_slashed"
  of ValidatorFilterKind.ExitedUnslashed:
    "exited_unslashed"
  of ValidatorFilterKind.ExitedSlashed:
    "exited_slashed"
  of ValidatorFilterKind.WithdrawalPossible:
    "withdrawal_possible"
  of ValidatorFilterKind.WithdrawalDone:
    "withdrawal_done"

proc installBeaconApiHandlers*(router: var RestRouter, node: BeaconNode) =
  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getGenesis
  router.api(MethodGet, "/api/eth/v1/beacon/genesis") do () -> RestApiResponse:
    return RestApiResponse.jsonResponse(
      (
        genesis_time: node.chainDag.headState.data.data.genesis_time,
        genesis_validators_root:
          node.chainDag.headState.data.data.genesis_validators_root,
        genesis_fork_version: node.runtimePreset.GENESIS_FORK_VERSION
      )
    )

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getStateRoot
  router.api(MethodGet, "/api/eth/v1/beacon/states/{state_id}/root") do (
    state_id: StateIdent) -> RestApiResponse:
    let bslot =
      block:
        if state_id.isErr():
          return RestApiResponse.jsonError(Http400, "Invalid state_id",
                                           $state_id.error())
        let bres = node.getBlockSlot(state_id.get())
        if bres.isErr():
          return RestApiResponse.jsonError(Http404, "State not found",
                                           $bres.error())
        bres.get()
    node.withStateForBlockSlot(bslot):
      return RestApiResponse.jsonResponse((root: hashedState().root))
    return RestApiResponse.jsonError(Http500, "Internal server error")

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getStateFork
  router.api(MethodGet, "/api/eth/v1/beacon/states/{state_id}/fork") do (
    state_id: StateIdent) -> RestApiResponse:
    let bslot =
      block:
        if state_id.isErr():
          return RestApiResponse.jsonError(Http400, "Invalid state_id",
                                           $state_id.error())
        let bres = node.getBlockSlot(state_id.get())
        if bres.isErr():
          return RestApiResponse.jsonError(Http404, "State not found",
                                           $bres.error())
        bres.get()
    node.withStateForBlockSlot(bslot):
      return RestApiResponse.jsonResponse(
        (
          previous_version: state().fork.previous_version,
          current_version: state().fork.current_version,
          epoch: state().fork.epoch
        )
      )
    return RestApiResponse.jsonError(Http500, "Internal server error")

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getStateFinalityCheckpoints
  router.api(MethodGet,
             "/api/eth/v1/beacon/states/{state_id}/finality_checkpoints") do (
    state_id: StateIdent) -> RestApiResponse:
    let bslot =
      block:
        if state_id.isErr():
          return RestApiResponse.jsonError(Http400, "Invalid state_id",
                                           $state_id.error())
        let bres = node.getBlockSlot(state_id.get())
        if bres.isErr():
          return RestApiResponse.jsonError(Http404, "State not found",
                                           $bres.error())
        bres.get()
    node.withStateForBlockSlot(bslot):
      return RestApiResponse.jsonResponse(
        (
          previous_justified: state().previous_justified_checkpoint,
          current_justified: state().current_justified_checkpoint,
          finalized: state().finalized_checkpoint
        )
      )
    return RestApiResponse.jsonError(Http500, "Internal server error")

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getStateValidators
  router.api(MethodGet, "/api/eth/v1/beacon/states/{state_id}/validators") do (
    state_id: StateIdent, id: seq[ValidatorIdent],
    status: seq[ValidatorFilter]) -> RestApiResponse:
    let bslot =
      block:
        if state_id.isErr():
          return RestApiResponse.jsonError(Http400, "Invalid state_id",
                                           $state_id.error())
        let bres = node.getBlockSlot(state_id.get())
        if bres.isErr():
          return RestApiResponse.jsonError(Http404, "State not found",
                                           $bres.error())
        bres.get()
    let validatorIds =
      block:
        if id.isErr():
          return RestApiResponse.jsonError(Http400,
                                           "Invalid validator identifier(s)")
        id.get()

    let validatorsMask =
      block:
        if status.isErr():
          return RestApiResponse.jsonError(Http400,
                                           "Invalid validator status(es)")
        let res = validateFilter(status.get())
        if res.isErr():
          return RestApiResponse.jsonError(Http400,
                                           "Invalid validator status value",
                                           $res.error())
        res.get()

    let (keySet, indexSet) =
      block:
        var res1: HashSet[ValidatorPubKey]
        var res2: HashSet[ValidatorIndex]
        for item in validatorIds:
          case item.kind
          of ValidatorQueryKind.Key:
            if item.key in res1:
              return RestApiResponse.jsonError(Http400,
                                           "Only unique validator keys allowed")
            res1.incl(item.key)
          of ValidatorQueryKind.Index:
            if item.index in res2:
              return RestApiResponse.jsonError(Http400,
                                        "Only unique validator indexes allowed")
            res2.incl(item.index)
        (res1, res2)

    node.withStateForBlockSlot(bslot):
      let current_epoch = get_current_epoch(node.chainDag.headState.data.data)
      var res: seq[ValidatorTuple]
      for index, validator in state().validators.pairs():
        let r1 =
          if len(keySet) == 0:
            true
          else:
            (validator.pubkey in keySet)
        let r2 =
          if len(indexSet) == 0:
            true
          else:
            (ValidatorIndex(index) in indexSet)
        let sres = validator.getStatus(current_epoch)
        if sres.isOk():
          let vstatus = sres.get()
          let r3 = vstatus in validatorsMask
          if (r1 or r2) and r3:
            res.add((
              index: ValidatorIndex(index),
              balance: Base10.toString(state().balances[index]),
              status: toString(vstatus),
              validator: validator
            ))
      return RestApiResponse.jsonResponse(res)

    return RestApiResponse.jsonError(Http500, "Internal server error")

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getStateValidator
  router.api(MethodGet,
          "/api/eth/v1/beacon/states/{state_id}/validators/{validator_id}") do (
    state_id: StateIdent, validator_id: ValidatorIdent) -> RestApiResponse:
    let bslot =
      block:
        if state_id.isErr():
          return RestApiResponse.jsonError(Http400, "Invalid state_id",
                                           $state_id.error())
        let bres = node.getBlockSlot(state_id.get())
        if bres.isErr():
          return RestApiResponse.jsonError(Http404, "State not found",
                                           $bres.error())
        bres.get()
    if validator_id.isErr():
      return RestApiResponse.jsonError(Http400, "Invalid validator_id",
                                       $validator_id.error())
    node.withStateForBlockSlot(bslot):
      let current_epoch = get_current_epoch(node.chainDag.headState.data.data)
      let vid = validator_id.get()
      case vid.kind
      of ValidatorQueryKind.Key:
        for index, validator in state().validators.pairs():
          if validator.pubkey == vid.key:
            let sres = validator.getStatus(current_epoch)
            if sres.isOk():
              return RestApiResponse.jsonResponse(
                (
                  index: ValidatorIndex(index),
                  balance: Base10.toString(state().balances[index]),
                  status: toString(sres.get()),
                  validator: validator
                )
              )
            else:
              return RestApiResponse.jsonError(Http400,
                                          "Could not obtain validator's status")
        return RestApiResponse.jsonError(Http404, "Could not find validator")
      of ValidatorQueryKind.Index:
        let index = uint64(vid.index)
        if index >= uint64(len(state().validators)):
          return RestApiResponse.jsonError(Http404, "Could not find validator")
        let validator = state().validators[index]
        let sres = validator.getStatus(current_epoch)
        if sres.isOk():
          return RestApiResponse.jsonResponse(
            (
              index: ValidatorIndex(index),
              balance: Base10.toString(state().balances[index]),
              status: toString(sres.get()),
              validator: validator
            )
          )
        else:
          return RestApiResponse.jsonError(Http400,
                                          "Could not obtain validator's status")
    return RestApiResponse.jsonError(Http500, "Internal server error")

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getStateValidatorBalances
  router.api(MethodGet,
             "/api/eth/v1/beacon/states/{state_id}/validator_balances") do (
    state_id: StateIdent, id: seq[ValidatorIdent]) -> RestApiResponse:
    let bslot =
      block:
        if state_id.isErr():
          return RestApiResponse.jsonError(Http400, "Invalid state_id",
                                           $state_id.error())
        let bres = node.getBlockSlot(state_id.get())
        if bres.isErr():
          return RestApiResponse.jsonError(Http404, "State not found",
                                           $bres.error())
        bres.get()
    let validatorIds =
      block:
        if id.isErr():
          return RestApiResponse.jsonError(Http400,
                                           "Invalid validator identifier(s)")
        id.get()
    let (keySet, indexSet) =
      block:
        var res1: HashSet[ValidatorPubKey]
        var res2: HashSet[ValidatorIndex]
        for item in validatorIds:
          case item.kind
          of ValidatorQueryKind.Key:
            if item.key in res1:
              return RestApiResponse.jsonError(Http400,
                                           "Only unique validator keys allowed")
            res1.incl(item.key)
          of ValidatorQueryKind.Index:
            if item.index in res2:
              return RestApiResponse.jsonError(Http400,
                                        "Only unique validator indexes allowed")
            res2.incl(item.index)
        (res1, res2)
    node.withStateForBlockSlot(bslot):
      let current_epoch = get_current_epoch(node.chainDag.headState.data.data)
      var res: seq[ValidatorBalanceTuple]
      for index, validator in state().validators.pairs():
        let rflag =
          if (len(keySet) == 0) and (len(indexSet) == 0):
            true
          else:
            (validator.pubkey in keySet) or (ValidatorIndex(index) in indexSet)
        let sres = validator.getStatus(current_epoch)
        if sres.isOk():
          let vstatus = sres.get()
          if rflag:
            res.add((
              index: ValidatorIndex(index),
              balance: Base10.toString(state().balances[index]),
            ))
      return RestApiResponse.jsonResponse(res)

    return RestApiResponse.jsonError(Http500, "Internal server error")

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getEpochCommittees
  router.api(MethodGet,
             "/api/eth/v1/beacon/states/{state_id}/committees") do (
    state_id: StateIdent, epoch: Option[Epoch], index: Option[CommitteeIndex],
    slot: Option[Slot]) -> RestApiResponse:
    let bslot =
      block:
        if state_id.isErr():
          return RestApiResponse.jsonError(Http400, "Invalid state_id",
                                           $state_id.error())
        let bres = node.getBlockSlot(state_id.get())
        if bres.isErr():
          return RestApiResponse.jsonError(Http404, "State not found",
                                           $bres.error())
        bres.get()
    let vepoch =
      if epoch.isSome():
        let repoch = epoch.get()
        if repoch.isErr():
          return RestApiResponse.jsonError(Http400, "Invalid epoch value",
                                           $repoch.error())
        some(repoch.get())
      else:
        none[Epoch]()
    let vindex =
      if index.isSome():
        let rindex = index.get()
        if rindex.isErr():
          return RestApiResponse.jsonError(Http400, "Invalid index value",
                                           $rindex.error())
        some(rindex.get())
      else:
        none[CommitteeIndex]()
    let vslot =
      if slot.isSome():
        let rslot = slot.get()
        if rslot.isErr():
          return RestApiResponse.jsonError(Http400, "Invalid slot value",
                                           $rslot.error())
        some(rslot.get())
      else:
        none[Slot]()
    node.withStateForBlockSlot(bslot):
      proc getCommittee(slot: Slot,
                        index: CommitteeIndex): BeaconStatesCommitteesTuple =
        let validators = get_beacon_committee(state, slot, index,
                                              cache).mapIt(it)
        (index: index, slot: slot, validators: validators)

      proc forSlot(slot: Slot, cindex: Option[CommitteeIndex],
                   res: var seq[BeaconStatesCommitteesTuple]) =
        let committees_per_slot =
          get_committee_count_per_slot(state, Epoch(slot), cache)

        if cindex.isNone:
          for committee_index in 0'u64 ..< committees_per_slot:
            res.add(getCommittee(slot, CommitteeIndex(committee_index)))
        else:
          let idx = cindex.get()
          if uint64(idx) < committees_per_slot:
            res.add(getCommittee(slot, CommitteeIndex(idx)))

      var res: seq[BeaconStatesCommitteesTuple]
      let qepoch =
        if vepoch.isNone:
          compute_epoch_at_slot(state().slot)
        else:
          vepoch.get()

      if vslot.isNone():
        for i in 0 ..< SLOTS_PER_EPOCH:
          forSlot(compute_start_slot_at_epoch(qepoch) + i, vindex, res)
      else:
        forSlot(vslot.get(), vindex, res)

      return RestApiResponse.jsonResponse(res)

    return RestApiResponse.jsonError(Http500, "Internal server error")

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getBlockHeaders
  router.api(MethodGet, "/api/eth/v1/beacon/headers") do (
    slot: Option[Slot], parent_root: Option[Eth2Digest]) -> RestApiResponse:
    return RestApiResponse.jsonError(Http500, "Not implemented yet")

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getBlockHeader
  router.api(MethodGet, "/api/eth/v1/beacon/headers/{block_id}") do (
    block_id: BlockIdent) -> RestApiResponse:
    let bdata =
      block:
        if block_id.isErr():
          return RestApiResponse.jsonError(Http400, "Invalid block_id",
                                           $block_id.error())
        let res = node.getBlockDataFromBlockIdent(block_id.get())
        if res.isErr():
          return RestApiResponse.jsonError(Http404, "Block not found")
        res.get()

    return RestApiResponse.jsonResponse(
      (
        root: bdata.data.root,
        canonical: bdata.refs.isAncestorOf(node.chainDag.head),
        header: (
          message: (
            slot: bdata.data.message.slot,
            proposer_index: bdata.data.message.proposer_index,
            parent_root: bdata.data.message.parent_root,
            state_root: bdata.data.message.state_root,
            body_root: bdata.data.message.body.hash_tree_root()
          ),
          signature: bdata.data.signature
        )
      )
    )

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/publishBlock
  router.api(MethodPost, "/api/eth/v1/beacon/blocks") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let blck =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http400, "Empty request's body")
        let dres = decodeBody(SignedBeaconBlock, contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400, "Unable to decode block " &
                                           "object", $dres.error())
        dres.get()
    let head = node.chainDag.head
    if not(node.isSynced(head)):
      return RestApiResponse.jsonError(Http503, "Beacon node is currently " &
        "syncing and not serving request on that endpoint")

    if head.slot >= blck.message.slot:
      node.network.broadcast(getBeaconBlocksTopic(node.forkDigest), blck)
      return RestApiResponse.jsonError(Http202, "The block failed " &
        "validation, but was successfully broadcast anyway. It was not " &
        "integrated into the beacon node's database.")
    else:
      let res = proposeSignedBlock(node, head, AttachedValidator(), blck)
      if res == head:
        node.network.broadcast(getBeaconBlocksTopic(node.forkDigest), blck)
        return RestApiResponse.jsonError(Http202, "The block failed " &
          "validation, but was successfully broadcast anyway. It was not " &
          "integrated into the beacon node's database.")
      else:
        return RestApiResponse.jsonError(Http200, "The block was validated " &
          "successfully and has been broadcast")

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getBlock
  router.api(MethodGet, "/api/eth/v1/beacon/blocks/{block_id}") do (
    block_id: BlockIdent) -> RestApiResponse:
    let bdata =
      block:
        if block_id.isErr():
          return RestApiResponse.jsonError(Http400, "Invalid block_id",
                                           $block_id.error())
        let res = node.getBlockDataFromBlockIdent(block_id.get())
        if res.isErr():
          return RestApiResponse.jsonError(Http404, "Block not found")
        res.get()
    return RestApiResponse.jsonResponse(bdata.data)

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getBlockRoot
  router.api(MethodGet, "/api/eth/v1/beacon/blocks/{block_id}/root") do (
    block_id: BlockIdent) -> RestApiResponse:
    let bdata =
      block:
        if block_id.isErr():
          return RestApiResponse.jsonError(Http400, "Invalid block_id",
                                           $block_id.error())
        let res = node.getBlockDataFromBlockIdent(block_id.get())
        if res.isErr():
          return RestApiResponse.jsonError(Http404, "Block not found")
        res.get()
    return RestApiResponse.jsonResponse((root: bdata.data.root))

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getBlockAttestations
  router.api(MethodGet,
             "/api/eth/v1/beacon/blocks/{block_id}/attestations") do (
    block_id: BlockIdent) -> RestApiResponse:
    let bdata =
      block:
        if block_id.isErr():
          return RestApiResponse.jsonError(Http400, "Invalid block_id",
                                           $block_id.error())
        let res = node.getBlockDataFromBlockIdent(block_id.get())
        if res.isErr():
          return RestApiResponse.jsonError(Http404, "Block not found")
        res.get()
    return RestApiResponse.jsonResponse(
      bdata.data.message.body.attestations.asSeq()
    )

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getPoolAttestations
  router.api(MethodGet, "/api/eth/v1/beacon/pool/attestations") do (
    slot: Option[Slot],
    committee_index: Option[CommitteeIndex]) -> RestApiResponse:
    let vindex =
      if committee_index.isSome():
        let rindex = committee_index.get()
        if rindex.isErr():
          return RestApiResponse.jsonError(Http400,
                                           "Invalid committee_index value",
                                           $rindex.error())
        some(rindex.get())
      else:
        none[CommitteeIndex]()
    let vslot =
      if slot.isSome():
        let rslot = slot.get()
        if rslot.isErr():
          return RestApiResponse.jsonError(Http400, "Invalid slot value",
                                           $rslot.error())
        some(rslot.get())
      else:
        none[Slot]()
    var res: seq[Attestation]
    for item in node.attestationPool[].attestations(vslot, vindex):
      res.add(item)
    return RestApiResponse.jsonResponse(res)

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/submitPoolAttestations
  router.api(MethodPost, "/api/eth/v1/beacon/pool/attestations") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let attestations =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http400, "Empty request's body")
        let dres = decodeBody(seq[Attestation], contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400, "Unable to decode " &
                                           "attestation object(s)",
                                           $dres.error())
        dres.get()

    var failures: seq[FailureTuple]
    for atindex, attestation in attestations.pairs():
      let wallTime = node.processor.getWallTime()
      let res = node.attestationPool[].validateAttestation(
        attestation, wallTime, attestation.data.index, true
      )
      if res.isErr():
        failures.add((index: uint64(atindex), message: $res.error()))
      else:
        node.sendAttestation(attestation)

    if len(failures) > 0:
      return RestApiResponse.jsonErrorList(Http400, "Some failures happened",
                                           failures)
    else:
      return RestApiResponse.jsonError(Http200,
                                       "Attestation(s) was broadcasted")

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getPoolAttesterSlashings
  router.api(MethodGet, "/api/eth/v1/beacon/pool/attester_slashings") do (
    ) -> RestApiResponse:
    var res: seq[AttesterSlashing]
    if isNil(node.exitPool):
      return RestApiResponse.jsonResponse(res)
    let length = len(node.exitPool.attester_slashings)
    res = newSeqOfCap[AttesterSlashing](length)
    for item in node.exitPool.attester_slashings.items():
      res.add(item)
    return RestApiResponse.jsonResponse(res)

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/submitPoolAttesterSlashings
  router.api(MethodPost, "/api/eth/v1/beacon/pool/attester_slashings") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let slashing =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http400, "Empty request's body")
        let dres = decodeBody(AttesterSlashing, contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400, "Unable to decode " &
            "attester slashing object", $dres.error())
        let res = dres.get()
        let vres = node.exitPool[].validateAttesterSlashing(res)
        if vres.isErr():
          return RestApiResponse.jsonError(Http400, "Invalid attester " &
            "slashing, it will never pass validation so it's rejected",
            $vres.error())
        res
    node.sendAttesterSlashing(slashing)
    return RestApiResponse.jsonError(Http200,
                                     "Attester slashing was broadcasted")

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getPoolProposerSlashings
  router.api(MethodGet, "/api/eth/v1/beacon/pool/proposer_slashings") do (
    ) -> RestApiResponse:
    var res: seq[ProposerSlashing]
    if isNil(node.exitPool):
      return RestApiResponse.jsonResponse(res)
    let length = len(node.exitPool.proposer_slashings)
    res = newSeqOfCap[ProposerSlashing](length)
    for item in node.exitPool.proposer_slashings.items():
      res.add(item)
    return RestApiResponse.jsonResponse(res)

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/submitPoolProposerSlashings
  router.api(MethodPost, "/api/eth/v1/beacon/pool/proposer_slashings") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let slashing =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http400, "Empty request's body")
        let dres = decodeBody(ProposerSlashing, contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400, "Unable to decode " &
            "proposer slashing object", $dres.error())
        let res = dres.get()
        let vres = node.exitPool[].validateProposerSlashing(res)
        if vres.isErr():
          return RestApiResponse.jsonError(Http400, "Invalid proposer " &
            "slashing, it will never pass validation so it's rejected",
            $vres.error())
        res
    node.sendProposerSlashing(slashing)
    return RestApiResponse.jsonError(Http200,
                                     "Proposer slashing was broadcasted")

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getPoolVoluntaryExits
  router.api(MethodGet, "/api/eth/v1/beacon/pool/voluntary_exits") do (
    ) -> RestApiResponse:
    var res: seq[SignedVoluntaryExit]
    if isNil(node.exitPool):
      return RestApiResponse.jsonResponse(res)
    let length = len(node.exitPool.voluntary_exits)
    res = newSeqOfCap[SignedVoluntaryExit](length)
    for item in node.exitPool.voluntary_exits.items():
      res.add(item)
    return RestApiResponse.jsonResponse(res)

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/submitPoolVoluntaryExit
  router.api(MethodPost, "/api/eth/v1/beacon/pool/voluntary_exits") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let exit =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http400, "Empty request's body")
        let dres = decodeBody(SignedVoluntaryExit, contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400, "Unable to decode " &
            "voluntary exit object", $dres.error())
        let res = dres.get()
        let vres = node.exitPool[].validateVoluntaryExit(res)
        if vres.isErr():
          return RestApiResponse.jsonError(Http400, "Invalid voluntary exit, " &
            "it will never pass validation so it's rejected", $vres.error())
        res
    node.sendVoluntaryExit(exit)
    return RestApiResponse.jsonError(Http200,
                                     "Voluntary exit was broadcasted")
